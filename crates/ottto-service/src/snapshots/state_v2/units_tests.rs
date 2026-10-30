//! CI fixtures. No test is executed by the local implementation helper.
use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Repeat(u64);
impl Value for Repeat {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let block = [b'x'; 4096];
        let mut left = self.0;
        while left != 0 {
            let n = left.min(block.len() as u64) as usize;
            out.write_all(&block[..n])?;
            left -= n as u64;
        }
        Ok(())
    }
}
fn identity() -> Identity {
    Identity {
        format: FORMAT,
        db_id: "synthetic-units".into(),
        fence_generation: 0,
        binding: super::super::super::scan_index_persistence::Binding {
            source: super::super::super::scan_index_persistence::Source::Claude,
            namespace_hash: "a".repeat(64),
        },
    }
}
fn header(name: &str, len: u64) -> Header {
    let key = RowKey::record("raw_hold.files", name.as_bytes(), 0).unwrap();
    preflight(&RowInput {
        key: &key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &Repeat(len),
    })
    .unwrap()
}
fn change(name: &str) -> Change {
    Change {
        before: None,
        after: Some(header(name, 1)),
        refs_only: false,
    }
}
fn scope(n: u8) -> Scope {
    Scope::File(vec![n])
}
fn plan() -> Planner {
    Planner::new(identity(), 0, Schedule::default())
}
fn add(p: &mut Planner, name: &str, scopes: Vec<Scope>, stage: u64) {
    p.add(scopes, vec![change(name)], stage, 0).unwrap();
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-v2-unit-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("index.v2.sqlite.import")
    }
    fn store(&self) -> sqlite::Sqlite {
        let mut db = sqlite::Sqlite::create_import(&self.path()).unwrap();
        db.control("identity", &identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        db.finish_import().unwrap();
        let mut db = sqlite::Sqlite::open(&self.path(), &identity()).unwrap();
        // Synthetic values contain repeated ASCII counts only, no private text.
        db.path_extractor(|_, _, _| Ok(()));
        db
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn write(tx: &mut impl Transaction, h: &Header) {
    let actual = tx
        .put(RowInput {
            key: &h.key,
            fixed: &h.fixed,
            value_version: 1,
            value: &Repeat(h.len),
        })
        .unwrap();
    assert_eq!(actual, *h);
}

#[test]
fn transitive_file_family_census_ack_units_are_never_split() {
    let mut p = plan();
    add(
        &mut p,
        "progress-a",
        vec![scope(1), Scope::Family(b"family".to_vec())],
        12 * 1024 * 1024,
    );
    add(
        &mut p,
        "census-b",
        vec![
            scope(2),
            Scope::Family(b"family".to_vec()),
            Scope::Census(b"c".to_vec()),
        ],
        12 * 1024 * 1024,
    );
    add(
        &mut p,
        "ack-c",
        vec![
            Scope::Census(b"c".to_vec()),
            Scope::Ack(b"receipt".to_vec()),
        ],
        12 * 1024 * 1024,
    );
    let selection = p.select().unwrap();
    assert_eq!(selection.selected_units, 1);
    assert_eq!(selection.keys().count(), 3);
    assert!(selection.charge.bytes > SOFT_BYTES);
    assert!(selection.charge.fits(Charge::hard()));
}

#[test]
fn fair_cursor_drains_larger_unit_before_small_new_work_after_restart() {
    let mut p = plan();
    for n in 0..4 {
        add(&mut p, &format!("{n}"), vec![scope(n)], 20 * 1024 * 1024);
    }
    let first = p.select().unwrap();
    assert_eq!(first.keys().count(), 1);
    let first_key = first.keys().next().unwrap().clone();
    let restored: Schedule =
        serde_json::from_slice(&serde_json::to_vec(&first.next_schedule).unwrap()).unwrap();
    let mut p = Planner::new(identity(), 1, restored);
    // Include the same still-dirty resource to model immediate renewed work.
    for n in 0..4 {
        add(&mut p, &format!("{n}"), vec![scope(n)], 20 * 1024 * 1024);
    }
    let second = p.select().unwrap();
    assert_eq!(second.keys().count(), 1);
    assert_ne!(second.keys().next(), Some(&first_key));
    assert_eq!(second.next_schedule.deferred, 3);
}

#[test]
fn hard_ceiling_holds_whole_unit_but_other_units_can_drain() {
    let mut p = plan();
    add(
        &mut p,
        "held-a",
        vec![scope(1), Scope::Family(b"huge".to_vec())],
        HARD_BYTES,
    );
    add(
        &mut p,
        "held-b",
        vec![scope(2), Scope::Family(b"huge".to_vec())],
        1,
    );
    add(&mut p, "safe", vec![scope(3)], 0);
    let selection = p.select().unwrap();
    assert_eq!(selection.held, 1);
    assert_eq!(
        selection.holds().values().copied().collect::<Vec<_>>(),
        vec![UnitHold::HardCeiling]
    );
    assert_eq!(
        selection.keys().cloned().collect::<Vec<_>>(),
        vec![change("safe").after.unwrap().key]
    );
    assert_eq!(selection.next_schedule.deferred, 1);
}

#[test]
fn exact_ceiling_includes_staging_system_controls_and_metadata() {
    let c = change("boundary");
    let overhead = c.charge().unwrap().bytes + Charge::reserve().bytes;
    let mut p = plan();
    p.add(vec![scope(1)], vec![c.clone()], HARD_BYTES - overhead, 65)
        .unwrap();
    let selection = p.select().unwrap();
    assert_eq!(selection.charge.bytes, HARD_BYTES);
    assert_eq!((selection.selected_units, selection.windows_alarm), (1, 1));
    let mut p = plan();
    p.add(vec![scope(1)], vec![c], HARD_BYTES - overhead + 1, 0)
        .unwrap();
    let selection = p.select().unwrap();
    assert_eq!((selection.selected_units, selection.held), (0, 1));
}

#[test]
fn charge_counts_old_and_new_chunks_tombstone_and_ref_changes() {
    let old = header("chunked", PART_BYTES as u64 + 1);
    let new = header("chunked", 1);
    let replacement = Charge::mutation(Some(&old), Some(&new), false).unwrap();
    let deletion = Charge::mutation(Some(&old), None, false).unwrap();
    assert_eq!((replacement.rows, deletion.rows), (3, 3));
    assert!(replacement.bytes > old.len + new.len);
    assert!(deletion.bytes > old.len);
    let ref_change = Charge::mutation(Some(&old), Some(&new), true).unwrap();
    assert_eq!(ref_change.rows, 1);
    assert!(ref_change.bytes < deletion.bytes);
}

#[test]
fn malformed_or_duplicate_fragment_cannot_leave_a_committable_prefix() {
    let mut p = plan();
    assert!(p.add(Vec::<Scope>::new(), vec![change("a")], 0, 0).is_err());
    let wrong = Change {
        before: Some(header("old", 1)),
        after: Some(header("other", 2)),
        refs_only: false,
    };
    assert!(p
        .add(vec![scope(1)], vec![change("a"), wrong], 0, 0)
        .is_err());
    assert!(p.keys.is_empty() && p.fragments.is_empty());
    assert!(p
        .add(vec![scope(1)], vec![change("a"), change("a")], 0, 0)
        .is_err());
    add(&mut p, "a", vec![scope(1)], 0);
    assert!(p.add(vec![scope(2)], vec![change("a")], 0, 0).is_err());
    assert_eq!(p.select().unwrap().keys().count(), 1);
}

#[test]
fn selected_headers_all_commit_or_none_and_schedule_is_transactional() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let mut p = plan();
    add(&mut p, "a", vec![scope(1)], 0);
    add(&mut p, "b", vec![scope(1)], 0);
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    write(&mut tx, &header("a", 1));
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    assert_eq!(db.read_control::<u64>("generation").unwrap(), Some(0));
    assert!(db
        .read_control::<Schedule>("unit_schedule")
        .unwrap()
        .is_none());
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&header("a", 1).key).unwrap().is_none());
    drop(tx);
    let mut p = plan();
    add(&mut p, "a", vec![scope(1)], 0);
    add(&mut p, "b", vec![scope(1)], 0);
    let selection = p.select().unwrap();
    let expected_schedule = selection.next_schedule.clone();
    let mut tx = db.begin_selected(selection).unwrap();
    write(&mut tx, &header("a", 1));
    write(&mut tx, &header("b", 1));
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    assert_eq!(
        db.read_control::<Schedule>("unit_schedule").unwrap(),
        Some(expected_schedule)
    );
}

#[test]
fn unplanned_change_wrong_final_value_and_stale_generation_refuse_publication() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let mut p = plan();
    add(&mut p, "a", vec![scope(1)], 0);
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    assert!(tx
        .put(RowInput {
            key: &header("b", 1).key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &Repeat(1)
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    let mut p = plan();
    add(&mut p, "a", vec![scope(1)], 0);
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    // Same size, distinct bytes: header digest equality is checked at COMMIT.
    struct Other;
    impl Value for Other {
        fn write(&self, out: &mut dyn Write) -> Result<()> {
            out.write_all(b"y")?;
            Ok(())
        }
    }
    tx.put(RowInput {
        key: &header("a", 1).key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &Other,
    })
    .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    let p = Planner::new(identity(), 1, Schedule::default());
    assert!(db.begin_selected(p.select().unwrap()).is_err());
}

#[test]
fn standalone_large_unit_exceeds_soft_limit_and_survives_reopen() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let h = header("large", 33 * 1024 * 1024);
    let mut p = plan();
    p.add(
        vec![scope(1)],
        vec![Change {
            before: None,
            after: Some(h.clone()),
            refs_only: false,
        }],
        4096,
        0,
    )
    .unwrap();
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    write(&mut tx, &h);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    drop(db);
    let mut db = sqlite::Sqlite::open(&scratch.path(), &identity()).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert_eq!(tx.get(&h.key).unwrap(), Some(h.clone()));
    tx.read_value(&h, &mut std::io::sink()).unwrap();
    assert_eq!(Schedule::read(&mut tx).unwrap().passes, 1);
}

#[test]
fn actual_cost_increase_and_stale_before_header_are_rejected() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let mut p = plan();
    add(&mut p, "a", vec![scope(1)], 0);
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    assert!(tx
        .put(RowInput {
            key: &header("a", 1).key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &Repeat(1024 * 1024)
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
    let mut p = plan();
    p.add(
        vec![scope(1)],
        vec![Change {
            before: Some(header("a", 1)),
            after: Some(header("a", 2)),
            refs_only: false,
        }],
        0,
        0,
    )
    .unwrap();
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    assert!(tx
        .put(RowInput {
            key: &header("a", 2).key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &Repeat(2)
        })
        .is_err());
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::NotPublished);
}

#[test]
fn selected_reference_update_then_last_release_marks_erasure_with_its_generation() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let key = RowKey::RequestSet(1);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let before = tx
        .put(RowInput {
            key: &key,
            fixed: &Fixed::RequestSet {
                commitment: [3; 32],
                refs: 1,
            },
            value_version: 1,
            value: &Repeat(10),
        })
        .unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut after = before.clone();
    if let Fixed::RequestSet { refs, .. } = &mut after.fixed {
        *refs = 2;
    }
    after.row_checksum = row_checksum(&after).unwrap();
    let mut p = Planner::new(identity(), 1, Schedule::default());
    p.add(
        vec![Scope::Family(b"family".to_vec())],
        vec![Change {
            before: Some(before),
            after: Some(after.clone()),
            refs_only: true,
        }],
        0,
        0,
    )
    .unwrap();
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    assert_eq!(tx.adjust_refs(&key, 1).unwrap(), 2);
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(db.read_control::<u64>("erasure_pending").unwrap().is_none());
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let schedule = Schedule::read(&mut tx).unwrap();
    drop(tx);
    let mut p = Planner::new(identity(), 2, schedule);
    p.add(
        vec![Scope::Family(b"family".to_vec())],
        vec![Change {
            before: Some(after),
            after: None,
            refs_only: false,
        }],
        0,
        0,
    )
    .unwrap();
    let mut tx = db.begin_selected(p.select().unwrap()).unwrap();
    assert_eq!(tx.adjust_refs(&key, -2).unwrap(), 0);
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(3));
}

#[test]
fn persisted_cursor_drains_next_unit_and_stale_schedule_cannot_override_it() {
    let scratch = Scratch::new();
    let mut db = scratch.store();
    let mut p = plan();
    for n in 0..3 {
        add(&mut p, &format!("{n}"), vec![scope(n)], 20 * 1024 * 1024);
    }
    let selection = p.select().unwrap();
    let first_key = selection.keys().next().unwrap().clone();
    let mut tx = db.begin_selected(selection).unwrap();
    let h = preflight(&RowInput {
        key: &first_key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &Repeat(1),
    })
    .unwrap();
    write(&mut tx, &h);
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    drop(db);
    let mut db = sqlite::Sqlite::open(&scratch.path(), &identity()).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let restored = Schedule::read(&mut tx).unwrap();
    drop(tx);
    let mut p = Planner::new(identity(), 1, restored);
    for n in 0..3 {
        let original = header(&format!("{n}"), 1);
        let c = if original.key == first_key {
            Change {
                before: Some(original),
                after: Some(header(&format!("{n}"), 2)),
                refs_only: false,
            }
        } else {
            Change {
                before: None,
                after: Some(original),
                refs_only: false,
            }
        };
        p.add(vec![scope(n)], vec![c], 20 * 1024 * 1024, 0).unwrap();
    }
    let selection = p.select().unwrap();
    assert_ne!(selection.keys().next(), Some(&first_key));
    let mut stale = Planner::new(identity(), 1, Schedule::default());
    add(&mut stale, "stale", vec![scope(4)], 0);
    assert!(db.begin_selected(stale.select().unwrap()).is_err());
    // A different source generation/identity cannot borrow this unit budget.
    let mut foreign_id = identity();
    foreign_id.db_id = "other-db".into();
    let foreign = Planner::new(foreign_id, 1, selection.prior_schedule.clone());
    assert!(db.begin_selected(foreign.select().unwrap()).is_err());
}
