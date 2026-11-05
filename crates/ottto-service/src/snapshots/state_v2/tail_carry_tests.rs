//! Carry-specific transaction cases use the existing native route fixture.
use super::super::tail_route::carry_tail;
use super::*;
use crate::snapshots::ScanResidueWitness;

const MOVED: &str = "/synthetic/tail/file.jsonl.zst";
fn facts() -> InventoryFacts {
    InventoryFacts {
        owner: "session".into(),
        created_unix_ms: Some(123),
        read_bytes: 0,
        stamp: crate::snapshots::sampled_scan::codex_cursor::ContentStamp::from_parts(
            1,
            2,
            3,
            (4, 5),
        ),
    }
}
fn pair(index: &mut ScanIndex) -> Result<()> {
    carry_tail(
        index,
        MOVED,
        tail::PathCarry {
            from: FILE.into(),
            scan_root: PathBuf::from("/synthetic/tail"),
            head: b"rebound".to_vec(),
            inventory: facts(),
        },
    )
}
fn seed(f: &Fixture) -> ScanIndex {
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let mut entry = progress_row();
    entry.last_snapshot_fingerprint = Some("e".repeat(64));
    entry.last_upload_body_witness = Some("f".repeat(64));
    entry.set_unverified_deadline(11);
    index.files.insert(FILE.into(), entry);
    index
        .file_snapshot_fingerprints
        .insert(FILE.into(), BTreeSet::from(["e".repeat(64)]));
    index
        .accepted_rebuild_incidence
        .insert(FILE.into(), BTreeSet::from(["d".repeat(64)]));
    index.confirmed_empty_files.insert(FILE.into());
    index.v2_mut().growth_retention.insert(
        FILE.into(),
        serde_json::from_value(serde_json::json!({
            "predecessor_size": 2, "uncertain_passes": 3, "checked_generation": 5,
            "last_growth_full_unix": crate::snapshots::sampled_scan::now_seconds()
        }))
        .unwrap(),
    );
    index.scan_residue_witness = Some(ScanResidueWitness {
        index_keys: BTreeSet::from([FILE.into()]),
        ..Default::default()
    });
    stage_tail(
        &f.path,
        FILE,
        staged(b"old", &[(Collection::Responses, 0, &long_value())]),
    )
    .unwrap();
    observe_tail(&f.path, FILE, observation(&[b"unaccepted revision"])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    set_aside_tail(&f.path, FILE, SetAsideCause::Encode).unwrap();
    save_with(&f.path, &mut index).unwrap();
    index
}
fn assert_pair(index: &ScanIndex, moved: bool) {
    let (live, absent) = if moved { (MOVED, FILE) } else { (FILE, MOVED) };
    assert!(index.files.contains_key(live));
    assert!(!index.files.contains_key(absent));
    let entry = &index.files[live];
    assert_eq!(
        entry.last_snapshot_fingerprint.as_deref(),
        Some("e".repeat(64).as_str())
    );
    assert_eq!(
        entry.last_upload_body_witness.as_deref(),
        Some("f".repeat(64).as_str())
    );
    assert!(entry.has_unverified_source());
    assert_eq!(entry.unverified_deadline(), Some(11));
    assert!(index.confirmed_empty_files.contains(live));
    assert!(!index.confirmed_empty_files.contains(absent));
    assert!(index.v2().growth_retention.contains_key(live));
    assert!(!index.v2().growth_retention.contains_key(absent));
    assert_eq!(
        index.v2().growth_retention[live].checked_generation,
        Some(5)
    );
    assert!(index.accepted_rebuild_incidence.contains_key(live));
    assert!(!index.accepted_rebuild_incidence.contains_key(absent));
    assert_eq!(
        index.scan_residue_witness.as_ref().unwrap().index_keys,
        BTreeSet::from([live.into()])
    );
    assert!(load_head(index, absent, REVISION).unwrap().is_none());
    let (head, pages) = read(index, live).unwrap();
    let head = head.unwrap();
    assert_eq!(head.body, if moved { &b"rebound"[..] } else { &b"old"[..] });
    assert_eq!(head.common.debt.earliest_unacked_change_at, Some(7_000));
    assert_eq!(head.common.next_revision_id, 1);
    assert_eq!(pages[&(Collection::Responses, 0)], long_value());
    assert_eq!(
        revisions(index, live),
        BTreeMap::from([(0, b"unaccepted revision".to_vec())])
    );
    assert!(tail_set_aside(index, live).unwrap().is_some());
    assert!(tail_set_aside(index, absent).unwrap().is_none());
    if moved {
        assert_eq!(head.common.inventory, Some(facts()));
    }
}

/// [format] Before-COMMIT failure exposes the old pair. A confirmed COMMIT
/// followed by failed digest promotion exposes the complete new pair.
#[test]
fn paired_carry_commit_outcomes_are_complete_old_or_complete_new() {
    for published in [false, true] {
        let f = Fixture::new();
        let mut index = seed(&f);
        if published {
            kinds::FAIL_DIGEST_PROMOTION.with(|fail| fail.set(true));
        } else {
            with_session_db(&index, |db| sqlite::fence_commit_writing(db, "generation"));
        }
        assert!(pair(&mut index).is_err());
        assert!(index.files.contains_key(FILE));
        assert!(!index.files.contains_key(MOVED));
        drop(BaselineRelease::new(&f.path, &index));
        let index = load_with(&f.path, false).unwrap().unwrap();
        assert_pair(&index, published);
    }
}
