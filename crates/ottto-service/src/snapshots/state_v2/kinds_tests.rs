//! Integration fixtures; compiled locally, executed only in later CI.
use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn binding() -> super::super::super::scan_index_persistence::Binding {
        super::super::super::scan_index_persistence::Binding {
            source: super::super::super::scan_index_persistence::Source::Claude,
            namespace_hash: "a".repeat(64),
        }
    }
    fn store() -> (Self, sqlite::Sqlite) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-kinds-integration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        let mut db = sqlite::Sqlite::create_import(&dir.join("index.v2.sqlite.import")).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db.control(
            "identity",
            &Identity {
                format: FORMAT,
                db_id: "synthetic-integration".into(),
                binding: Self::binding(),
                fence_generation: 0,
            },
        )
        .unwrap();
        db.control("generation", &0_u64).unwrap();
        (Self(dir), db)
    }
    fn live_store() -> (Self, sqlite::Sqlite) {
        let (scratch, db) = Self::store();
        db.finish_import().unwrap();
        let mut db = sqlite::Sqlite::open(
            &scratch.0.join("index.v2.sqlite.import"),
            &Identity {
                format: FORMAT,
                db_id: "synthetic-integration".into(),
                binding: Self::binding(),
                fence_generation: 0,
            },
        )
        .unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        (scratch, db)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> ScanIndex {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let mut index: ScanIndex = serde_json::from_value(fixture["logical"].clone()).unwrap();
    index.generation = 0;
    index.upload_context_fingerprint = Some("/synthetic/exact-context".into());
    index
}
fn commit_populate(db: &mut sqlite::Sqlite, index: &ScanIndex) {
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut cx = KindCx {
        binding: Some(Scratch::binding()),
        ..Default::default()
    };
    populate(index, &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
}
#[test]
fn all_groups_share_one_snapshot_and_roundtrip_real_v1_without_losing_context_or_membership() {
    let (_scratch, mut db) = Scratch::store();
    let mut index = fixture();
    commit_populate(&mut db, &index);
    index.generation = 1;
    let (restored, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&index).unwrap()
    );
    assert_eq!(
        restored.decode_holds.v2_provenance(),
        index.decode_holds.v2_provenance()
    );
    assert!(cx.valid && cx.accounts_ready && !cx.misc_rows.is_empty());
    // Account hydration must not replace the common context and discard MISC
    // inventory or the source binding while installing its own resident headers.
    assert_eq!(cx.binding, Some(Scratch::binding()));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut after = None;
    let mut owners = 0;
    loop {
        let page = tx
            .scan_kind(
                &RecordKind::parse("family.requests").unwrap(),
                after.as_ref(),
                128,
            )
            .unwrap();
        if page.is_empty() {
            break;
        }
        owners += page.len();
        after = page.last().map(|h| h.key.clone());
    }
    let expected: usize = index
        .claude_usage_family_pending
        .values()
        .map(|p| 1 + p.member_request_id_hashes.len())
        .sum();
    assert_eq!(owners, expected);
}
#[test]
fn incomplete_census_group_cannot_escape_as_a_partially_hydrated_graph() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.delete(&RowKey::record("v1_field.census_shadow", Vec::new(), 0).unwrap())
        .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(hydrate(&mut db, Scratch::binding()).is_err());
}
#[test]
fn unchanged_groups_preserve_bytes_and_a_context_error_refuses_reuse() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation = 2;
    let before = cx.account_rows.clone();
    cx.preflight(&prev, &next, &mut kinds_files::NoResumeHooks)
        .unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    delta(&prev, &next, &mut tx, &mut cx, std::iter::empty::<String>()).unwrap();
    let outcome = tx.commit(1, 2);
    assert_eq!(outcome, DurableCommitOutcome::Committed(2));
    cx.post_commit(&outcome, &mut kinds_files::NoResumeHooks)
        .unwrap();
    assert_eq!(cx.account_rows, before);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    assert!(delta(&next, &next, &mut tx, &mut cx, ["unknown_money_class"]).is_err());
    assert!(!cx.valid);
    assert!(delta(&next, &next, &mut tx, &mut cx, std::iter::empty::<String>()).is_err());
}
#[test]
fn noop_resume_adapter_cannot_publish_new_file_progress() {
    let prev = ScanIndex::default();
    let next = fixture();
    let mut cx = KindCx {
        binding: Some(Scratch::binding()),
        ..Default::default()
    };
    assert!(cx
        .preflight(&prev, &next, &mut kinds_files::NoResumeHooks)
        .is_err());
    assert!(cx.prepared.is_none());
}

struct Stored(Vec<u8>);
impl Value for Stored {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}
#[test]
fn last_shared_literal_release_marks_erasure_in_the_deleting_transaction_and_rollback_keeps_it() {
    let (_scratch, mut db) = Scratch::live_store();
    let evidence = interning::RequestEvidence::Account {
        prefixes: "/synthetic/private-prefix",
        fingerprint: "literal/fp",
        identity_revision: Some("literal/rev"),
        hash_count: None,
    };
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let id = interning::intern_request_set(&mut tx, &evidence).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        interning::release_request_set(&mut tx, id).unwrap();
        // Dropping the transaction preserves both the reference and privacy state.
    }
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = tx.get(&RowKey::RequestSet(id)).unwrap().unwrap();
    let mut value = Vec::new();
    tx.read_value(&h, &mut value).unwrap();
    let mut strings = BTreeSet::new();
    private_paths(&h, &Stored(value), &mut |s| {
        strings.insert(s.to_owned());
        Ok(())
    })
    .unwrap();
    assert!(strings.contains("/synthetic/private-prefix"));
    interning::release_request_set(&mut tx, id).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&RowKey::RequestSet(id)).unwrap().is_none());
    let marker = tx
        .get(&RowKey::Meta("erasure_pending".into()))
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    tx.read_value(&marker, &mut bytes).unwrap();
    assert_eq!(serde_json::from_slice::<u64>(&bytes).unwrap(), 2);
}

#[test]
fn foreign_source_and_registered_but_unmapped_money_kinds_refuse_hydration() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let mut other = Scratch::binding();
    other.namespace_hash = "b".repeat(64);
    assert!(hydrate(&mut db, other).is_err());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    tx.put(RowInput {
        key: &RowKey::record("v1_field.census_money_marks", Vec::new(), 0).unwrap(),
        fixed: &Fixed::None,
        value_version: 1,
        value: &Stored(b"null".to_vec()),
    })
    .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(hydrate(&mut db, Scratch::binding())
        .err()
        .unwrap()
        .to_string()
        .contains("state_v2_unmapped_kind"));
}
#[test]
fn shared_privacy_dispatch_preserves_both_census_domains_and_account_exclusion_literals() {
    // Census's numeric domain contains no literal text; the string domain and
    // the independent account exclusion encoding retain exact spellings.
    for (payload, expected, count) in [
        (vec![1, 0, 0, 0, 0, 0, 0, 0, 7], None, 1),
        (
            {
                let mut bytes = vec![2];
                packed::Json(&BTreeSet::from(["/synthetic/private-membership"]))
                    .write(&mut bytes)
                    .unwrap();
                bytes
            },
            Some("/synthetic/private-membership"),
            1,
        ),
        (
            br#"["/synthetic/private-exclusion"]"#.to_vec(),
            Some("/synthetic/private-exclusion"),
            1,
        ),
    ] {
        let (_scratch, mut db) = Scratch::store();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let id = interning::intern_request_set(
            &mut tx,
            &interning::RequestEvidence::Census {
                hashes: &Stored(payload),
                hash_count: Some(count),
            },
        )
        .unwrap();
        let h = tx.get(&RowKey::RequestSet(id)).unwrap().unwrap();
        let mut bytes = Vec::new();
        tx.read_value(&h, &mut bytes).unwrap();
        let mut texts = Vec::new();
        private_paths(&h, &Stored(bytes), &mut |s| {
            texts.push(s.to_owned());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            texts,
            expected.into_iter().map(str::to_owned).collect::<Vec<_>>()
        );
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    }
}

#[derive(Default)]
struct SelectedHooks(Vec<&'static str>);
impl kinds_files::ResumeHooks for SelectedHooks {
    fn preflight_selected(
        &mut self,
        _: &ScanIndex,
        _: &ScanIndex,
        _: &BTreeMap<String, kinds_files::ResumeCheckpoint>,
    ) -> Result<u64> {
        self.0.push("preflight");
        Ok(0)
    }
    fn stage(
        &mut self,
        _: &ScanIndex,
        _: &ScanIndex,
        _: &BTreeMap<String, kinds_files::ResumeCheckpoint>,
    ) -> Result<kinds_files::StagedCheckpoints> {
        self.0.push("stage");
        Ok(Default::default())
    }
    fn post_commit(
        &mut self,
        _: u64,
        _: &BTreeMap<String, kinds_files::ResumeCheckpoint>,
    ) -> Result<()> {
        self.0.push("post_commit");
        Ok(())
    }
}
fn empty_selection(db: &mut sqlite::Sqlite, generation: u64) -> units::Selection {
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let schedule = units::Schedule::read(&mut tx).unwrap();
    units::Planner::new(identity, generation, schedule)
        .select()
        .unwrap()
}
#[test]
fn selected_save_installs_context_and_calls_r1_only_after_confirmed_commit() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    let selection = empty_selection(&mut db, prev.generation);
    let mut hooks = SelectedHooks::default();
    save_selected_graph(&mut db, &prev, &mut next, &mut cx, selection, &mut hooks).unwrap();
    assert_eq!(hooks.0, ["preflight", "stage", "post_commit"]);
    assert!(cx.valid && !cx.ambiguous && cx.prepared.is_none());
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let key = RowKey::Meta("generation".into());
    assert_eq!(cx.misc_rows[&key].0, tx.get(&key).unwrap().unwrap());
}
#[test]
fn unplanned_semantic_write_rolls_back_and_invalidates_context_without_r1_gc() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    next.upload_context_fingerprint = Some("selected-but-not-admitted".into());
    let selection = empty_selection(&mut db, prev.generation);
    let mut hooks = SelectedHooks::default();
    assert!(
        save_selected_graph(&mut db, &prev, &mut next, &mut cx, selection, &mut hooks).is_err()
    );
    assert_eq!(hooks.0, ["preflight", "stage"]);
    assert!(!cx.valid && cx.ambiguous);
    let (current, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(current.generation, prev.generation);
    assert_eq!(
        current.upload_context_fingerprint,
        prev.upload_context_fingerprint
    );
}
#[test]
fn stale_selected_generation_refuses_before_r1_preflight_or_staging() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    let selection = empty_selection(&mut db, 0);
    let mut hooks = SelectedHooks::default();
    assert!(
        save_selected_graph(&mut db, &prev, &mut next, &mut cx, selection, &mut hooks).is_err()
    );
    assert!(hooks.0.is_empty());
    assert!(!cx.valid);
}
#[test]
fn complete_misc_dirty_plan_covers_scalar_map_ack_and_raw_hold_changes() {
    let prev = fixture();
    let mut next = prev.clone();
    next.generation += 1;
    assert!(kinds_misc::dirty_fields(&prev, &next).unwrap().is_empty());
    next.upload_context_fingerprint = Some("different-context".into());
    next.accepted_snapshot_fingerprints.insert("e".repeat(64));
    next.decode_holds
        .v2_insert(
            "files",
            "/synthetic/held".into(),
            b"false".to_vec(),
            None,
            128,
        )
        .unwrap();
    assert_eq!(
        kinds_misc::dirty_fields(&prev, &next).unwrap(),
        BTreeSet::from([
            "upload_context_fingerprint".into(),
            "accepted_snapshot_fingerprints".into(),
            "decode_holds".into()
        ])
    );
}

#[test]
fn streamed_cas_merges_retry_and_growth_maxima_without_resurrecting_removed_quarantine() {
    let (_scratch, mut db) = Scratch::store();
    let mut index = fixture();
    let mut record =
        crate::snapshots::snapshot_quarantine_record(crate::snapshots::SnapshotSource::ClaudeCode);
    record.contract_retry_claims = Some(7);
    let key = "a".repeat(64);
    index
        .quarantined_snapshot_fingerprints
        .insert(key.clone(), record.clone());
    index
        .quarantined_snapshot_fingerprints
        .insert("b".repeat(64), record);
    index.growth_retention.insert(
        "/synthetic/grown".into(),
        serde_json::from_value(serde_json::json!({"last_growth_full_unix":20})).unwrap(),
    );
    commit_populate(&mut db, &index);
    let (mut working, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    let current_claims = working.quarantined_snapshot_fingerprints[&key].contract_retry_claims;
    working
        .quarantined_snapshot_fingerprints
        .get_mut(&key)
        .unwrap()
        .contract_retry_claims = Some(0);
    working
        .quarantined_snapshot_fingerprints
        .remove(&"b".repeat(64));
    working.growth_retention.clear();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    kinds_misc::merge_cas(&mut tx, &mut working).unwrap();
    kinds_files::merge_growth_cas(&mut tx, &mut working).unwrap();
    assert_eq!(
        working.quarantined_snapshot_fingerprints[&key].contract_retry_claims,
        current_claims
    );
    assert!(!working
        .quarantined_snapshot_fingerprints
        .contains_key(&"b".repeat(64)));
    assert_eq!(
        serde_json::to_value(&working.growth_retention["/synthetic/grown"]).unwrap()
            ["last_growth_full_unix"],
        20
    );
    working.generation += 1;
    assert!(kinds_misc::merge_cas(&mut tx, &mut working).is_err());
}
#[test]
fn growth_raw_hold_survives_composed_hydration_and_cas_cannot_release_it() {
    let (_scratch, mut db) = Scratch::store();
    let mut index = fixture();
    index
        .decode_holds
        .v2_insert(
            "growth_retention",
            "/synthetic/grown".into(),
            br#""opaque-clock""#.to_vec(),
            None,
            256,
        )
        .unwrap();
    index.decode_holds.v2_finish((19, 3));
    commit_populate(&mut db, &index);
    let (mut working, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(working.decode_holds.same_as(&index.decode_holds));
    assert_eq!(working.decode_holds.v2_provenance(), (19, 3));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    kinds_misc::merge_cas(&mut tx, &mut working).unwrap();
    working.decode_holds = Default::default();
    assert!(kinds_misc::merge_cas(&mut tx, &mut working).is_err());
}
#[test]
fn writer_capability_refuses_selected_save_before_any_r1_side_effect() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    let selection = empty_selection(&mut db, prev.generation);
    sqlite::future_writer_for_test(&mut db);
    let mut hooks = SelectedHooks::default();
    assert!(
        save_selected_graph(&mut db, &prev, &mut next, &mut cx, selection, &mut hooks).is_err()
    );
    assert!(hooks.0.is_empty());
    assert_eq!(next.generation, prev.generation);
}
