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
/// [regress] v2 hydration's closed catalogue includes its own growth raw holds.
#[test]
fn owned_kinds_are_admitted_without_adding_v1_growth_slots() {
    for (kind, _) in catalogue::OWNED {
        assert_eq!(RecordKind::parse(kind).unwrap().name(), *kind);
    }
    // Names no semantic group owns refuse like any other unknown kind.
    for kind in [
        "raw_hold.future",
        "v1_field.growth_retention",
        "file.receipt",
        "account.window_retention",
    ] {
        let error = RecordKind::parse(kind).unwrap_err();
        assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::UnknownRecordKind));
    }
}

/// [format] all groups share one snapshot and roundtrip real v1 without losing context or membership.
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
    assert!(cx.valid && !cx.misc_rows.is_empty());
    // Account hydration must not replace the common context and discard MISC
    // inventory or the source binding while hydrating its own graph.
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
    let expected = 1 + index.claude_usage_family_pending.len();
    assert_eq!(owners, expected);
}

/// [format] incomplete census group cannot escape as a partially hydrated graph.
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

struct Stored(Vec<u8>);
impl Value for Stored {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&self.0)?;
        Ok(())
    }
}
/// [format] last shared literal release marks erasure in the deleting transaction and rollback keeps it.
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

/// [format] foreign source and registered but unmapped money kinds refuse hydration.
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
        value: b"null",
    })
    .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(hydrate(&mut db, Scratch::binding())
        .err()
        .unwrap()
        .to_string()
        .contains("state_v2_unmapped_kind"));
}
/// [format] generic erasure extraction visits nested text keys and shared evidence.
#[test]
fn generic_erasure_extraction_visits_nested_text_keys_and_shared_evidence() {
    let (_scratch, mut db) = Scratch::store();
    let payload = serde_json::json!({"/synthetic/private-key":["literal/title",{"nested":"private/evidence"}]});
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let id = interning::intern(&mut tx, &payload).unwrap();
    let h = tx.get(&RowKey::RequestSet(id)).unwrap().unwrap();
    let mut raw = Vec::new();
    tx.read_value(&h, &mut raw).unwrap();
    let mut strings = BTreeSet::new();
    private_paths(&h, &Stored(raw), &mut |s| {
        strings.insert(s.to_owned());
        Ok(())
    })
    .unwrap();
    for text in [
        "/synthetic/private-key",
        "literal/title",
        "private/evidence",
    ] {
        assert!(strings.contains(text));
    }
}

/// [format] complete misc dirty plan covers scalar map ack and raw hold changes.
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

/// [money] streamed cas merges retry and growth maxima without resurrecting removed quarantine.
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
    index.v2_mut().growth_retention.insert(
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
    working.v2_mut().growth_retention.clear();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let generation = working.generation;
    kinds_misc::merge_cas_at(&mut tx, &mut working, generation).unwrap();
    kinds_files::merge_growth_cas(&mut tx, &mut working).unwrap();
    assert_eq!(
        working.quarantined_snapshot_fingerprints[&key].contract_retry_claims,
        current_claims
    );
    assert!(!working
        .quarantined_snapshot_fingerprints
        .contains_key(&"b".repeat(64)));
    assert_eq!(
        serde_json::to_value(&working.v2().growth_retention["/synthetic/grown"]).unwrap()
            ["last_growth_full_unix"],
        20
    );
    assert!(kinds_misc::merge_cas_at(&mut tx, &mut working, generation + 1).is_err());
}
/// [money] growth raw hold survives composed hydration and cas cannot release it.
#[test]
fn growth_raw_hold_survives_composed_hydration_and_cas_cannot_release_it() {
    for present in [false, true] {
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
        index.v2_mut().growth_retention.insert(
            "/synthetic/claim".into(),
            serde_json::from_value(serde_json::json!({"last_growth_full_unix": 100})).unwrap(),
        );
        commit_populate(&mut db, &index);
        let mut presence: BTreeMap<String, bool> =
            db.read_control("field_presence").unwrap().unwrap();
        presence.insert("growth_retention".into(), present);
        db.control("field_presence", &presence).unwrap();
        let (mut working, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(cx.presence.get("growth_retention"), Some(&present));
        assert_eq!(working.v2().growth_retention, index.v2().growth_retention);
        assert!(working.decode_holds.same_as(&index.decode_holds));
        assert_eq!(working.decode_holds.v2_provenance(), (19, 3));
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let generation = working.generation;
        kinds_misc::merge_cas_at(&mut tx, &mut working, generation).unwrap();
        working.decode_holds = Default::default();
        assert!(kinds_misc::merge_cas_at(&mut tx, &mut working, generation).is_err());
    }
}

/// [format] committed saves publish their generation; page-cap failures keep the committed graph.
#[test]
fn committed_save_gcs_after_its_generation_and_failed_save_never_gcs() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut next = prev.clone();
    next.upload_context_fingerprint = Some("new-context".into());
    save_graph(&mut db, &identity, &prev, &mut next, &mut cx).unwrap();
    assert_eq!(
        db.read_control::<u64>("generation").unwrap(),
        Some(next.generation)
    );
    let (current, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        current.upload_context_fingerprint,
        next.upload_context_fingerprint
    );
    let mut retry = current.clone();
    retry.upload_context_fingerprint = Some("never-committed".into());
    // Enough new rows that the save must grow the file past SQLite's page cap.
    for n in 0..2048 {
        retry
            .accepted_snapshot_fingerprints
            .insert(format!("{n:064x}"));
    }
    sqlite::cap_pages(&db);
    assert!(save_graph(&mut db, &identity, &current, &mut retry, &mut cx).is_err());
    assert!(!cx.valid && cx.ambiguous);
    assert_eq!(
        hydrate(&mut db, Scratch::binding())
            .unwrap()
            .0
            .upload_context_fingerprint,
        current.upload_context_fingerprint
    );
}

/// [regress] A refused COMMIT is a definite rollback: save_graph refuses with
/// ReloadRequired (no save hold), keeps the prior
/// generation and graph, and a fresh save then commits.
#[test]
fn refused_commit_refuses_reload_required_without_post_commit() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let (current, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut next = current.clone();
    next.upload_context_fingerprint = Some("never-committed".into());
    sqlite::fence_commit_writing(&db, "generation");
    let error = save_graph(&mut db, &identity, &current, &mut next, &mut cx).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    assert!(!cx.valid && cx.ambiguous);
    assert_eq!(next.generation, current.generation);
    assert!(!db.reload_required());
    let (hydrated, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(hydrated.generation, current.generation);
    assert_eq!(
        hydrated.upload_context_fingerprint,
        current.upload_context_fingerprint
    );
    let mut next = hydrated.clone();
    next.upload_context_fingerprint = Some("committed".into());
    save_graph(&mut db, &identity, &hydrated, &mut next, &mut cx).unwrap();
}

/// [format] stale generation or future writer refuses before saving.
#[test]
fn stale_generation_or_future_writer_refuses_before_restart_side_effects() {
    for future_writer in [false, true] {
        let (_scratch, mut db) = Scratch::live_store();
        commit_populate(&mut db, &fixture());
        let (mut prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        let mut next = prev.clone();
        if future_writer {
            sqlite::future_writer_for_test(&mut db);
        } else {
            prev.generation += 1;
        }
        assert!(save_graph(&mut db, &identity, &prev, &mut next, &mut cx).is_err());
        assert!(!cx.valid && cx.ambiguous);
    }
}

/// [money] window ids are monotonic across a b a and complete family removal.
#[test]
fn window_ids_are_monotonic_across_a_b_a_and_complete_family_removal() {
    let (_scratch, mut db) = Scratch::store();
    let mut prev = fixture();
    prev.files.clear();
    commit_populate(&mut db, &prev);
    prev.generation = 1;
    let mut prior_id = 0;
    for boundary in ["A", "B", "A", "gone", "A"] {
        let (_, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let mut next = prev.clone();
        next.generation += 1;
        if boundary == "gone" {
            next.claude_account_family_pending.clear();
        } else {
            if next.claude_account_family_pending.is_empty() {
                next.claude_account_family_pending = fixture().claude_account_family_pending;
            }
            let p = next
                .claude_account_family_pending
                .get_mut("synthetic-family")
                .unwrap();
            if p.census_window_end != boundary {
                p.previous_windows.push(p.current.clone());
                p.current.census_window_end = boundary.into();
            }
        }
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(&prev, &next, &mut tx, &mut cx, std::iter::empty::<String>()).unwrap();
        let key = mapper::key("account.current", "synthetic-family", 1).unwrap();
        let h = tx.get(&key).unwrap().unwrap();
        let (id, high, _): (Option<u64>, u64, Vec<u64>) = mapper::read(&mut tx, &h).unwrap();
        if let Some(id) = id {
            assert!(id > prior_id);
            assert!(high > id);
            prior_id = id;
        }
        let outcome = tx.commit(prev.generation, next.generation);
        assert_eq!(outcome, DurableCommitOutcome::Committed(next.generation));
        let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&next).unwrap()
        );
        prev = next;
    }
}

/// [money] a refused COMMIT preserves unsettled custody through subsequent independent saves.
#[test]
fn refused_commit_preserves_owed_custody_through_independent_saves() {
    let (_scratch, mut db) = Scratch::live_store();
    let mut prev = fixture();
    prev.accepted_rebuild_incidence
        .insert("synthetic-file".into(), BTreeSet::from(["owed".into()]));
    commit_populate(&mut db, &prev);
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    next.files.get_mut("synthetic-file").unwrap().size_bytes += 7;
    next.file_snapshot_fingerprints.insert(
        "synthetic-file".into(),
        BTreeSet::from(["unpublished".into()]),
    );
    next.accepted_snapshot_fingerprints
        .insert("unpublished".into());
    next.snapshot_activity_at
        .insert("unpublished".into(), Some("2026-10-31T00:00:00Z".into()));
    next.accepted_rebuild_incidence.clear();
    next.claude_account_family_pending.clear();
    next.claude_owned_start_census.insert("unpublished-session".into(), serde_json::from_value(serde_json::json!({
        "marker_source_file_fingerprint":"unpublished", "verified_source_file_fingerprint":"unpublished",
        "emitted_source_file_fingerprint":"unpublished"
    })).unwrap());
    next.upload_ack_retirement_handoff = Some(super::super::super::UploadAckRetirementHandoff {
        destination_namespace_hash: Scratch::binding().namespace_hash,
        committed_generation: next.generation,
        bodies: BTreeMap::from([("unpublished".into(), "body".into())]),
        pending_bodies: BTreeMap::new(),
    });
    next.upload_context_fingerprint = Some("independent-change".into());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    sqlite::fence_commit_writing(&db, "generation");
    let error = save_graph(&mut db, &identity, &prev, &mut next, &mut cx).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    assert_eq!(next.v2().growth_retention, prev.v2().growth_retention);
    assert!(cx.ambiguous);
    let (restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&prev).unwrap()
    );
    // Independent work can commit from a fresh durable graph on the next pass.
    let mut selected = restored.clone();
    selected.upload_context_fingerprint = Some("independent-change".into());
    selected.files.insert(
        "independent-file".into(),
        selected.files["synthetic-file"].clone(),
    );
    save_graph(&mut db, &identity, &restored, &mut selected, &mut cx).unwrap();
    let (reopened, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(reopened.files.contains_key("independent-file"));
    assert_eq!(
        reopened.upload_context_fingerprint.as_deref(),
        Some("independent-change")
    );
    assert_eq!(
        reopened.accepted_rebuild_incidence,
        prev.accepted_rebuild_incidence
    );
    assert_eq!(
        serde_json::to_value(&reopened.claude_account_family_pending).unwrap(),
        serde_json::to_value(&prev.claude_account_family_pending).unwrap()
    );
    assert!(reopened.upload_ack_retirement_handoff.is_none());
    let mut advanced = reopened.clone();
    advanced.files.get_mut("synthetic-file").unwrap().size_bytes += 1;
    save_graph(&mut db, &identity, &reopened, &mut advanced, &mut cx).unwrap();
    let (final_graph, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        final_graph.files["synthetic-file"].size_bytes,
        prev.files["synthetic-file"].size_bytes + 1
    );
    assert_eq!(
        final_graph.accepted_rebuild_incidence,
        prev.accepted_rebuild_incidence
    );
}

/// [format] census evidence larger than the projected row cap roundtrips.
#[test]
fn census_evidence_larger_than_the_projected_row_cap_roundtrips() {
    use base64::Engine as _;
    let (_scratch, mut db) = Scratch::store();
    let hashes: Vec<_> = (0_u64..100_000).flat_map(u64::to_be_bytes).collect();
    let mut index = fixture();
    index.claude_request_census = serde_json::from_value(serde_json::json!({"large-census":{
        "v":1,"fp":"f".repeat(64),"w":17,"s":"exact",
        "b":base64::engine::general_purpose::STANDARD.encode(hashes)
    }}))
    .unwrap();
    assert!(
        serde_json::to_vec(&index.claude_request_census)
            .unwrap()
            .len()
            > MUTABLE_VALUE_BYTES as usize
    );
    commit_populate(&mut db, &index);
    index.generation = 1;
    let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&index).unwrap()
    );
}

/// [format] #938 copy removals map losslessly between checked v1 bytes and v2.
/// Goldens are CCR2 of #938's persisted-field fixture plus one prefix-hold
/// debt file, with definite and lost metadata; an absent slot stays empty.
#[test]
fn copy_removals_roundtrip_checked_v1_bytes_through_v2() {
    use crate::snapshots::claude_money_birth_store::location_key;
    const DEFINITE: &str = super::super::money_test_support::CCR2_DEFINITE;
    const LOST: &str = "Q0NSMgECAAAAEhWSo6RMxEDjJVe1q0p5xwAAAAAAAAAAAQAAAAhTn1hKY1r1cpjByPzdpVwCAAAAAQAAAAAAAAACAAAAAAAAAJGPX3TzuiqIHEpSPndxZkoBAAAAAAAAAAAAAAA";
    let (copy, held) = (
        location_key("/synthetic/copy.jsonl"),
        location_key("/synthetic/held.jsonl"),
    );
    for (golden, metadata_lost) in [(Some(DEFINITE), false), (Some(LOST), true), (None, false)] {
        let mut v1 = serde_json::to_value(fixture()).unwrap();
        let object = v1.as_object_mut().unwrap();
        object.remove("claude_copy_removals");
        if let Some(golden) = golden {
            object.insert("claude_copy_removals".into(), golden.into());
        }
        let mut index: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&v1).unwrap()).unwrap();
        let removals = &index.claude_copy_removals;
        assert_eq!(removals.metadata_lost(), metadata_lost);
        if golden.is_some() {
            let holder = location_key("/synthetic/original.jsonl");
            assert_eq!(
                removals.get(copy),
                &[(holder, Box::<[u64]>::from([1_u64, 2]))]
            );
            assert!(removals.get(held).is_empty() && removals.pending(held));
            assert!(!removals.pending(copy));
        } else {
            assert!(removals.is_empty());
        }
        let (_scratch, mut db) = Scratch::store();
        commit_populate(&mut db, &index);
        index.generation = 1;
        let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(restored.claude_copy_removals, index.claude_copy_removals);
        // The restored v1 slot writes the exact checked bytes back (or stays absent).
        let written = serde_json::to_value(&restored).unwrap();
        assert_eq!(
            written.get("claude_copy_removals").and_then(|v| v.as_str()),
            golden
        );
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&index).unwrap()
        );
    }
}
