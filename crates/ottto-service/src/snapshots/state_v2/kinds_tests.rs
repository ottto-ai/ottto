//! Integration fixtures; compiled locally, executed only in later CI.
use super::*;
use std::collections::BTreeSet;

fn save_graph(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    previous: &ScanIndex,
    next: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    let (_, mut hydrated) = hydrate(db, identity.binding.clone())?;
    let previous = baseline(previous, &mut hydrated)?;
    super::save_graph(db, identity, previous, next, cx).map(|_| ())
}
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
        let db = sqlite::Sqlite::open(
            &scratch.0.join("index.v2.sqlite.import"),
            &Identity {
                format: FORMAT,
                db_id: "synthetic-integration".into(),
                binding: Self::binding(),
                fence_generation: 0,
            },
        )
        .unwrap();
        (scratch, db)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn assert_persisted(db: &mut sqlite::Sqlite, expected: &ScanIndex) {
    let (restored, _) = hydrate(db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(expected).unwrap()
    );
    assert!(restored.decode_holds.same_as(&expected.decode_holds));
    assert_eq!(
        restored.decode_holds.v2_provenance(),
        expected.decode_holds.v2_provenance()
    );
    assert_eq!(
        restored.v2().growth_retention,
        expected.v2().growth_retention
    );
}
pub(in crate::snapshots::state_v2) fn fixture() -> ScanIndex {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let mut index: ScanIndex = serde_json::from_value(fixture["logical"].clone()).unwrap();
    index.generation = 0;
    index.historical_replay_generation = Some("/synthetic/exact-context".into());
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
/// [regress] previous-layout stores default only newly introduced kinds, then
/// save them and their inventory atomically; damage in supported kinds refuses.
#[test]
fn previous_layout_defaults_new_kinds_and_upgrades_on_save_without_masking_damage() {
    let previous_layout = 1;
    // The released format has no layout control.
    let (scratch, mut db) = Scratch::store();
    let index = fixture();
    commit_populate(&mut db, &index);
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut presence: BTreeMap<String, bool> = db.read_control("field_presence").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut v1 = serde_json::to_value(&index).unwrap();
    for (kind, field, introduced) in catalogue::LAYOUTS {
        if *introduced > previous_layout {
            mapper::rows(&mut tx, kind, |tx, h| mapper::remove(tx, &h.key)).unwrap();
            v1.as_object_mut().unwrap().remove(*field);
            presence.remove(*field);
        }
    }
    tx.delete(&RowKey::Meta("catalogue_layout".into())).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.control("field_presence", &presence).unwrap();
    // Recreate the released writer capability, without the current commit
    // hook advancing it again. Both controls retain their checksums.
    sqlite::delete_row_for_test(&db, &RowKey::Meta("minimum_writer_capability".into()));
    db.control("minimum_writer_capability", &1_u64).unwrap();
    db.finish_import().unwrap();
    let mut db =
        sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
    db.path_extractor(private_paths);
    db.reference_extractor(references);
    let mut expected: ScanIndex = serde_json::from_value(v1).unwrap();
    expected.generation = 2;
    let (mut restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, previous_layout);
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert!(restored.decode_holds.same_as(&expected.decode_holds));
    let baseline = baseline(&restored, &mut cx).unwrap();
    assert!(!baseline
        .rows
        .contains_key(&RowKey::Meta("catalogue_layout".into())));
    assert!(!baseline
        .rows
        .contains_key(&RowKey::Meta("field_presence".into())));
    for (kind, _, introduced) in catalogue::LAYOUTS {
        if *introduced > previous_layout {
            assert!(!baseline
                .rows
                .contains_key(&mapper::key(kind, "", 0).unwrap()));
        }
    }
    super::save_graph(&mut db, &identity, baseline, &mut restored, &mut cx).unwrap();
    assert_eq!(
        db.read_control::<u32>("catalogue_layout").unwrap(),
        Some(catalogue::LAYOUT)
    );
    {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        for (kind, field, introduced) in catalogue::LAYOUTS {
            // Archive custody is written only while held; this fixture holds
            // none. A retired kind is never written.
            if *introduced > previous_layout
                && !kinds_misc::ARCHIVE_KINDS.contains(kind)
                && !field.starts_with("retired_")
            {
                assert!(
                    tx.get(&mapper::key(kind, "", 0).unwrap())
                        .unwrap()
                        .is_some(),
                    "{kind}"
                );
            }
        }
    }
    drop(db);
    let mut db =
        sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
    db.path_extractor(private_paths);
    db.reference_extractor(references);
    let (reopened, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert!(cx.presence.contains_key("upload_context_proof"));
    assert_persisted(&mut db, &restored);
    assert_eq!(reopened.generation, 3);
    // A root that the saved layout includes is still damage. An active
    // layout-1 kind: the retired upload-context root is never required.
    sqlite::delete_row_for_test(
        &db,
        &mapper::key("setting.historical_replay_generation", "", 0).unwrap(),
    );
    assert!(hydrate(&mut db, Scratch::binding()).is_err());
}

/// [format] An earlier store's retired `setting.upload_context_fingerprint`
/// row (layout 1) is accepted and never read: hydrate names its key, the next
/// save removes it, and no source-wide context reaches the model.
#[test]
fn retired_upload_context_row_is_purged_by_the_next_save() {
    let row = mapper::key("setting.upload_context_fingerprint", "", 0).unwrap();
    let (scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    mapper::put(&mut tx, &row, &"d".repeat(64)).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.finish_import().unwrap();
    let reopen = || {
        let mut db =
            sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db
    };
    let mut db = reopen();
    let (mut restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert!(restored.active_upload_context_fingerprint.is_none());
    assert!(cx.retired.contains(&row));
    let baseline = baseline(&restored, &mut cx).unwrap();
    super::save_graph(&mut db, &identity, baseline, &mut restored, &mut cx).unwrap();
    {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        assert!(tx.get(&row).unwrap().is_none(), "the save removes the row");
    }
    drop(db);
    let mut db = reopen();
    let (reopened, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert!(reopened.active_upload_context_fingerprint.is_none());
    assert!(cx.retired.is_empty());
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&row).unwrap().is_none(), "still absent after reopen");
}

/// [format] A store that never had the retired row opens at the current
/// layout: the root is not required.
#[test]
fn store_without_the_retired_upload_context_row_opens_at_the_current_layout() {
    let row = mapper::key("setting.upload_context_fingerprint", "", 0).unwrap();
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        assert!(tx.get(&row).unwrap().is_none(), "never written");
    }
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
}

/// [format] An earlier store's retired rows (layout 1's
/// `v1_field.claude_desktop_census_witness`, layout 5's
/// `v1_field.claude_folder_login_ledger` member) are still accepted kinds: the
/// store hydrates without reading them, and each row stays until a save names
/// it for removal.
#[test]
fn retired_desktop_census_witness_row_still_hydrates() {
    let witness = serde_json::json!({
        "completed_at_unix_seconds": 1, "process_id": 1, "inventory": "inventory"
    });
    let folder = serde_json::json!({
        "fresh": true, "mixed": false, "login": "a".repeat(64), "org": "b".repeat(64),
        "owner_proven": true, "census_complete": true, "covered_from": 3600, "matched": [7, 9]
    });
    for (kind, introduced, name, position, value) in [
        ("v1_field.claude_desktop_census_witness", 1, "", 0, witness),
        (
            "v1_field.claude_folder_login_ledger",
            5,
            "folder",
            1,
            folder,
        ),
    ] {
        assert_eq!(catalogue::introduced(kind).unwrap(), introduced);
        let row = mapper::key(kind, name, position).unwrap();
        let (_scratch, mut db) = Scratch::store();
        commit_populate(&mut db, &fixture());
        let mut tx = db.begin(TxnMode::Write).unwrap();
        mapper::put(&mut tx, &row, &value).unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(cx.layout, catalogue::LAYOUT, "{kind}");
        assert!(cx.retired.contains(&row), "{kind}");
        let mut tx = db.begin(TxnMode::Read).unwrap();
        assert!(tx.get(&row).unwrap().is_some(), "{kind}");
    }
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
    assert!(cx.valid && !cx.presence.is_empty());
    // Account hydration must not replace the common context and discard MISC
    // inventory or the source binding while hydrating its own graph.
    assert_eq!(cx.binding, Some(Scratch::binding()));
    // A current writer never stores a retired kind.
    assert!(cx.retired.is_empty());
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

/// [format] row commitments cover scalar, member and exact opaque custody changes.
#[test]
fn misc_row_digests_cover_scalar_map_ack_and_raw_hold_changes() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let (prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let before = baseline(&prev, &mut cx).unwrap();
    let (_, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let mut next = prev.clone();
    next.generation += 1;
    assert_eq!(before.rows, baseline(&next, &mut cx).unwrap().rows);
    next.historical_replay_generation = Some("different-context".into());
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
    let (_, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    // Commit to `next` itself, not to the stored rows decoded by hydrate.
    cx.digests.clear();
    let after = baseline(&next, &mut cx).unwrap();
    let changed: BTreeSet<_> = after
        .rows
        .iter()
        .filter(|(k, v)| before.rows.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(
        changed,
        BTreeSet::from([
            mapper::key("setting.historical_replay_generation", "", 0).unwrap(),
            mapper::key("accepted.entity", "", 0).unwrap(),
            mapper::key("accepted.entity", &"e".repeat(64), 1).unwrap(),
            mapper::key("v1_field.repair_provenance", "", 0).unwrap(),
            mapper::key("raw_hold.files", "/synthetic/held", 0).unwrap(),
        ])
    );
}

/// [format] digests recorded while decoding equal those the seed computes,
/// for every logical row except untyped census records and opaque holds.
#[test]
fn decoded_row_digests_equal_seed_computed_digests() {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let (index, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let decoded = cx.digests.clone();
    let seeded = baseline(&index, &mut cx).unwrap();
    assert!(cx.digests.is_empty());
    let (_, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    cx.digests.clear();
    let computed = baseline(&index, &mut cx).unwrap();
    assert_eq!(seeded.rows, computed.rows);
    let uncached: BTreeSet<_> = computed
        .rows
        .keys()
        .filter(|key| !decoded.contains_key(*key))
        .filter_map(|key| match key {
            RowKey::Record { kind, .. } => Some(kind.name()),
            _ => None,
        })
        .collect();
    assert!(uncached.contains("file.census"));
    assert!(uncached
        .iter()
        .all(|kind| *kind == "file.census" || kind.starts_with("raw_hold.")));
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
    drop(tx);
    let (previous, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    save_graph(&mut db, &identity, &previous, &mut working, &mut cx).unwrap();
    assert_persisted(&mut db, &working);
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
    next.historical_replay_generation = Some("new-context".into());
    let digests = baseline(&prev, &mut cx).unwrap();
    let digests = super::save_graph(&mut db, &identity, digests, &mut next, &mut cx).unwrap();
    assert_persisted(&mut db, &next);
    let mut unchanged = next.clone();
    let attempts = db.save_row_attempts();
    let rows = digests.rows.len() as u64;
    let digests = super::save_graph(&mut db, &identity, digests, &mut unchanged, &mut cx).unwrap();
    // Only backend-owned controls advance on an unchanged selected graph:
    // no logical row is rewritten or deleted.
    assert_eq!(db.save_row_attempts().1, attempts.1);
    assert!(db.save_row_attempts().0 - attempts.0 < rows);
    assert_persisted(&mut db, &unchanged);
    next = unchanged;
    assert_eq!(
        db.read_control::<u64>("generation").unwrap(),
        Some(next.generation)
    );
    let (current, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        current.historical_replay_generation,
        next.historical_replay_generation
    );
    let mut retry = current.clone();
    retry.historical_replay_generation = Some("never-committed".into());
    // Enough new rows that the save must grow the file past SQLite's page cap.
    for n in 0..2048 {
        retry
            .accepted_snapshot_fingerprints
            .insert(format!("{n:064x}"));
    }
    sqlite::cap_pages(&db);
    assert!(super::save_graph(&mut db, &identity, digests, &mut retry, &mut cx).is_err());
    assert!(!cx.valid && cx.ambiguous);
    assert_persisted(&mut db, &current);
    assert_eq!(
        hydrate(&mut db, Scratch::binding())
            .unwrap()
            .0
            .historical_replay_generation,
        current.historical_replay_generation
    );
}

/// [regress] Failure before COMMIT rolls back; failure before digest promotion
/// reloads the complete committed graph. Either path can retry from hydration.
#[test]
fn refused_commit_refuses_reload_required_without_post_commit() {
    for after_commit in [false, true] {
        let (_scratch, mut db) = Scratch::live_store();
        commit_populate(&mut db, &fixture());
        let (current, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        let mut next = current.clone();
        next.historical_replay_generation = Some("never-committed".into());
        next.files.clear();
        next.accepted_snapshot_fingerprints.insert("f".repeat(64));
        if after_commit {
            FAIL_DIGEST_PROMOTION.with(|fail| fail.set(true));
        } else {
            sqlite::fence_commit_writing(&db, "generation");
        }
        let error = save_graph(&mut db, &identity, &current, &mut next, &mut cx).unwrap_err();
        assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
        assert!(!cx.valid && cx.ambiguous);
        assert_eq!(
            next.generation,
            current.generation + u64::from(after_commit)
        );
        assert_persisted(&mut db, if after_commit { &next } else { &current });
        assert!(!db.reload_required());
        let (hydrated, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(
            hydrated.generation,
            current.generation + u64::from(after_commit)
        );
        assert_eq!(
            hydrated.historical_replay_generation,
            if after_commit {
                next.historical_replay_generation.clone()
            } else {
                current.historical_replay_generation
            }
        );
        let mut next = hydrated.clone();
        next.historical_replay_generation = Some("committed".into());
        save_graph(&mut db, &identity, &hydrated, &mut next, &mut cx).unwrap();
        assert_persisted(&mut db, &next);
    }
}

/// [format] stale generation or future writer refuses before saving.
#[test]
fn stale_generation_or_future_writer_refuses_before_restart_side_effects() {
    for future_writer in [false, true] {
        let (_scratch, mut db) = Scratch::live_store();
        commit_populate(&mut db, &fixture());
        let (mut prev, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        let original = prev.clone();
        let mut next = prev.clone();
        if future_writer {
            sqlite::future_writer_for_test(&mut db);
        } else {
            prev.generation += 1;
        }
        assert!(save_graph(&mut db, &identity, &prev, &mut next, &mut cx).is_err());
        assert!(!cx.valid && cx.ambiguous);
        if !future_writer {
            assert_persisted(&mut db, &original);
        }
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
    next.upload_ack_retirement_handoff = Some(super::super::super::UploadAckRetirementHandoff {
        destination_namespace_hash: Scratch::binding().namespace_hash,
        committed_generation: next.generation,
        bodies: BTreeMap::from([("unpublished".into(), "body".into())]),
        pending_bodies: BTreeMap::new(),
    });
    next.historical_replay_generation = Some("independent-change".into());
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
    selected.historical_replay_generation = Some("independent-change".into());
    selected.files.insert(
        "independent-file".into(),
        selected.files["synthetic-file"].clone(),
    );
    save_graph(&mut db, &identity, &restored, &mut selected, &mut cx).unwrap();
    assert_persisted(&mut db, &selected);
    let (reopened, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(reopened.files.contains_key("independent-file"));
    assert_eq!(
        reopened.historical_replay_generation.as_deref(),
        Some("independent-change")
    );
    assert_eq!(
        reopened.accepted_rebuild_incidence,
        prev.accepted_rebuild_incidence
    );
    assert!(reopened.upload_ack_retirement_handoff.is_none());
    let mut advanced = reopened.clone();
    advanced.files.get_mut("synthetic-file").unwrap().size_bytes += 1;
    save_graph(&mut db, &identity, &reopened, &mut advanced, &mut cx).unwrap();
    assert_persisted(&mut db, &advanced);
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

#[path = "codex_archive_kinds_tests.rs"]
mod codex_archive_tests;
#[path = "field_schema_tests.rs"]
mod field_schema_tests;

/// Stores `row` (exact 0.1.215 serialized shape) as `kind`'s field row of an
/// otherwise current store, then reads it back through the production
/// hydrate (mapper::field_read -> mapper::read -> codec::exact_json).
fn hydrate_with_shipped_row(kind: &str, row: serde_json::Value) -> Result<ScanIndex> {
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let mut tx = db.begin(TxnMode::Write).unwrap();
    mapper::put(&mut tx, &mapper::key(kind, "", 0).unwrap(), &row).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    hydrate(&mut db, Scratch::binding()).map(|(index, _)| index)
}
fn shipped_direction() -> serde_json::Value {
    serde_json::json!({
        "policy": [true, true, false, false, false],
        "context": "c".repeat(64),
        "previous_context": null,
        "last_change_mask": 0
    })
}
fn shipped_traversal(edit: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
    let mut traversal = serde_json::to_value(fixture().traversal).unwrap();
    edit(&mut traversal["counts"]);
    traversal
}

/// [regress] 0.1.215 writes `upload_context_proof.direction` every source
/// cycle (383f8bca6 upload_context_receipt.rs:920-934); #1287 retired it as a
/// decode-only placeholder. The real v2 read path must still decode it.
#[test]
fn shipped_0_1_215_upload_context_proof_direction_hydrates() {
    let row = serde_json::json!({ "direction": shipped_direction() });
    if let Err(e) = hydrate_with_shipped_row("v1_field.upload_context_proof", row) {
        panic!("0.1.215 direction refused: {e:#}");
    }
}

/// [regress] 0.1.212-0.1.215 persist nonzero
/// `counts.caps.inventory_hold_keys_discarded` (removed by #1290).
#[test]
fn shipped_0_1_215_traversal_caps_inventory_hold_keys_discarded_hydrates() {
    let row = shipped_traversal(|counts| {
        counts["caps"] = serde_json::json!({ "inventory_hold_keys_discarded": 3 });
    });
    if let Err(e) = hydrate_with_shipped_row("scan_state.traversal", row) {
        panic!("0.1.215 inventory_hold_keys_discarded refused: {e:#}");
    }
}

/// [regress] 0.1.208-0.1.215 persist nonzero
/// `counts.listing_owed_pace_evicted` (removed by #1290).
#[test]
fn shipped_0_1_215_traversal_listing_owed_pace_evicted_hydrates() {
    let row = shipped_traversal(|counts| {
        counts["listing_owed_pace_evicted"] = 2.into();
    });
    if let Err(e) = hydrate_with_shipped_row("scan_state.traversal", row) {
        panic!("0.1.215 listing_owed_pace_evicted refused: {e:#}");
    }
}

/// [regress] A store holding all three 0.1.215 retired leaves opens, and its
/// next save rewrites both rows without them; the reopened store hydrates.
#[test]
fn shipped_0_1_215_retired_leaves_are_dropped_by_the_next_save() {
    let proof = mapper::key("v1_field.upload_context_proof", "", 0).unwrap();
    let traversal = mapper::key("scan_state.traversal", "", 0).unwrap();
    let (scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let row = serde_json::json!({ "direction": shipped_direction() });
    mapper::put(&mut tx, &proof, &row).unwrap();
    let row = shipped_traversal(|counts| {
        counts["listing_owed_pace_evicted"] = 2.into();
        counts["caps"] = serde_json::json!({ "inventory_hold_keys_discarded": 3 });
    });
    mapper::put(&mut tx, &traversal, &row).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.finish_import().unwrap();
    let reopen = || {
        let mut db =
            sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db
    };
    let mut db = reopen();
    let (mut restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    let baseline = baseline(&restored, &mut cx).unwrap();
    super::save_graph(&mut db, &identity, baseline, &mut restored, &mut cx).unwrap();
    drop(db);
    let mut db = reopen();
    let (reopened, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_vec(&reopened.traversal).unwrap(),
        serde_json::to_vec(&restored.traversal).unwrap()
    );
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (key, leaves) in [
        (&proof, &["/direction"][..]),
        (
            &traversal,
            &[
                "/counts/listing_owed_pace_evicted",
                "/counts/caps/inventory_hold_keys_discarded",
            ][..],
        ),
    ] {
        // An emptied proof row may be deleted rather than rewritten.
        let Some(header) = tx.get(key).unwrap() else {
            assert_eq!(key, &proof, "the traversal row stays");
            continue;
        };
        let stored = mapper::bytes(&mut tx, &header).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&codec::expand(&stored, value_cap(key)).unwrap()).unwrap();
        for leaf in leaves {
            assert!(json.pointer(leaf).is_none(), "{leaf} kept after save");
        }
    }
}

/// [format] A previous-release store holding the six retired Codex state-only
/// rows and both residue leaves (witness populated) loads at the current
/// layout; its next save writes neither leaf and removes the retired rows,
/// and the reopened store hydrates the same model.
#[test]
fn retired_state_only_kinds_and_leaves_load_inert() {
    let retired = [
        (
            "v1_field.codex_state_only_snapshot_fingerprints",
            serde_json::json!({ "session-a": "a".repeat(64) }),
        ),
        (
            "v1_field.codex_state_only_blocked_session_ids",
            serde_json::json!(["session-a"]),
        ),
        (
            "v1_field.codex_state_only_blocked_by_file",
            serde_json::json!({ "/tmp/rollout-a.jsonl": ["session-a"] }),
        ),
        (
            "v1_field.codex_state_only_blocked_unattributed",
            serde_json::json!(["session-b"]),
        ),
        (
            "v1_field.codex_state_only_blocked_legacy",
            serde_json::json!(["session-c"]),
        ),
        (
            "v1_field.codex_state_only_blocked_attributed",
            serde_json::json!(true),
        ),
    ];
    let traversal = mapper::key("scan_state.traversal", "", 0).unwrap();
    let witness = mapper::key("scan_state.scan_residue_witness", "", 0).unwrap();
    let (scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &fixture());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (kind, row) in &retired {
        assert_eq!(catalogue::introduced(kind).unwrap(), 1, "{kind}");
        mapper::put(&mut tx, &mapper::key(kind, "", 0).unwrap(), row).unwrap();
    }
    let mut row = shipped_traversal(|_| {});
    row["residue"] = serde_json::json!({ "blocked_session_ids": ["session-a"] });
    mapper::put(&mut tx, &traversal, &row).unwrap();
    let row = serde_json::json!({
        "census_window_end": "2026-01-01T00:00:00Z", "ownership_incomplete_file_count": 1,
        "zero_snapshot_usage_evidence_count": 0, "dropped_usage_record_count": 0,
        "codex_state_only_blocked_session_ids": ["session-a"]
    });
    mapper::put(&mut tx, &witness, &row).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    db.finish_import().unwrap();
    let reopen = || {
        let mut db =
            sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db
    };
    let mut db = reopen();
    let (mut restored, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert_eq!(
        restored
            .scan_residue_witness
            .as_ref()
            .map(|w| w.ownership_incomplete_file_count),
        Some(1)
    );
    let baseline = baseline(&restored, &mut cx).unwrap();
    super::save_graph(&mut db, &identity, baseline, &mut restored, &mut cx).unwrap();
    drop(db);
    let mut db = reopen();
    let (reopened, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert_eq!(
        serde_json::to_vec(&reopened).unwrap(),
        serde_json::to_vec(&restored).unwrap()
    );
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for (key, leaf) in [
        (&traversal, "/residue/blocked_session_ids"),
        (&witness, "/codex_state_only_blocked_session_ids"),
    ] {
        let header = tx.get(key).unwrap().expect("the row stays");
        let stored = mapper::bytes(&mut tx, &header).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&codec::expand(&stored, value_cap(key)).unwrap()).unwrap();
        assert!(json.pointer(leaf).is_none(), "{leaf} kept after save");
    }
    for (kind, _) in &retired {
        let key = mapper::key(kind, "", 0).unwrap();
        assert!(tx.get(&key).unwrap().is_none(), "{kind} retired on save");
    }
}

/// [format] Old -> new -> old -> new: the shipped member layout is accepted,
/// an older reader HOLDs after ordinary saves retire
/// the old contents without changing unrelated money or request custody.
#[test]
fn retired_codex_kinds_cross_old_new_old_new_without_a_rebuild() {
    use mapper::Members::{Field, Map, Set};
    use serde_json::json;
    let rows = [
        (
            "codex_parent_ownership_refs",
            Set,
            json!(["parent"]),
            json!([]),
        ),
        (
            "codex_parent_ownership_ledgers",
            Map,
            json!({"parent":{"signatures":["signature"],"scan_complete":true}}),
            json!({}),
        ),
        (
            "codex_parent_side_requests",
            Map,
            json!({"parent":{"dev_ino":[1,2],"needed_extent":1,"state":{"kind":"live"},"state_extent":1,"state_ctime":[1,0],"attempt_extent":1,"attempt_ctime":[1,0],"attempts":1,"not_before_unix_seconds":1}}),
            json!({}),
        ),
        (
            "codex_parent_side",
            Map,
            json!({"parent":{"verdict":{"kind":"settled"},"generation":1,"referenced_epoch":1,"parsed":{"length":1,"device":1,"inode":2,"modified":[1,0],"changed":[1,0]},"seal":{"stamp":{"length":1,"device":1,"inode":2,"modified":[1,0],"changed":[1,0]},"scope":"retired","sample_len":1,"head_sha256":"a".repeat(64),"boundary_sha256":"b".repeat(64),"verified_unix_seconds":1,"sealed_unix_seconds":1}}}),
            json!({}),
        ),
        ("codex_parent_side_generation", Field, json!(7), json!(0)),
        ("codex_parent_proof_wrap_epoch", Field, json!(2), json!(0)),
        (
            "codex_parent_prefix_proofs",
            Map,
            json!({"child":{"state":"owed","parent":"parent","seq":9,"cause":255,"origin":"lineage","wake":{"kind":"due"},"outcome":0,"attempts":0,"not_before_unix_seconds":0}}),
            json!({}),
        ),
        (
            "codex_parent_proof_cursor",
            Field,
            json!("child"),
            json!(null),
        ),
        (
            "codex_parent_side_cursor",
            Field,
            json!("parent"),
            json!(null),
        ),
        ("codex_parent_proof_seq", Field, json!(9), json!(0)),
        (
            "codex_proof_index_incarnation",
            Field,
            json!("0123456789abcdef0123456789abcdef"),
            json!(""),
        ),
    ];
    let (scratch, mut db) = Scratch::store();
    let original = fixture();
    commit_populate(&mut db, &original);
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    db.finish_import().unwrap();
    let mut db =
        sqlite::Sqlite::open(&scratch.0.join("index.v2.sqlite.import"), &identity).unwrap();
    for round in 0..2 {
        // The old writer's existing split-field representation.
        let generation: u64 = db.read_control("generation").unwrap().unwrap();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        let mut old = mapper::Rows {
            tx: Some(&mut tx),
            ..Default::default()
        };
        for (field, mode, value, _) in &rows {
            mapper::field_write(&mut old, &format!("v1_field.{field}"), value, *mode).unwrap();
        }
        old.finish().unwrap();
        assert_eq!(
            tx.commit(generation, generation + 1),
            DurableCommitOutcome::Committed(generation + 1)
        );
        let (mut upgraded, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let mut expected = original.clone();
        expected.generation = upgraded.generation;
        assert_persisted(&mut db, &expected);
        let before = baseline(&upgraded, &mut cx).unwrap();
        super::save_graph(&mut db, &identity, before, &mut upgraded, &mut cx).unwrap();
        expected.generation = upgraded.generation;
        assert_persisted(&mut db, &expected);
        // D59: a previous reader HOLDs when its required root is absent.
        // A later old writer can restore its original rows before the next upgrade.
        let mut tx = db.begin(TxnMode::Read).unwrap();
        for (field, mode, _, empty) in &rows {
            let kind = format!("v1_field.{field}");
            assert!(
                mapper::field_read::<serde_json::Value>(&mut tx, &kind, *mode, None, || empty
                    .clone())
                .is_err(),
                "round {round}: old reader must HOLD {field}"
            );
            let mut count = 0;
            mapper::rows(&mut tx, &kind, |_, _| {
                count += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(count, 0, "retired kind is unwritten");
        }
    }
}

/// [money] H8. Past both old caps (65,537 records; one record holding one
/// hash more than the old 2,097,152 cap), the census survives a v2 save and
/// hydrate whole, and the restored graph's v1 bytes decode to it too. The
/// synthetic keys have no index entry: held-new custody restores as well.
#[test]
fn no_cap_money_survives_v1_v2_restore() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
    };
    // The old caps: request hashes and records the census held.
    const OLD_HASH_CAP: u64 = 2_097_152;
    const OLD_RECORD_CAP: u64 = 65_536;
    let fp = "a".repeat(64);
    let mut index = fixture();
    let before = index.claude_request_census.hash_total();
    index.claude_request_census.insert(
        "/synthetic/full.jsonl".into(),
        Record::synthetic_for_test(&fp, 7, Shape::Exact, (0..=OLD_HASH_CAP).collect()),
    );
    for n in 0..OLD_RECORD_CAP {
        index.claude_request_census.insert(
            format!("/synthetic/s{n:05}.jsonl"),
            Record::synthetic_for_test(&fp, 7, Shape::Exact, vec![OLD_HASH_CAP + 1 + n]),
        );
    }
    let (_scratch, mut db) = Scratch::store();
    commit_populate(&mut db, &index);
    index.generation = 1;
    let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(restored.claude_request_census, index.claude_request_census);
    assert_eq!(
        restored.claude_request_census.hash_total(),
        before + (OLD_HASH_CAP + 1 + OLD_RECORD_CAP) as usize
    );
    let v1: ScanIndex = serde_json::from_slice(&serde_json::to_vec(&restored).unwrap()).unwrap();
    assert_eq!(v1.claude_request_census, index.claude_request_census);
}

/// [format] H10. Transcript records as an older release wrote them (every
/// field and shape, retired and over-budget included) decode through the v1
/// index map, write back byte-identical, and hydrate from v2 rows to the
/// same records: one record codec for both stores.
#[test]
fn transcript_codec_compatibility() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensus, CLAUDE_REQUEST_CENSUS_DERIVATION as V,
    };
    use base64::Engine as _;
    let fp = "a".repeat(64);
    let b = base64::engine::general_purpose::STANDARD.encode(
        [1_u64, 5, u64::MAX]
            .iter()
            .flat_map(|hash| hash.to_be_bytes())
            .collect::<Vec<_>>(),
    );
    let rows = serde_json::json!({
        "/synthetic/live.jsonl": {"v": V, "fp": fp, "w": 7, "s": "exact", "tw": true,
            "u": true, "b": b, "bi": 1_700_000_000_u64, "bd": 5, "bn": 42, "ur": 3,
            "ut": 900, "m": 1_700_000_200_u64},
        "/synthetic/retired.jsonl": {"v": V, "fp": fp, "w": 7, "s": "exact", "r": 2, "m": 1},
        "/synthetic/over.jsonl": {"v": V, "fp": fp, "w": 7, "s": "over_budget"},
        "/synthetic/lossy.jsonl": {"v": V, "fp": fp, "w": 7, "s": "lossy", "u": true, "b": b},
        "/synthetic/empty.jsonl": {"v": V, "fp": fp, "w": 7, "s": "empty"},
    });
    let v1: ClaudeRequestCensus =
        serde_json::from_slice(&serde_json::to_vec(&rows).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&v1).unwrap(), rows);
    let (_scratch, mut db) = Scratch::store();
    let mut index = fixture();
    for name in rows.as_object().unwrap().keys() {
        let record = v1.get(name).expect("decoded").clone();
        index.claude_request_census.insert(name.clone(), record);
    }
    commit_populate(&mut db, &index);
    let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    for name in rows.as_object().unwrap().keys() {
        assert_eq!(
            restored.claude_request_census.get(name),
            v1.get(name),
            "{name}"
        );
    }
    assert_eq!(restored.claude_request_census, index.claude_request_census);
}

/// The family whose retired usage row shares a request set with its live
/// `proof.usage` witness.
const CO_OWNER: &str = "synthetic-co-owner";
/// The family whose retired usage row is large enough to be stored in chunks.
pub(in crate::snapshots::state_v2) const CHUNKED: &str = "synthetic-chunked";
fn co_owned_hash() -> String {
    "c".repeat(64)
}
/// `index` with a live `proof.usage` witness whose excluded hashes are the
/// request set a seeded retired usage row also holds, and a live authority row.
pub(in crate::snapshots::state_v2) fn with_co_owned_witness(mut index: ScanIndex) -> ScanIndex {
    let witness = serde_json::json!({
        "evidence_fingerprint": "e".repeat(64),
        "member_request_id_fingerprints": {CO_OWNER: "f".repeat(64)},
        "assigned_request_id_fingerprints": {},
        "legacy_excluded_request_id_hashes": {CO_OWNER: [co_owned_hash()]},
    });
    index
        .claude_usage_family_witnesses
        .insert(CO_OWNER.into(), serde_json::from_value(witness).unwrap());
    index.insert_retry_pending_claude_authority_for_test("synthetic-authority");
    index
}
/// Rows of every retired kind as a previous release left them, committed at
/// the next generation. Every store gets each retired kind's manifest or
/// scalar row. `members` adds usage families (one sharing its request set
/// with `with_co_owned_witness`, one stored in chunks) and their census
/// counts, and account families: two windows of one family sharing one
/// request set, a window stored in chunks holding its own, and a family's
/// current, absent-member and proof rows. Returns the seeded keys.
pub(in crate::snapshots::state_v2) fn seed_retired_rows(
    db: &mut sqlite::Sqlite,
    members: bool,
) -> BTreeSet<RowKey> {
    use sha2::Digest;
    let generation: u64 = db.read_control("generation").unwrap().unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let mut keys = BTreeSet::new();
    let mut put = |tx: &mut dyn Transaction, key: RowKey, value: serde_json::Value| {
        mapper::put(tx, &key, &value).unwrap();
        keys.insert(key);
    };
    for (kind, _) in catalogue::OWNED
        .iter()
        .filter(|(k, _)| catalogue::retired(k))
    {
        // A raw hold has no manifest; its own test seeds one with its metadata.
        if kind.starts_with("raw_hold.") {
            continue;
        }
        let count: u64 = match *kind {
            "usage.pending" | "family.requests" if members => 2,
            "account_window" if members => 3,
            "account.current" | "account.absent_members" | "proof.account" if members => 1,
            _ => 0,
        };
        put(&mut tx, mapper::key(kind, "", 0).unwrap(), count.into());
    }
    if members {
        let family = |hash: String, occurrences: u64| {
            let occurrences: serde_json::Map<_, _> = (0..occurrences)
                .map(|i| {
                    let request = format!("{:x}", sha2::Sha256::digest(i.to_le_bytes()));
                    let usage = serde_json::json!({"sequence": i, "input_tokens": i,
                        "output_tokens": 1, "cache_read_tokens": 0, "cache_creation_5m_tokens": 0,
                        "cache_creation_1h_tokens": 0, "reasoning_output_tokens": 0,
                        "model": null, "speed_mode": null, "reasoning_effort": null});
                    (request, usage)
                })
                .collect();
            serde_json::json!({
                "census_window_end": "2026-10-29T00:00:00Z",
                "member_request_id_hashes": {"synthetic-file": [hash]},
                "member_occurrences": {"synthetic-file": occurrences},
                "invalid": false,
            })
        };
        let key =
            |kind: &str, root: &str, position: u64| mapper::key(kind, root, position).unwrap();
        put(
            &mut tx,
            key("usage.pending", CO_OWNER, 1),
            family(co_owned_hash(), 1),
        );
        put(
            &mut tx,
            key("usage.pending", CHUNKED, 1),
            family("d".repeat(64), 64),
        );
        put(&mut tx, key("family.requests", CO_OWNER, 1), 1_u64.into());
        put(&mut tx, key("family.requests", CHUNKED, 1), 1_u64.into());
        let window = |set: &str, members: u64| {
            let members: serde_json::Map<_, _> = (0..members)
                .map(|i| {
                    let member = format!("{:x}", sha2::Sha256::digest((i + 1000).to_le_bytes()));
                    (member, 1.into())
                })
                .collect();
            serde_json::json!({"account_identifier_hash": "a".repeat(64),
                "census_window_end": "2026-10-29T00:00:00Z", "complete": true,
                "evidence_request_count": 1, "invalid": false, "members": members,
                "r": {"synthetic-file": set}, "v": "claude_account_request_set:v2"})
        };
        put(
            &mut tx,
            key("account_window", CO_OWNER, 1),
            window("co-owned", 1),
        );
        put(
            &mut tx,
            key("account_window", CO_OWNER, 2),
            window("co-owned", 1),
        );
        put(
            &mut tx,
            key("account_window", CHUNKED, 1),
            window("exclusive", 64),
        );
        put(
            &mut tx,
            key("account.current", CO_OWNER, 1),
            serde_json::json!([2, 3, [1, 2]]),
        );
        put(
            &mut tx,
            key("account.absent_members", CO_OWNER, 1),
            serde_json::json!(["synthetic-absent"]),
        );
        put(
            &mut tx,
            key("proof.account", CO_OWNER, 1),
            serde_json::json!({"account_identifier_hash": "a".repeat(64),
                "evidence_request_count": 1, "members": {"synthetic-file": 1},
                "member_request_id_fingerprints": {"synthetic-file": "b".repeat(64)}}),
        );
    }
    let next = generation + 1;
    assert_eq!(
        tx.commit(generation, next),
        DurableCommitOutcome::Committed(next)
    );
    keys
}
/// Hydrate and save the hydrated graph unchanged, as a load and its first
/// save do: the save removes the retired rows that hydrate named.
pub(in crate::snapshots::state_v2) fn purge(
    db: &mut sqlite::Sqlite,
    binding: super::super::super::scan_index_persistence::Binding,
) -> Result<()> {
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let (mut index, mut cx) = hydrate(db, binding)?;
    let previous = baseline(&index, &mut cx)?;
    super::save_graph(db, &identity, previous, &mut index, &mut cx).map(|_| ())
}
/// The request sets a stored row references.
pub(in crate::snapshots::state_v2) fn referenced_sets(
    tx: &mut dyn Transaction,
    key: &RowKey,
) -> Vec<RowKey> {
    let h = tx.get(key).unwrap().unwrap();
    let raw = mapper::bytes(tx, &h).unwrap();
    let mut sets = Vec::new();
    mapper::references(&h, &codec::Bytes(&raw), &mut |set| {
        sets.push(set.clone());
        Ok(())
    })
    .unwrap();
    sets
}
/// A request set's reference count; `None` once it is released.
pub(in crate::snapshots::state_v2) fn set_refs(
    tx: &mut dyn Transaction,
    set: &RowKey,
) -> Option<u64> {
    tx.get(set).unwrap().map(|h| match h.fixed {
        Fixed::RequestSet { refs, .. } => refs,
        Fixed::None => panic!("{set:?} has no reference count"),
    })
}
fn present(db: &mut sqlite::Sqlite, keys: &BTreeSet<RowKey>) -> usize {
    let mut tx = db.begin(TxnMode::Read).unwrap();
    keys.iter()
        .filter(|key| tx.get(key).unwrap().is_some())
        .count()
}

/// [money] A request set that a retired usage row and a live `proof.usage`
/// row both reference survives the purge with one reference less; the set
/// only the retired row held is released. An account set two retired windows
/// share is released once both go, as is a chunked window's own set. A
/// second save brings none of them back.
#[test]
fn retired_purge_keeps_co_owned_request_set() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &with_co_owned_witness(fixture()));
    let keys = seed_retired_rows(&mut db, true);
    let live = mapper::key("proof.usage", CO_OWNER, 1).unwrap();
    let retired = mapper::key("usage.pending", CO_OWNER, 1).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let shared = referenced_sets(&mut tx, &live);
    assert_eq!(shared.len(), 1);
    assert_eq!(
        referenced_sets(&mut tx, &retired),
        shared,
        "one set, two owners"
    );
    assert_eq!(set_refs(&mut tx, &shared[0]), Some(2));
    let only = referenced_sets(&mut tx, &mapper::key("usage.pending", CHUNKED, 1).unwrap());
    assert_eq!(only.len(), 1);
    assert_eq!(set_refs(&mut tx, &only[0]), Some(1));
    let windows = [1, 2].map(|n| mapper::key("account_window", CO_OWNER, n).unwrap());
    let account = referenced_sets(&mut tx, &windows[0]);
    assert_eq!(account.len(), 1);
    assert_eq!(
        referenced_sets(&mut tx, &windows[1]),
        account,
        "two windows, one set"
    );
    assert_eq!(set_refs(&mut tx, &account[0]), Some(2));
    let chunked = mapper::key("account_window", CHUNKED, 1).unwrap();
    assert!(
        tx.get(&chunked).unwrap().unwrap().parts > 0,
        "stored in chunks"
    );
    let exclusive = referenced_sets(&mut tx, &chunked);
    assert_eq!(exclusive.len(), 1);
    assert_ne!(exclusive, account);
    assert_eq!(set_refs(&mut tx, &exclusive[0]), Some(1));
    drop(tx);
    purge(&mut db, Scratch::binding()).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(tx.get(&retired).unwrap().is_none());
    assert_eq!(referenced_sets(&mut tx, &live), shared);
    assert_eq!(set_refs(&mut tx, &shared[0]), Some(1));
    assert_eq!(set_refs(&mut tx, &only[0]), None);
    assert_eq!(set_refs(&mut tx, &account[0]), None);
    assert_eq!(set_refs(&mut tx, &exclusive[0]), None);
    drop(tx);
    assert_eq!(present(&mut db, &keys), 0);
    db.validate_references().unwrap();
    // The next save finds nothing retired and writes none of it back.
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(cx.retired.is_empty());
    purge(&mut db, Scratch::binding()).unwrap();
    assert_eq!(present(&mut db, &keys), 0);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for set in [&only[0], &account[0], &exclusive[0]] {
        assert_eq!(set_refs(&mut tx, set), None);
    }
    drop(tx);
    db.validate_references().unwrap();
    let (restored, _) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(
        serde_json::to_value(&restored.claude_usage_family_witnesses).unwrap(),
        serde_json::to_value(&with_co_owned_witness(fixture()).claude_usage_family_witnesses)
            .unwrap()
    );
}

/// [money] A save that fails to commit leaves every retired row (and the
/// sets they hold) for the next hydrate, which names them again; the next
/// good save removes them.
#[test]
fn interrupted_purge_save_keeps_rows() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &with_co_owned_witness(fixture()));
    let keys = seed_retired_rows(&mut db, true);
    assert_eq!(present(&mut db, &keys), keys.len());
    sqlite::fence_commit_writing(&db, "generation");
    let error = purge(&mut db, Scratch::binding()).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    assert_eq!(
        present(&mut db, &keys),
        keys.len(),
        "a failed save keeps them"
    );
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.retired, keys);
    purge(&mut db, Scratch::binding()).unwrap();
    assert_eq!(present(&mut db, &keys), 0);
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(cx.retired.is_empty());
    db.audit_headers().unwrap();
    db.validate_references().unwrap();
}

/// [format] Raw holds of the retired usage-pending and family account
/// fields, as an earlier release left them with their hold metadata, still
/// load. The metadata entries are dropped, so no hold custody or file state
/// comes back from them, and the next save removes the rows and rewrites the
/// metadata without the fields.
#[test]
fn retired_raw_holds_load_and_are_purged_by_the_next_save() {
    const FIELDS: [&str; 3] = [
        "claude_usage_family_pending",
        "claude_account_family_pending",
        "claude_account_family_witnesses",
    ];
    let (_scratch, mut db) = Scratch::live_store();
    let index = fixture();
    commit_populate(&mut db, &index);
    let holds = FIELDS.map(|field| mapper::key(&format!("raw_hold.{field}"), CHUNKED, 0).unwrap());
    let metadata = mapper::key("v1_field.repair_provenance", "", 0).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = tx.get(&metadata).unwrap().unwrap();
    let mut value: serde_json::Value = mapper::read(&mut tx, &h, None).unwrap();
    for (field, hold) in FIELDS.iter().zip(&holds) {
        mapper::put(&mut tx, hold, &serde_json::json!({"invalid": "held"})).unwrap();
        value["entries"][*field] = serde_json::json!({CHUNKED: {"owner": null, "charge": 64}});
    }
    mapper::put(&mut tx, &metadata, &value).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let (restored, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.retired, BTreeSet::from(holds.clone()));
    assert!(
        restored.decode_holds.same_as(&index.decode_holds),
        "no hold custody"
    );
    assert_eq!(
        serde_json::to_value(&restored.files).unwrap(),
        serde_json::to_value(&index.files).unwrap(),
        "no file is re-armed for a re-read"
    );
    purge(&mut db, Scratch::binding()).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for hold in &holds {
        assert!(tx.get(hold).unwrap().is_none());
    }
    let h = tx.get(&metadata).unwrap().unwrap();
    let value: serde_json::Value = mapper::read(&mut tx, &h, None).unwrap();
    for field in FIELDS {
        assert!(value["entries"].get(field).is_none(), "{field}");
    }
    drop(tx);
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(cx.retired.is_empty());
    db.audit_headers().unwrap();
}

/// [format] An earlier store's retired-family tombstone rows (a map entry with
/// its manifest, the marker and a raised uncertainty fence) still load:
/// hydrate names their keys without reading them, no file is re-armed for a
/// re-read, and the next save removes every row.
#[test]
fn retired_family_tombstone_rows_load_and_are_purged_by_the_next_save() {
    let (_scratch, mut db) = Scratch::live_store();
    let index = fixture();
    commit_populate(&mut db, &index);
    let map = "tombstone.claude_retired_family_tombstones";
    let rows = [
        (mapper::key(map, "", 0).unwrap(), serde_json::json!(1)),
        (
            mapper::key(map, &"a".repeat(64), 1).unwrap(),
            serde_json::json!(7),
        ),
        (
            mapper::key(
                "setting.claude_retired_family_tombstones_initialized",
                "",
                0,
            )
            .unwrap(),
            serde_json::json!(true),
        ),
        (
            mapper::key("setting.claude_retired_family_tombstones_uncertain", "", 0).unwrap(),
            serde_json::json!(true),
        ),
    ];
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for (key, value) in &rows {
        mapper::put(&mut tx, key, value).unwrap();
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let keys = rows
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let (restored, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.retired, keys);
    assert_eq!(
        serde_json::to_value(&restored.files).unwrap(),
        serde_json::to_value(&index.files).unwrap(),
        "no file is re-armed for a re-read"
    );
    purge(&mut db, Scratch::binding()).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    for key in &keys {
        assert!(tx.get(key).unwrap().is_none(), "the save removes {key:?}");
    }
    drop(tx);
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(cx.retired.is_empty());
    db.audit_headers().unwrap();
}

/// [format] Hydrate visits a retired row's header only: a value no codec
/// can read does not fail the load, and the row is still named for removal.
#[test]
fn corrupt_retired_row_does_not_fail_load() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let rows = [
        mapper::key("usage.pending", "synthetic-corrupt", 1).unwrap(),
        mapper::key("proof.owned_start", "", 0).unwrap(),
    ];
    let mut tx = db.begin(TxnMode::Write).unwrap();
    for key in &rows {
        tx.put(RowInput {
            key,
            fixed: &Fixed::None,
            value_version: 1,
            value: b"\xff not a stored value",
        })
        .unwrap();
    }
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    let (restored, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(restored.generation, 2);
    assert_eq!(cx.retired, BTreeSet::from(rows));
}
