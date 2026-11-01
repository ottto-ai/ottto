//! Integration fixtures; compiled locally, executed only in later CI.
use super::*;
use crate::snapshots::account_pending_retention::ArchivedWindows;
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
    assert!(cx.valid && !cx.presence.is_empty());
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
            mapper::key("setting.upload_context_fingerprint", "", 0).unwrap(),
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
/// One accounts-only view, as CAS custody loads it (`Some`) or a full load does.
fn accounts_view(tx: &mut dyn Transaction, roots: Option<&BTreeSet<String>>) -> Result<ScanIndex> {
    let mut view = ScanIndex::default();
    kinds_accounts::hydrate_filtered(
        tx,
        &mut view,
        &mut KindCx::default(),
        roots.map(|roots| (roots, false)),
    )?;
    if roots.is_none() {
        kinds_accounts::materialize(tx, &mut view)?;
    }
    Ok(view)
}
/// [money] filtered hydrate equals those families of a full hydrate and refuses the same damage.
#[test]
fn filtered_account_hydrate_equals_full_for_requested_families_only() {
    const WITH_WINDOWS: &str = "synthetic-family";
    const WITH_ABSENT: &str = "synthetic-absent";
    const MANY_WINDOWS: &str = "synthetic-many";
    // Sorts straight after a requested family, and extends its key.
    const EXTENDED: &str = "synthetic-family2";
    const UNREQUESTED: &str = "synthetic-unrequested";
    const MISSING: &str = "synthetic-missing";
    // Published, so a rolled-back damage transaction leaves the store usable.
    let (_scratch, mut db) = Scratch::live_store();
    let mut index = fixture();
    let family = index.claude_account_family_pending[WITH_WINDOWS].clone();
    assert!(!family.previous_windows.resident().is_empty());
    let mut absent = family.clone();
    absent.confirmed_absent_members.insert("gone-member".into());
    let pending = &mut index.claude_account_family_pending;
    pending.insert(WITH_ABSENT.into(), absent);
    let mut many = family.clone();
    many.previous_windows = ArchivedWindows::Resident(vec![family.current.clone(); 8]);
    pending.insert(MANY_WINDOWS.into(), many);
    pending.insert(EXTENDED.into(), family.clone());
    pending.insert(UNREQUESTED.into(), family);
    let usage = index.claude_usage_family_pending[WITH_WINDOWS].clone();
    index
        .claude_usage_family_pending
        .insert(EXTENDED.into(), usage.clone());
    index
        .claude_usage_family_pending
        .insert(UNREQUESTED.into(), usage);
    commit_populate(&mut db, &index);
    let roots: BTreeSet<String> = [WITH_WINDOWS, WITH_ABSENT, MANY_WINDOWS, MISSING]
        .map(str::to_owned)
        .into();

    let mut tx = db.begin(TxnMode::Read).unwrap();
    let mut expected = accounts_view(&mut tx, None).unwrap();
    assert!(expected
        .claude_account_family_pending
        .contains_key(UNREQUESTED));
    expected
        .claude_account_family_pending
        .retain(|family, _| roots.contains(family));
    expected
        .claude_usage_family_pending
        .retain(|family, _| roots.contains(family));
    let subset = accounts_view(&mut tx, Some(&roots)).unwrap();
    assert_eq!(subset.claude_account_family_pending.len(), 3);
    assert_eq!(
        subset.claude_account_family_pending[MANY_WINDOWS]
            .previous_windows
            .resident()
            .len(),
        8
    );
    assert_eq!(subset.claude_usage_family_pending.len(), 1);
    assert!(!subset.claude_account_family_pending.contains_key(MISSING));
    assert_eq!(
        serde_json::to_vec(&subset).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    let control = mapper::key("account.current", WITH_WINDOWS, 1).unwrap();
    let h = tx.get(&control).unwrap().unwrap();
    let (_, _, ids): (Option<u64>, u64, Vec<u64>) = mapper::read(&mut tx, &h, None).unwrap();
    drop(tx);
    let key = mapper::key;

    // Same refusal as the full scan: undecodable (`Some`), removed (`None`),
    // and an orphan or misplaced row that no control lists.
    let window = key("account_window", WITH_WINDOWS, ids[0]).unwrap();
    let absent = key("account.absent_members", WITH_ABSENT, 1).unwrap();
    for (row, damage) in [
        (control.clone(), Some("undecodable")),
        (window.clone(), Some("undecodable")),
        (absent.clone(), Some("undecodable")),
        (
            key("usage.pending", WITH_WINDOWS, 1).unwrap(),
            Some("undecodable"),
        ),
        (window, None),
        (absent, None),
        (
            key("account_window", WITH_WINDOWS, 0).unwrap(),
            Some("orphan"),
        ),
        (
            key("account_window", WITH_ABSENT, 9_999).unwrap(),
            Some("orphan"),
        ),
        (
            // Past the first page of this family's rows.
            key("account_window", MANY_WINDOWS, 9_999).unwrap(),
            Some("orphan"),
        ),
        (
            key("account.absent_members", MISSING, 1).unwrap(),
            Some("orphan"),
        ),
        (
            key("account.absent_members", WITH_ABSENT, 2).unwrap(),
            Some("orphan"),
        ),
        (
            key("account.current", WITH_ABSENT, 2).unwrap(),
            Some("orphan"),
        ),
    ] {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        match damage {
            Some(value) => drop(mapper::put(&mut tx, &row, value).unwrap()),
            None => assert!(tx.delete(&row).unwrap()),
        }
        let full = accounts_view(&mut tx, None).err().map(|e| format!("{e:#}"));
        let filtered = accounts_view(&mut tx, Some(&roots))
            .err()
            .map(|e| format!("{e:#}"));
        assert!(full.is_some(), "{row:?}");
        assert_eq!(filtered, full, "{row:?}");
        drop(tx);
    }

    // A removed control still refuses, by its orphaned rows. Only the full
    // scan can see the manifest count.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    assert!(tx.delete(&control).unwrap());
    let full = accounts_view(&mut tx, None).err().unwrap();
    assert_eq!(full.to_string(), "accounts_missing_family");
    let filtered = accounts_view(&mut tx, Some(&roots)).err().unwrap();
    assert_eq!(filtered.to_string(), "accounts_orphan_window");
    drop(tx);

    // Damage outside the requested families is the full load's to refuse: a
    // filtered read never touches it.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let other = key("account.current", UNREQUESTED, 1).unwrap();
    mapper::put(&mut tx, &other, "undecodable").unwrap();
    assert!(accounts_view(&mut tx, None).is_err());
    assert_eq!(
        serde_json::to_vec(&accounts_view(&mut tx, Some(&roots)).unwrap()).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    drop(tx);

    // Nor does it validate the headers of the adjacent family, the next rows
    // in every kind. This damage stays: nothing below may need a clean store.
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let windows = RecordKind::parse("account_window").unwrap();
    let page = tx
        .scan_record_key(&windows, EXTENDED.as_bytes(), None, 1)
        .unwrap();
    drop(tx);
    for row in [
        key("account.current", EXTENDED, 1).unwrap(),
        page[0].key.clone(),
        key("account.absent_members", EXTENDED, 1).unwrap(),
        key("usage.pending", EXTENDED, 1).unwrap(),
    ] {
        sqlite::corrupt_row_header_for_test(&db, &row);
    }
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert!(accounts_view(&mut tx, None).is_err());
    assert_eq!(
        serde_json::to_vec(&accounts_view(&mut tx, Some(&roots)).unwrap()).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
/// [behaviour] rows lost out of band at an equal generation are refused or rewritten, never Absent.
#[test]
fn out_of_band_family_row_loss_is_refused_or_rewritten_never_silently_absent() {
    const FAMILY: &str = "synthetic-family";
    for (lost_account, dirty) in [(true, false), (true, true), (false, false), (false, true)] {
        let (_scratch, mut db) = Scratch::live_store();
        let mut index = fixture();
        // Its authority row makes the CAS merge request this family.
        index.insert_retry_pending_claude_authority_for_test(FAMILY);
        commit_populate(&mut db, &index);
        let (previous, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let committed = baseline(&previous, &mut cx).unwrap();
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();

        let mut lost = vec![mapper::key("usage.pending", FAMILY, 1).unwrap()];
        if lost_account {
            let control = mapper::key("account.current", FAMILY, 1).unwrap();
            let mut tx = db.begin(TxnMode::Read).unwrap();
            let h = tx.get(&control).unwrap().unwrap();
            let (_, _, ids): (Option<u64>, u64, Vec<u64>) =
                mapper::read(&mut tx, &h, None).unwrap();
            drop(tx);
            lost = ids
                .iter()
                .map(|id| mapper::key("account_window", FAMILY, *id).unwrap())
                .collect();
            lost.push(mapper::key("account.absent_members", FAMILY, 1).unwrap());
            lost.push(control);
        }
        for row in &lost {
            sqlite::delete_row_for_test(&db, row);
        }

        let mut next = previous.clone();
        if dirty && lost_account {
            let family = next.claude_account_family_pending.get_mut(FAMILY).unwrap();
            family.current.census_window_end = "2026-10-31T00:00:00Z".into();
        } else if dirty {
            next.insert_claude_usage_family_pending_for_test(FAMILY, "2026-10-31T00:00:00Z");
        }
        // Claim-only skips window retirement, so a clean family stays clean.
        let saved = import::ClaudeMapper
            .save(&mut db, &identity, committed, &mut next, &mut cx, true)
            .err()
            .map(|error| error.to_string());
        let generation = db.read_control::<u64>("generation").unwrap();
        let reload = |db: &mut sqlite::Sqlite| {
            hydrate(db, Scratch::binding())
                .err()
                .map(|error| error.to_string())
        };
        match (lost_account, dirty) {
            // Unchanged rows match their baseline digests, so the save writes
            // neither them nor the manifest, which still counts them.
            (true, false) => {
                assert_eq!(saved, None);
                assert_eq!(generation, Some(2));
                assert_eq!(reload(&mut db).unwrap(), "accounts_missing_family");
            }
            (false, false) => {
                assert_eq!(saved, None);
                assert_eq!(generation, Some(2));
                assert_eq!(reload(&mut db).unwrap(), "state_v2_missing_member");
            }
            // A changed family needs its control, whose absence refuses the save.
            (true, true) => {
                assert_eq!(saved.unwrap(), "accounts_window_inventory");
                assert_eq!(generation, Some(1));
                assert_eq!(reload(&mut db).unwrap(), "accounts_missing_family");
            }
            // A changed map row is written whole from RAM: the loss is healed.
            (false, true) => {
                assert_eq!(saved, None);
                assert_eq!(generation, Some(2));
                assert_eq!(
                    next.claude_account_family_pending,
                    previous.claude_account_family_pending
                );
                assert_persisted(&mut db, &next);
            }
        }
    }
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
    assert!(super::save_graph(&mut db, &identity, digests, &mut retry, &mut cx).is_err());
    assert!(!cx.valid && cx.ambiguous);
    assert_persisted(&mut db, &current);
    assert_eq!(
        hydrate(&mut db, Scratch::binding())
            .unwrap()
            .0
            .upload_context_fingerprint,
        current.upload_context_fingerprint
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
        next.upload_context_fingerprint = Some("never-committed".into());
        next.files.clear();
        next.claude_account_family_pending.clear();
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
            hydrated.upload_context_fingerprint,
            if after_commit {
                next.upload_context_fingerprint.clone()
            } else {
                current.upload_context_fingerprint
            }
        );
        let mut next = hydrated.clone();
        next.upload_context_fingerprint = Some("committed".into());
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

/// One strict rollover step (no raw holds): archive current under a new
/// boundary, or remove all.
fn roll(index: &mut ScanIndex, boundary: &str) {
    if boundary == "gone" {
        index.claude_account_family_pending.clear();
        return;
    }
    if index.claude_account_family_pending.is_empty() {
        index.claude_account_family_pending = fixture().claude_account_family_pending;
    }
    let p = index
        .claude_account_family_pending
        .get_mut("synthetic-family")
        .unwrap();
    if p.census_window_end != boundary {
        let old = p.current.clone();
        p.current.census_window_end = boundary.into();
        p.archive(old, true);
    }
}
/// [money] window ids are monotonic across a b a and complete family removal.
/// Cold arm: the production v2 graph keeps its archive in the store and
/// queues each rollover; its summary equals the stored windows' and its save
/// leaves the same decoded rows as the resident save.
#[test]
fn window_ids_are_monotonic_across_a_b_a_and_complete_family_removal() {
    let (_scratch, mut db) = Scratch::store();
    let (_cold_scratch, mut cold_db) = Scratch::store();
    let mut prev = fixture();
    prev.files.clear();
    commit_populate(&mut db, &prev);
    commit_populate(&mut cold_db, &prev);
    prev.generation = 1;
    let mut prior_id = 0;
    for boundary in ["A", "B", "A", "gone", "A"] {
        let mut tx = cold_db.begin(TxnMode::Read).unwrap();
        let (mut cold, mut cold_cx) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
        drop(tx);
        let (stored, _) = hydrate(&mut cold_db, Scratch::binding()).unwrap();
        for (root, family) in &cold.claude_account_family_pending {
            let resident = &stored.claude_account_family_pending[root];
            assert!(
                family.history_summary() == resident.history_summary(),
                "{root}"
            );
            assert_eq!(family.has_history(), resident.has_history(), "{root}");
            if resident.has_history() {
                assert!(matches!(family.previous_windows, ArchivedWindows::Cold(_)));
            }
        }
        let cold_baseline = baseline(&cold, &mut cold_cx).unwrap();
        // Seed mode keeps every stored cold row in the baseline.
        for (root, window) in &cold_baseline.windows {
            for id in &window.ids {
                let key = mapper::key("account_window", root, *id).unwrap();
                assert!(cold_baseline.rows.contains_key(&key), "{root} {id}");
            }
        }
        cold.generation += 1;
        roll(&mut cold, boundary);
        let mut tx = cold_db.begin(TxnMode::Write).unwrap();
        delta(cold_baseline, &cold, &mut tx, &mut cold_cx).unwrap();
        let outcome = tx.commit(cold.generation - 1, cold.generation);
        assert_eq!(outcome, DurableCommitOutcome::Committed(cold.generation));

        let (_, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        let mut next = prev.clone();
        next.generation += 1;
        roll(&mut next, boundary);
        let baseline = baseline(&prev, &mut cx).unwrap();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(baseline, &next, &mut tx, &mut cx).unwrap();
        let key = mapper::key("account.current", "synthetic-family", 1).unwrap();
        let h = tx.get(&key).unwrap().unwrap();
        let (id, high, _): (Option<u64>, u64, Vec<u64>) = mapper::read(&mut tx, &h, None).unwrap();
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
        let (cold_restored, _) = hydrate(&mut cold_db, Scratch::binding()).unwrap();
        assert_eq!(
            serde_json::to_vec(&cold_restored).unwrap(),
            serde_json::to_vec(&next).unwrap(),
            "cold {boundary}"
        );
        prev = next;
    }
}

/// [money] A cold archive replays the endpoint rule over at most its last two
/// stored rows to the rows a resident save writes, replaced endpoints
/// included. A stored tail that no longer matches the baseline is Unknown:
/// the save refuses, counted, and removes nothing. A stale base with no
/// shared rollover refuses as a lineage miss, counted separately.
#[test]
fn cold_archive_replays_endpoints_like_resident_and_refuses_unknown_rows() {
    const FAMILY: &str = "synthetic-family";
    let at = |minute: u32| format!("2026-08-02T07:{minute:02}:00Z");
    let mut index = fixture();
    index.files.clear();
    let p = index.claude_account_family_pending.get_mut(FAMILY).unwrap();
    let mut window = p.current.clone();
    *p.previous_windows.resident_mut() = (0..3)
        .map(|minute| {
            window.census_window_end = at(minute);
            window.clone()
        })
        .collect();
    p.current.census_window_end = at(3);
    let (_resident_scratch, mut resident_db) = Scratch::store();
    let (_cold_scratch, mut cold_db) = Scratch::store();
    commit_populate(&mut resident_db, &index);
    commit_populate(&mut cold_db, &index);
    let mut saved = Vec::new();
    for (db, cold) in [(&mut resident_db, false), (&mut cold_db, true)] {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let (mut graph, mut cx) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
        if !cold {
            kinds_accounts::materialize(&mut tx, &mut graph).unwrap();
        }
        drop(tx);
        let archive = &graph.claude_account_family_pending[FAMILY].previous_windows;
        assert_eq!(matches!(archive, ArchivedWindows::Cold(_)), cold);
        let previous = baseline(&graph, &mut cx).unwrap();
        graph.generation += 1;
        // Equal evidence at increasing boundaries: each rollover replaces the
        // stored last endpoint.
        roll(&mut graph, &at(4));
        roll(&mut graph, &at(5));
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(previous, &graph, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        let restored = hydrate(db, Scratch::binding()).unwrap().0;
        let archive = restored.claude_account_family_pending[FAMILY]
            .previous_windows
            .resident();
        let ends: Vec<_> = archive
            .iter()
            .map(|w| w.census_window_end.clone())
            .collect();
        assert_eq!(ends, [at(0), at(1), at(4)]);
        saved.push(serde_json::to_vec(&restored).unwrap());
    }
    assert_eq!(saved[0], saved[1]);

    // Unknown arm: the stored last endpoint changes under the baseline.
    let mut tx = cold_db.begin(TxnMode::Read).unwrap();
    let (mut graph, mut cx) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
    drop(tx);
    let previous = baseline(&graph, &mut cx).unwrap();
    graph.generation += 1;
    roll(&mut graph, &at(6));
    let mut tx = cold_db.begin(TxnMode::Write).unwrap();
    let control = mapper::key("account.current", FAMILY, 1).unwrap();
    let h = tx.get(&control).unwrap().unwrap();
    let (_, _, ids): (Option<u64>, u64, Vec<u64>) = mapper::read(&mut tx, &h, None).unwrap();
    let key = mapper::key("account_window", FAMILY, ids[ids.len() - 2]).unwrap();
    let mut changed = graph.claude_account_family_pending[FAMILY].current.clone();
    changed.evidence_request_count += 1;
    mapper::put(&mut tx, &key, &changed).unwrap();
    let count = |name: &str| {
        telemetry::latest_for_test(name)
            .and_then(|count| count.as_u64())
            .unwrap_or(0)
    };
    let before = count("cold_row_unknown");
    let error = delta(previous, &graph, &mut tx, &mut cx).err().unwrap();
    assert!(format!("{error:#}").contains("state_v2_cold_row_unknown"));
    assert!(count("cold_row_unknown") > before);
    drop(tx);
    let restored = hydrate(&mut cold_db, Scratch::binding()).unwrap().0;
    assert_eq!(serde_json::to_vec(&restored).unwrap(), saved[1]);

    // Lineage miss: a graph whose base predates a commit it shares no
    // rollover with refuses, counted apart from row damage.
    let mut tx = cold_db.begin(TxnMode::Read).unwrap();
    let (mut stale, mut cx) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
    drop(tx);
    let previous = baseline(&stale, &mut cx).unwrap();
    stale.generation += 1;
    roll(&mut stale, &at(7));
    let mut tx = cold_db.begin(TxnMode::Write).unwrap();
    delta(previous, &stale, &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
    let mut tx = cold_db.begin(TxnMode::Read).unwrap();
    let (current, mut fresh) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
    drop(tx);
    let previous = baseline(&current, &mut fresh).unwrap();
    roll(&mut stale, &at(8));
    let before = count("cold_lineage_miss");
    let mut tx = cold_db.begin(TxnMode::Write).unwrap();
    let error = delta(previous, &stale, &mut tx, &mut fresh).err().unwrap();
    assert!(format!("{error:#}").contains("state_v2_cold_lineage_miss"));
    assert!(count("cold_lineage_miss") > before);
}

/// [behaviour] A complete hydrate keeps one summary per archive: 1 or 200
/// archived windows with the same members leave the same account heap.
#[test]
fn cold_archive_heap_does_not_grow_with_history() {
    let heap = |windows: u32| {
        let (_scratch, mut db) = Scratch::store();
        let mut index = fixture();
        index.files.clear();
        let p = index
            .claude_account_family_pending
            .get_mut("synthetic-family")
            .unwrap();
        let mut window = p.current.clone();
        *p.previous_windows.resident_mut() = (0..windows)
            .map(|n| {
                window.census_window_end = format!("2026-08-01T{:02}:{:02}:00Z", n / 60, n % 60);
                window.clone()
            })
            .collect();
        commit_populate(&mut db, &index);
        let mut tx = db.begin(TxnMode::Read).unwrap();
        let (hydrated, _) = hydrate_txn(&mut tx, Scratch::binding()).unwrap();
        let archive = &hydrated.claude_account_family_pending["synthetic-family"].previous_windows;
        assert!(matches!(archive, ArchivedWindows::Cold(_)));
        crate::heap_layout_bound::completed_bound(
            &hydrated.claude_account_family_pending,
            usize::MAX,
        )
        .unwrap()
    };
    assert_eq!(heap(1), heap(200));
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
    assert_persisted(&mut db, &selected);
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
