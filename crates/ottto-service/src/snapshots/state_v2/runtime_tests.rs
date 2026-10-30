//! Table-agnostic F5–F7 fixtures. The fake mapper carries only generation;
//! these tests make no condition-b/hydration parity claim.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    support: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let support = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-v2-route-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = support.join("snapshots/destinations").join("b".repeat(64));
        fs::create_dir_all(&parent).unwrap();
        Self {
            path: parent.join("claude_code-test-scan-index.json"),
            support,
        }
    }
    fn identity(&self) -> Identity {
        Identity {
            format: FORMAT,
            db_id: "fixture-db".into(),
            binding: binding(&self.path).unwrap(),
            fence_generation: 0,
        }
    }
    fn imported(&self) {
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&self.path, ".v2.sqlite.import"))
                .unwrap();
        db.control("identity", &self.identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        db.finish_import().unwrap();
        // Synthetic fixture has no original ledger; seal that exact absence
        // before any publication boundary, as the production importer must.
        super::super::ack::ProgressRecovery::seal_import(self.identity(), 0, &self.path, None)
            .unwrap();
    }
    fn published(&self) {
        self.imported();
        fence::publish(&self.path, &self.identity(), &mut false).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.support);
    }
}

/// [off=main] Unbound v1 loads ignore growth fields for every source and never
/// consult the v2 registry, even when another route owns it.
#[test]
fn off_v1_growth_is_unknown_and_diagnostics_need_no_registry() {
    let root = crate::test_scratch::private_dir("v1-off-growth");
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let registry = states().lock().unwrap();
        let root = &root;
        scope.spawn(move || {
            for source in [
                crate::snapshots::SnapshotSource::ClaudeCode,
                crate::snapshots::SnapshotSource::Codex,
                crate::snapshots::SnapshotSource::Pi,
            ] {
                // An unbound path has no custody-probe exception. The bound
                // Claude probe is covered by the existing custody regression.
                let path = root.join(format!("{}-test-scan-index.json", source.api_slug()));
                for growth in [
                    serde_json::Value::Null,
                    serde_json::json!(42),
                    serde_json::json!({"/synthetic/grown": {"last_growth_full_unix": 100}}),
                ] {
                    let mut wire = serde_json::to_value(ScanIndex::default()).unwrap();
                    wire["growth_retention"] = growth;
                    fs::write(&path, serde_json::to_vec(&wire).unwrap()).unwrap();
                    crate::local_resource_diagnostics::source_prepare(
                        source.api_slug(),
                        || {
                            let mut index =
                                ScanIndex::load_attributed(&path, Some(source)).unwrap();
                            assert!(index.v2.is_none());
                            assert!(index.decode_holds.is_empty());
                            index.save(&path).unwrap();
                            let saved: serde_json::Value =
                                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                            assert!(saved.get("growth_retention").is_none());
                        },
                        |_| false,
                    );
                }
            }
            done.send(()).unwrap();
        });
        let completed = finished.recv_timeout(Duration::from_secs(10));
        drop(registry);
        assert!(completed.is_ok(), "OFF loads waited for the v2 registry");
    });
    fs::remove_dir_all(root).unwrap();
}

/// [regress] F5: uninstall must not flock or latch a paused v1 import route.
#[test]
fn uninstall_leaves_unpublished_routes_to_existing_cleanup() {
    let f = Fixture::new();
    fs::write(&f.path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    assert!(load_with(&f.path, true, &ClaudeMapper).unwrap().is_none());
    let before = fs::read(&f.path).unwrap();
    // An ordinary v1 owner must not prevent uninstall from reaching its
    // established cleanup, and an absent checkpoint lock must stay absent.
    close_tree(&f.support, false).unwrap();
    assert!(!f.path.with_extension("lock").exists());
    let lock = crate::snapshots::CheckpointLock::acquire(&f.path).unwrap();
    close_tree(&f.support, false).unwrap();
    drop(lock);
    with_state(&f.path, |state| {
        assert!(!state.latched);
        Ok(())
    })
    .unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), before);
    let live = Fixture::new();
    live.published();
    let index = load_with(&live.path, false, &EmptyMapper).unwrap().unwrap();
    let runtime = index.v2().persistence_v2.as_ref().unwrap();
    assert!(runtime.session.lock().unwrap().is_some());
    let fence = fs::read(&live.path).unwrap();
    close_tree(&live.support, false).unwrap();
    assert!(runtime.session.lock().unwrap().is_none());
    assert!(guard_external(&live.path, Some(runtime), index.generation).is_err());
    assert_eq!(fs::read(&live.path).unwrap(), fence);
}
struct EmptyMapper;
impl Mapper for EmptyMapper {
    fn references(
        _: &Header,
        _: &dyn Value,
        _: &mut dyn FnMut(&RowKey) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
    fn private_paths(
        _: &Header,
        _: &dyn Value,
        _: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
    fn inventory(&self, _: &Path) -> std::result::Result<(), Pause> {
        Ok(())
    }
    fn preflight(&self, _: &ScanIndex) -> std::result::Result<(), Pause> {
        Ok(())
    }
    fn import_graph<S: Store>(
        &self,
        _: &mut S,
        _: &ScanIndex,
        _: Option<&import::Original>,
    ) -> Result<KindCx> {
        Ok(KindCx::default())
    }
    fn hydrate<S: Store>(&self, db: &mut S) -> Result<ScanIndex> {
        let mut tx = db.begin(TxnMode::Read)?;
        let h = tx.get(&RowKey::Meta("generation".into()))?.unwrap();
        let mut packed = Vec::new();
        tx.read_value(&h, &mut packed)?;
        let json = packed;
        Ok(ScanIndex {
            generation: serde_json::from_slice(&json)?,
            ..ScanIndex::default()
        })
    }
    fn merge_cas<T: Transaction>(&self, _: &mut T, _: &mut ScanIndex) -> Result<()> {
        Ok(())
    }
    fn delta<T: Transaction>(&self, _: &mut T, _: &ScanIndex) -> Result<()> {
        Ok(())
    }
}
/// [format] f5 missing v1 garbled fences never authenticate final db.
#[test]
fn f5_missing_v1_garbled_fences_never_authenticate_final_db() {
    for root in [
        None,
        Some(b"{\"schema_version\":3}".as_slice()),
        Some(b"bad".as_slice()),
    ] {
        let f = Fixture::new();
        f.published();
        if let Some(bytes) = root {
            fs::write(&f.path, bytes).unwrap();
        } else {
            fs::remove_file(&f.path).unwrap();
        }
        let db = fence::sibling(&f.path, ".v2.sqlite");
        let before = fs::read(&db).unwrap();
        assert_eq!(
            load_with(&f.path, false, &EmptyMapper)
                .unwrap_err()
                .downcast_ref::<Hold>(),
            Some(&Hold::FenceLost)
        );
        assert!(guard_containment_locked(&f.path).is_err());
        assert!(save_with(&f.path, &mut ScanIndex::default(), &EmptyMapper).is_err());
        assert_eq!(fs::read(db).unwrap(), before);
        assert!(!fence::sibling(&f.path, ".v2.sqlite.import").exists());
    }
}
/// [format] f7 publication failures keep latch and artifacts and restart recovers.
#[test]
fn f7_publication_failures_keep_latch_and_artifacts_and_restart_recovers() {
    for point in [
        fence::Boundary::FenceAttempt,
        fence::Boundary::FenceRenamed,
        fence::Boundary::FenceSynced,
        fence::Boundary::DbRenamed,
        fence::Boundary::FinalSynced,
    ] {
        let f = Fixture::new();
        fs::write(&f.path, b"v1-before-publication").unwrap();
        f.imported();
        let mut latch = false;
        fence::fail_at(point);
        assert!(fence::publish(&f.path, &f.identity(), &mut latch).is_err());
        assert!(latch);
        assert!(fence::cleanup_unpublished(&f.path, latch).is_err());
        if point == fence::Boundary::FenceAttempt {
            assert!(fence::reconcile(&f.path, &f.identity().binding, true).is_err());
            assert_eq!(fs::read(&f.path).unwrap(), b"v1-before-publication");
        } else {
            let pair = fence::reconcile(&f.path, &f.identity().binding, false)
                .unwrap()
                .unwrap();
            assert_eq!(pair.0, f.identity());
            assert!(pair.1.exists());
            assert!(load_with(&f.path, false, &EmptyMapper).unwrap().is_some());
            assert!(guard_containment_locked(&f.path).is_err());
        }
    }
}
/// [format] f7 off after publication and ambiguous commits cannot ack or fallback.
#[test]
fn f7_off_after_publication_and_ambiguous_commits_cannot_ack_or_fallback() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert!(save_with(&f.path, &mut index, &EmptyMapper).unwrap());
    assert_eq!(index.generation, 1);
    for outcome in [
        DurableCommitOutcome::Published(2),
        DurableCommitOutcome::Ambiguous,
    ] {
        let mut index = index.clone();
        let mut reload = false;
        assert!(apply_outcome(&mut index, &mut reload, outcome).is_err());
        assert!(reload);
    }
    let mut reload = false;
    assert!(apply_outcome(&mut index, &mut reload, DurableCommitOutcome::NotPublished).is_err());
    assert!(!reload);
    assert_eq!(index.generation, 1);
    // EmptyMapper deliberately caches a graph without semantic custody rows.
    // Use a fresh route so the production mapper must decode those missing rows.
    let f = Fixture::new();
    f.published();
    assert!(load_locked(&f.path, None).is_err()); // unmapped published custody holds
}
/// [format] f6 explicit forget deletes all artifacts and invalidates stale clones.
#[test]
fn f6_explicit_forget_deletes_all_artifacts_and_invalidates_stale_clones() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    let mut stale = index.clone();
    assert!(fence::sibling(&f.path, ".v2.sqlite.owner").exists());
    for suffix in [
        ".v2.sqlite.migration-backup",
        ".v1-readonly",
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v2-fence.tmp",
        ".v2-ack-receipt",
    ] {
        fs::write(fence::sibling(&f.path, suffix), b"forgotten-path-canary").unwrap();
    }
    let shards = fence::sibling(&f.path, ".v1-readonly.shards");
    fs::create_dir(&shards).unwrap();
    fs::write(shards.join("payload"), b"forgotten-path-canary").unwrap();
    let recovery = fence::sibling(&f.path, ".v2-recovery");
    fs::create_dir(&recovery).unwrap();
    fs::write(
        recovery.join("interrupted-member"),
        b"forgotten-path-canary",
    )
    .unwrap();
    let records = crate::durable_tail_store::store_dir_for_index(&f.path);
    fs::create_dir(&records).unwrap();
    fs::write(records.join("synthetic.rec"), b"restart-record").unwrap();
    crate::snapshots::erase_claude_state_v2_artifacts(&f.support).unwrap();
    assert!(!records.exists());
    assert!(!recovery.exists());
    for suffix in [
        ".v2.sqlite.migration-backup",
        "",
        ".v2.sqlite",
        ".v2.sqlite-wal",
        ".v2.sqlite-shm",
        ".v2.sqlite.owner",
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v1-readonly",
        ".v1-readonly.shards",
        ".v2-fence.tmp",
        ".v2-ack-receipt",
    ] {
        assert!(!fence::sibling(&f.path, suffix).exists());
    }
    assert!(save_with(&f.path, &mut stale, &EmptyMapper).is_err());
    assert!(load_with(&f.path, false, &EmptyMapper).is_err());
}
/// [format] publication pending pause does not touch v1 and off cancels inventory slot.
#[test]
fn publication_pending_pause_does_not_touch_v1_and_off_cancels_inventory_slot() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&ScanIndex::default()).unwrap();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true, &ClaudeMapper).unwrap().is_none());
    let mut index = ScanIndex::default();
    import_with(&f.path, &mut index, &ClaudeMapper).unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
    assert_eq!(fs::read_dir(f.path.parent().unwrap()).unwrap().count(), 1);
    let f = Fixture::new();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true, &EmptyMapper).unwrap().is_none());
    assert!(load_with(&f.path, false, &EmptyMapper).unwrap().is_none());
    import_with(&f.path, &mut index, &EmptyMapper).unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
}

/// [format] absent parent containment guard never promotes a database.
#[test]
fn absent_parent_containment_guard_never_promotes_a_database() {
    let f = Fixture::new();
    f.imported();
    let mut file = fence::create_private(&f.path).unwrap();
    serde_json::to_writer(&mut file, &fence::Fence::new(&f.identity())).unwrap();
    drop(file);
    assert!(guard_containment_locked(&f.path).is_err());
    assert!(fence::sibling(&f.path, ".v2.sqlite.import").exists());
    assert!(!fence::sibling(&f.path, ".v2.sqlite").exists());
}

/// [format] damaged and oversized fence claims hold before v1 containment.
#[test]
fn damaged_and_oversized_fence_claims_hold_before_v1_containment() {
    for bytes in [
        b"{\"storage_format\":2,".to_vec(),
        b"{\"storage_format\":3,".to_vec(),
        b"{\"schema_version\":4,".to_vec(),
        format!(
            "{{\"schema_version\":4,\"padding\":\"{}\"}}",
            "x".repeat(5000)
        )
        .into_bytes(),
    ] {
        let f = Fixture::new();
        fs::write(&f.path, &bytes).unwrap();
        assert!(load_with(&f.path, false, &EmptyMapper).is_err());
        assert!(guard_containment_locked(&f.path).is_err());
        assert_eq!(fs::read(&f.path).unwrap(), bytes);
    }
}

/// [format] generation and capability are checked before external effects.
#[test]
fn generation_and_capability_are_checked_before_external_effects() {
    for future_writer in [false, true] {
        let f = Fixture::new();
        f.published();
        let index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
        let check = crate::snapshots::state_v2_side_effect_guard(&f.path, &index);
        check().unwrap();
        {
            let mut session = index
                .v2()
                .persistence_v2
                .as_ref()
                .unwrap()
                .session
                .lock()
                .unwrap();
            let session = session.as_mut().unwrap();
            if future_writer {
                sqlite::future_writer_for_test(&mut session.db);
            } else {
                session.db.control("generation", &1_u64).unwrap();
            }
        }
        assert!(check().is_err());
    }
}

/// [format] another graph save cannot advance a stale external guard.
#[test]
fn another_graph_save_cannot_advance_a_stale_external_guard() {
    let f = Fixture::new();
    f.published();
    let mut first = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    let second = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    let stale = crate::snapshots::state_v2_side_effect_guard(&f.path, &second);
    stale().unwrap();
    assert!(save_with(&f.path, &mut first, &EmptyMapper).unwrap());
    assert_eq!(second.generation, 0);
    assert_eq!(first.generation, 1);
    assert!(stale().is_err());
    crate::snapshots::state_v2_side_effect_guard(&f.path, &first)().unwrap();
}

/// [format] route replays receipt before fresh or cached graph and missing receipt holds.
#[test]
fn route_replays_receipt_before_fresh_or_cached_graph_and_missing_receipt_holds() {
    for cached in [false, true] {
        let f = Fixture::new();
        f.published();
        if cached {
            load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
        }
        let recovery =
            super::super::ack::ProgressRecovery::seal_import(f.identity(), 0, &f.path, None)
                .unwrap();
        let progress = f.path.with_file_name(format!(
            "{}-upload-progress.json",
            f.path.file_stem().unwrap().to_str().unwrap()
        ));
        let next = br#"{"generation":1,"accepted":"exact-body"}"#;
        recovery.before_progress_save(None, next).unwrap();
        assert!(!progress.exists());
        // Holds the same owner lock as the production load entry point; replay
        // must not recursively acquire it through the external side-effect guard.
        let _lock = super::super::super::CheckpointLock::acquire(&f.path).unwrap();
        assert!(load_with(&f.path, false, &EmptyMapper).unwrap().is_some());
        assert_eq!(fs::read(&progress).unwrap(), next);
        fs::remove_file(fence::sibling(&f.path, ".v2-ack-receipt")).unwrap();
        assert!(load_with(&f.path, false, &EmptyMapper).is_err());
        assert_eq!(fs::read(&progress).unwrap(), next);
        assert!(guard_containment_locked(&f.path).is_err());
    }
}

/// [format] real mapper runtime saves admitted state and keeps runtime policy.
#[test]
fn real_mapper_runtime_saves_admitted_state_and_keeps_runtime_policy() {
    let f = Fixture::new();
    let mut db =
        sqlite::Sqlite::create_import(&fence::sibling(&f.path, ".v2.sqlite.import")).unwrap();
    db.path_extractor(kinds::private_paths);
    db.reference_extractor(kinds::references);
    db.control("identity", &f.identity()).unwrap();
    let mut cx = KindCx::default();
    cx.binding = Some(f.identity().binding);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    kinds::populate(&ScanIndex::default(), &mut tx, &mut cx).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    db.finish_import().unwrap();
    super::super::ack::ProgressRecovery::seal_import(f.identity(), 1, &f.path, None).unwrap();
    fence::publish(&f.path, &f.identity(), &mut false).unwrap();
    let mut index = load_with(&f.path, false, &ClaudeMapper).unwrap().unwrap();
    index.upload_context_fingerprint = Some("synthetic-policy".into());
    index.active_upload_context_fingerprint = Some("active-synthetic-policy".into());
    index.file_upload_context_enabled = true;
    assert!(save_locked(&f.path, &mut index, false, None).unwrap());
    assert_eq!(index.generation, 2);
    assert_eq!(
        index.active_upload_context_fingerprint.as_deref(),
        Some("active-synthetic-policy")
    );
    assert!(index.file_upload_context_enabled && index.v2().persistence_v2.is_some());
    let current = load_with(&f.path, false, &ClaudeMapper).unwrap().unwrap();
    assert_eq!(
        current.upload_context_fingerprint,
        index.upload_context_fingerprint
    );
    assert_eq!(current.generation, index.generation);
}

/// [format] newly adopted import can save without an intervening load.
#[test]
fn newly_adopted_import_can_save_without_an_intervening_load() {
    let f = Fixture::new();
    fs::write(&f.path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    // Use the real inventory/publication path so import seals the external
    // progress receipt. EmptyMapper only stands in for semantic row mapping.
    assert!(load_with(&f.path, true, &ClaudeMapper).unwrap().is_none());
    let mut index = ScanIndex::default();
    import_with(&f.path, &mut index, &EmptyMapper).unwrap();
    assert!(index.v2().persistence_v2.is_some());
    assert!(fence::sibling(&f.path, ".v2-ack-receipt").is_file());
    let runtime = index.v2().persistence_v2.clone().unwrap();
    assert!(save_with(&f.path, &mut index, &EmptyMapper).unwrap());
    assert_eq!(index.generation, 1);
    assert!(Arc::ptr_eq(
        &runtime,
        index.v2().persistence_v2.as_ref().unwrap()
    ));
}

/// [format] import without original inventory refuses publication.
#[test]
fn import_without_original_inventory_refuses_publication() {
    let f = Fixture::new();
    let bytes = b"synthetic-v1-authority";
    fs::write(&f.path, bytes).unwrap();
    assert!(load_with(&f.path, true, &EmptyMapper).unwrap().is_none());
    let mut index = ScanIndex::default();
    import_with(&f.path, &mut index, &EmptyMapper).unwrap();
    assert!(index.v2().persistence_v2.is_none());
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
    for (suffix, _, _) in fence::ARTIFACTS
        .iter()
        .filter(|(_, cleanup, _)| *cleanup != fence::Cleanup::SourceOnly)
    {
        assert!(!fence::sibling(&f.path, suffix).exists());
    }
    assert!(!fence::sibling(&f.path, ".v2.sqlite").exists());
    assert!(!fence::sibling(&f.path, ".v2-ack-receipt").exists());
}

// Real mapper coverage for the raw decoder/load route (the fixtures above use
// EmptyMapper only to isolate publication and recovery).
mod hydrate_parity {
    use super::*;
    use crate::snapshots as s;
    use s::lenient_decode;
    use serde_json::value::RawValue;
    use std::collections::BTreeSet;
    use std::time::SystemTime;

    fn seed() -> ScanIndex {
        let mut index = ScanIndex::default();
        index.accepted_snapshot_fingerprints.insert("a".repeat(64));
        index.files.insert(
            "/synthetic/family.jsonl".into(),
            s::tests::manifest_index_entry(Some(&"a".repeat(64))),
        );
        index.insert_retry_pending_claude_authority_for_test("family");
        index.insert_claude_usage_family_pending_for_test("family", "2026-10-30T00:00:00Z");
        index
    }
    fn raw_slot(bytes: &[u8], field: &str, key: &str) -> String {
        let root: BTreeMap<String, &RawValue> = serde_json::from_slice(bytes).unwrap();
        let records: BTreeMap<String, &RawValue> = serde_json::from_str(root[field].get()).unwrap();
        records[key].get().into()
    }
    fn attach_raw(index: &mut ScanIndex, field: &str, key: &str, raw: &str) {
        // Reuse the v1 hold codec to derive its platform-specific bookkeeping
        // charge rather than duplicating the private HeldRaw layout in a fixture.
        let probe =
            lenient_decode::read_bounded(br#"{"files":{"probe":{"size_bytes":[]}}}"#).unwrap();
        let (_, _, bytes, _, charge) = probe.decode_holds.v2_entries().next().unwrap();
        let overhead =
            charge - bytes.len() as u64 - serde_json::to_vec("probe").unwrap().len() as u64;
        index
            .decode_holds
            .v2_insert(
                field,
                key.into(),
                raw.as_bytes().to_vec(),
                None,
                overhead + raw.len() as u64 + serde_json::to_vec(key).unwrap().len() as u64,
            )
            .unwrap();
        index.decode_holds.v2_finish((0, 0));
    }
    fn publish(f: &Fixture, index: &ScanIndex) {
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&f.path, ".v2.sqlite.import")).unwrap();
        db.control("identity", &f.identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        let mut cx = KindCx::default();
        cx.binding = Some(f.identity().binding);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(index, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        db.finish_import().unwrap();
        super::super::super::ack::ProgressRecovery::seal_import(f.identity(), 1, &f.path, None)
            .unwrap();
        fence::publish(&f.path, &f.identity(), &mut false).unwrap();
    }
    fn assert_graph(expected: &ScanIndex, actual: &ScanIndex) {
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        assert!(actual.decode_holds.same_as(&expected.decode_holds));
        assert_eq!(
            actual.decode_holds.v2_provenance(),
            expected.decode_holds.v2_provenance()
        );
        let custody = |index: &ScanIndex| {
            index
                .decode_holds
                .v2_entries()
                .map(|(field, key, raw, owner, charge)| {
                    (
                        field.to_owned(),
                        key.to_owned(),
                        raw.to_vec(),
                        owner,
                        charge,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(custody(actual), custody(expected));
        assert_eq!(
            actual.codex_parent_proof_parents_live,
            expected.codex_parent_proof_parents_live
        );
    }
    fn compare(bytes: &[u8], mapped: ScanIndex) -> ScanIndex {
        // Exercise the shared API with the stage used by both ordinary and
        // claim-only CAS. SAVE owns installing its current-snapshot caller.
        for bounded in [false, true] {
            let expected = if bounded {
                lenient_decode::read_bounded(bytes).unwrap()
            } else {
                lenient_decode::read(std::io::Cursor::new(bytes), "cas", "claude_code").unwrap()
            };
            let mut current = mapped.clone();
            lenient_decode::post_decode_hydrated(&mut current, "cas", "claude_code").unwrap();
            assert_graph(&expected, &current);
        }
        let f = Fixture::new();
        let v1 = f.support.join("v1-index.json");
        fs::write(&v1, bytes).unwrap();
        let (mut expected, _) = ScanIndex::load_inner_with_support(
            &v1,
            Some(s::SnapshotSource::ClaudeCode),
            None,
            SystemTime::now(),
        )
        .unwrap();
        publish(&f, &mapped);
        expected.generation = 1;
        let fence_bytes = fs::read(&f.path).unwrap();
        let load = || {
            ScanIndex::load_inner_with_support(
                &f.path,
                Some(s::SnapshotSource::ClaudeCode),
                None,
                SystemTime::now(),
            )
            .unwrap()
            .0
        };
        let actual = load();
        // Both production save modes enter this exact current-snapshot CAS.
        // Keep working edits/removals intact; compare normalized custody only.
        for claim_only in [false, true] {
            let mut working = actual.clone();
            if !claim_only {
                working.accepted_snapshot_fingerprints.clear();
            }
            let runtime = working.v2().persistence_v2.clone().unwrap();
            let mut guard = runtime.session.lock().unwrap();
            let session = guard.as_mut().unwrap();
            let mut tx = session.db.begin(TxnMode::Read).unwrap();
            import::ClaudeMapper
                .merge_cas(&mut tx, &mut working)
                .unwrap();
            assert!(working.decode_holds.same_as(&actual.decode_holds));
            assert_eq!(
                working.decode_holds.v2_provenance(),
                actual.decode_holds.v2_provenance()
            );
            if !claim_only {
                assert!(working.accepted_snapshot_fingerprints.is_empty());
            }
        }

        assert_graph(&expected, &actual);
        assert_graph(&expected, &load()); // cached graph still runs outer load steps
        with_state(&f.path, |state| {
            state.cached = None;
            Ok(())
        })
        .unwrap();
        assert_graph(&expected, &load()); // hydrate again on the resident connection
        assert_eq!(fs::read(&v1).unwrap(), bytes);
        assert_eq!(fs::read(&f.path).unwrap(), fence_bytes);
        assert!(!fence::sibling(&f.path, ".v1-readonly").exists());
        actual
    }
    fn typed_case(index: ScanIndex) -> ScanIndex {
        let bytes = serde_json::to_vec(&index).unwrap();
        // Mapped tombstone codecs, like serde, reconstruct decoded evidence.
        let mapped = serde_json::from_slice(&bytes).unwrap();
        compare(&bytes, mapped)
    }
    /// [format] future controls refuse before hydrate normalization and keep custody.
    #[test]
    fn future_controls_refuse_before_hydrate_normalization_and_keep_custody() {
        for schema in [false, true] {
            let mut index = seed();
            if schema {
                index.schema_version = s::SCAN_INDEX_SCHEMA_VERSION + 1;
            } else {
                index.accepted_snapshot_fingerprint_ledger_version =
                    s::SNAPSHOT_ACCEPTED_LEDGER_VERSION + 1;
            }
            let f = Fixture::new();
            publish(&f, &index);
            let before = fs::read(&f.path).unwrap();
            let error = load_locked(&f.path, None).unwrap_err();
            assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::Future));
            assert_eq!(fs::read(&f.path).unwrap(), before);
        }
    }
    /// [format] every hydrate runs deadline drop cutoff and tombstone rules.
    #[test]
    fn every_hydrate_runs_deadline_drop_cutoff_and_tombstone_rules() {
        let mut index = seed();
        let mut quarantine = s::snapshot_quarantine_record(s::SnapshotSource::ClaudeCode);
        quarantine.retry_after_unix_seconds = u64::MAX;
        index
            .quarantined_snapshot_fingerprints
            .insert("b".repeat(64), quarantine);
        let actual = typed_case(index);
        assert!(s::snapshot_quarantine_deadline_is_bounded(
            &actual.quarantined_snapshot_fingerprints[&"b".repeat(64)]
        ));

        let mut index = seed();
        index
            .snapshot_activity_at
            .insert("c".repeat(64), Some("invalid time".into()));
        index.accepted_snapshot_fingerprints.insert("bad".into());
        index.legacy_settlement_reconcile_after_fingerprint = Some("bad".into());
        index.claude_history_cutoff_unix_seconds = Some(s::MALFORMED_CLAUDE_HISTORY_CUTOFF);
        index.claude_history_gate_loaded = true;
        let actual = typed_case(index);
        assert!(!actual.snapshot_activity_at.contains_key(&"c".repeat(64)));
        assert!(!actual.accepted_snapshot_fingerprints.contains("bad"));
        assert!(!actual.claude_history_gate_loaded);

        let mut index = seed();
        index.claude_retired_family_tombstones_initialized = true;
        let actual = typed_case(index);
        assert!(actual.claude_retired_family_tombstones_initialized);
    }
    /// [money] missing and damaged retirement evidence keep the v1 uncertainty and commitment.
    #[test]
    fn missing_and_damaged_retirement_evidence_keep_the_v1_uncertainty_and_commitment() {
        for missing in [false, true] {
            let mut index = seed();
            index.claude_retired_family_tombstones_initialized = true;
            let mut value = serde_json::to_value(index).unwrap();
            if missing {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("claude_retired_family_tombstones");
            } else {
                value["claude_retired_family_tombstones"] =
                    serde_json::json!({"invalid": "timestamp"});
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            // The importer already carries the original tombstone repair
            // commitment. Hydration must settle without forgetting or doubling it.
            let mapped = lenient_decode::read_bounded(&bytes).unwrap();
            let actual = compare(&bytes, mapped);
            assert!(actual.claude_retired_family_tombstones_uncertain);
            assert_eq!(actual.decode_holds.v2_provenance().1, 1);
        }
    }
    /// [format] v2 load rearms legacy terminal with the v1 pacing rule.
    #[test]
    fn v2_load_rearms_legacy_terminal_with_the_v1_pacing_rule() {
        let mut index = seed();
        let fingerprint = "b".repeat(64);
        let mut quarantine = s::snapshot_quarantine_record(s::SnapshotSource::ClaudeCode);
        quarantine.disposition = s::SnapshotQuarantineDisposition::UnprovenTerminal;
        quarantine.failed_reconstruction_count = s::MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        quarantine.retry_after_unix_seconds = 0;
        quarantine.reconstruction_contract = 0;
        index
            .quarantined_snapshot_fingerprints
            .insert(fingerprint.clone(), quarantine);
        let f = Fixture::new();
        let v1 = f.support.join("v1-index.json");
        fs::write(&v1, serde_json::to_vec(&index).unwrap()).unwrap();
        let (mut expected, _) = ScanIndex::load_inner_with_support(
            &v1,
            Some(s::SnapshotSource::ClaudeCode),
            None,
            SystemTime::now(),
        )
        .unwrap();
        publish(&f, &index);
        let earliest = crate::snapshot_sync::quarantine_retry_after(&fingerprint);
        let (mut actual, _) = ScanIndex::load_inner_with_support(
            &f.path,
            Some(s::SnapshotSource::ClaudeCode),
            None,
            SystemTime::now(),
        )
        .unwrap();
        let latest = crate::snapshot_sync::quarantine_retry_after(&fingerprint);
        let record = &actual.quarantined_snapshot_fingerprints[&fingerprint];
        assert_eq!(record.contract_retry_claims, Some(0));
        assert!((earliest..=latest).contains(&record.retry_after_unix_seconds));
        // Separate loads sample the wall clock independently. Compare the full
        // graph after accounting solely for that clock sample, and prove the
        // actual deadline against the shared jitter/pacing rule above.
        expected.generation = 1;
        expected
            .quarantined_snapshot_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        actual
            .quarantined_snapshot_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        assert_graph(&expected, &actual);
    }
    /// [money] typed unbound authority rearms files and collapse uses shared load tail.
    #[test]
    fn typed_unbound_authority_rearms_files_and_collapse_uses_shared_load_tail() {
        let mut index = seed();
        index
            .claude_usage_family_witnesses
            .get_mut("family")
            .unwrap()
            .legacy_owner_roots
            .insert("unbound-owner".into());
        let actual = typed_case(index);
        assert!(actual.claude_usage_authority_quarantine.is_empty());
        assert!(actual.files["/synthetic/family.jsonl"]
            .source_file_fingerprint
            .is_empty());

        let mut index = seed();
        let window = |day| s::ClaudeAccountFamilyPendingWindow {
            version: "v2".into(),
            census_window_end: format!("2026-10-{day:02}T00:00:00Z"),
            account_identifier_hash: "d".repeat(64),
            evidence_request_count: 0,
            census_complete: true,
            members: BTreeMap::new(),
            member_requests: BTreeMap::new(),
            invalid: false,
        };
        index.claude_account_family_pending.insert(
            "other-family".into(),
            s::ClaudeAccountFamilyPending {
                current: window(30),
                previous_windows: vec![window(25), window(26), window(27)],
                confirmed_absent_members: BTreeSet::new(),
            },
        );
        let actual = typed_case(index);
        assert_eq!(
            actual.claude_account_family_pending["other-family"]
                .previous_windows
                .len(),
            2
        );
    }
    /// [money] raw quarantine repairs and opaque file freezes match v1 custody.
    #[test]
    fn raw_quarantine_repairs_and_opaque_file_freezes_match_v1_custody() {
        let mut index = seed();
        let fingerprint = "b".repeat(64);
        index.quarantined_snapshot_fingerprints.insert(
            fingerprint.clone(),
            s::snapshot_quarantine_record(s::SnapshotSource::ClaudeCode),
        );
        let canonical = serde_json::to_string(&index).unwrap();
        let old = raw_slot(
            canonical.as_bytes(),
            "quarantined_snapshot_fingerprints",
            &fingerprint,
        );
        let mut value: serde_json::Value = serde_json::from_str(&old).unwrap();
        value["retry_after_unix_seconds"] = "mistyped-original".into();
        let raw = serde_json::to_string_pretty(&value).unwrap();
        let bytes = canonical.replace(&old, &raw).into_bytes();
        index.quarantined_snapshot_fingerprints.clear();
        attach_raw(
            &mut index,
            "quarantined_snapshot_fingerprints",
            &fingerprint,
            &raw,
        );
        let actual = compare(&bytes, index);
        assert!(actual.decode_holds.is_empty());
        assert_eq!(actual.decode_holds.v2_provenance().1, 1);

        let mut index = seed();
        let key = "/synthetic/family.jsonl";
        let canonical = serde_json::to_string(&index).unwrap();
        let old = raw_slot(canonical.as_bytes(), "files", key);
        let mut value: serde_json::Value = serde_json::from_str(&old).unwrap();
        value["size_bytes"] = serde_json::json!([]);
        let raw = serde_json::to_string_pretty(&value).unwrap();
        let bytes = canonical.replace(&old, &raw).into_bytes();
        index.files.clear();
        attach_raw(&mut index, "files", key, &raw);
        let actual = compare(&bytes, index);
        assert!(actual.decode_holds_family("family"));
        assert!(actual.claude_usage_authority_quarantine.is_empty());
        assert!(actual.claude_usage_family_pending.is_empty());
    }
    /// [money] original mistyped authority freezes siblings before canonicalization and bound control repairs.
    #[test]
    fn original_mistyped_authority_freezes_siblings_before_canonicalization_and_bound_control_repairs(
    ) {
        for bound in [false, true] {
            let mut index = seed();
            if !bound {
                index
                    .claude_usage_family_witnesses
                    .get_mut("family")
                    .unwrap()
                    .legacy_owner_roots
                    .insert("unbound-owner".into());
            }
            // Preserve noncanonical spacing and number spelling in the original
            // raw slot. Re-encoding the repaired authority would lose this proof.
            let canonical = serde_json::to_vec(&index).unwrap();
            let original = raw_slot(&canonical, "claude_usage_authority_quarantine", "family");
            let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
            value["retry_after_unix_seconds"] = "mistyped-original".into();
            let raw = serde_json::to_string_pretty(&value).unwrap();
            let bytes = String::from_utf8(canonical)
                .unwrap()
                .replace(&original, &raw)
                .into_bytes();
            // A forced-unbound v1 read supplies the exact held slot's lexical
            // charge. The mapped graph itself retains only this raw authority;
            // all pending/witness siblings are still typed and must be frozen.
            let mut unbound: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            unbound["claude_usage_family_witnesses"]["family"]["legacy_owner_roots"] =
                serde_json::json!(["unbound-owner"]);
            let unbound_bytes = serde_json::to_string(&unbound).unwrap();
            let compact_raw = raw_slot(
                unbound_bytes.as_bytes(),
                "claude_usage_authority_quarantine",
                "family",
            );
            let unbound_bytes = unbound_bytes.replace(&compact_raw, &raw);
            let held = lenient_decode::read_bounded(unbound_bytes.as_bytes()).unwrap();
            let (_, _, raw_bytes, owner, charge) = held
                .decode_holds
                .v2_entries()
                .find(|(field, key, ..)| {
                    *field == "claude_usage_authority_quarantine" && *key == "family"
                })
                .unwrap();
            assert_eq!(raw_bytes, raw.as_bytes());
            index.claude_usage_authority_quarantine.clear();
            index
                .decode_holds
                .v2_insert(
                    "claude_usage_authority_quarantine",
                    "family".into(),
                    raw_bytes.to_vec(),
                    owner,
                    charge,
                )
                .unwrap();
            index.decode_holds.v2_finish((0, 0));
            let actual = compare(&bytes, index);
            assert_eq!(actual.decode_holds_family("family"), !bound);
            assert!(actual
                .accepted_snapshot_fingerprints
                .contains(&"a".repeat(64)));
            assert_eq!(actual.decode_holds.v2_provenance().1, u64::from(bound));
            if !bound {
                assert!(actual.claude_usage_family_witnesses.is_empty());
                assert!(actual.claude_usage_family_pending.is_empty());
                assert_eq!(
                    actual.files["/synthetic/family.jsonl"].source_file_fingerprint,
                    "source"
                );
            }
        }
    }
}

/// [format] ceiling reloads the prior generation halves then retries and grows back.
#[test]
fn ceiling_reloads_the_prior_generation_halves_then_retries_and_grows_back() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert_eq!(collection_page_limit(&index, 250), 250);
    sqlite::seed_next_save_bytes_for_test(256 * 1024 * 1024);
    let error = save_with(&f.path, &mut index, &EmptyMapper).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveCeiling));
    assert_eq!(collection_page_limit(&index, 250), 125);
    assert!(guard_external(
        &f.path,
        index.v2().persistence_v2.as_ref(),
        index.generation
    )
    .is_err());
    let mut retry = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert_eq!(retry.generation, 0);
    // Reopen cannot clear a failed-save upload fence.
    assert!(guard_external(
        &f.path,
        retry.v2().persistence_v2.as_ref(),
        retry.generation
    )
    .is_err());
    let recovery = crate::snapshots::state_v2_recovery_save_guard(&f.path, &retry)
        .unwrap()
        .unwrap();
    recovery().unwrap();
    assert!(save_with(&f.path, &mut retry, &EmptyMapper).unwrap());
    assert_eq!(retry.generation, 1);
    assert_eq!(collection_page_limit(&retry, 250), 150);
    guard_external(
        &f.path,
        retry.v2().persistence_v2.as_ref(),
        retry.generation,
    )
    .unwrap();
    for expected in [175, 200, 225, 250, 250] {
        save_with(&f.path, &mut retry, &EmptyMapper).unwrap();
        assert_eq!(collection_page_limit(&retry, 250), expected);
    }
}

/// [money] page one oversize holds and fences upload ack and publication.
#[test]
fn page_one_oversize_holds_and_fences_upload_ack_and_publication() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert_eq!(collection_page_limit(&index, 1), 1);
    sqlite::seed_next_save_bytes_for_test(256 * 1024 * 1024);
    let error = save_with(&f.path, &mut index, &EmptyMapper).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveOversize));
    let current = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert_eq!(current.generation, 0);
    assert_eq!(collection_page_limit(&current, 1), 1);
    // This is the production external boundary used before uploads and ACKs.
    let guard = crate::snapshots::state_v2_side_effect_guard(&f.path, &current);
    assert_eq!(
        guard().unwrap_err().downcast_ref::<Hold>(),
        Some(&Hold::SaveOversize)
    );
    assert_eq!(
        with_state(&f.path, |state| Ok(state.save_hold)).unwrap(),
        Some(Hold::SaveOversize)
    );
}

/// [money] sqlite full holds across reopen until a complete save succeeds.
#[test]
fn sqlite_full_holds_across_reopen_until_a_complete_save_succeeds() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    sqlite::fail_commit_full_for_test();
    let error = save_with(&f.path, &mut index, &EmptyMapper).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveFull));
    let mut retry = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert_eq!(retry.generation, 0);
    let guard = crate::snapshots::state_v2_side_effect_guard(&f.path, &retry);
    assert_eq!(
        guard().unwrap_err().downcast_ref::<Hold>(),
        Some(&Hold::SaveFull)
    );
    assert!(save_with_mode(&f.path, &mut retry, &EmptyMapper, true, None).unwrap());
    assert_eq!(
        guard_external(
            &f.path,
            retry.v2().persistence_v2.as_ref(),
            retry.generation
        )
        .unwrap_err()
        .downcast_ref::<Hold>(),
        Some(&Hold::SaveFull)
    );
    let recovery = crate::snapshots::state_v2_recovery_save_guard(&f.path, &retry)
        .unwrap()
        .unwrap();
    recovery().unwrap();
    assert!(save_with(&f.path, &mut retry, &EmptyMapper).unwrap());
    guard_external(
        &f.path,
        retry.v2().persistence_v2.as_ref(),
        retry.generation,
    )
    .unwrap();
}

/// [format] unpublished import does not reorder v1 progress admission.
#[test]
fn unpublished_import_does_not_reorder_v1_progress_admission() {
    let f = Fixture::new();
    fs::write(&f.path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    assert!(load_with(&f.path, true, &EmptyMapper).unwrap().is_none());
    assert!(states().lock().unwrap().contains_key(&f.path));
    assert!(!published(&f.path).unwrap());
    f.published();
    assert!(published(&f.path).unwrap());
}

/// [money] Unknown state preserves v1 before publication, holds afterward, and rollback keeps the last good graph.
#[test]
fn unknown_fields_and_interrupted_save_never_reset_progress_or_publish_partial_custody() {
    let f = Fixture::new();
    let progress = br#"{"generation":0}"#;
    let progress_path = crate::snapshot_sync::with_state_v2_progress_lock(&f.path, |path| {
        ottto_core::write_owner_only_file_atomic(path, progress)?;
        Ok(path.to_owned())
    })
    .unwrap();
    let mut raw = serde_json::to_value(ScanIndex::default()).unwrap();
    raw["future_money"] = serde_json::json!({"owed": 19});
    fs::write(&f.path, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(load_with(&f.path, true, &ClaudeMapper).unwrap().is_none());
    let legacy = ScanIndex::load(&f.path).unwrap();
    assert!(legacy.persistence_available());
    assert!(legacy.v2().persistence_v2.is_none());
    assert_eq!(fs::read(&progress_path).unwrap(), progress);
    assert!(!fence::sibling(&f.path, ".v2.sqlite").exists());

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let mut seed: ScanIndex = serde_json::from_value(fixture["logical"].clone()).unwrap();
    seed.generation = 0;
    let mut current = super::super::money_test_support::publish(&seed, &f.path, progress);
    let committed_generation = current.generation;
    let committed_context = current.upload_context_fingerprint.clone();
    current.upload_context_fingerprint = Some("uncommitted-context".into());
    sqlite::fail_commit_full_for_test();
    assert!(save_locked(&f.path, &mut current, false, None).is_err());
    let restored = load_locked(&f.path, None).unwrap().0.unwrap();
    assert_eq!(restored.generation, committed_generation);
    assert_eq!(restored.upload_context_fingerprint, committed_context);
    assert_eq!(fs::read(&progress_path).unwrap(), progress);

    let path = seed.files.keys().next().unwrap();
    let mut unknown = serde_json::to_value(&seed.files[path]).unwrap();
    unknown["future_money"] = serde_json::json!({"owed": 23});
    let encoded = codec::encode(&serde_json::to_vec(&unknown).unwrap()).unwrap();
    let runtime = restored.v2().persistence_v2.as_ref().unwrap();
    {
        let mut guard = runtime.session.lock().unwrap();
        let session = guard.as_mut().unwrap();
        let mut tx = session.db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            key: &mapper::key("file.progress", path, 1).unwrap(),
            fixed: &Fixed::None,
            value_version: 1,
            value: &codec::Bytes(&encoded),
        })
        .unwrap();
        assert_eq!(
            tx.commit(committed_generation, committed_generation + 1),
            DurableCommitOutcome::Committed(committed_generation + 1)
        );
    }
    invalidate_locked(&f.path).unwrap();
    let db_path = fence::sibling(&f.path, ".v2.sqlite");
    let before_db = fs::read(&db_path).unwrap();
    let before_fence = fs::read(&f.path).unwrap();
    // A held load returns no graph to collection, so it cannot authorize a Full
    // or a transcript re-read. A compatible build must recover these same bytes.
    assert!(ScanIndex::load(&f.path).is_err());
    assert_eq!(fs::read(&db_path).unwrap(), before_db);
    assert_eq!(fs::read(&f.path).unwrap(), before_fence);
    assert_eq!(fs::read(&progress_path).unwrap(), progress);
}

/// [regress] reloading after R1 staging failure preserves exclusion before transcript parsing.
#[test]
fn resume_exclusion_survives_reload_and_skips_transcript_before_parse() {
    for forced_family in [false, true] {
        let f = Fixture::new();
        f.published();
        let roots = f.support.join("transcripts");
        fs::create_dir(&roots).unwrap();
        let root_id = "11111111-1111-4111-8111-111111111111";
        let transcript = roots.join(format!("{root_id}.jsonl"));
        fs::write(&transcript, b"invalid json\n").unwrap();
        let key = super::super::super::local_index_key(&transcript);
        let _index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
        with_state(&f.path, |state| {
            state
                .resume_excluded
                .insert(key.clone(), Instant::now() + Duration::from_secs(60));
            state.cached = None;
            Ok(())
        })
        .unwrap();
        let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
        if forced_family {
            assert!(super::super::super::claude_index_path_family_member(&transcript).is_some());
            index.claude_usage_authority_quarantine.insert(
                root_id.into(),
                serde_json::from_value(serde_json::json!({
                    "contract":"synthetic-contract", "proven_witness_fingerprint":"a".repeat(64),
                    "member_source_file_fingerprints":{}, "retry_after_unix_seconds":0
                }))
                .unwrap(),
            );
        }
        let scan = super::super::super::scan_source_roots_with_test_limit(
            super::super::super::SnapshotSource::ClaudeCode,
            &[roots],
            &mut index,
            "2026-10-31T12:00:00Z",
            30,
            10,
            false,
        )
        .unwrap();
        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.scanned_file_count, 0);
        assert_eq!(scan.malformed_json_line_count, 0);
        assert!(!index.files.contains_key(&key));
    }
}
