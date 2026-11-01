//! F5–F7 route fixtures over native stores: the shipped Mapper writes,
//! loads and saves every graph; these tests make no hydration parity claim.
use super::*;
use std::collections::BTreeSet;

/// Release synthetic custody and its registry slot when a fixture is finished.
pub(in crate::snapshots) fn erase_published(path: &Path) {
    // Cleanup also owns deliberately malformed fences; it must not decode them.
    let _owner =
        super::super::super::CheckpointLock::acquire_with_custody(path, false, Some(true)).unwrap();
    erase_locked(path, None).unwrap();
    states().lock().unwrap().remove(path);
}

fn load_with(path: &Path, switched: bool) -> Result<Option<ScanIndex>> {
    load_with_custody(path, switched, published(path)?)
}
fn save_with(path: &Path, index: &mut ScanIndex) -> Result<bool> {
    save_with_mode(path, index, false, None)
}
fn save_with_mode(
    path: &Path,
    index: &mut ScanIndex,
    claim_only: bool,
    owner: Option<&crate::snapshot_sync::SnapshotProgressLock>,
) -> Result<bool> {
    save_with_custody(path, index, claim_only, owner, published(path)?)
}

/// Generation of a freshly imported native fixture store.
const G: u64 = 1;

/// Apply a per-store seam to the live session store behind `index`; the
/// failed save's reload reopens the store without it.
pub(super) fn with_session_db(index: &ScanIndex, f: impl FnOnce(&mut sqlite::Sqlite)) {
    let runtime = index.v2().persistence_v2.as_ref().unwrap();
    let mut guard = runtime.session.lock().unwrap();
    f(&mut guard.as_mut().unwrap().db);
}
/// Cap the session at its current pages and add enough new rows that the
/// next save must grow the file: SQLite's own SQLITE_FULL, no fault knob.
fn fill_session(index: &mut ScanIndex) {
    with_session_db(index, |db| sqlite::cap_pages(db));
    for n in 0..2048 {
        index
            .accepted_snapshot_fingerprints
            .insert(format!("{n:064x}"));
    }
}

struct Fixture {
    support: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let support = crate::test_scratch::canonical_private_dir("ottto-v2-route");
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
    /// Native store: the shipped row mapper writes an empty graph at G.
    fn imported(&self) {
        self.import(true);
    }
    fn import(&self, mapped: bool) {
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&self.path, ".v2.sqlite.import"))
                .unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db.control("identity", &self.identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        let mut generation = 0;
        if mapped {
            let mut cx = KindCx::default();
            cx.binding = Some(self.identity().binding);
            let mut tx = db.begin(TxnMode::Write).unwrap();
            kinds::populate(&ScanIndex::default(), &mut tx, &mut cx).unwrap();
            assert_eq!(tx.commit(0, G), DurableCommitOutcome::Committed(G));
            generation = G;
        }
        db.finish_import().unwrap();
        // Synthetic fixture has no original ledger; seal that exact absence
        // before any publication boundary, as the production importer must.
        super::super::ack::ProgressRecovery::seal_import(
            self.identity(),
            generation,
            &self.path,
            None,
        )
        .unwrap();
    }
    fn published(&self) {
        self.imported();
        fence::publish(&self.path, &self.identity(), &mut false).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        super::super::money_test_support::erase_published(&self.path);
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
    assert!(load_with(&f.path, true).unwrap().is_none());
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
    let index = load_with(&live.path, false).unwrap().unwrap();
    let runtime = index.v2().persistence_v2.as_ref().unwrap();
    assert!(runtime.session.lock().unwrap().is_some());
    let fence = fs::read(&live.path).unwrap();
    close_tree(&live.support, false).unwrap();
    assert!(runtime.session.lock().unwrap().is_none());
    assert!(guard_external(&live.path, Some(runtime), index.generation).is_err());
    assert_eq!(fs::read(&live.path).unwrap(), fence);
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
            load_with(&f.path, false)
                .unwrap_err()
                .downcast_ref::<Hold>(),
            Some(&Hold::FenceLost)
        );
        assert!(guard_containment_locked(&f.path).is_err());
        assert!(save_with(&f.path, &mut ScanIndex::default()).is_err());
        assert_eq!(fs::read(db).unwrap(), before);
        assert!(!fence::sibling(&f.path, ".v2.sqlite.import").exists());
    }
}
/// [format] f7 publication failures keep latch and artifacts and restart recovers.
#[test]
fn f7_publication_failures_keep_latch_and_artifacts_and_restart_recovers() {
    // Reconstruct the actual on-disk crash states, without process-global failpoints.
    for point in ["before_fence_rename", "before_db_rename", "after_db_rename"] {
        let f = Fixture::new();
        fs::write(&f.path, b"v1-before-publication").unwrap();
        f.imported();
        let temp = fence::sibling(&f.path, ".v2-fence.tmp");
        ottto_core::write_owner_only_file_atomic(
            &temp,
            &serde_json::to_vec(&fence::Fence::new(&f.identity())).unwrap(),
        )
        .unwrap();
        if point != "before_fence_rename" {
            fs::rename(&temp, &f.path).unwrap();
        }
        if point == "after_db_rename" {
            fs::rename(
                fence::sibling(&f.path, ".v2.sqlite.import"),
                fence::sibling(&f.path, ".v2.sqlite"),
            )
            .unwrap();
        }
        assert!(fence::cleanup_unpublished(&f.path, true).is_err());
        if point == "before_fence_rename" {
            assert!(fence::reconcile(&f.path, &f.identity().binding, true).is_err());
            assert_eq!(fs::read(&f.path).unwrap(), b"v1-before-publication");
        } else {
            let pair = fence::reconcile(&f.path, &f.identity().binding, false)
                .unwrap()
                .unwrap();
            assert_eq!(pair.0, f.identity());
            assert!(pair.1.exists());
            assert!(load_with(&f.path, false).unwrap().is_some());
            assert!(guard_containment_locked(&f.path).is_err());
        }
    }
}
/// [format] f7 off after publication saves through the one semantic save and
/// published custody without semantic rows holds.
#[test]
fn f7_off_after_publication_saves_natively_and_unmapped_custody_holds() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert!(save_with(&f.path, &mut index).unwrap());
    assert_eq!(index.generation, G + 1);
    // A fresh route must decode the missing semantic rows, never treat them as empty.
    let f = Fixture::new();
    f.import(false);
    fence::publish(&f.path, &f.identity(), &mut false).unwrap();
    assert!(load_locked(&f.path, None, published(&f.path).unwrap()).is_err());
}
/// [format] f6 explicit forget deletes all artifacts, invalidates stale clones,
/// and exposes only committed file membership to the restart-record sweep.
#[test]
fn f6_explicit_forget_deletes_all_artifacts_and_invalidates_stale_clones() {
    let mut f = Fixture::new();
    // This API is binding-scoped (source + namespace dir name), so a shared
    // literal namespace collides with parallel fixtures: use a unique one.
    let namespace = {
        use sha2::Digest;
        format!(
            "{:x}",
            sha2::Sha256::digest(f.support.to_string_lossy().as_bytes())
        )
    };
    let parent = f.path.parent().unwrap().with_file_name(namespace);
    fs::rename(f.path.parent().unwrap(), &parent).unwrap();
    f.path = parent.join(f.path.file_name().unwrap());
    let live = || {
        let _owner = super::super::super::CheckpointLock::acquire(&f.path).unwrap();
        crate::snapshots::state_v2::live_key_digests(&f.path).unwrap()
    };
    assert_eq!(live().incomplete_reason, Some(IncompleteReason::Off));
    // Pi has no key mapping: never an empty complete set that a sweep could erase by.
    let pi = crate::snapshots::state_v2::live_key_digests(
        &f.path.with_file_name("pi-test-scan-index.json"),
    )
    .unwrap();
    assert!(!pi.complete && pi.digests.is_empty());
    assert_eq!(pi.incomplete_reason, Some(IncompleteReason::Off));
    f.published();
    // Published custody before this process's first load: v1 JSON is stale.
    assert_eq!(live().incomplete_reason, Some(IncompleteReason::Import));
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let file = serde_json::from_value(serde_json::json!({
        "size_bytes": 4, "modified_unix_seconds": 1,
        "source_file_fingerprint": "a".repeat(64),
        "scan_identity_version": crate::snapshots::LOCAL_SCAN_INDEX_IDENTITY_VERSION
    }))
    .unwrap();
    index.files.insert("committed".into(), file);
    save_with(&f.path, &mut index).unwrap();
    let digest = crate::durable_tail_store::key_digest(
        crate::durable_tail_store::DurableSource::ClaudeCode,
        "committed",
    );
    let committed = live();
    assert!(committed.complete);
    assert_eq!(committed.incomplete_reason, None);
    assert_eq!(committed.generation, index.generation);
    assert_eq!(committed.digests, BTreeSet::from([digest]));
    index
        .files
        .insert("uncommitted".into(), index.files["committed"].clone());
    // Even a mutated live graph cannot add an uncommitted key to membership.
    assert_eq!(live().digests, BTreeSet::from([digest]));
    with_session_db(&index, |db| sqlite::set_save_ceiling(db, 0));
    assert!(save_with(&f.path, &mut index).is_err());
    let held = live();
    assert!(!held.complete);
    assert_eq!(held.incomplete_reason, Some(IncompleteReason::Hold));
    let mut retry = load_with(&f.path, false).unwrap().unwrap();
    assert!(!retry.files.contains_key("uncommitted"));
    save_with(&f.path, &mut retry).unwrap();
    let committed = live();
    assert!(committed.complete);
    assert_eq!(committed.generation, retry.generation);
    assert_eq!(committed.digests, BTreeSet::from([digest]));
    let fence_bytes = fs::read(&f.path).unwrap();
    fs::write(&f.path, b"invalid-publication-fence").unwrap();
    {
        let _owner = super::super::super::CheckpointLock::acquire(&f.path).unwrap();
        assert!(crate::snapshots::state_v2::live_key_digests(&f.path).is_err());
    }
    fs::write(&f.path, fence_bytes).unwrap();
    let mut stale = retry.clone();
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
    with_session_db(&retry, |db| {
        db.control("erasure_pending", &retry.generation).unwrap()
    });
    let pending = live();
    assert!(!pending.complete);
    assert_eq!(pending.incomplete_reason, Some(IncompleteReason::Hold));
    assert_eq!(pending.generation, retry.generation);
    crate::snapshots::erase_claude_state_v2_artifacts(&f.support).unwrap();
    let erased = live();
    assert!(erased.complete);
    assert_eq!(erased.incomplete_reason, None);
    assert!(erased.digests.is_empty());
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
    assert!(save_with(&f.path, &mut stale).is_err());
    assert!(load_with(&f.path, false).is_err());
}
/// [format] publication pending pause does not touch v1 and off cancels inventory slot.
#[test]
fn publication_pending_pause_does_not_touch_v1_and_off_cancels_inventory_slot() {
    let f = Fixture::new();
    let mut raw = serde_json::to_value(ScanIndex::default()).unwrap();
    raw["future_money"] = serde_json::json!({"owed": 1});
    let bytes = serde_json::to_vec(&raw).unwrap();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true).unwrap().is_none());
    let mut index = ScanIndex::default();
    after_v1_locked(&f.path, &mut index).unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
    assert_eq!(fs::read_dir(f.path.parent().unwrap()).unwrap().count(), 1);
    // An OFF load cancels a valid unpublished inventory slot.
    let bytes = serde_json::to_vec(&ScanIndex::default()).unwrap();
    let f = Fixture::new();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true).unwrap().is_none());
    assert!(load_with(&f.path, false).unwrap().is_none());
    after_v1_locked(&f.path, &mut index).unwrap();
    assert!(index.v2().persistence_v2.is_none());
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
        assert!(load_with(&f.path, false).is_err());
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
        let index = load_with(&f.path, false).unwrap().unwrap();
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
                session.db.control("generation", &(G + 1)).unwrap();
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
    let (mut first, load_events) =
        crate::local_resource_diagnostics::capture(|| load_with(&f.path, false).unwrap().unwrap());
    let load = &load_events.last().unwrap()["counts"]["latest"]["load_span"];
    assert!(load["duration_ms"].is_u64());
    assert_eq!(load["generation"], G);
    assert_eq!(load.as_object().unwrap().len(), 2);
    let second = load_with(&f.path, false).unwrap().unwrap();
    let stale = crate::snapshots::state_v2_side_effect_guard(&f.path, &second);
    stale().unwrap();
    let (saved, save_events) =
        crate::local_resource_diagnostics::capture(|| save_with(&f.path, &mut first).unwrap());
    assert!(saved);
    let save = &save_events.last().unwrap()["counts"]["latest"]["save_span"];
    assert!(save["duration_ms"].is_u64());
    assert_eq!(save["outcome"], "committed");
    assert_eq!(save["generation"], G + 1);
    assert!(save["rows_put"].as_u64().unwrap() > 0);
    assert_eq!(save["rows_removed"], 0);
    assert_eq!(save.as_object().unwrap().len(), 5);
    assert_eq!(second.generation, G);
    assert_eq!(first.generation, G + 1);
    assert!(stale().is_err());
    crate::snapshots::state_v2_side_effect_guard(&f.path, &first)().unwrap();
}

/// [format] route replays receipt before fresh or reused connection and missing receipt holds.
#[test]
fn route_replays_receipt_before_fresh_or_reused_connection_and_missing_receipt_holds() {
    for reused in [false, true] {
        let f = Fixture::new();
        f.published();
        if reused {
            load_with(&f.path, false).unwrap().unwrap();
        }
        let recovery =
            super::super::ack::ProgressRecovery::seal_import(f.identity(), G, &f.path, None)
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
        assert!(load_with(&f.path, false).unwrap().is_some());
        assert_eq!(fs::read(&progress).unwrap(), next);
        fs::remove_file(fence::sibling(&f.path, ".v2-ack-receipt")).unwrap();
        assert!(load_with(&f.path, false).is_err());
        assert_eq!(fs::read(&progress).unwrap(), next);
        assert!(guard_containment_locked(&f.path).is_err());
    }
}

/// [format] real mapper runtime saves admitted state and keeps runtime policy.
#[test]
fn real_mapper_runtime_saves_admitted_state_and_keeps_runtime_policy() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    index.upload_context_fingerprint = Some("synthetic-policy".into());
    index.active_upload_context_fingerprint = Some("active-synthetic-policy".into());
    index.file_upload_context_enabled = true;
    assert!(save_locked(
        &f.path,
        &mut index,
        false,
        None,
        published(&f.path).unwrap()
    )
    .unwrap());
    // Committed row digests seed the next page; idle releases them.
    with_state(&f.path, |state| {
        assert_eq!(
            state.save_digests.as_ref().map(|b| b.generation),
            Some(G + 1)
        );
        Ok(())
    })
    .unwrap();
    // A cycle that errors skips idle; its drop guard still releases it.
    drop(BaselineRelease::new(&f.path, &index));
    with_state(&f.path, |state| {
        assert!(state.save_digests.is_none());
        Ok(())
    })
    .unwrap();
    assert!(save_locked(&f.path, &mut index, false, None, true).unwrap());
    with_state(&f.path, |state| {
        assert!(state.save_digests.is_some());
        Ok(())
    })
    .unwrap();
    let _ = idle(&f.path, &index, true);
    with_state(&f.path, |state| {
        assert!(state.save_digests.is_none());
        Ok(())
    })
    .unwrap();
    assert_eq!(index.generation, G + 2);
    assert_eq!(
        index.active_upload_context_fingerprint.as_deref(),
        Some("active-synthetic-policy")
    );
    assert!(index.file_upload_context_enabled && index.v2().persistence_v2.is_some());
    let current = load_with(&f.path, false).unwrap().unwrap();
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
    // Use the real inventory/import/publication path so import seals the
    // external progress receipt through the production mapper.
    assert!(load_with(&f.path, true).unwrap().is_none());
    let mut index = ScanIndex::default();
    after_v1_locked(&f.path, &mut index).unwrap();
    assert!(index.v2().persistence_v2.is_some());
    assert!(fence::sibling(&f.path, ".v2-ack-receipt").is_file());
    assert_eq!(index.generation, 1);
    let runtime = index.v2().persistence_v2.clone().unwrap();
    assert!(save_with(&f.path, &mut index).unwrap());
    assert_eq!(index.generation, 2);
    assert!(Arc::ptr_eq(
        &runtime,
        index.v2().persistence_v2.as_ref().unwrap()
    ));
}

/// [format] import without original inventory refuses publication, even with
/// the conversion hook installed.
#[test]
fn import_without_original_inventory_refuses_publication() {
    let f = Fixture::new();
    let bytes = b"synthetic-v1-authority";
    fs::write(&f.path, bytes).unwrap();
    assert!(load_with(&f.path, true).unwrap().is_none());
    let mut index = ScanIndex::default();
    after_v1_locked(&f.path, &mut index).unwrap();
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

// Real mapper coverage for the raw decoder/load route.
mod hydrate_parity {
    use super::*;
    use crate::snapshots as s;
    use s::lenient_decode;
    use serde_json::value::RawValue;
    use std::collections::BTreeSet;
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    /// Every decode and load clamps an out-of-range quarantine deadline to
    /// its own wall-clock read, so two of them can land a second apart. Pin
    /// deadlines clamped since `since` to `since`; anything else is untouched.
    fn settled(mut index: ScanIndex, since: u64) -> ScanIndex {
        let now = unix_now();
        for record in index.quarantined_snapshot_fingerprints.values_mut() {
            if (since..=now).contains(&record.retry_after_unix_seconds) {
                record.retry_after_unix_seconds = since;
            }
        }
        index
    }
    fn compare(bytes: &[u8], mapped: ScanIndex) -> ScanIndex {
        let since = unix_now();
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
            assert_graph(&settled(expected, since), &settled(current, since));
        }
        let f = Fixture::new();
        let v1 = f.support.join("v1-index.json");
        fs::write(&v1, bytes).unwrap();
        // One clock for every load's own time checks.
        let now = SystemTime::now();
        let (mut expected, _) =
            ScanIndex::load_inner_with_support(&v1, Some(s::SnapshotSource::ClaudeCode), None, now)
                .unwrap();
        publish(&f, &mapped);
        expected.generation = 1;
        let fence_bytes = fs::read(&f.path).unwrap();
        let load = || {
            ScanIndex::load_inner_with_support(
                &f.path,
                Some(s::SnapshotSource::ClaudeCode),
                None,
                now,
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
            let generation = working.generation;
            kinds_misc::merge_cas_at(&mut tx, &mut working, generation).unwrap();
            kinds_files::merge_growth_cas(&mut tx, &mut working).unwrap();
            assert!(working.decode_holds.same_as(&actual.decode_holds));
            assert_eq!(
                working.decode_holds.v2_provenance(),
                actual.decode_holds.v2_provenance()
            );
            if !claim_only {
                assert!(working.accepted_snapshot_fingerprints.is_empty());
            }
        }

        let expected = settled(expected, since);
        assert_graph(&expected, &settled(actual.clone(), since));
        assert_graph(&expected, &settled(load(), since)); // hydrate again on the same connection
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
            let error = load_locked(&f.path, None, published(&f.path).unwrap()).unwrap_err();
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
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(collection_page_limit(&index, 250), 250);
    with_session_db(&index, |db| sqlite::set_save_ceiling(db, 0));
    let error = save_with(&f.path, &mut index).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveCeiling));
    assert_eq!(collection_page_limit(&index, 250), 125);
    assert!(guard_external(
        &f.path,
        index.v2().persistence_v2.as_ref(),
        index.generation
    )
    .is_err());
    let mut retry = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(retry.generation, G);
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
    assert!(save_with(&f.path, &mut retry).unwrap());
    assert_eq!(retry.generation, G + 1);
    assert_eq!(collection_page_limit(&retry, 250), 150);
    guard_external(
        &f.path,
        retry.v2().persistence_v2.as_ref(),
        retry.generation,
    )
    .unwrap();
    for expected in [175, 200, 225, 250, 250] {
        save_with(&f.path, &mut retry).unwrap();
        assert_eq!(collection_page_limit(&retry, 250), expected);
    }
}

/// [money] page one oversize holds and fences upload ack and publication.
#[test]
fn page_one_oversize_holds_and_fences_upload_ack_and_publication() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(collection_page_limit(&index, 1), 1);
    with_session_db(&index, |db| sqlite::set_save_ceiling(db, 0));
    let error = save_with(&f.path, &mut index).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveOversize));
    let current = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(current.generation, G);
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
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    fill_session(&mut index);
    let error = save_with(&f.path, &mut index).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::SaveFull));
    let mut retry = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(retry.generation, G);
    let guard = crate::snapshots::state_v2_side_effect_guard(&f.path, &retry);
    assert_eq!(
        guard().unwrap_err().downcast_ref::<Hold>(),
        Some(&Hold::SaveFull)
    );
    assert!(save_with_mode(&f.path, &mut retry, true, None).unwrap());
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
    assert!(save_with(&f.path, &mut retry).unwrap());
    guard_external(
        &f.path,
        retry.v2().persistence_v2.as_ref(),
        retry.generation,
    )
    .unwrap();
}

/// [regress] The store itself may demand a reload outside any save: its
/// erasure COMMIT was refused. The next load reopens it at the durable
/// generation instead of failing on the refused stamp read, and the erasure
/// debt survives (never marked complete).
#[test]
fn store_reload_demand_outside_a_save_reopens_on_next_load() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false).unwrap().unwrap();
    with_session_db(&index, |db| {
        db.control("erasure_pending", &G).unwrap();
        db.control("erasure_since", &0_u64).unwrap();
        sqlite::fence_commit_writing(db, "erasure_purged_epoch");
        assert!(db.maintenance(true).is_err());
        assert!(db.reload_required());
    });
    let reloaded = load_with(&f.path, false).unwrap().unwrap();
    assert_eq!(reloaded.generation, G);
    with_session_db(&reloaded, |db| {
        assert!(!db.reload_required());
        assert_eq!(db.read_control::<u64>("erasure_pending").unwrap(), Some(G));
    });
}

/// [format] unpublished import does not reorder v1 progress admission.
#[test]
fn unpublished_import_does_not_reorder_v1_progress_admission() {
    let f = Fixture::new();
    fs::write(&f.path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    assert!(load_with(&f.path, true).unwrap().is_none());
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
    assert!(load_with(&f.path, true).unwrap().is_none());
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
    let committed = current.clone();
    let committed_generation = current.generation;
    let committed_context = current.upload_context_fingerprint.clone();
    current.upload_context_fingerprint = Some("uncommitted-context".into());
    fill_session(&mut current);
    assert!(save_locked(
        &f.path,
        &mut current,
        false,
        None,
        published(&f.path).unwrap()
    )
    .is_err());
    with_state(&f.path, |state| {
        assert!(state.save_digests.is_none());
        Ok(())
    })
    .unwrap();
    // Publication returns a public load, which settles the tombstone marker.
    // Compare at that same boundary after rollback, including load settlement.
    let restored = ScanIndex::load(&f.path).unwrap_or_else(|e| {
        panic!(
            "reload after FULL: {e:#}; cause={:?}",
            telemetry::latest_for_test("db_unavailable_cause")
        )
    });
    assert_eq!(
        serde_json::to_vec(&restored).unwrap(),
        serde_json::to_vec(&committed).unwrap()
    );
    assert!(restored.decode_holds.same_as(&committed.decode_holds));
    assert_eq!(
        restored.decode_holds.v2_provenance(),
        committed.decode_holds.v2_provenance()
    );
    assert_eq!(
        restored.v2().growth_retention,
        committed.v2().growth_retention
    );
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
            value: &encoded,
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
    let error = ScanIndex::load(&f.path).unwrap_err();
    // A newer build's key holds as "update", not as local damage.
    assert!(crate::snapshots::scan_index_health::is_version_refusal(
        &error
    ));
    assert_eq!(fs::read(&db_path).unwrap(), before_db);
    assert_eq!(fs::read(&f.path).unwrap(), before_fence);
    assert_eq!(fs::read(&progress_path).unwrap(), progress);
}

/// [money] aged growing keys remain readable and retain owed custody.
#[test]
fn aged_published_key_gets_normal_read_and_keeps_owed_debt() {
    use crate::snapshots::{local_index_key, scan_source_roots_with_test_limit, SnapshotSource};
    let f = Fixture::new();
    let roots = f.support.join("transcripts");
    fs::create_dir(&roots).unwrap();
    let transcript = roots.join("11111111-1111-4111-8111-111111111111.jsonl");
    fs::write(&transcript, b"invalid json\n").unwrap();
    let key = local_index_key(&transcript);
    let mut seed = ScanIndex::default();
    seed.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 4, "modified_unix_seconds": 1,
            "source_file_fingerprint": "a".repeat(64),
            "scan_identity_version": crate::snapshots::LOCAL_SCAN_INDEX_IDENTITY_VERSION
        }))
        .unwrap(),
    );
    seed.accepted_rebuild_incidence
        .insert(key.clone(), BTreeSet::from(["owed".into()]));
    let progress = br#"{"generation":0}"#;
    let mut index = super::super::money_test_support::publish(&seed, &f.path, progress);
    let fence_before = fs::read(&f.path).unwrap();
    let scan = |index: &mut ScanIndex| {
        scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&roots),
            index,
            "2050-10-31T12:00:00Z",
            30,
            10,
            false,
        )
        .unwrap()
    };
    let result = scan(&mut index);
    assert_eq!(
        result.malformed_json_line_count, 1,
        "a due aged key gets a normal read"
    );
    assert!(index.files.contains_key(&key));
    assert_eq!(index.files[&key].size_bytes, 4);
    assert_eq!(fs::read(&f.path).unwrap(), fence_before);
    assert_eq!(
        index.accepted_rebuild_incidence[&key],
        BTreeSet::from(["owed".into()])
    );
}

/// [off=main] a bound v1-only source never opens, creates or migrates SQLite custody.
#[test]
fn off_bound_v1_load_and_save_leave_all_database_paths_absent() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&ScanIndex::default()).unwrap();
    fs::write(&f.path, &bytes).unwrap();
    let mut index = ScanIndex::load(&f.path).unwrap();
    assert!(index.v2().persistence_v2.is_none());
    index.save(&f.path).unwrap();
    assert!(f.path.exists());
    assert!(!states().lock().unwrap().contains_key(&f.path));
    for suffix in [
        ".v2.sqlite",
        ".v2.sqlite.import",
        ".v2.sqlite.owner",
        ".v2.sqlite-wal",
        ".v2.sqlite-shm",
        ".v2-ack-receipt",
        ".v1-readonly",
    ] {
        assert!(
            !fence::sibling(&f.path, suffix).exists(),
            "OFF created {suffix}"
        );
    }
}
