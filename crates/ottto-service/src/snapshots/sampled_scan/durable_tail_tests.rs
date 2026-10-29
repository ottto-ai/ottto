//! GC against a committed index much larger than the store (F3, F5).
use super::*;
use crate::locked_state_dir::test_locks;
use crate::transcript_acquisition::ReadPlan;
use std::io::Read;

const INDEX_KEYS: usize = 20_000;

#[test]
fn admissible_codex_records_survive_above_the_retired_aggregate_disk_cap() {
    let root = crate::test_scratch::ScratchDir::new("dt-aggregate-disk");
    let lock = crate::locked_state_dir::LockedStateDir::acquire(&root).unwrap();
    let path = root.join("source.jsonl");
    codex_budget_fixture(
        &path,
        "019fa111-2222-7333-8444-555555555555",
        Some(1024 * 1024),
    );
    let scope = Scope("aggregate-file".into());
    let (reduction, _) = native_record_of(&path, &scope, SnapshotSource::Codex);
    let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
    assert!(
        body.len() >= 1024 * 1024,
        "the real open-call id is retained"
    );
    assert!(body.len() <= store::BODY_BYTES);
    let ds = DurableSource::Codex;
    let allowlist = codec::allowlist_digest(SnapshotSource::Codex);
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&root.join("index.json")), ds);
    let mut keys = Vec::new();
    for n in 0..40 {
        let key = store::key_digest(ds, &format!("session-{n}"));
        let pending = PendingRecord {
            binding: Binding {
                source: ds,
                key,
                context: store::context_digest("aggregate", None),
                scope: store::scope_digest(&scope.0, &allowlist, "identity", "v2"),
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate(&path, &scope),
            body: body.clone(),
            allowlist,
        };
        assert_eq!(
            disk.write_after_save(&lock, 1, 0, vec![pending])
                .unwrap()
                .written,
            1
        );
        keys.push(key);
    }
    assert_eq!(disk.counters().disk_records, 40);
    assert!(disk.counters().disk_bytes > 32 * 1024 * 1024);
    assert_eq!(disk.counters().budget_refused, 0);
    let mut cold = DurableTailStore::new(disk.dir().to_owned(), ds);
    for key in keys {
        let record = store::tests::found(cold.read(&key, &allowlist));
        assert_eq!(record.record.body, body);
    }
}

#[test]
fn receipt_pending_guard_keeps_accepted_witness_and_census_without_unreadable() {
    use std::os::unix::fs::MetadataExt;
    let root = crate::test_scratch::ScratchDir::new("dt-pending-census");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let path = root.join("source.jsonl");
    native_fixture(&path);
    let mut census = ScanCensus::default();
    let mut candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: root.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        365,
        &BTreeMap::new(),
    )
    .unwrap();
    candidate.source_file_fingerprint = "b".repeat(64); // Synthetic committed version.
    let key = local_index_key(&path);
    let modified = candidate.modified_unix_seconds;
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":candidate.size_bytes,"modified_unix_seconds":modified,
            "source_file_fingerprint":candidate.source_file_fingerprint,
        "last_upload_body_witness":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .unwrap(),
    );
    let metadata = std::fs::metadata(&path).unwrap();
    candidate.physical_identity = Some([metadata.dev(), metadata.ino()]);
    let census_record = claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
        &candidate.source_file_fingerprint,
        1_800_000_000,
        claude_request_census::ClaudeRequestCensusShape::Exact,
        vec![11, 22],
    )
    .with_modified_for_test(Some(modified))
    .with_birth_for_test(Some(claude_request_census::ClaudeRequestBirth {
        unix_seconds: 1,
        device: metadata.dev(),
        inode: metadata.ino(),
    }));
    index
        .claude_request_census
        .insert(key.clone(), census_record.clone());
    assert!(claude_request_census::retain_held(&mut index, &candidate));
    let before = serde_json::to_value(&index).unwrap();
    let cache = SharedCache::default();
    let index_path = root.join("index.json");
    cache.durable_begin_pass(source, &index_path, &Scope("pending".into()), false);
    let mut b = store::tests::binding("account", "scope", ("fp-a", None));
    b.key = store::key_digest(DurableSource::ClaudeCode, &key);
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
        let cert = store::tests::certificate(&path);
        slot.store
            .write_after_save(
                lock,
                1,
                0,
                vec![store::tests::pending(b.clone(), cert.clone(), 1)],
            )
            .unwrap();
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            Err(std::io::Error::other("rename EIO"))
        })));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| {
            Err(std::io::Error::other("unlink EIO"))
        })));
        slot.store
            .write_after_save(lock, 2, 0, vec![store::tests::pending(b, cert, 2)])
            .unwrap();
        store::test_hooks::set_before_rename(None);
        assert!(slot.store.has_pending());
    }
    let reason = cache.durable_guard(source, &candidate, &mut index).unwrap();
    store::test_hooks::set_before_unlink(None);
    assert_eq!(reason, store::Refusal::ReceiptPending);
    cache.durable_hold_exit(source, reason, &mut index, &candidate, &mut census);
    assert_eq!(census.unreadable_path_count, 0);
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    assert_eq!(index.claude_request_census.get(&key), Some(&census_record));
    let (counts, disk) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.durable_held.len(), 7);
    assert_eq!(store::Refusal::ReceiptPending as usize, 6);
    assert_eq!(counts.durable_held[6], 1);
    assert_eq!(counts.held_census, [1, 0]);
    assert_eq!(counts.restored, 0);
    assert_eq!(disk.receipt_pending_records, 1);
    // Switching store namespaces cannot discard an unresolved obligation.
    cache.durable_begin_pass(
        source,
        &root.join("other-index.json"),
        &Scope("other".into()),
        false,
    );
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
    assert_eq!(slot.index_path, index_path);
    assert!(slot.store.has_pending());
    assert_eq!(slot.store.disabled(), Some("namespace_pending"));
}

/// Includes the directory itself, all names/bytes, identity, mode and mutation times.
fn store_snapshot(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, Vec<i128>)> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = vec![dir.to_path_buf()];
    paths.extend(std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()));
    paths
        .into_iter()
        .map(|path| {
            let m = std::fs::symlink_metadata(&path).unwrap();
            let bytes = if m.is_file() {
                std::fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            let stamp = vec![
                m.dev() as i128,
                m.ino() as i128,
                m.len() as i128,
                m.mode() as i128,
                m.mtime() as i128,
                m.mtime_nsec() as i128,
                m.ctime() as i128,
                m.ctime_nsec() as i128,
            ];
            (path, (bytes, stamp))
        })
        .collect()
}

struct ClearWriteFaults;
impl Drop for ClearWriteFaults {
    fn drop(&mut self) {
        store::test_hooks::set_write_failure(None);
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_unlink(None);
        store::test_hooks::set_before_dir_sync(None);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn disabled_pending_store_publishes_valid_ram_through_production_scan_without_mutation() {
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for cause in [
        "obligation_overflow",
        "namespace_pending",
        "receipt_unreconciled",
    ] {
        let root = crate::test_scratch::ScratchDir::new("dt-disabled-native");
        let lock = test_locks::hold(&root);
        let _clear = ClearWriteFaults;
        let source = SnapshotSource::ClaudeCode;
        let ds = DurableSource::ClaudeCode;
        let namespace = Scope("disabled-native".into());
        let index_path = root.join("index.json");
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let run = |index| {
            let mut scan = OwnedSourceScan::new(
                source,
                std::slice::from_ref(&sessions),
                index,
                "2026-10-20T12:00:00Z",
                365,
                100,
                false,
                None,
                &[],
                false,
                true,
            )
            .with_sampled_acquisition(cache.clone(), namespace.clone());
            for _ in 0..10_000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
                }
            }
            panic!("production scan did not complete");
        };
        let (mut index, first) = run(ScanIndex::default());
        assert_eq!(first.snapshots.len(), 1, "real native output premise");
        assert_eq!(first.snapshots[0].input_tokens, 100);
        assert_eq!(first.snapshots[0].output_tokens, 10);
        assert!(
            cache.retained().unwrap().peek(&key).is_some(),
            "funded native RAM premise"
        );
        let expected_body = snapshot_upload_body_witness(&first.snapshots[0]);
        // Retry the same valid body through ordinary gates; keep its accepted witness/census.
        index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
        let witness = index.files[&key]
            .last_upload_body_witness
            .clone()
            .expect("accepted witness");
        let census = index
            .claude_request_census
            .get(&key)
            .cloned()
            .expect("native census");
        let records = (0..=store::MAX_BATCH)
            .map(|n| {
                let mut b = store::tests::binding("account", "scope", ("fp-a", None));
                b.key = store::key_digest(ds, if n == 0 { &key } else { "unused" });
                if n > 0 {
                    b.key = store::key_digest(ds, &format!("pending-{n}"));
                }
                store::tests::pending(b, store::tests::certificate(&path), 1)
            })
            .collect::<Vec<_>>();
        {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            for record in &records {
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 1, 0, vec![record.clone()])
                        .unwrap()
                        .written,
                    1
                );
            }
            store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(std::io::Error::other("rename EIO"))
            })));
            store::test_hooks::set_before_unlink(Some(Box::new(|_| {
                Err(std::io::Error::other("unlink EIO"))
            })));
            for record in &records[..store::MAX_BATCH] {
                let mut next = record.clone();
                next.body =
                    store::tests::pending(next.binding.clone(), next.certificate.clone(), 2).body;
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 2, 0, vec![next])
                        .unwrap()
                        .written,
                    0
                );
            }
            assert_eq!(
                slot.store.counters().receipt_pending_records,
                store::MAX_BATCH as u64
            );
            assert_eq!(slot.store.disabled(), None, "fill table before disabling");
            if cause == "receipt_unreconciled" {
                for _ in 0..2 {
                    assert!(slot
                        .store
                        .reconcile_pending(lock, &records[0].binding.key)
                        .is_err());
                }
            }
            if cause == "obligation_overflow" {
                let mut next = records[store::MAX_BATCH].clone();
                next.body =
                    store::tests::pending(next.binding.clone(), next.certificate.clone(), 2).body;
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 2, 0, vec![next])
                        .unwrap()
                        .written,
                    0
                );
            }
        }
        // Remove the injected failure: no retirement/reconciliation may erase custody.
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_unlink(None);
        if cause == "namespace_pending" {
            cache.durable_begin_pass(
                source,
                &root.join("other-index.json"),
                &Scope("other".into()),
                true,
            );
        }
        let dir = store::store_dir_for_index(&index_path);
        let before = store_snapshot(&dir);
        let (debt, counters) = {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            assert_eq!(slot.store.disabled(), Some(cause));
            assert!(slot.store.receipt_pending(&store::key_digest(ds, &key)));
            (
                store::tests::pending_snapshot(&slot.store),
                slot.store.counters(),
            )
        };
        // These hooks prove no write/unlink/sync, in addition to full disk equality.
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("disabled rename"))));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| panic!("disabled unlink"))));
        store::test_hooks::set_before_dir_sync(Some(Box::new(|_| panic!("disabled sync"))));
        assert_eq!(cache.reconcile_pending_key(source, &key), None);
        assert_eq!(cache.durable_hold(source, &key), None);
        let ((mut index, degraded), events) =
            crate::local_resource_diagnostics::capture(|| run(index));
        assert_eq!(
            degraded.snapshots.len(),
            1,
            "disabled capacity must publish"
        );
        assert_eq!(
            snapshot_upload_body_witness(&degraded.snapshots[0]),
            expected_body
        );
        assert_eq!(degraded.unreadable_path_count, 0);
        assert!(events
            .iter()
            .any(|e| e["counts"]["store_disabled"] == cause));
        assert_eq!(
            index.files[&key].last_upload_body_witness.as_ref(),
            Some(&witness)
        );
        assert_eq!(index.claude_request_census.get(&key), Some(&census));
        let reads = events
            .iter()
            .filter_map(|e| e["counts"].get("sampled_acquisition"))
            .filter(|r| r.is_object())
            .collect::<Vec<_>>();
        assert!(!reads.is_empty(), "real acquisition diagnostics reached");
        assert!(reads.iter().all(|r| r["full_selections"] == 0));
        assert!(reads
            .iter()
            .any(|r| r["unchanged_selections"].as_u64().unwrap() > 0));
        assert!(reads.iter().all(|r| r["completed_native_bytes"] == 0));
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.restored, 0);
        assert_eq!(counts.durable_held, [0; 7]);
        {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            assert_eq!(store::tests::pending_snapshot(&slot.store), debt);
            assert_eq!(
                slot.store.read(
                    &store::key_digest(ds, &key),
                    &codec::allowlist_digest(source)
                ),
                ReadOutcome::Missing
            );
            assert_eq!(
                slot.store.counters(),
                counters,
                "disabled store performs no work"
            );
        }
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            0
        );
        cache.durable_gc(lock, source, &index).unwrap();
        assert_eq!(store_snapshot(&dir), before);
        let mut stores = cache.durable().unwrap();
        assert_eq!(
            store::tests::pending_snapshot(&stores.slot(ds).as_ref().unwrap().store),
            debt
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn m1_setup_inventory_and_statvfs_failures_are_counted_and_retry_with_original_provenance() {
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for (stage_index, stage) in ["setup", "inventory", "statvfs"].into_iter().enumerate() {
            let root = crate::test_scratch::ScratchDir::new("dt-write-attempt-failure");
            let lock = test_locks::hold(&root);
            let _clear = ClearWriteFaults;
            let path = root.join("source.jsonl");
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            } else {
                native_fixture(&path);
            }
            let scope = Scope("failure-file".into());
            let namespace = Scope("failure-attempt".into());
            let index_path = root.join("index.json");
            let key = local_index_key(&path);
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let (reduction, checkpoint) = native_record_of(&path, &scope, source);
            let expected_body =
                codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "original-fingerprint");
            let mut index = ScanIndex::default();
            index.files.insert(
                key.clone(),
                serde_json::from_value(serde_json::json!({
                    "size_bytes":std::fs::metadata(&path).unwrap().len(),
                    "modified_unix_seconds":1,"source_file_fingerprint":"original-fingerprint"
                }))
                .unwrap(),
            );
            index.save(&index_path).unwrap();
            store::test_hooks::set_write_failure(Some(stage));
            let (failed, events) = crate::local_resource_diagnostics::capture(|| {
                cache.durable_write_after_save(lock, source, &index)
            });
            store::test_hooks::set_write_failure(None);
            assert!(
                failed.is_none(),
                "no false batch receipt: {source:?}/{stage}"
            );
            let (counts, disk) = cache.durable_counters(source).unwrap();
            assert_eq!(counts.not_persisted.get(stage), Some(&1));
            assert_eq!(
                disk.store_write_failed,
                std::array::from_fn(|i| u64::from(i == stage_index))
            );
            assert_eq!(disk.records_written, 0);
            assert_eq!(disk.receipt_pending_records, 0);
            assert_eq!(disk.receipt_reconciled, 0);
            assert!(events
                .iter()
                .any(|e| e["counts"]["store_write_failed"][stage] == 1
                    && e["counts"]["not_persisted"][stage] == 1
                    && e["source"] == source.api_slug()));
            {
                let stores = cache.durable().unwrap();
                assert!(stores.touched.contains(&key));
                assert_eq!(
                    stores.selected.get(&key).map(String::as_str),
                    Some("original-fingerprint")
                );
            }
            let ds = durable_source(source).unwrap();
            {
                let mut stores = cache.durable().unwrap();
                assert_eq!(
                    stores.slot(ds).as_mut().unwrap().store.read(
                        &store::key_digest(ds, &key),
                        &codec::allowlist_digest(source)
                    ),
                    ReadOutcome::Missing
                );
            }
            // No new selection/admission/acquisition: next save retries the same provenance.
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let mut stores = cache.durable().unwrap();
            assert!(!stores.touched.contains(&key));
            assert!(!stores.selected.contains_key(&key));
            let record = store::tests::found(stores.slot(ds).as_mut().unwrap().store.read(
                &store::key_digest(ds, &key),
                &codec::allowlist_digest(source),
            ));
            assert_eq!(record.record.body, expected_body);
            assert_eq!(record.index_generation, index.generation);
        }
    }
}

#[test]
fn oversized_active_request_refuses_without_waiting_or_opening_a_store() {
    let cache = SharedCache::default();
    let (result, events) = crate::local_resource_diagnostics::capture(|| {
        cache.acquire_active(SnapshotSource::Codex, store::ACTIVE_BYTES + 1)
    });
    assert!(matches!(result, store::LeaseWait::Busy));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["counts"]["active_budget_refused"], 1);
    assert!(cache.durable_counters(SnapshotSource::Codex).is_none());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn existing_m1_writer_uses_and_releases_active_credit_on_success_and_io_error() {
    use std::sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    };
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let root = crate::test_scratch::private_dir("ottto-writer-active-credit");
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let scope = Scope("writer-active-file".into());
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &Scope("writer-active".into()), false);
        let mut index = ScanIndex::default();
        for fail in [false, true] {
            let path = root.join(if fail { "fault.jsonl" } else { "success.jsonl" });
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            } else {
                std::fs::write(&path, serde_json::json!({"type":"assistant", "sessionId":"active-credit",
                    "message":{"id":"msg-active", "model":"claude-opus-4-1", "role":"assistant", "content":[],
                        "usage":{"input_tokens":5,"output_tokens":2}}}).to_string()+"\n").unwrap();
            }
            let key = local_index_key(&path);
            let (reduction, checkpoint) = native_record_of(&path, &scope, source);
            let body =
                codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "fp");
            index.files.insert(
                key.clone(),
                serde_json::from_value(serde_json::json!({
                    "size_bytes":std::fs::metadata(&path).unwrap().len(),
                    "modified_unix_seconds":1,"source_file_fingerprint":"fp"
                }))
                .unwrap(),
            );
            index.save(&index_path).unwrap();
            let reached = Arc::new(AtomicBool::new(false));
            if fail {
                let reached = reached.clone();
                store::test_hooks::set_before_rename(Some(Box::new(move |_, _| {
                    reached.store(true, AtomicOrdering::SeqCst);
                    Err(std::io::Error::other("synthetic rename failure"))
                })));
            }
            let (receipt, events) = crate::local_resource_diagnostics::capture(|| {
                cache.durable_write_after_save(lock, source, &index)
            });
            store::test_hooks::set_before_rename(None);
            assert_eq!(reached.load(AtomicOrdering::SeqCst), fail);
            assert!(receipt.is_some());
            if fail {
                assert_eq!(receipt.as_ref().unwrap().written, 0);
                assert_eq!(
                    cache
                        .durable_counters(source)
                        .unwrap()
                        .1
                        .durable_write_failed_published,
                    1
                );
            }
            if !fail {
                assert_eq!(receipt.unwrap().written, 1);
                let ds = durable_source(source).unwrap();
                let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
                let ReadOutcome::Found(record) = disk.read(
                    &store::key_digest(ds, &key),
                    &codec::allowlist_digest(source),
                ) else {
                    panic!("real M1 write produced no readable record");
                };
                assert_eq!(record.record.body, body);
            }
            let reserved = (4 * store::RECORD_BYTES + WRITE_PASS_BYTES) as u64;
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_current_bytes"] == reserved));
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_peak_bytes"] == reserved));
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_current_bytes"] == 0));
            assert!(!events
                .iter()
                .any(|e| e["counts"]["active_drop_release"] == 1));
            let store::LeaseWait::Granted(lease) = cache.acquire_active(source, 0) else {
                panic!("writer exit leaked active ownership");
            };
            lease.release();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn indexed_key(n: usize) -> String {
    format!("/synthetic/sessions/rollout-{n:05}.jsonl")
}

/// A real committed checkpoint's certificate for `path`.
fn certificate(path: &Path, scope: &Scope) -> DurableCertificate {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let checkpoint = plan
        .commit_after_native_completion(&file, scope, 1_800_000_000)
        .unwrap();
    checkpoint
        .durable_certificate(birth_unix_nanos(&std::fs::metadata(path).unwrap()))
        .unwrap()
}

/// F3/F5 receipt: GC after a save of a 20 000-entry index over a 4-record
/// store looks up only the store's inventory (its keep map holds the 3
/// indexed records, never the index), reads one header per record and no
/// body, and drops the record whose key the index no longer holds.
#[test]
fn gc_on_a_large_index_looks_up_only_the_store_inventory() {
    let root = crate::test_scratch::private_dir("ottto-dt-gc-large-index");
    let lock = test_locks::hold(&root);
    let index_path = root.join("index.json");
    let transcript = root.join("t.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let certificate = certificate(&transcript, &Scope("dt-gc-file".into()));
    let source = SnapshotSource::Codex;
    let namespace = Scope("dt-gc".into());
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);

    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!(
        {"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}
    ))
    .unwrap();
    let mut index = ScanIndex::default();
    for n in 0..INDEX_KEYS {
        index.files.insert(indexed_key(n), entry.clone());
    }
    let mut store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        durable_source(source).unwrap(),
    );
    let allowlist = codec::allowlist_digest(source);
    let context = store::context_digest(&namespace.0, None);
    let keys = [
        indexed_key(7),
        indexed_key(12_345),
        indexed_key(INDEX_KEYS - 1),
        "/synthetic/sessions/rollout-dropped.jsonl".to_string(),
    ];
    let pending = keys
        .iter()
        .map(|key| PendingRecord {
            binding: Binding {
                source: DurableSource::Codex,
                key: store::key_digest(DurableSource::Codex, key),
                context,
                scope: [0; 32],
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate.clone(),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist,
        })
        .collect();
    store.write_after_save(lock, 1, 0, pending).unwrap();

    cache.durable_gc(lock, source, &index).unwrap();
    let (counters, stats) = cache.durable_counters(source).unwrap();
    // The old keep map held one (digest, scope) pair per index key.
    let pair = std::mem::size_of::<(store::Digest32, Option<store::Digest32>)>();
    println!(
        "dt_gc_receipt: index_keys={INDEX_KEYS} store_records={} inventory_bound={} \
         gc_keep_peak={} keep_pair_bytes={pair} keep_bytes={} unbounded_keep_bytes={} \
         gc_records_read={} gc_bytes_read={} gc_records_deleted={} disk_records={}",
        keys.len(),
        store::INVENTORY_BOUND,
        counters.gc_keep_peak,
        counters.gc_keep_peak as usize * pair,
        INDEX_KEYS * pair,
        stats.gc_records_read,
        stats.gc_bytes_read,
        stats.gc_records_deleted,
        stats.disk_records,
    );
    assert_eq!(counters.gc_keep_peak, 3);
    assert!(counters.gc_keep_peak as usize <= store::INVENTORY_BOUND);
    assert_eq!(stats.gc_records_read, keys.len() as u64);
    assert_eq!(
        stats.gc_bytes_read,
        (keys.len() * store::HEADER_BYTES) as u64
    );
    assert_eq!(stats.gc_records_deleted, 1);
    assert_eq!(stats.disk_records, 3);
    let _ = std::fs::remove_dir_all(&root);
}

/// Replay bindings are independent of the field codec. A revision, rule or
/// per-file marker change refuses even with unchanged scope, bytes and body.
#[test]
fn replay_revisions_and_applied_markers_bind_without_changing_the_allowlist() {
    let source = SnapshotSource::ClaudeCode;
    let key = "/synthetic/claude/fixture.jsonl";
    let scope = Scope("same-file-scope".into());
    let namespace = Scope("same-account".into());
    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
        "effective_upload_body_witness_revision":3
    }))
    .unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), entry);
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.claude_money_birth_store.set_money_rule_version(1);
    let binding = |index: &ScanIndex| {
        let interpretation = Interpretation::of(source, key, index, false, &namespace);
        expected(
            DurableSource::ClaudeCode,
            source,
            key,
            &scope,
            index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding
    };
    let prior = binding(&index);
    assert!(!index.effective_upload_body_witness_revision_requires_adoption(key));
    for arm in ["revision", "rule", "applied", "marks", "gate"] {
        let mut changed = index.clone();
        match arm {
            "revision" => changed.activate_effective_upload_body_witness_revision(2),
            "rule" => changed.claude_money_birth_store.set_money_rule_version(2),
            "applied" => {
                changed
                    .files
                    .get_mut(key)
                    .unwrap()
                    .effective_upload_body_witness_revision = 2
            }
            "marks" => changed
                .claude_money_birth_store
                .set_money_marks(key, claude_request_money::e2::money_mark::ESTIMATED),
            "gate" => {}
            _ => unreachable!(),
        }
        let after = if arm == "gate" {
            claude_request_money::e2::with_disabled(|| binding(&changed))
        } else {
            binding(&changed)
        };
        assert_ne!(prior, after, "{arm}");
        assert_eq!(prior.key, after.key, "{arm}");
        assert_eq!(prior.context, after.context, "{arm}");
        if matches!(arm, "applied" | "marks") {
            assert_ne!(prior.entry, after.entry, "{arm}");
        } else {
            assert_ne!(prior.scope, after.scope, "{arm}");
        }
    }
}

/// A real native reduction and certificate, encoded even on layouts where
/// RAM admission is unavailable. Positive restore/write controls still must
/// run on the supported macOS layout.
fn native_record(path: &Path, scope: &Scope) -> (CachedJsonlReduction, Checkpoint) {
    native_record_of(path, scope, SnapshotSource::ClaudeCode)
}

fn native_record_of(
    path: &Path,
    scope: &Scope,
    source: SnapshotSource,
) -> (CachedJsonlReduction, Checkpoint) {
    let apply = match source {
        SnapshotSource::Codex => apply_codex_line,
        _ => apply_claude_code_line,
    };
    let mut parser = OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        source,
        apply,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    parser
        .prepare_acquisition(None, scope, None, 1_800_000_000)
        .unwrap();
    while !parser.step().unwrap() {}
    let reduction = parser.durable_test_reduction_copy();
    let checkpoint = match parser
        .certify_without_retention(scope, 1_800_000_000)
        .unwrap()
    {
        sampled_jsonl::SideCertificate::Certified { completed, .. } => completed.checkpoint,
        _ => panic!("a clean native fixture is certified"),
    };
    (reduction, checkpoint)
}

fn native_fixture(path: &Path) {
    std::fs::write(
        path,
        concat!(
            "{\"type\":\"assistant\",\"sessionId\":\"11111111-2222-4333-8444-555555555555\",",
            "\"timestamp\":\"2026-10-07T10:00:00Z\",\"requestId\":\"req-dt-owed\",",
            "\"message\":{\"id\":\"msg-dt-owed\",\"model\":\"fixture-model\",",
            "\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}}\n"
        ),
    )
    .unwrap();
}

/// Money rules re-owe marked paths. Seed a usable record first, prove it
/// restores, then prove revision/money debt refuses before record I/O and
/// invalidates the existing record on the real post-save write path.
#[test]
fn owed_history_refuses_restore_before_disk_for_revision_and_money_replay() {
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-dt-owed");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("owed-test".into());
    let scope = Scope("owed-file".into());
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    for money in [false, true] {
        // Independent committed generations; both arms exercise real CAS.
        let index_path = root.join(if money {
            "money-index.json"
        } else {
            "revision-index.json"
        });
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":std::fs::metadata(&path).unwrap().len(),
                "modified_unix_seconds":1,"source_file_fingerprint":"fp",
                "effective_upload_body_witness_revision":if money {3} else {2}
            }))
            .unwrap(),
        );
        index.activate_effective_upload_body_witness_revision(if money { 3 } else { 2 });
        index.adopt_effective_upload_body_witness_revision_monotonically();
        if money {
            index.claude_money_birth_store.set_money_rule_version(1);
            index
                .claude_money_birth_store
                .set_money_marks(&key, claude_request_money::e2::money_mark::ESTIMATED);
        }
        assert!(!index.effective_upload_body_witness_revision_requires_adoption(&key));
        index.save(&index_path).unwrap();
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        let binding = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding;
        let (reduction, checkpoint) = native_record(&path, &scope);
        let body = codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
        let mut store = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            durable_source(source).unwrap(),
        );
        store
            .write_after_save(
                lock,
                index.generation,
                0,
                vec![PendingRecord {
                    binding,
                    certificate: certificate(&path, &scope),
                    body,
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
        let records = || {
            std::fs::read_dir(store::store_dir_for_index(&index_path))
                .unwrap()
                .count()
        };
        assert_eq!(records(), 1, "a real usable record exists");
        let positive = SharedCache::default();
        positive.durable_begin_pass(source, &index_path, &namespace, false);
        let restored = positive
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            )
            .into_test_option();
        let supported = crate::heap_layout_bound::layout_supported();
        assert_eq!(restored.is_some(), supported);
        assert_eq!(
            positive.durable_counters(source).unwrap().0.restored,
            u64::from(supported)
        );
        assert_eq!(positive.durable_counters(source).unwrap().1.records_read, 1);
        drop(restored);
        if money {
            claude_request_money::e2::with_money_rules(
                &[(1, 0), (2, claude_request_money::e2::money_mark::ESTIMATED)],
                || {
                    claude_request_money::e2::apply_money_rules(&mut index);
                },
            );
            assert_eq!(index.claude_money_birth_store.money_rule_version(), 2);
        } else {
            // Use the supported revision ceiling; do not loosen activation.
            index.activate_effective_upload_body_witness_revision(3);
        }
        assert!(index.effective_upload_body_witness_revision_requires_adoption(&key));
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        assert!(cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            )
            .into_test_option()
            .is_none());
        let (counts, disk) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.ineligible.get("history_owed"), Some(&1));
        assert_eq!(
            (counts.restored, counts.missing, disk.records_read),
            (0, 0, 0)
        );
        if supported {
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "fp");
            index.save(&index_path).unwrap();
            cache.durable_write_after_save(lock, source, &index);
            let (counts, disk) = cache.durable_counters(source).unwrap();
            println!(
                "owed_write money={money}: {}",
                counts.summary(source, &disk)
            );
            assert_eq!(counts.not_persisted.get("history_owed"), Some(&1));
            assert_eq!(disk.records_invalidated, 1);
            assert_eq!(records(), 0);
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// Capture is process-local in RAM, but a durable checkpoint crosses a
/// restart. Both toggle directions must change Claude's binding (Codex is
/// unaffected) and refuse the old record under the actual env setting.
#[test]
fn attribution_capture_toggle_refuses_the_previous_claude_record() {
    if !crate::test_isolation::run_here() {
        return;
    }
    let root = crate::test_scratch::private_dir("ottto-dt-attribution");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("attribution-test".into());
    let scope = Scope("attribution-file".into());
    let index_path = root.join("index.json");
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    for before in [false, true] {
        // Isolated child process: no concurrent test can observe the env.
        std::env::set_var(
            "OTTTO_CLAUDE_ATTRIBUTION_CAPTURE",
            if before { "1" } else { "0" },
        );
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        let codex_before =
            Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace);
        let binding = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding;
        let (reduction, _) = native_record(&path, &scope);
        let mut store = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            durable_source(source).unwrap(),
        );
        store
            .write_after_save(
                lock,
                index.generation,
                0,
                vec![PendingRecord {
                    binding: binding.clone(),
                    certificate: certificate(&path, &scope),
                    body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                        .unwrap(),
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
        std::env::set_var(
            "OTTTO_CLAUDE_ATTRIBUTION_CAPTURE",
            if before { "0" } else { "1" },
        );
        let after = Interpretation::of(source, &key, &index, false, &namespace);
        let changed = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &after,
            None,
        )
        .unwrap()
        .binding;
        assert_ne!(binding.scope, changed.scope);
        assert_eq!(binding.entry, changed.entry);
        assert_eq!(binding.key, changed.key);
        assert_eq!(binding.context, changed.context);
        assert_eq!(
            codex_before.identity_contract,
            Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace)
                .identity_contract
        );
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        assert!(cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &after
            )
            .into_test_option()
            .is_none());
        let (counts, disk) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.ineligible.get("scope"), Some(&1));
        assert_eq!(counts.restored, 0);
        assert_eq!(disk.records_read, 1);
    }
    let _ = std::fs::remove_dir_all(root);
}

/// A Codex transcript whose open call's id is `call_id_bytes` long: the id
/// is kept verbatim in the record body, so it sizes the body. Three counted
/// requests close the session-start window first, so its re-derived opening
/// content ends inside the 1 MiB head.
fn codex_budget_fixture(path: &Path, session: &str, call_id_bytes: Option<usize>) {
    let at = "2026-10-07T10:00:00Z";
    let usage = |input: u64, output: u64| {
        serde_json::json!({"input_tokens":input,"cached_input_tokens":0,
            "output_tokens":output,"reasoning_output_tokens":0})
    };
    let mut lines = vec![
        serde_json::json!({"type":"session_meta","timestamp":at,"payload":{"id":session,
            "timestamp":at,"cwd":"/tmp/dt-budget","originator":"codex_cli_rs",
            "cli_version":"0.50.0","source":"cli"}}),
        serde_json::json!({"type":"turn_context","timestamp":at,
            "payload":{"turn_id":"turn-1","cwd":"/tmp/dt-budget","model":"gpt-5.2"}}),
    ];
    for n in 1..=crate::snapshots::session_start::WINDOW_REQUESTS as u64 {
        lines.push(serde_json::json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"token_count","info":{
                "total_token_usage":usage(100 * n, 10 * n),
                "last_token_usage":usage(100, 10),"model":"gpt-5.2"}}}));
    }
    if let Some(bytes) = call_id_bytes {
        lines.push(open_call(bytes));
    }
    let text = lines
        .iter()
        .map(|line| line.to_string() + "\n")
        .collect::<String>();
    std::fs::write(path, text).unwrap();
}

fn open_call(call_id_bytes: usize) -> serde_json::Value {
    serde_json::json!({"type":"response_item","timestamp":"2026-10-07T10:00:01Z",
        "payload":{"type":"function_call","name":"shell",
            "arguments":"{\"command\":[\"true\"]}",
            "call_id":format!("call_{}", "x".repeat(call_id_bytes))}})
}

/// P2-1 (review r10): a resident deferred by the per-save byte budget
/// (`WRITE_PASS_BYTES`) keeps its acquired selection provenance. Its next
/// save, with no rescan or admission of the key in between, writes its
/// record: no selection refusal, no invalidation of the key's existing
/// record (intact while its replacement waits), and a restart restores the
/// replacement. Arm `spent`: the first two bodies use the allowance exactly
/// (`budget == 0`); arm `too_large`: the third body exceeds the remainder.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn byte_budget_deferral_keeps_selection_provenance_for_the_next_save() {
    let source = SnapshotSource::Codex;
    let namespace = Scope("dt-budget".into());
    let scope = Scope("dt-budget-file".into());
    let cap = jsonl_line_cap() as u64;
    let body_of = |path: &Path| {
        let (reduction, checkpoint) = native_record_of(path, &scope, source);
        let body = codec::encode(&reduction, store::RECORD_BYTES, cap).unwrap();
        (reduction, checkpoint, body)
    };
    let entry = |path: &Path, fingerprint: &str| -> ScanIndexEntry {
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":fingerprint
        }))
        .unwrap()
    };
    let admit = |cache: &SharedCache,
                 path: &Path,
                 fingerprint: &str,
                 (reduction, checkpoint): (CachedJsonlReduction, Checkpoint)| {
        let key = local_index_key(path);
        assert!(cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint,
                reduction: Some(reduction),
                released: None,
                unsealed: false,
            },
            0
        ));
        cache.durable_note_selection(&key, fingerprint);
    };
    for arm in ["spent", "too_large"] {
        let root = crate::test_scratch::private_dir(&format!("ottto-dt-budget-{arm}"));
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let store_dir = store::store_dir_for_index(&index_path);
        let record_files = || {
            std::fs::read_dir(store_dir.as_path())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        // Keys write in key order: a, b, then c.
        let [a, b, c] = ["a", "b", "c"].map(|name| root.join(format!("{name}.jsonl")));
        let [session_a, session_b, session_c] = [
            "019fa111-2222-7333-8444-00000000000a",
            "019fa111-2222-7333-8444-00000000000b",
            "019fa111-2222-7333-8444-00000000000c",
        ];
        let mut index = ScanIndex::default();

        // Process 0: c's existing valid record.
        codex_budget_fixture(&c, session_c, None);
        let prior = SharedCache::default();
        prior.durable_begin_pass(source, &index_path, &namespace, false);
        let (reduction, checkpoint, _) = body_of(&c);
        admit(&prior, &c, "fp-c0", (reduction, checkpoint));
        index.files.insert(local_index_key(&c), entry(&c, "fp-c0"));
        index.save(&index_path).unwrap();
        prior.durable_write_after_save(lock, source, &index);
        let existing = record_files();
        assert_eq!(existing.len(), 1, "{arm}: c's prior record");
        drop(prior);

        // Process 1: a and b, then c's replacement, all resident.
        let id_bytes = 3 * 1024 * 1024;
        codex_budget_fixture(&a, session_a, Some(id_bytes));
        let (reduction_a, checkpoint_a, body_a) = body_of(&a);
        let b_body = |bytes: usize| {
            codex_budget_fixture(&b, session_b, Some(bytes));
            body_of(&b)
        };
        let mut b_bytes = id_bytes;
        let mut found = b_body(b_bytes);
        if arm == "spent" {
            // Size b so a and b use the allowance exactly; the body grows
            // with the id byte for byte (no varint boundary nearby).
            let target = WRITE_PASS_BYTES - body_a.len();
            for _ in 0..4 {
                if found.2.len() == target {
                    break;
                }
                b_bytes = (b_bytes + target).checked_sub(found.2.len()).unwrap();
                found = b_body(b_bytes);
            }
            assert_eq!(
                body_a.len() + found.2.len(),
                WRITE_PASS_BYTES,
                "{arm}: a={} b={} id={b_bytes}",
                body_a.len(),
                found.2.len()
            );
        }
        let (reduction_b, checkpoint_b, body_b) = found;
        let mut appended = std::fs::OpenOptions::new().append(true).open(&c).unwrap();
        std::io::Write::write_all(
            &mut appended,
            (open_call(id_bytes).to_string() + "\n").as_bytes(),
        )
        .unwrap();
        drop(appended);
        let (reduction_c, checkpoint_c, body_c) = body_of(&c);
        if arm == "too_large" {
            let remainder = WRITE_PASS_BYTES - body_a.len() - body_b.len();
            assert!(remainder > 0 && body_c.len() > remainder, "{arm}");
        }
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        admit(&cache, &a, "fp-a", (reduction_a, checkpoint_a));
        admit(&cache, &b, "fp-b", (reduction_b, checkpoint_b));
        admit(&cache, &c, "fp-c1", (reduction_c, checkpoint_c));
        index.files.insert(local_index_key(&a), entry(&a, "fp-a"));
        index.files.insert(local_index_key(&b), entry(&b, "fp-b"));
        index.files.insert(local_index_key(&c), entry(&c, "fp-c1"));
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, disk) = cache.durable_counters(source).unwrap();
        println!(
            "dt_budget {arm} first save: {}",
            counts.summary(source, &disk)
        );
        assert_eq!(counts.write_deferred, 1, "{arm}: c deferred by bytes");
        assert_eq!(disk.records_written, 2, "{arm}: a and b");
        assert_eq!(disk.disk_records, 3, "{arm}: c's prior, a, b");
        assert!(counts.not_persisted.is_empty(), "{arm}");
        assert_eq!(disk.records_invalidated, 0, "{arm}");
        let after_first = record_files();
        assert_eq!(after_first.len(), 3, "{arm}");
        for (path, bytes) in &existing {
            assert_eq!(
                after_first.get(path),
                Some(bytes),
                "{arm}: c's record intact"
            );
        }
        {
            let stores = cache.durable().unwrap();
            let key_c = local_index_key(&c);
            assert!(stores.touched.contains(&key_c), "{arm}: c offered again");
            assert_eq!(
                stores.selected.get(&key_c).map(String::as_str),
                Some("fp-c1"),
                "{arm}: c keeps its acquired provenance"
            );
        }

        // The next save: no rescan or admission of c in between.
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, disk) = cache.durable_counters(source).unwrap();
        println!(
            "dt_budget {arm} second save: {}",
            counts.summary(source, &disk)
        );
        assert_eq!(counts.write_deferred, 1, "{arm}");
        assert_eq!(disk.records_written, 3, "{arm}: c's replacement written");
        assert_eq!(disk.disk_records, 3, "{arm}");
        assert!(
            counts.not_persisted.is_empty(),
            "{arm}: no selection refusal"
        );
        assert_eq!(disk.records_invalidated, 0, "{arm}");
        let after_second = record_files();
        assert_eq!(after_second.len(), 3, "{arm}");
        for path in existing.keys() {
            assert_ne!(
                after_second.get(path),
                existing.get(path),
                "{arm}: replaced"
            );
        }
        drop(cache);

        // Restart: all three restore from the committed index.
        let loaded = ScanIndex::load(&index_path).unwrap();
        let restart = SharedCache::default();
        restart.durable_begin_pass(source, &index_path, &namespace, false);
        for (path, body) in [(&a, &body_a), (&b, &body_b), (&c, &body_c)] {
            let key = local_index_key(path);
            let interpretation = Interpretation::of(source, &key, &loaded, false, &namespace);
            let taken = restart
                .durable_restore(
                    source,
                    &key,
                    path,
                    &scope,
                    &mut File::open(path).unwrap(),
                    &loaded,
                    &interpretation,
                )
                .into_test_option()
                .unwrap_or_else(|| {
                    let (counts, disk) = restart.durable_counters(source).unwrap();
                    panic!("{arm}: restore: {}", counts.summary(source, &disk))
                });
            assert_eq!(
                codec::encode(&taken.retained.state, store::RECORD_BYTES, cap).unwrap(),
                *body,
                "{arm}"
            );
        }
        let (counts, disk) = restart.durable_counters(source).unwrap();
        println!("dt_budget {arm} restart: {}", counts.summary(source, &disk));
        assert_eq!(counts.restored, 3, "{arm}");
        let _ = std::fs::remove_dir_all(root);
    }
}

trait RestoreTestOutcome {
    fn into_test_option(
        self,
    ) -> Option<crate::transcript_cache::Taken<sampled_jsonl::CachedJsonlReduction>>;
}
impl RestoreTestOutcome for sampled_scan::durable_tail::RestoreOutcome {
    fn into_test_option(
        self,
    ) -> Option<crate::transcript_cache::Taken<sampled_jsonl::CachedJsonlReduction>> {
        match self {
            Self::Restored(taken) => Some(*taken),
            Self::Miss => None,
            Self::Held(reason) => panic!("ordinary restore unexpectedly Held: {reason:?}"),
        }
    }
}

/// L23/F1: the production guard dominates all sampling, trust and dependency
/// fallbacks. Kind `none` is the non-held control: the same fixture with no
/// record reaches acquisition, and the arm's later gate observes its false value.
/// C1: `known_corrupt` (T14) is not held: one counted rebuild, acquired like
/// the control, record untouched before the save. C2: the pass's held keys and
/// rebuilds reach the `local_resources` alarm for this source.
#[test]
fn common_hold_precedes_outer_gates_and_full_acquisition() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for kind in [
            "newer",
            "unknown",
            "undecodable",
            "unbindable",
            "known_corrupt",
            "none",
        ] {
            let corrupt = kind == "known_corrupt";
            for bypass in [
                "ordinary",
                "sampling_none",
                "allow_sample_false",
                "state_false",
                "sidecar_false",
                "owning_header_false",
                "dependencies_missing",
                "fresh_index",
                "cleared",
                "owed",
                "compressed",
            ] {
                // Production never opens a compressed Codex rollout
                // (codex_compressed_input.rs: discovery does not enumerate them);
                // a gzip-bodied `.jsonl` has no readable session header, so the
                // join inventory withholds it before selection, held or not.
                let reachable = !(source == SnapshotSource::Codex && bypass == "compressed");
                let root = crate::test_scratch::private_dir("ottto-dt-common-hold");
                let lock = test_locks::hold(&root);
                let transcripts = root.join("sessions");
                std::fs::create_dir(&transcripts).unwrap();
                let path = transcripts.join("0199f7a0-0000-7000-8000-0000000d7a11.jsonl");
                if source == SnapshotSource::Codex {
                    codex_budget_fixture(&path, "0199f7a0-0000-7000-8000-0000000d7a11", None);
                } else {
                    native_fixture(&path);
                }
                if bypass == "compressed" {
                    use std::io::Write;
                    let text = std::fs::read(&path).unwrap();
                    let mut zip =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    zip.write_all(&text).unwrap();
                    std::fs::write(&path, zip.finish().unwrap()).unwrap();
                }
                let key = local_index_key(&path);
                let namespace = Scope("common-hold".into());
                let cache = Arc::new(SharedCache::default());
                let index_path = root.join("index.json");
                cache.durable_begin_pass(source, &index_path, &namespace, false);
                let ds = durable_source(source).unwrap();
                let store_key = store::key_digest(ds, &key);
                let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
                // Certificate source is irrelevant for preservation; it is never restored.
                let cert_path = root.join("certificate.jsonl");
                std::fs::write(&cert_path, b"{}\n").unwrap();
                // A verified known record of a key absent from every index:
                // production fresh-index cleanup must delete it.
                let absent_key = store::key_digest(ds, "/synthetic/absent-known.jsonl");
                let record = |key| PendingRecord {
                    binding: Binding {
                        source: ds,
                        key,
                        context: [0; 32],
                        scope: [0; 32],
                        entry: [0; 32],
                    },
                    certificate: certificate(&cert_path, &namespace),
                    body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                };
                disk.write_after_save(lock, 1, 0, vec![record(store_key), record(absent_key)])
                    .unwrap();
                let hex = |key: store::Digest32| {
                    key.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                let absent_path = disk.dir().join(format!("{}.rec", hex(absent_key)));
                assert!(absent_path.exists());
                let record_path = disk.dir().join(format!("{}.rec", hex(store_key)));
                let mut bytes = std::fs::read(&record_path).unwrap();
                if kind == "none" {
                    // Known unmarked R29 control: acquisition still runs.
                } else if kind == "unknown" {
                    bytes[10] ^= 1;
                } else if kind == "undecodable" {
                    bytes.truncate(5);
                } else if kind == "unbindable" {
                    bytes[43] ^= 1;
                } else if corrupt {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                } else {
                    bytes[8..10].copy_from_slice(&(store::FORMAT_VERSION + 1).to_le_bytes());
                    let end = bytes.len() - 32;
                    let trailer = Sha256::digest(&bytes[..end]);
                    bytes[end..].copy_from_slice(&trailer);
                }
                if kind != "none" {
                    std::fs::write(&record_path, &bytes).unwrap();
                    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                // New store owner, no RAM verification or reduction from the writer.
                drop(cache);
                drop(disk);
                let cache = Arc::new(SharedCache::default());
                let mut index = ScanIndex::default();
                if bypass == "fresh_index" {
                    // Production begin with a freshly loaded index runs the
                    // selective cleanup under the held lock.
                    crate::snapshots::begin_durable_pass(
                        &cache,
                        &root,
                        source,
                        &index_path,
                        true,
                        &namespace,
                        false,
                    );
                    assert!(!absent_path.exists(), "fresh cleanup ran");
                } else {
                    cache.durable_begin_pass(source, &index_path, &namespace, false);
                    let fingerprint = if bypass == "cleared" { "" } else { "fp" };
                    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":fingerprint,"last_snapshot_fingerprint":"accepted-body"})).unwrap();
                    index.files.insert(key.clone(), entry);
                    if bypass == "owed" {
                        index.activate_effective_upload_body_witness_revision(2);
                    }
                    // Distinct, asserted M1 veto states.
                    assert_eq!(
                        index.effective_upload_body_witness_revision_requires_adoption(&key),
                        bypass == "owed"
                    );
                    assert_eq!(
                        index.files[&key].source_file_fingerprint.is_empty(),
                        bypass == "cleared"
                    );
                }
                if kind != "none" {
                    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
                }
                let mut scan = OwnedSourceScan::new(
                    source,
                    std::slice::from_ref(&transcripts),
                    index,
                    "2026-10-20T12:00:00Z",
                    365,
                    100,
                    false,
                    None,
                    &[],
                    false,
                    true,
                )
                .with_sampled_acquisition(cache.clone(), namespace);
                if bypass == "sampling_none" || bypass == "compressed" {
                    scan.sampling = None;
                }
                if bypass == "allow_sample_false" {
                    scan.sampling.as_mut().unwrap().audit_metadata_supported = false;
                }
                if bypass == "state_false" {
                    scan.state_census_complete = false;
                }
                if bypass == "sidecar_false" {
                    scan.sidecar_census_complete = false;
                }
                struct ResetDependencies;
                impl Drop for ResetDependencies {
                    fn drop(&mut self) {
                        super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(false));
                    }
                }
                let _reset = ResetDependencies;
                if bypass == "dependencies_missing" {
                    super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(true));
                    let candidate = candidate_from_traversal_path(
                        source,
                        ScanTraversalPath {
                            scan_root: transcripts.clone(),
                            path: path.clone(),
                            census_member: true,
                            watcher_hint: false,
                        },
                        &mut ScanCensus::default(),
                        None,
                        365,
                        &BTreeMap::new(),
                    )
                    .unwrap();
                    assert!(sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &scan.codex_title_metadata,
                        &scan.claude_title_metadata,
                        None
                    )
                    .is_none());
                }
                let held = kind != "none" && !corrupt;
                let mut completed = false;
                let mut acquired = false;
                let mut header_dropped = false;
                let mut admission = None;
                for _ in 0..10_000 {
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(mut next) => {
                            acquired |= next.active_file.is_some();
                            if let Some(c) = next.sampling.as_ref() {
                                admission = Some(serde_json::to_value(c.admission).unwrap());
                                if held {
                                    assert_eq!(c.full_files, 0);
                                    assert_eq!(c.native_bytes, 0);
                                }
                            }
                            // The Codex owning header goes missing after the
                            // join was prepared: the candidate is selected and
                            // reaches the later owning-header gate.
                            if bypass == "owning_header_false"
                                && next.codex_join_prepared
                                && !header_dropped
                            {
                                if let Some(inventory) = next.codex_join_inventory.as_mut() {
                                    inventory
                                        .headers
                                        .retain(|header| header.candidate.path != path);
                                    header_dropped = true;
                                }
                            }
                            scan = next;
                        }
                        OwnedSourceScanStep::Complete { scan: result, .. } => {
                            if held {
                                assert!(
                                    result.snapshots.is_empty(),
                                    "Held key produces no POST body"
                                );
                                assert_eq!(result.scanned_file_count, 0, "{bypass}");
                            } else {
                                acquired |= result.scanned_file_count > 0;
                            }
                            completed = true;
                            break;
                        }
                    }
                }
                assert!(completed);
                assert_eq!(acquired, !held && reachable, "{source:?}/{kind}/{bypass}");
                let gate = |name: &str| {
                    admission
                        .as_ref()
                        .map(|a| (a[name]["assessed"].as_u64(), a[name]["matched"].as_u64()))
                };
                if held {
                    assert!(admission
                        .as_ref()
                        .map_or(true, |a| a["attempts"].as_u64() == Some(0)));
                } else if reachable {
                    let observed = match bypass {
                        "owning_header_false" if source == SnapshotSource::Codex => {
                            Some("owning_header_current")
                        }
                        "state_false" => Some("state_census_complete"),
                        "sidecar_false" => Some("sidecar_census_complete"),
                        "dependencies_missing" => Some("reduction_dependencies_available"),
                        _ => None,
                    };
                    if let Some(name) = observed {
                        let (assessed, matched) = gate(name).unwrap();
                        assert!(assessed.unwrap() >= 1, "{source:?}/{bypass}: {name}");
                        assert_eq!(matched, Some(0), "{source:?}/{bypass}: {name}");
                    }
                }
                let (counts, store_counts) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    store_counts.t14_rebuild,
                    u64::from(corrupt && reachable),
                    "{source:?}/{bypass}"
                );
                let ((), alarms) =
                    crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
                let alarmed = reachable && kind != "none";
                assert_eq!(
                    alarms.len(),
                    usize::from(alarmed),
                    "{source:?}/{kind}/{bypass}"
                );
                if alarmed {
                    let alarm = &alarms[0];
                    assert_eq!(alarm["stage"], "durable_tail_alarm");
                    assert_eq!(alarm["source"], source.api_slug());
                    let pair = |on: bool| serde_json::json!([u64::from(on), u64::from(on)]);
                    assert_eq!(alarm["counts"]["held_keys"], pair(held));
                    assert_eq!(alarm["counts"]["t14_rebuild"], pair(corrupt));
                    assert!(alarm["counts"].get("store_disabled").is_none());
                }
                let class = [
                    "newer",
                    "unknown",
                    "undecodable",
                    "unbindable",
                    "known_corrupt",
                ]
                .iter()
                .position(|class| *class == kind);
                if let Some(class) = class {
                    assert_eq!(
                        counts.durable_held[class],
                        u64::from(reachable && !corrupt),
                        "{source:?}/{corrupt}/{bypass}"
                    );
                    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
                } else {
                    assert_eq!(counts.durable_held, [0; 7]);
                }
                assert_eq!(counts.restored, 0);
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }
}

/// C1: a store this process does not own is disabled for the process with
/// ONE store-level alarm on the `local_resources` carrier; a newer-format
/// record in it is neither held nor rebuilt (memory-only, pre-#806).
#[test]
fn foreign_owned_store_alarms_once_and_holds_nothing() {
    struct OwnUid;
    impl Drop for OwnUid {
        fn drop(&mut self) {
            store::test_hooks::set_uid(None);
        }
    }
    let root = crate::test_scratch::private_dir("ottto-dt-foreign-owner");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let index_path = root.join("index.json");
    let namespace = Scope("foreign-owner".into());
    let key = "/synthetic/foreign-owner.jsonl";
    let cert_path = root.join("certificate.jsonl");
    std::fs::write(&cert_path, b"{}\n").unwrap();
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let pending = PendingRecord {
        binding: Binding {
            source: ds,
            key: store::key_digest(ds, key),
            context: [0; 32],
            scope: [0; 32],
            entry: [0; 32],
        },
        certificate: certificate(&cert_path, &namespace),
        body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
        allowlist: codec::allowlist_digest(source),
    };
    disk.write_after_save(lock, 1, 0, vec![pending]).unwrap();
    let record_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&record_path).unwrap();
    bytes[8..10].copy_from_slice(&(store::FORMAT_VERSION + 1).to_le_bytes());
    std::fs::write(&record_path, &bytes).unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(
        cache.durable_hold(source, key).is_some(),
        "control: U holds"
    );
    let _own = OwnUid;
    // SAFETY: geteuid has no preconditions.
    store::test_hooks::set_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1)));
    let fresh = SharedCache::default();
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        for _ in 0..2 {
            fresh.durable_begin_pass(source, &index_path, &namespace, false);
            assert_eq!(fresh.durable_hold(source, key), None);
            fresh.durable_alarm(source);
        }
    });
    assert_eq!(alarms.len(), 1, "one store-level alarm");
    let counts = &alarms[0]["counts"];
    assert_eq!(counts["store_disabled"], "foreign_owner");
    assert_eq!(counts["held_keys"], serde_json::json!([0, 0]));
    assert_eq!(counts["t14_rebuild"], serde_json::json!([0, 0]));
    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(root);
}

/// Lead B (#829): a production post-save that skipped the per-pass setup
/// never wipes valid records, even for keys the index does not hold. With
/// the setup, ordinary GC keeps an indexed but undecided key and collects
/// only the absent key's record (the control proving GC ran).
#[test]
fn save_without_per_pass_setup_keeps_valid_records() {
    let root = crate::test_scratch::private_dir("ottto-dt-no-setup-save");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let index_path = root.join("index.json");
    let namespace = Scope("no-setup".into());
    let transcript = root.join("t.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let context = store::context_digest(&namespace.0, None);
    let (indexed, absent) = ("/synthetic/indexed.jsonl", "/synthetic/absent.jsonl");
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let pending = [indexed, absent]
        .iter()
        .map(|key| PendingRecord {
            binding: Binding {
                source: ds,
                key: store::key_digest(ds, key),
                context,
                scope: [0; 32],
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate(&transcript, &Scope("no-setup-file".into())),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist: codec::allowlist_digest(source),
        })
        .collect();
    assert_eq!(
        disk.write_after_save(lock, 1, 0, pending).unwrap().written,
        2
    );
    let path = |key: &str| {
        let hex = store::key_digest(ds, key)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        disk.dir().join(format!("{hex}.rec"))
    };
    let before = [indexed, absent].map(|key| std::fs::read(path(key)).unwrap());
    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!(
        {"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}
    ))
    .unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(indexed.into(), entry);
    for empty in [true, false] {
        let saved = if empty {
            ScanIndex::default()
        } else {
            index.clone()
        };
        let cache = SharedCache::default();
        crate::snapshots::durable_after_save(&cache, &root, source, &saved);
        assert!(
            cache.durable_counters(source).is_none(),
            "no slot, no store"
        );
        let after = [indexed, absent].map(|key| std::fs::read(path(key)).unwrap());
        assert_eq!(after, before, "empty_index={empty}");
    }
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    crate::snapshots::durable_after_save(&cache, &root, source, &index);
    assert_eq!(std::fs::read(path(indexed)).unwrap(), before[0]);
    assert!(!path(absent).exists());
    let (_, disk_counters) = cache.durable_counters(source).unwrap();
    assert_eq!(disk_counters.gc_records_deleted, 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn v1_bootstrap_validates_each_original_binding_input_and_keeps_failed_rewrites() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for arm in [
            "equal",
            "file_scope",
            "namespace",
            "account",
            "identity",
            "entry",
            "generation",
            "counting",
        ] {
            if arm == "counting" && source != SnapshotSource::Codex {
                continue;
            }
            let root = crate::test_scratch::private_dir("ottto-dt-v1-bindings");
            let lock = test_locks::hold(&root);
            let path = root.join("session.jsonl");
            if source == SnapshotSource::ClaudeCode {
                native_fixture(&path);
            } else {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            }
            let key = local_index_key(&path);
            let index_path = root.join("index.json");
            let namespace = Scope("v1-bindings".into());
            let scope = Scope("v1-file-scope".into());
            let mut index = ScanIndex::default();
            index.files.insert(key.clone(),serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"real-native"})).unwrap());
            index.save(&index_path).unwrap();
            let interp = Interpretation::of(source, &key, &index, false, &namespace);
            let ds = durable_source(source).unwrap();
            let mut binding = expected(ds, source, &key, &scope, &index, &interp, None)
                .unwrap()
                .binding;
            binding.scope = scope_for(
                ds,
                source,
                &scope,
                &index,
                &interp,
                1,
                &codec::allowlist_digest(source),
            );
            let (reduction, _) = native_record_of(&path, &scope, source);
            let pending = PendingRecord {
                binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(source),
            };
            let bytes = store::tests::pinned_v1_bytes(&pending, index.generation);
            let dir = store::store_dir_for_index(&index_path);
            std::fs::create_dir_all(&dir).unwrap();
            let disk = dir.join(format!(
                "{}.rec",
                pending
                    .binding
                    .key
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            std::fs::write(&disk, &bytes).unwrap();
            std::fs::set_permissions(&disk, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            let mut changed_namespace = namespace.clone();
            let mut changed_scope = scope.clone();
            match arm {
                "file_scope" => changed_scope.0.push_str("changed"),
                "namespace" => changed_namespace.0.push_str("changed"),
                "account" => index.active_upload_context_fingerprint = Some("changed".into()),
                "identity" => index.claude_request_identity_contract = Some("changed".into()),
                "entry" => index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .source_file_fingerprint
                    .push_str("changed"),
                "generation" => index.generation = 0,
                _ => {}
            }
            let mut changed = Interpretation::of(source, &key, &index, false, &changed_namespace);
            if arm == "counting" {
                changed.counting_view = "changed".into();
            }
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &changed_namespace, false);
            let result = cache
                .durable_restore(
                    source,
                    &key,
                    &path,
                    &changed_scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &changed,
                )
                .into_test_option();
            assert_eq!(result.is_some(), arm == "equal", "{source:?} {arm}");
            assert_eq!(
                std::fs::read(&disk).unwrap(),
                bytes,
                "bootstrap never eagerly replaces"
            );
            if let Some(taken) = result {
                assert_eq!(
                    codec::encode(
                        &taken.retained.state,
                        store::RECORD_BYTES,
                        jsonl_line_cap() as u64
                    )
                    .unwrap(),
                    pending.body
                );
                // A failed format-only write leaves v1 authoritative even after GC.
                store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
                    Err(std::io::Error::other("injected"))
                })));
                let mut v2 = pending.clone();
                v2.binding = expected(ds, source, &key, &scope, &index, &interp, None)
                    .unwrap()
                    .binding;
                let mut disk_store = DurableTailStore::new(dir.clone(), ds);
                let receipt = disk_store
                    .write_after_save(lock, index.generation, 0, vec![v2])
                    .unwrap();
                assert_eq!(
                    receipt.written, 1,
                    "the byte-identical survivor is a reconciled receipt"
                );
                assert_eq!(disk_store.counters().receipt_reconciled, 1);
                store::test_hooks::set_before_rename(None);
                cache.durable_note_scope(source, &key, &scope);
                cache.durable_gc(lock, source, &index).unwrap();
                assert_eq!(std::fs::read(&disk).unwrap(), bytes);
                // An ordinary replacement may exceed an unchanged record/store
                // budget. It must not delete the still-authoritative v1 image.
                let mut over_budget = pending.clone();
                over_budget.binding = expected(ds, source, &key, &scope, &index, &interp, None)
                    .unwrap()
                    .binding;
                over_budget.body.resize(store::RECORD_BYTES, 0);
                let receipt = disk_store
                    .write_after_save(lock, index.generation, 0, vec![over_budget])
                    .unwrap();
                assert_eq!(receipt.budget_refused, 1);
                assert_eq!(receipt.written, 0);
                cache.durable_gc(lock, source, &index).unwrap();
                assert_eq!(std::fs::read(&disk).unwrap(), bytes);
                let restart = SharedCache::default();
                restart.durable_begin_pass(source, &index_path, &namespace, false);
                assert!(restart
                    .durable_restore(
                        source,
                        &key,
                        &path,
                        &scope,
                        &mut File::open(&path).unwrap(),
                        &index,
                        &interp
                    )
                    .into_test_option()
                    .is_some());
            } else {
                let (counts, _) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    counts.ineligible.values().sum::<u64>(),
                    1,
                    "{source:?} {arm}"
                );
            }
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// The same configured counting view can acquire different decisions: the
/// immutable header, not the current view, decides Legacy versus V2.
#[test]
fn v1_counting_provenance_comes_from_each_decoded_reduction() {
    use codex_counting_version::{AckEvidence, TestCutover};
    for (timestamp, evidence, version) in [
        ("1969-01-01T00:00:00Z", AckEvidence::None, 1),
        ("2026-10-07T00:00:00Z", AckEvidence::None, 2),
        ("2026-10-07T00:00:00Z", AckEvidence::LegacyAcked, 1),
    ] {
        let _cutover = TestCutover::set(0);
        let root = crate::test_scratch::private_dir("ottto-dt-v1-counting");
        let path = root.join("rollout.jsonl");
        std::fs::write(&path,serde_json::json!({"type":"session_meta","payload":{"id":"019fa111-2222-7333-8444-555555555555","timestamp":timestamp}}).to_string()+"\n").unwrap();
        let source = SnapshotSource::Codex;
        let scope = Scope("counting".into());
        let mut parser = OwnedJsonlParser::new(
            File::open(&path).unwrap(),
            &path,
            source,
            apply_codex_line,
            None,
            None,
            None,
            false,
            true,
        )
        .unwrap();
        codex_counting_version::configure(&mut parser.accumulator, evidence, Some(0));
        parser
            .prepare_acquisition(None, &scope, None, 1_800_000_000)
            .unwrap();
        while !parser.step().unwrap() {}
        let reduction = parser.durable_test_reduction_copy();
        let body = codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
        let key = local_index_key(&path);
        let namespace = Scope("counting-namespace".into());
        let index_path = root.join("index.json");
        let mut index = ScanIndex::default();
        let mut entry: ScanIndexEntry=serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"native-owned"})).unwrap();
        if evidence == AckEvidence::LegacyAcked {
            entry.last_snapshot_fingerprint = Some("prior-Legacy-ACK".into());
        }
        index.files.insert(key.clone(), entry);
        index.save(&index_path).unwrap();
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        assert_eq!(
            interpretation.counting_view,
            if evidence == AckEvidence::None {
                "0:none"
            } else {
                "0:legacy_acked"
            }
        );
        let pending = PendingRecord {
            binding: expected(
                DurableSource::Codex,
                source,
                &key,
                &scope,
                &index,
                &interpretation,
                Some((1, codec::allowlist_digest(source))),
            )
            .unwrap()
            .binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(source),
        };
        let bytes = store::tests::pinned_v1_bytes(&pending, 1);
        let lock = test_locks::hold(&root);
        let dir = store::store_dir_for_index(&index_path);
        std::fs::create_dir_all(&dir).unwrap();
        let disk = dir.join(format!(
            "{}.rec",
            pending
                .binding
                .key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::write(&disk, &bytes).unwrap();
        std::fs::set_permissions(&disk, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let mut store = DurableTailStore::new(dir.clone(), DurableSource::Codex);
        let old = match store.read(&pending.binding.key, &pending.allowlist) {
            ReadOutcome::Found(r) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(old.format, 1);
        let fact = codec::decode(&old.record.body, source)
            .unwrap()
            .counting()
            .unwrap();
        assert_eq!(fact.0, Some(0));
        assert_eq!(fact.1, version);
        if crate::heap_layout_bound::layout_supported() {
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let restored = cache
                .durable_restore(
                    source,
                    &key,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &interpretation,
                )
                .into_test_option()
                .expect("v1 maps without content acquisition");
            assert_eq!(restored.retained.state.durable_counting(), Some(fact));
            cache.insert(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint: restored.retained.checkpoint,
                    reduction: Some(restored.retained.state),
                    released: None,
                    unsealed: false,
                },
                0,
            );
            cache.durable_note_selection(&key, &index.files[&key].source_file_fingerprint);
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let next = match store.read(&pending.binding.key, &pending.allowlist) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert_eq!(next.format, store::FORMAT_VERSION);
            let restart = SharedCache::default();
            restart.durable_begin_pass(source, &index_path, &namespace, false);
            let second = restart
                .durable_restore(
                    source,
                    &key,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &interpretation,
                )
                .into_test_option()
                .expect("second restart");
            assert_eq!(second.retained.state.durable_counting(), Some(fact));
            // A record whose old pinned binding proves the configured cutover
            // but whose own decoded cutover disagrees is R29, never mapped.
            let _new_cutover = TestCutover::set(1);
            let changed = Interpretation::of(source, &key, &index, false, &namespace);
            let mut disagreement = pending.clone();
            disagreement.binding = expected(
                DurableSource::Codex,
                source,
                &key,
                &scope,
                &index,
                &changed,
                Some((1, pending.allowlist)),
            )
            .unwrap()
            .binding;
            std::fs::write(
                &disk,
                store::tests::pinned_v1_bytes(&disagreement, index.generation),
            )
            .unwrap();
            let refused = SharedCache::default();
            refused.durable_begin_pass(source, &index_path, &namespace, false);
            assert!(refused
                .durable_restore(
                    source,
                    &key,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &changed
                )
                .into_test_option()
                .is_none());
            assert_eq!(
                refused
                    .durable_counters(source)
                    .unwrap()
                    .0
                    .ineligible
                    .get("scope"),
                Some(&1)
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn compressed_record_refuses_before_certificate_restore_or_body_decode() {
    let root = crate::test_scratch::private_dir("zst-record-refusal");
    let plain = root.join("plain.jsonl");
    std::fs::write(&plain, b"{\"n\":1}\n").unwrap();
    let scope = Scope("fixture".into());
    let compressed = root.join("rollout.jsonl.zst");
    let key = local_index_key(&compressed);
    let binding = Binding {
        source: DurableSource::Codex,
        key: store::key_digest(DurableSource::Codex, &key),
        context: [0; 32],
        scope: [0; 32],
        entry: [0; 32],
    };
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let contract_index = ScanIndex::default();
    let contract = Interpretation::of(SnapshotSource::Codex, &key, &contract_index, false, &scope);
    let record = store::DurableRecord {
        format: store::FORMAT_VERSION,
        record: PendingRecord {
            binding,
            certificate: certificate(&plain, &scope),
            body: Vec::new(),
            allowlist: [0; 32],
        },
        index_generation: 1,
    };
    let mut held = File::open(&plain).unwrap();
    codex_zst_refusal_tests::assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(matches!(
            SharedCache::default().durable_restore_record(
                SnapshotSource::Codex,
                &record,
                &expected,
                &compressed,
                &scope,
                &mut held,
                &contract
            ),
            Err(Failure::NotRederived(_))
        ));
    });
    // #830's wrapper rechecks holds on a restore miss. The compressed
    // refusal must precede that record IO too, not just restore_known.
    let lock = test_locks::hold(&root);
    let index_path = root.join("index.json");
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::Codex,
    );
    disk.write_after_save(lock, 1, 0, vec![record.record.clone()])
        .unwrap();
    let record_path = disk.dir().join(format!(
        "{}.rec",
        expected
            .binding
            .key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let before_bytes = std::fs::read(&record_path).unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::Codex;
    cache.durable_begin_pass(source, &index_path, &scope, false);
    let index = ScanIndex::default();
    let interpretation = Interpretation::of(source, "fixture", &index, false, &scope);
    let before_counters = cache.durable_counters(source).unwrap();
    let before_offset = std::io::Seek::stream_position(&mut held).unwrap();
    codex_zst_refusal_tests::assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(matches!(
            cache.durable_restore(
                source,
                &key,
                &compressed,
                &scope,
                &mut held,
                &index,
                &interpretation
            ),
            RestoreOutcome::Miss
        ));
    });
    assert_eq!(cache.durable_counters(source).unwrap(), before_counters);
    assert_eq!(
        std::io::Seek::stream_position(&mut held).unwrap(),
        before_offset
    );
    assert_eq!(std::fs::read(record_path).unwrap(), before_bytes);
    std::fs::remove_dir_all(root).unwrap();
}

/// Real guard + native scan: repeated receipt failure cannot outlive a quiet
/// sampled obligation. Existing audit debt keeps this file discoverable past W.
#[test]
fn receipt_retry_bound_reads_growth_after_quiet_window_and_restart_is_idle() {
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::ScratchDir::new("receipt-growth-quiet");
    let lock = test_locks::hold(&root);
    let _clear = ClearWriteFaults;
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let namespace = Scope("receipt-growth".into());
    let index_path = root.join("index.json");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, true);
    let run = |cache: Arc<SharedCache>, index, at: &str| {
        let mut scan = OwnedSourceScan::new(
            source,
            std::slice::from_ref(&sessions),
            index,
            at,
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        for _ in 0..10000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("native scan did not complete")
    };
    let (index, first) = run(cache.clone(), ScanIndex::default(), "2026-10-29T12:00:00Z");
    assert_eq!(first.snapshots.len(), 1);
    let append = |n| {
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .replace("req-dt-owed", &format!("req-growth-{n}"))
            .replace("msg-dt-owed", &format!("msg-growth-{n}"));
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
            "{text}"
        )
        .unwrap();
    };
    append(1);
    let (mut index, tail) = run(cache.clone(), index, "2026-10-29T12:00:00Z");
    assert_eq!(
        tail.snapshots[0].input_tokens, 200,
        "no prefix duplication on real Tail"
    );
    assert!(
        index.files[&key].has_unverified_source(),
        "real sampled discoverability premise"
    );
    let mut binding = store::tests::binding("account", "scope", ("fp-a", None));
    binding.key = store::key_digest(ds, &key);
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        let cert = store::tests::certificate(&path);
        slot.store
            .write_after_save(
                lock,
                1,
                0,
                vec![store::tests::pending(binding.clone(), cert.clone(), 1)],
            )
            .unwrap();
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            Err(std::io::Error::other("rename EIO"))
        })));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| {
            Err(std::io::Error::other("unlink EIO"))
        })));
        slot.store
            .write_after_save(
                lock,
                2,
                0,
                vec![store::tests::pending(binding.clone(), cert, 2)],
            )
            .unwrap();
        assert!(slot.store.receipt_pending(&binding.key));
    }
    append(2);
    let before_disk = store_snapshot(&store::store_dir_for_index(&index_path));
    let ((held, scan), events) = crate::local_resource_diagnostics::capture(|| {
        run(cache.clone(), index, "2026-10-29T12:00:00Z")
    });
    assert!(scan.snapshots.is_empty());
    assert!(events.iter().all(
        |e| e["counts"]["sampled_acquisition"]["completed_native_bytes"]
            .as_u64()
            .unwrap_or(0)
            == 0
    ));
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .slot(ds)
            .as_ref()
            .unwrap()
            .store
            .disabled(),
        None
    );
    index = held;
    // Preserve genuine sampled debt; move its existing deadline past due as in
    // the native audit fixtures. The source mtime is now more than W old.
    index
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(1);
    std::fs::File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1791370000)),
        )
        .unwrap();
    let (_, oracle) = run(
        Arc::new(SharedCache::default()),
        index.clone(),
        "2028-10-29T12:00:00Z",
    );
    assert_eq!(
        oracle.snapshots.len(),
        1,
        "independent real Full under the same persisted audit obligation"
    );
    let expected_body = serde_json::to_value(&oracle.snapshots).unwrap();
    let ((mut index, caught), events) = crate::local_resource_diagnostics::capture(|| {
        run(cache.clone(), index, "2028-10-29T12:00:00Z")
    });
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .slot(ds)
            .as_ref()
            .unwrap()
            .store
            .disabled(),
        Some("receipt_unreconciled")
    );
    assert_eq!(caught.snapshots.len(), 1);
    assert_eq!(caught.snapshots[0].input_tokens, 300);
    assert_eq!(caught.snapshots[0].output_tokens, 30);
    let reads = events
        .iter()
        .filter_map(|e| e["counts"].get("sampled_acquisition"))
        .collect::<Vec<_>>();
    assert_eq!(
        reads
            .iter()
            .filter_map(|r| r["full_selections"].as_u64())
            .sum::<u64>(),
        1
    );
    assert_eq!(
        reads
            .iter()
            .filter_map(|r| r["completed_native_bytes"].as_u64())
            .sum::<u64>(),
        std::fs::metadata(&path).unwrap().len()
    );
    let witness = snapshot_upload_body_witness(&caught.snapshots[0]);
    assert_eq!(
        serde_json::to_value(&caught.snapshots).unwrap(),
        expected_body,
        "exact independent Full body, no repeated prefix"
    );
    assert_eq!(witness, snapshot_upload_body_witness(&oracle.snapshots[0]));
    assert_eq!(
        store_snapshot(&store::store_dir_for_index(&index_path)),
        before_disk
    );
    store::test_hooks::set_before_rename(None);
    store::test_hooks::set_before_unlink(None);
    index.save(&index_path).unwrap();
    drop(cache);
    let restarted = Arc::new(SharedCache::default());
    restarted.durable_begin_pass(source, &index_path, &namespace, true);
    let ((index, idle), events) = crate::local_resource_diagnostics::capture(|| {
        run(
            restarted,
            ScanIndex::load(&index_path).unwrap(),
            "2028-10-29T12:00:00Z",
        )
    });
    assert!(
        idle.snapshots.is_empty(),
        "quiet restart publishes no duplicate prefix"
    );
    assert!(events.iter().all(
        |e| e["counts"]["sampled_acquisition"]["completed_native_bytes"]
            .as_u64()
            .unwrap_or(0)
            == 0
    ));
    assert!(!index
        .files
        .get(&key)
        .is_some_and(ScanIndexEntry::has_unverified_source));
}
