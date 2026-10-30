//! Restart fixtures for the OFF/M1 route and the dependency-gated M3 route.
use super::*;
use crate::snapshots::RestartRestoreForTest;
use crate::transcript_acquisition::ReadMode;
use std::io::Write;

#[test]
fn off_restart_keeps_native_m1_rederive_and_never_writes_new_records() {
    let _off = RestartRestoreForTest::disabled();
    off_restart_fixture(false);
}

fn off_restart_fixture(require_restore: bool) {
    if !crate::test_isolation::run_here() {
        return;
    }
    let root = crate::test_scratch::ScratchDir::new("restart-restore-off-m1");
    let lock = crate::locked_state_dir::test_locks::hold(&root);
    let path = root.join("source.jsonl");
    // A first prompt exercises main's native M1 replay. OFF must never enter
    // the bounded M3 content replay or its custody/proxy accounting.
    std::fs::write(&path, concat!(
        "{\"type\":\"user\",\"cwd\":\"/synthetic/workspace\",\"message\":{\"role\":\"user\",\"content\":\"synthetic prompt\"}}\n",
        "{\"type\":\"assistant\",\"sessionId\":\"11111111-2222-4333-8444-555555555555\",\"timestamp\":\"2026-10-07T10:00:00Z\",\"requestId\":\"request\",\"message\":{\"id\":\"message\",\"model\":\"fixture-model\",\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}}\n"
    )).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let scope = Scope("m1-file".into());
    let namespace = Scope("m1-account".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "effective_upload_body_witness_revision":3
        }))
        .unwrap(),
    );
    index.activate_effective_upload_body_witness_revision(3);
    index.save(&index_path).unwrap();
    let (native, _) = tests::native_record_of(&path, &scope, source);
    let body = codec::encode(&native, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
    assert!(codec::decode(&body, source)
        .unwrap()
        .without_rederive()
        .is_err());
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let binding = expected(ds, source, &key, &scope, &index, &interpretation, None)
        .unwrap()
        .binding;
    let mut store = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    assert_eq!(
        store
            .write_after_save(
                lock,
                index.generation,
                0,
                vec![PendingRecord {
                    acquisition: None,
                    binding,
                    certificate: tests::certificate(&path, &scope),
                    body,
                    allowlist: codec::allowlist_digest(source),
                }]
            )
            .unwrap()
            .written,
        1
    );
    drop(store);
    let record_path = store::store_dir_for_index(&index_path).join(format!(
        "{}.rec",
        store::key_digest(ds, &key)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let before = std::fs::read(&record_path).unwrap();
    let suffix = b"{\"type\":\"progress\"}\n";
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(suffix)
        .unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    // Saturate M3 credit: OFF must not consult its admission/typed extractor.
    let store::LeaseWait::Granted(mut lease) = cache.acquire_active(source, 0) else {
        panic!("fixture credit")
    };
    lease.charge(store::ACTIVE_BYTES).unwrap();
    let restored = cache.durable_restore(
        source,
        &key,
        &path,
        &scope,
        &mut File::open(&path).unwrap(),
        &index,
        &interpretation,
    );
    let counts = cache.durable_counters(source).unwrap().0;
    assert!(
        counts.rederive_head_bytes > 0,
        "native M1 rederivation still reads its bounded head"
    );
    assert_eq!(counts.rederive_budget, [0, 0]);
    assert_eq!(counts.active_bound, [[0, 0]; 3]);
    match restored {
        RestoreOutcome::M1Restored(taken) => {
            assert!(taken.durable.is_empty());
            let restored_body = codec::encode(
                &taken.retained.state,
                store::BODY_BYTES,
                jsonl_line_cap() as u64,
            )
            .unwrap();
            assert_eq!(
                restored_body,
                codec::encode(&native, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap()
            );
            let mut parser = OwnedJsonlParser::new(
                File::open(&path).unwrap(),
                &path,
                source,
                apply_claude_code_line,
                None,
                None,
                None,
                false,
                true,
            )
            .unwrap();
            assert_eq!(
                parser
                    .prepare_acquisition_owned(Some(taken), &scope, None, 1_800_000_001)
                    .unwrap_or_else(|_| panic!("M1 preparation")),
                ReadMode::Tail
            );
            while !parser.step().unwrap() {}
            assert_eq!(parser.reader.consumed_bytes(), suffix.len() as u64);
        }
        RestoreOutcome::Miss(MissClass::BudgetRefused) => {
            assert!(
                !require_restore,
                "qualified M1 warm restore must still restore"
            );
            assert!(
                !crate::heap_layout_bound::layout_supported(),
                "main's unsupported-layout admission only"
            );
        }
        _ => panic!("OFF must follow main M1 restore/admission, never M3 deferral"),
    }
    lease.release();
    for generation_ahead in [false, true] {
        let mut changed = index.clone();
        if generation_ahead {
            changed.generation -= 1;
        } else {
            changed.files.get_mut(&key).unwrap().source_file_fingerprint = "changed".into();
        }
        let interpretation = Interpretation::of(source, &key, &changed, false, &namespace);
        let result = cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &changed,
            &interpretation,
        );
        assert!(
            matches!(result, RestoreOutcome::Miss(MissClass::Failure(Failure::Ineligible(reason)))
            if reason == if generation_ahead { store::Ineligible::GenerationAhead } else { store::Ineligible::EntryChanged })
        );
    }
    assert!(cache
        .durable_write_after_save(lock, source, &index)
        .is_none());
    cache.durable_gc(lock, source, &index).unwrap();
    assert_eq!(
        std::fs::read(&record_path).unwrap(),
        before,
        "no OFF successor or GC write"
    );
    let stores = cache.durable().unwrap();
    assert!(stores.retail_spent.is_empty());
    assert!(stores.key_debt.is_empty());
    assert!(stores.restore_pending.is_empty());
    assert_eq!(stores.counters.rederive_failed_first_attempt, [0; 3]);
    assert_eq!(stores.counters.restore_pending_quiet, [0; 3]);
    drop(stores);
    let (_, events) =
        crate::local_resource_diagnostics::capture(|| cache.durable_rederive_proxies(source));
    assert!(events.is_empty());
    let (counters, store) = cache.durable_counters(source).unwrap();
    assert_eq!(store.records_written, 0);
    assert!(counters
        .summary(source, &store)
        .contains("restart_restore=off"));
}

#[test]
fn on_without_discovery_is_off_and_diagnostic_counts_one_refused_request() {
    let _refused = RestartRestoreForTest::requested_without_dependency();
    assert!(!restart_restore::enabled());
    let summary =
        Counters::default().summary(SnapshotSource::ClaudeCode, &store::StoreCounters::default());
    assert!(summary.contains("restart_restore=off"));
    assert!(summary.contains("restart_restore_on_refused{reason=discovery_dependency}=1"));
    // Exercise the same restart route under the refused request, rather than
    // merely checking the boolean. The nested OFF guard restores this request.
    off_restart_fixture(false);
    assert_eq!(restart_restore::on_refused_discovery_dependency(), 1);
}

#[test]
fn off_discovery_keeps_main_predicate_and_on_adds_only_its_recovery_path() {
    let source = SnapshotSource::ClaudeCode;
    let path = Path::new("/synthetic/source.jsonl");
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(path),
        serde_json::from_value(serde_json::json!({
            "size_bytes":100,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "effective_upload_body_witness_revision":999
        }))
        .unwrap(),
    );
    let main = sampled_audit::path_requires_verification(&index.files, path);
    assert!(!main);
    for length in [1, 100, 200] {
        let _off = RestartRestoreForTest::disabled();
        assert_eq!(
            sampled_audit::path_requires_recovery(source, &index.files, path, length),
            main
        );
        let _on = RestartRestoreForTest::enabled();
        assert!(sampled_audit::path_requires_recovery(
            source,
            &index.files,
            path,
            length
        ));
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 warm cache requires qualified native heap layout"
)]
fn off_restart_restores_native_m1_to_tail_on_qualified_layout() {
    let _off = RestartRestoreForTest::disabled();
    off_restart_fixture(true);
}

#[test]
fn off_admission_keeps_main_budget_and_on_keeps_m3_custody_funded() {
    let main = crate::transcript_cache::CACHE_BYTES
        - crate::source_rotation::OVERLAP_BUDGET
        - super::super::AUDIT_AND_SCRATCH_BYTES;
    let _off = RestartRestoreForTest::disabled();
    assert_eq!(super::super::state_bytes(), main);
    let _on = RestartRestoreForTest::enabled();
    assert_eq!(super::super::state_bytes(), super::super::STATE_BYTES);
    assert!(super::super::state_bytes() < main);
}
