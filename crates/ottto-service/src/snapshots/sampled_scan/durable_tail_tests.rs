//! GC against a committed index much larger than the store (F3, F5).
use super::*;
use crate::locked_state_dir::test_locks;
use crate::transcript_acquisition::ReadPlan;
use std::io::Read;

const INDEX_KEYS: usize = 20_000;

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
    store.write_after_save(lock, 1, pending).unwrap();

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
        SnapshotSource::ClaudeCode => apply_claude_code_line,
        SnapshotSource::Pi => apply_pi_line,
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

#[test]
fn pi_stripped_section_refuses_restore_and_preserves_the_record() {
    use crate::durable_tail_codec::{Dec, Durable};
    let root = crate::test_scratch::private_dir("ottto-dt-pi-held");
    let lock = test_locks::hold(&root);
    let path = root.join("pi.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"type\":\"message\",\"timestamp\":\"2026-10-20T10:00:00Z\",",
            "\"message\":{\"role\":\"assistant\",\"responseId\":\"fixture-response\",",
            "\"model\":\"fixture-model\",\"usage\":{\"input\":10,\"output\":3}}}\n"
        ),
    )
    .unwrap();
    let source = SnapshotSource::Pi;
    let namespace = Scope("pi-held".into());
    let scope = Scope("pi-held-file".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let binding = expected(
        DurableSource::Pi,
        source,
        &key,
        &scope,
        &index,
        &interpretation,
    )
    .unwrap()
    .binding;
    let (reduction, _) = native_record_of(&path, &scope, source);
    let body = codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
    let mut d = Dec::new(&body);
    CachedJsonlReduction::take(&mut d).unwrap();
    codec::Rederive::take(&mut d).unwrap();
    let prefix = body.len() - d.remaining();
    let mut store =
        DurableTailStore::new(store::store_dir_for_index(&index_path), DurableSource::Pi);
    store
        .write_after_save(
            lock,
            index.generation,
            vec![PendingRecord {
                binding: binding.clone(),
                certificate: certificate(&path, &scope),
                body: body[..prefix].to_vec(),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
    for _ in 0..2 {
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
                &interpretation
            )
            .into_test_option()
            .is_none());
        // The store's structural verify refuses it (T14): read Full once and
        // rebuilt after the save, never decoded as an empty ledger.
        let (counts, disk) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.refused_record, 1);
        assert_eq!(counts.restored, 0);
        assert_eq!(disk.t14_rebuild, 1);
        assert_eq!(disk.records_invalidated, 0);
        assert_eq!(
            store.read(&binding.key, &codec::allowlist_digest(source)),
            ReadOutcome::Refused(store::Refusal::Corrupt),
            "T14 is preserved until its rebuild, never deleted"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

/// A Pi ledger past `PI_LEDGER_MAX_KEYS` refuses on the post-save write and
/// counts once, with no record. The 8 MiB RAM entry bound refuses such a
/// reduction before it is retained (one tree node charged per key), so only
/// this test cache widens it.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_ledger_cap_refusal_counts_on_the_write_path() {
    let root = crate::test_scratch::private_dir("ottto-dt-pi-cap");
    let lock = test_locks::hold(&root);
    let path = root.join("pi.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"type\":\"message\",\"timestamp\":\"2026-10-20T10:00:00Z\",",
            "\"message\":{\"role\":\"assistant\",\"responseId\":\"fixture-response\",",
            "\"model\":\"fixture-model\",\"usage\":{\"input\":10,\"output\":3}}}\n"
        ),
    )
    .unwrap();
    let source = SnapshotSource::Pi;
    let namespace = Scope("pi-cap".into());
    let scope = Scope("pi-cap-file".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    let (mut reduction, checkpoint) = native_record_of(&path, &scope, source);
    codec::overfill_pi_ledger(&mut reduction);
    let cache = SharedCache::default();
    *cache.inner.lock().unwrap() =
        crate::transcript_cache::TranscriptCache::with_entry_limit(512 << 20, 256 << 20);
    cache.durable_begin_pass(source, &index_path, &namespace, false);
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
    let receipt = cache
        .durable_write_after_save(lock, source, &index)
        .unwrap();
    let (counts, disk) = cache.durable_counters(source).unwrap();
    let summary = counts.summary(source, &disk);
    println!("pi_cap: {summary}");
    assert_eq!(counts.retained_refused_pi_ledger_cap, 1);
    assert_eq!(counts.not_persisted.get("pi_ledger_cap"), Some(&1));
    assert_eq!((receipt.written, disk.disk_records), (0, 0));
    assert!(summary.contains(" retained_refused_pi_ledger_cap=1 "));
    assert!(!Counters::default()
        .summary(SnapshotSource::Codex, &disk)
        .contains("pi_ledger_cap"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pi_uses_shared_content_only_ctime_adoption_and_store_slots() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_scratch::private_dir("ottto-pi-ctime");
    let path = root.join("pi.jsonl");
    std::fs::write(&path, b"{\"type\":\"session\",\"id\":\"fixture\"}\n").unwrap();
    let candidate = || CandidateFile {
        physical_identity: None,
        scan_root: root.clone(),
        path: path.clone(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    };
    let source = SnapshotSource::Pi;
    let mut first = candidate();
    let (_, stat) = open_candidate_file_stat(source, &mut first).unwrap();
    assert_eq!(
        first.fingerprint_changed_nanos,
        stat.unwrap().changed_unix_nanos()
    );
    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes": first.size_bytes, "modified_unix_seconds": first.modified_unix_seconds,
        "modified_unix_nanos": first.modified_unix_nanos,
        "opened_changed_nanos":first.fingerprint_changed_nanos,
        "opened_birth_nanos":first.fingerprint_birth_nanos,
        "source_file_fingerprint":"fp"
    }))
    .unwrap();
    let files = BTreeMap::from([(local_index_key(&path), entry)]);
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let mut after = candidate();
    let (mut file, stat) = open_candidate_file_stat(source, &mut after).unwrap();
    assert_eq!(after.size_bytes, first.size_bytes);
    assert_eq!(after.modified_unix_nanos, first.modified_unix_nanos);
    let adopted = adopt_stored_changed_time(&mut after, &files, stat, &mut file).unwrap();
    let exercised = first.fingerprint_birth_nanos != 0
        && stat.unwrap().changed_unix_nanos() != first.fingerprint_changed_nanos;
    // APFS has birth times and chmod moves ctime: macOS never skips this control.
    assert!(
        exercised || !cfg!(target_os = "macos"),
        "chmod must move ctime of a born file"
    );
    if !exercised {
        println!("SKIP pi ctime adoption: no birth time, or chmod left ctime unchanged");
    } else {
        assert_eq!(
            adopted.as_deref(),
            Some(first.opened_object_identity.as_str())
        );
        assert_eq!(
            after.fingerprint_changed_nanos,
            first.fingerprint_changed_nanos
        );
    }
    // A changed mtime remains a reread input on exactly the same path.
    let mut moved = after.clone();
    moved.modified_unix_nanos += 1;
    assert!(
        adopt_stored_changed_time(&mut moved, &files, stat, &mut file)
            .unwrap()
            .is_none()
    );
    let cache = SharedCache::default();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        cache.durable_begin_pass(
            source,
            &root.join(format!("{}.json", source.api_slug())),
            &Scope("slots".into()),
            false,
        );
        assert!(cache.durable_counters(source).is_some());
        let _ = rederive_head_bytes_total(source);
    }
    let _ = std::fs::remove_dir_all(root);
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
                disk.write_after_save(lock, 1, vec![record(store_key), record(absent_key)])
                    .unwrap();
                let hex = |key: store::Digest32| {
                    key.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                let absent_path = disk.dir().join(format!("{}.rec", hex(absent_key)));
                assert!(absent_path.exists());
                let record_path = disk.dir().join(format!("{}.rec", hex(store_key)));
                let mut bytes = std::fs::read(&record_path).unwrap();
                if kind == "none" {
                    std::fs::remove_file(&record_path).unwrap();
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
                    bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
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
                    assert_eq!(counts.durable_held, [0; 5]);
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
    disk.write_after_save(lock, 1, vec![pending]).unwrap();
    let record_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&record_path).unwrap();
    bytes[8..10].copy_from_slice(&2_u16.to_le_bytes());
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
    assert_eq!(disk.write_after_save(lock, 1, pending).unwrap().written, 2);
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

/// A copy above the ordinary RAM entry bound never reaches the durable writer.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_retention_bound_refusal_counts_bytes_without_a_record() {
    let root = crate::test_scratch::private_dir("ottto-dt-pi-retention");
    let lock = test_locks::hold(&root);
    let path = root.join("pi.jsonl");
    std::fs::write(&path, b"{\"type\":\"session\",\"id\":\"fixture\"}\n").unwrap();
    let source = SnapshotSource::Pi;
    let scope = Scope("pi-retention".into());
    let mut parser = OwnedJsonlParser::new(
        File::open(&path).unwrap(),
        &path,
        source,
        apply_pi_line,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    parser
        .prepare_acquisition(None, &scope, None, 1_800_000_000)
        .unwrap();
    while !parser.step().unwrap() {}
    for n in 0..8_000 {
        parser
            .accumulator
            .seen_pi_usage_keys
            .insert(format!("{n:064x}"), PiUsageDedupState::default());
    }
    let charge = crate::heap_layout_bound::completed_bound(&parser.accumulator, usize::MAX)
        .unwrap()
        + std::mem::size_of::<CachedJsonlReduction>()
        - std::mem::size_of::<SnapshotAccumulator>();
    assert!(parser
        .retention_bound(crate::transcript_cache::ENTRY_BYTES)
        .is_none());
    assert!(charge > crate::transcript_cache::ENTRY_BYTES);
    let before: [u64; 2] =
        pi_retention_bound(|totals| std::array::from_fn(|i| totals[i].load(Ordering::Relaxed)));
    let completed = parser
        .retain_reduction(
            &scope,
            1_800_000_000,
            sampled_scan::RetainBudget::granted_unclassified(usize::MAX),
        )
        .unwrap()
        .unwrap();
    assert!(completed.reduction.is_none());
    let after: [u64; 2] =
        pi_retention_bound(|totals| std::array::from_fn(|i| totals[i].load(Ordering::Relaxed)));
    assert_eq!(after, [before[0] + 1, before[1] + charge as u64]);
    assert!(after[1] > 0);
    let cache = SharedCache::default();
    let index_path = root.join("index.json");
    cache.durable_begin_pass(source, &index_path, &scope, false);
    assert!(!cache.insert_admitted(local_index_key(&path), completed, 0));
    let mut index = ScanIndex::default();
    index.save(&index_path).unwrap();
    let receipt = cache
        .durable_write_after_save(lock, source, &index)
        .unwrap();
    let (counts, disk) = cache.durable_counters(source).unwrap();
    assert_eq!((receipt.written, disk.disk_records), (0, 0));
    let summary = counts.summary(source, &disk);
    assert!(summary.contains(&format!("not_persisted={{retention_bound:{}}}", after[0])));
    assert!(summary.contains(&format!(
        "not_persisted_bytes={{retention_bound:{}}}",
        after[1]
    )));
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        assert!(!counts.summary(source, &disk).contains("retention_bound"));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn pi_insertion_counts_claude_and_codex_cache_victims_only() {
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    let root = crate::test_scratch::private_dir("ottto-pi-cache-victims");
    let path = root.join("fixture.jsonl");
    std::fs::write(&path, b"{\"type\":\"session\",\"id\":\"fixture\"}\n").unwrap();
    let scope = Scope("pi-cache-victims".into());
    let states = [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .map(|source| native_record_of(&path, &scope, source));
    let insert = |cache: &SharedCache, key: String, source: usize, rank| {
        let (state, checkpoint) = &states[source];
        cache.insert_admitted(
            key,
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint: checkpoint.clone(),
                reduction: Some(state.clone()),
                released: Some((rank, 0)),
                unsealed: false,
            },
            0,
        )
    };
    let cache = SharedCache::default();
    for n in 0..crate::transcript_cache::CACHE_ENTRIES {
        assert!(insert(&cache, format!("resident-{n}"), n % 2, 1));
    }
    let (_, counts) = observe(|| {
        assert!(insert(&cache, "pi-first".into(), 2, 2));
        assert!(insert(&cache, "pi-second".into(), 2, 2));
        assert!(cache.take("resident-0").is_none());
        assert!(cache.take("resident-1").is_none());
        assert!(insert(&cache, "claude-control".into(), 0, 3));
    });
    assert_eq!(counts.insert_entries_evicted, 3);
    assert_eq!(counts.cache_evicted_by_pi_claude_code, 1);
    assert_eq!(counts.cache_evicted_by_pi_codex, 1);
    cache.clear();
    for n in 0..crate::transcript_cache::CACHE_ENTRIES {
        assert!(insert(&cache, format!("pi-resident-{n}"), 2, 1));
    }
    let (_, counts) = observe(|| assert!(insert(&cache, "pi-control".into(), 2, 2)));
    assert_eq!(counts.insert_entries_evicted, 1);
    assert_eq!(counts.cache_evicted_by_pi_claude_code, 0);
    assert_eq!(counts.cache_evicted_by_pi_codex, 0);
    let _ = std::fs::remove_dir_all(root);
}
