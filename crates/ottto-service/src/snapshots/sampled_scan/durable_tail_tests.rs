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
pub(super) fn certificate(path: &Path, scope: &Scope) -> DurableCertificate {
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

pub(super) fn native_fixture(path: &Path) {
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
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
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
    for (arm, t14) in [
        ("spent", false),
        ("too_large", false),
        ("spent", true),
        ("too_large", true),
    ] {
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
        let mut existing = record_files();
        assert_eq!(existing.len(), 1, "{arm}: c's prior record");
        drop(prior);
        if t14 {
            for (path, bytes) in &mut existing {
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
        }

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
        assert_eq!(
            cache.durable_full_hold(source, &local_index_key(&c), true),
            None
        );
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
        assert_eq!(disk.t14_rebuild_full_started, u64::from(t14));
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
        assert_eq!(disk.t14_rebuild_full_started, 0);
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
            Self::Miss(_) => None,
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
                "audit_metadata_unsupported",
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
                )
                .with_sampled_acquisition(cache.clone(), namespace);
                if bypass == "sampling_none" || bypass == "compressed" {
                    scan.sampling = None;
                }
                if bypass == "audit_metadata_unsupported" {
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
                        &mut crate::snapshots::CandidateDiscovery::new(
                            &mut ScanIndex::default(),
                            None,
                        ),
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
    bytes[8..10].copy_from_slice(&(store::FORMAT_VERSION + 1).to_le_bytes());
    std::fs::write(&record_path, &bytes).unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(
        cache
            .durable_hold(source, key, &ScanIndex::default(), &mut None)
            .is_some(),
        "control: U holds"
    );
    let _own = OwnUid;
    // SAFETY: geteuid has no preconditions.
    store::test_hooks::set_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1)));
    let fresh = SharedCache::default();
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        for _ in 0..2 {
            fresh.durable_begin_pass(source, &index_path, &namespace, false);
            assert_eq!(
                fresh.durable_hold(source, key, &ScanIndex::default(), &mut None),
                None
            );
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

/// F1 needs the real acquisition/publication seam, beyond store-only outcomes.
#[test]
fn store_io_failures_emit_cold_production_body_without_holds() {
    use std::os::unix::fs::PermissionsExt;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            store::test_hooks::set_before_access(None);
        }
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for fault in ["permission", "open", "header", "body", "restore_open"] {
            if fault == "restore_open" && !crate::heap_layout_bound::layout_supported() {
                continue;
            }
            let _reset = Reset;
            let root = crate::test_scratch::private_dir("ottto-dt-access-body");
            let lock = test_locks::hold(&root);
            let sessions = root.join("sessions");
            std::fs::create_dir(&sessions).unwrap();
            let path = sessions.join("0199f7a0-0000-7000-8000-0000000d7a11.jsonl");
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "0199f7a0-0000-7000-8000-0000000d7a11", None);
            } else {
                native_fixture(&path);
            }
            let key = local_index_key(&path);
            let index_path = root.join("index.json");
            let namespace = Scope("access-body".into());
            let run = |cache: Arc<SharedCache>, index: ScanIndex| {
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
                )
                .with_sampled_acquisition(cache, namespace.clone());
                for _ in 0..10_000 {
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(next) => scan = next,
                        OwnedSourceScanStep::Complete {
                            index,
                            scan: mut result,
                            ..
                        } => {
                            apply_upload_policy(
                                source,
                                &mut result.snapshots,
                                SnapshotUploadPolicy::default(),
                            );
                            assert!(!result.snapshots.is_empty(), "production body emitted");
                            return (index, serde_json::to_value(result.snapshots).unwrap());
                        }
                    }
                }
                panic!("scan did not finish");
            };
            let (_, cold_body) = run(Arc::new(SharedCache::default()), ScanIndex::default());
            let ds = durable_source(source).unwrap();
            let digest = store::key_digest(ds, &key);
            let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
            disk.write_after_save(
                lock,
                1,
                vec![PendingRecord {
                    binding: Binding {
                        source: ds,
                        key: digest,
                        context: [0; 32],
                        scope: [0; 32],
                        entry: [0; 32],
                    },
                    certificate: certificate(&path, &namespace),
                    body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
            let record = disk.dir().join(format!(
                "{}.rec",
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            let before = std::fs::read(&record).unwrap();
            if fault == "permission" {
                std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let denied = record.clone();
            let opens = std::rc::Rc::new(std::cell::Cell::new(0));
            let calls = opens.clone();
            store::test_hooks::set_before_access(Some(Box::new(move |path, op| {
                if path == denied && op == "open" {
                    calls.set(calls.get() + 1);
                }
                if path == denied && op == if fault == "permission" { "open" } else { fault } {
                    Err(if fault == "permission" {
                        std::io::ErrorKind::PermissionDenied.into()
                    } else {
                        std::io::Error::from_raw_os_error(libc::EIO)
                    })
                } else {
                    Ok(())
                }
            })));
            let cache = Arc::new(SharedCache::default());
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let mut index = ScanIndex::default();
            if fault == "restore_open" {
                index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"})).unwrap());
            }
            let (index, body) = run(cache.clone(), index);
            assert_eq!(body, cold_body);
            assert_eq!(
                opens.get(),
                if matches!(fault, "permission" | "restore_open") {
                    2
                } else {
                    1
                },
                "{fault}: bounded reads"
            );
            let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
                crate::snapshots::durable_after_save(&cache, &root, source, &index);
                cache.durable_begin_pass(source, &index_path, &namespace, false);
                assert_eq!(
                    cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
                    None
                );
                cache.durable_alarm(source);
            });
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0]["counts"]["store_disabled"], "record_access");
            assert_eq!(alarms[0]["counts"]["held_keys"], serde_json::json!([0, 0]));
            assert_eq!(
                alarms[0]["counts"]["t14_rebuild"],
                serde_json::json!([0, 0])
            );
            assert_eq!(
                alarms[0]["counts"]["mode_repaired"],
                serde_json::json!([
                    u64::from(fault == "permission"),
                    u64::from(fault == "permission")
                ])
            );
            let (counts, stats) = cache.durable_counters(source).unwrap();
            assert_eq!(counts.durable_held, [0; 5]);
            assert_eq!(stats.format_hold, [0; 5]);
            assert_eq!(stats.records_written, 0);
            assert_eq!(stats.gc_records_deleted + stats.gc_temps_deleted, 0);
            assert_eq!(std::fs::read(&record).unwrap(), before);
            assert_eq!(
                std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// N8: the allowance is spent even when the production write adapter never
/// receives a replacement (retention or allowlist codec refusal).
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn t14_without_retention_or_encodable_reduction_holds_on_later_passes() {
    let source = SnapshotSource::ClaudeCode;
    for arm in ["retention", "codec"] {
        let root = crate::test_scratch::private_dir("ottto-dt-unreplaced");
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let path = root.join("session.jsonl");
        native_fixture(&path);
        if arm == "codec" {
            use std::io::Write;
            let line = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555", "timestamp":"2026-10-07T10:00:01Z","requestId":"req-skill", "message":{"id":"msg-skill","role":"assistant","model":"fixture-model","content":[{"type":"tool_use","id":"tool-skill","name":"Bash","input":{"command":"cat ~/.claude/skills/pdf/SKILL.md"}}],"usage":{"input_tokens":1,"output_tokens":1}}});
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
                "{line}"
            )
            .unwrap();
        }
        let key = local_index_key(&path);
        let namespace = Scope("unreplaced".into());
        let (reduction, checkpoint) = native_record(&path, &namespace);
        if arm == "codec" {
            assert!(matches!(
                codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64),
                Err(Refuse::NonEmpty("SnapshotAccumulator.activity_skills"))
            ));
        }
        let ds = durable_source(source).unwrap();
        let digest = store::key_digest(ds, &key);
        let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        disk.write_after_save(
            lock,
            1,
            vec![PendingRecord {
                binding: Binding {
                    source: ds,
                    key: digest,
                    context: [0; 32],
                    scope: [0; 32],
                    entry: [0; 32],
                },
                certificate: certificate(&path, &namespace),
                body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
        let record = disk.dir().join(format!(
            "{}.rec",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let mut before = std::fs::read(&record).unwrap();
        *before.last_mut().unwrap() ^= 1;
        std::fs::write(&record, &before).unwrap();
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        assert_eq!(
            cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
            None
        );
        assert_eq!(cache.durable_full_hold(source, &key, true), None);
        let admitted = cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                checkpoint,
                reduction: (arm == "codec").then_some(reduction),
                released: None,
                unsealed: false,
            },
            0,
        );
        assert_eq!(admitted, arm == "codec");
        cache.durable_note_selection(&key, "fp");
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"fp"})).unwrap());
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, stats) = cache.durable_counters(source).unwrap();
        assert_eq!(stats.records_written, 0);
        assert_eq!(stats.t14_rebuild, 1);
        if arm == "codec" {
            assert_eq!(
                counts
                    .not_persisted
                    .get("SnapshotAccumulator.activity_skills"),
                Some(&1)
            );
        }
        let previous_holds = stats.format_hold[store::Refusal::Corrupt as usize];
        for n in 1..=3 {
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            assert_eq!(
                cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
                (arm == "retention").then_some(store::Refusal::Corrupt)
            );
            let (counts, stats) = cache.durable_counters(source).unwrap();
            assert_eq!(stats.t14_rebuild, 1);
            assert_eq!(counts.durable_held, [0; 5]);
            assert_eq!(
                stats.format_hold[store::Refusal::Corrupt as usize],
                previous_holds + n
            );
        }
        assert_eq!(std::fs::read(&record).unwrap(), before);
        let _ = std::fs::remove_dir_all(root);
    }
}

pub(super) fn known_corrupt_scan(
    source: SnapshotSource,
    sessions: &Path,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    namespace: &Scope,
    at: &str,
) -> (ScanIndex, SourceScanResult, [u64; 3]) {
    let capture = claude_request_identity::captures(source);
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        source,
        &[sessions.to_path_buf()],
        index,
        at,
        365,
        100,
        false,
        None,
        &[],
        false,
        capture,
    )
    .with_sampled_acquisition(cache.clone(), namespace.clone());
    assert!(scan.sampling.as_ref().unwrap().audit_metadata_supported);
    assert_eq!(scan.claude_request_identity_capture, capture);
    let mut reads = [0; 3];
    for _ in 0..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => {
                if let Some(context) = next.sampling.as_ref() {
                    reads = [
                        context.full_files as u64,
                        context.tail_files as u64,
                        context.native_bytes,
                    ];
                }
                scan = next;
            }
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
                finalize_scan_after_policy(source, &mut scan, &mut index);
                index.record_accepted_snapshot_fingerprints(
                    &scan
                        .snapshots
                        .iter()
                        .map(|item| item.snapshot_fingerprint.clone())
                        .collect(),
                );
                return (index, scan, reads);
            }
        }
    }
    panic!("synthetic scan did not finish");
}

/// The fixture premise runs on Linux too, without requiring retained layout.
#[test]
fn known_corrupt_fixture_capture_and_audit_premises_match() {
    let root = crate::test_scratch::private_dir("ottto-known-corrupt-premises");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    native_fixture(&sessions.join("session.jsonl"));
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("known-corrupt-premises".into());
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &namespace,
        claude_request_identity::captures(source),
    );
    let (_, scan, _) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:00:00Z",
    );
    assert!(scan.census_complete);
    std::fs::remove_dir_all(root).unwrap();
}

/// B1: exercise the REAL scanner hold exit, retained Tail and eviction. A
/// healthy peer publishes, and terminal census settlement retires an absent
/// file despite the held key. The held key's accepted body is never replaced.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS retained layout"
)]
fn known_corrupt_ram_tail_then_eviction_keeps_source_census_healthy() {
    for fail_replacement in [false, true] {
        known_corrupt_replacement_case(fail_replacement);
    }
}

fn known_corrupt_replacement_case(fail_replacement: bool) {
    use std::io::Write;
    let root = crate::test_scratch::private_dir("ottto-known-corrupt-census");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let capture = claude_request_identity::captures(source);
    let namespace = Scope("known-corrupt-census".into());
    let index_path = root.join("index.json");
    let [held, peer, gone] =
        ["held", "peer", "gone"].map(|name| sessions.join(format!("{name}.jsonl")));
    for (n, path) in [&held, &peer, &gone].into_iter().enumerate() {
        native_fixture(path);
        let text = std::fs::read_to_string(path)
            .unwrap()
            .replace(
                "11111111-2222-4333-8444-555555555555",
                &format!("11111111-2222-4333-8444-{n:012}"),
            )
            .replace("req-dt-owed", &format!("req-{n}"))
            .replace("msg-dt-owed", &format!("msg-{n}"));
        std::fs::write(path, text).unwrap();
    }
    let seed = Arc::new(SharedCache::default());
    let (mut index, seeded, _) = known_corrupt_scan(
        source,
        &sessions,
        &seed,
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:00:00Z",
    );
    assert!(seeded.census_complete);
    let key = local_index_key(&held);
    let gone_key = local_index_key(&gone);
    let digest = store::key_digest(DurableSource::ClaudeCode, &key);
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    disk.write_after_save(
        lock,
        1,
        vec![PendingRecord {
            binding: Binding {
                source: DurableSource::ClaudeCode,
                key: digest,
                context: [0; 32],
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate: certificate(&held, &namespace),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist: codec::allowlist_digest(source),
        }],
    )
    .unwrap();
    let record = disk.dir().join(format!(
        "{}.rec",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut corrupt = std::fs::read(&record).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&record, &corrupt).unwrap();
    let mut cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let (mut index, rebuilt, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:01:00Z",
    );
    assert!(
        reads[0] >= 1,
        "rebuild Full plus cold peer cache admissions"
    );
    assert_eq!(rebuilt.unreadable_path_count, 0);
    assert!(cache.retained().unwrap().peek(&key).is_some());
    assert_eq!(
        cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
        None,
        "fresh RAM in the SAME pass wins"
    );
    index.save(&index_path).unwrap();
    if fail_replacement {
        let record = record.clone();
        store::test_hooks::set_before_rename(Some(Box::new(move |_, target| {
            if target == record {
                Err(std::io::Error::other("rebuild replacement failed"))
            } else {
                Ok(())
            }
        })));
    }
    let ((), startup_alarms) = crate::local_resource_diagnostics::capture(|| {
        crate::snapshots::durable_after_save(&cache, &root, source, &index)
    });
    store::test_hooks::set_before_rename(None);
    assert_eq!(startup_alarms.len(), 1);
    assert_eq!(startup_alarms[0]["counts"]["t14_rebuild_full_started"], 1);
    if fail_replacement {
        assert_eq!(std::fs::read(&record).unwrap(), corrupt);
    } else {
        assert!(matches!(disk.read(&digest), store::ReadOutcome::Found(_)));
        cache.retained().unwrap().remove(&key);
        assert_eq!(
            cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
            None,
            "repaired record never holds"
        );
        // A fresh process restores the healthy replacement, with no T14 Full.
        cache = Arc::new(SharedCache::default());
    }
    let append = |path: &Path, request: &str| {
        let row = serde_json::json!({"type":"assistant","sessionId": if path == held.as_path() {"11111111-2222-4333-8444-000000000000"} else {"11111111-2222-4333-8444-000000000001"},"timestamp":"2026-10-07T10:00:01Z","requestId":request,"message":{"id":request,"model":"fixture-model","usage":{"input_tokens":200,"output_tokens":20}}});
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "{row}"
        )
        .unwrap();
    };
    append(&held, "req-held-append");
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let (next, tailed, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:02:00Z",
    );
    index = next;
    let (restore_counts, restore_store) = cache.durable_counters(source).unwrap();
    assert_eq!(
        reads[0],
        0,
        "failed_replacement={fail_replacement}: {}",
        restore_counts.summary(source, &restore_store)
    );
    assert!(reads[1] >= 1);
    assert!(tailed.census_complete);
    assert!(tailed
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000"));
    let (_, full, _) = known_corrupt_scan(
        source,
        &sessions,
        &Arc::new(SharedCache::default()),
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:02:00Z",
    );
    let held_body = |scan: &SourceScanResult| {
        serde_json::to_value(
            scan.snapshots
                .iter()
                .filter(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000")
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    assert_eq!(held_body(&tailed), held_body(&full));
    if !fail_replacement {
        let (_, stats) = cache.durable_counters(source).unwrap();
        assert_eq!(
            restore_counts.restored, 1,
            "healthy replacement restored after restart"
        );
        assert_eq!(
            stats.t14_rebuild_full_started, 0,
            "restart restored the repaired record"
        );
        std::fs::remove_dir_all(root).unwrap();
        return;
    }
    let accepted = index.files[&key].clone();
    cache.retained().unwrap().remove(&key);
    append(&held, "req-held-after-eviction");
    append(&peer, "req-peer-progress");
    std::fs::remove_file(&gone).unwrap();
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let (index, held_scan, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:03:00Z",
    );
    assert_eq!(reads[0], 0, "held key does not Full; peer has RAM");
    assert!(
        held_scan.census_complete,
        "one known_corrupt key must not poison source census"
    );
    assert_eq!(held_scan.unreadable_path_count, 0);
    assert!(
        held_scan.claude_request_census_shadow.is_some(),
        "terminal close/settle ran"
    );
    assert!(
        !index.files.contains_key(&gone_key),
        "healthy terminal retired absent peer"
    );
    assert_eq!(
        index.files[&key].last_snapshot_fingerprint,
        accepted.last_snapshot_fingerprint
    );
    assert_eq!(
        index.files[&key].last_upload_body_witness,
        accepted.last_upload_body_witness
    );
    assert!(!held_scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000"));
    assert!(held_scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000001"));
    let (counts, stats) = cache.durable_counters(source).unwrap();
    assert!(counts.not_persisted["known_corrupt_memory_only"] > 0);
    assert!(counts.not_persisted["known_corrupt_held"] > 0);
    assert_eq!(counts.durable_held, [0; 5]);
    assert_eq!(stats.t14_rebuild_full_started, 1);
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert!(alarms
        .iter()
        .all(|alarm| alarm["counts"]["t14_rebuild_full_started"]
            .as_u64()
            .unwrap()
            <= 1));
    assert_eq!(std::fs::read(&record).unwrap(), corrupt);
    // P2 review: preserve size/mtime while replacing the object. The healthy
    // production exit must still invalidate stale request-hash authority.
    let mut index = index;
    assert!(index.claude_request_census.get(&key).is_some());
    let replacement = held.with_extension("replacement");
    let bytes = std::fs::read(&held).unwrap();
    std::fs::write(&replacement, &bytes[..accepted.size_bytes as usize]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(accepted.modified_unix_seconds),
        )
        .unwrap();
    std::fs::rename(&replacement, &held).unwrap();
    let mut census = ScanCensus::default();
    let candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: sessions.clone(),
            path: held.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        365,
        &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
    )
    .unwrap();
    cache.durable_hold_exit(
        source,
        store::Refusal::Corrupt,
        &mut index,
        &candidate,
        &mut census,
    );
    assert!(index.claude_request_census.get(&key).is_none());
    assert_eq!(census.unreadable_path_count, 0);
    let mut restarted = DurableTailStore::new(disk.dir().to_path_buf(), DurableSource::ClaudeCode);
    assert_eq!(restarted.full_hold(&digest, true), None);
    assert_eq!(
        restarted.counters().t14_rebuild_full_started,
        1,
        "a restart gets one fresh attempt, not a persisted repetition count"
    );
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
                assert!(disk_store
                    .write_after_save(lock, index.generation, vec![v2])
                    .is_err());
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
                    .write_after_save(lock, index.generation, vec![over_budget])
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
        let old = match store.read(&pending.binding.key) {
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
            // A format-1 restore alone is clean: the current writer still emits
            // v1. Stage real current-index debt to exercise an ordinary dirty
            // replacement without changing the decoded counting decision.
            let due = unix_seconds(SystemTime::now()).unwrap() + 120;
            let fingerprint = index.files[&key].source_file_fingerprint.clone();
            assert!(index.stage_sampled_audit(
                &key,
                &fingerprint,
                crate::transcript_acquisition::AuditDebt {
                    due_unix_seconds: due
                }
            ));
            cache.durable_note_selection(&key, &index.files[&key].source_file_fingerprint);
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let next = match store.read(&pending.binding.key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert_eq!(next.format, store::FORMAT_VERSION);
            assert_eq!(next.envelope_audit_debt, Some(due));
            assert_ne!(std::fs::read(&disk).unwrap(), bytes);
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
fn restore_scope_attribution_is_typed_and_preserves_binding_formula() {
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("diagnostic-namespace".into());
    let scope = Scope("diagnostic-scope".into());
    let mut index = ScanIndex {
        active_effective_upload_body_witness_revision: 3,
        ..ScanIndex::default()
    };
    index.claude_money_birth_store.set_money_rule_version(2);
    let interpretation = Interpretation::of(source, "fixture", &index, false, &namespace);
    let base = replay_scope(source, &scope, &index, &interpretation, None);
    let prior_formula = store::replay_scope_digest(
        &store::scope_digest(
            &scope.0,
            &codec::allowlist_digest(source),
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
        crate::snapshot_sync::effective_upload_body_witness_revision(source),
        index.active_effective_upload_body_witness_revision,
        index.claude_money_birth_store.money_rule_version(),
        claude_request_money::e2::enabled(),
    );
    assert_eq!(
        base, prior_formula,
        "existing persisted binding is unchanged"
    );
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        None
    );
    index.active_effective_upload_body_witness_revision = 4;
    let body = Obligation {
        kind: ObligationKind::BodyWitness,
        revision: 4,
    };
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        Some(body)
    );
    assert_eq!(
        MissClass::Unregistered(body).label(),
        "unregistered_replay.body_witness"
    );
    assert_eq!(
        unregistered_scope(
            source,
            &Scope("other".into()),
            &index,
            &interpretation,
            base
        ),
        None
    );
    index.active_effective_upload_body_witness_revision = 3;
    index.claude_money_birth_store.set_money_rule_version(3);
    let money = Obligation {
        kind: ObligationKind::MoneyRule,
        revision: 3,
    };
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        Some(money)
    );
    assert_eq!(
        MissClass::Unregistered(money).label(),
        "unregistered_replay.money_rule"
    );
    // Codex has no money-rule scope input, even when the store knows a rule.
    let codex = SnapshotSource::Codex;
    let codex_scope = replay_scope(codex, &scope, &index, &interpretation, None);
    assert_eq!(
        unregistered_scope(codex, &scope, &index, &interpretation, codex_scope),
        None
    );
}

#[test]
fn restore_reports_each_early_exit_without_changing_old_totals() {
    let root = crate::test_scratch::private_dir("ottto-restore-provenance");
    let _lock = test_locks::hold(&root);
    let path = root.join("fixture.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("restore-outcome".into());
    let scope = Scope("restore-file".into());
    let index_path = root.join("index.json");
    let cache = SharedCache::default();
    let mut index = ScanIndex::default();
    let attempt = |index: &ScanIndex| {
        let interpretation = Interpretation::of(source, &key, index, false, &namespace);
        cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            index,
            &interpretation,
        )
    };
    let label = |outcome: RestoreOutcome| match outcome {
        RestoreOutcome::Miss(class) => class.label(),
        _ => panic!("expected a typed miss"),
    };
    assert_eq!(label(attempt(&index)), "no_entry");
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "effective_upload_body_witness_revision":3
        }))
        .unwrap(),
    );
    index.active_effective_upload_body_witness_revision = 3;
    assert_eq!(label(attempt(&index)), "unavailable");
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert_eq!(label(attempt(&index)), "missing");
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert_eq!(label(attempt(&index)), "ineligible.selection_cleared");
    index.files.get_mut(&key).unwrap().source_file_fingerprint = "fp".into();
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = 2;
    assert_eq!(label(attempt(&index)), "ineligible.history_owed");
    let (old, disk) = cache.durable_counters(source).unwrap();
    assert_eq!((old.restore_attempts, old.missing, old.restored), (4, 1, 0));
    assert_eq!(old.ineligible["selection_cleared"], 1);
    assert_eq!(old.ineligible["history_owed"], 1);
    assert_eq!(old.durable_held, [0; 5]);
    let text = old.summary(source, &disk);
    assert!(!text.contains("restore_attempts="));
    assert!(text.contains("disk_records="));
    assert!(text.contains("not_persisted="));
    // No new record or recovery operation is performed by these diagnostics.
    assert_eq!(disk.records_read, 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn certificate_read_error_is_not_edit_evidence() {
    let root = crate::test_scratch::private_dir("ottto-certificate-read-error");
    let path = root.join("fixture.jsonl");
    std::fs::write(&path, b"{\"n\":1}\n").unwrap();
    let scope = Scope("certificate-error".into());
    let certificate = certificate(&path, &scope);
    // Preserve the nested codec's content-refusal field label as a static key.
    assert_eq!(
        MissClass::Failure(Failure::NotRederived(Refuse::NonEmpty(
            "CodexPrelude.skills_body"
        )))
        .label(),
        "not_rederived.CodexPrelude.skills_body"
    );
    // Metadata succeeds; the first existing sample read fails on a write-only FD.
    let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert_eq!(
        certificate.restore(&mut held, scope.clone()).err(),
        Some(CertificateRefusal::ReadError)
    );
    assert_eq!(
        MissClass::Failure(Failure::Certificate(CertificateRefusal::ReadError)).label(),
        "certificate_refused.read_error"
    );
    let mut invalid = certificate.clone();
    invalid.sample_len += 1;
    assert_eq!(
        invalid
            .restore(&mut File::open(&path).unwrap(), scope.clone())
            .err(),
        Some(CertificateRefusal::Changed(FullReason::InvalidCheckpoint))
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope)
            .err(),
        Some(CertificateRefusal::Changed(FullReason::Shrunk))
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Fixture (e): crossing T14's breaker disables the store; later attempts
/// report unavailable rather than conflating the disable with a missing record.
#[test]
fn store_unavailable_after_t14_breaker_is_not_missing() {
    let root = crate::test_scratch::private_dir("ottto-restore-store-unavailable");
    let lock = test_locks::hold(&root);
    let path = root.join("fixture.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let namespace = Scope("breaker-outcome".into());
    let scope = Scope("breaker-file".into());
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let attempt = || {
        cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        )
    };
    assert!(matches!(
        attempt(),
        RestoreOutcome::Miss(MissClass::Missing)
    ));
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let keys: Vec<_> = (0..=store::T14_BREAKER)
        .map(|n| store::key_digest(ds, &format!("/synthetic/corrupt-{n}.jsonl")))
        .collect();
    let allowlist = codec::allowlist_digest(source);
    let certificate = certificate(&path, &scope);
    disk.write_after_save(
        lock,
        1,
        keys.iter()
            .map(|key| PendingRecord {
                binding: Binding {
                    source: ds,
                    key: *key,
                    context: [0; 32],
                    scope: [0; 32],
                    entry: [0; 32],
                },
                certificate: certificate.clone(),
                body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                allowlist,
            })
            .collect(),
    )
    .unwrap();
    for key in &keys {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let record = disk.dir().join(format!("{hex}.rec"));
        let mut bytes = std::fs::read(&record).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&record, bytes).unwrap();
    }
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        for key in &keys {
            assert_eq!(slot.store.hold(key), None);
        }
        assert_eq!(slot.store.disabled(), Some("t14_breaker"));
    }
    let outcome = attempt();
    assert!(matches!(
        outcome,
        RestoreOutcome::Miss(MissClass::Unavailable)
    ));
    let mut page = crate::local_resource_diagnostics::RestoreCounts::default();
    page.record(&outcome);
    let json = serde_json::to_value(page).unwrap();
    assert_eq!(json["miss"]["unavailable"], 1);
    assert!(json["miss"].get("missing").is_none());
    let (old, disk) = cache.durable_counters(source).unwrap();
    assert_eq!((old.restore_attempts, old.missing), (2, 2));
    assert_eq!(disk.t14_rebuild, store::T14_BREAKER);
    assert_eq!(disk.records_read, 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn certificate_sample_truncation_is_shrunk_for_both_windows() {
    use crate::transcript_acquisition::set_between_guards;
    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            set_between_guards(None);
        }
    }
    let root = crate::test_scratch::private_dir("ottto-certificate-sample-truncation");
    let path = root.join("fixture.jsonl");
    let scope = Scope("sample-truncation".into());
    for target in [1, 2] {
        std::fs::write(&path, b"{}\n".repeat(10_000)).unwrap();
        let certificate = certificate(&path, &scope);
        let shrink_to = if target == 1 {
            u64::from(certificate.sample_len) - 1
        } else {
            certificate.sealed_offset - 1
        };
        let truncate = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = calls.clone();
        let _clear = ClearHook;
        set_between_guards(Some(Box::new(move || {
            observed.set(observed.get() + 1);
            if observed.get() == target {
                truncate.set_len(shrink_to).unwrap();
            }
        })));
        // Opening metadata still matches; the selected existing sample read
        // consumes a partial window then hits UnexpectedEof after truncation.
        assert_eq!(
            certificate
                .restore(&mut File::open(&path).unwrap(), scope.clone())
                .err(),
            Some(CertificateRefusal::Changed(FullReason::Shrunk))
        );
        assert_eq!(calls.get(), target);
    }
    let _ = std::fs::remove_dir_all(root);
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
    let record = store::DurableRecord {
        envelope_audit_debt: None,
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
    disk.write_after_save(lock, 1, vec![record.record.clone()])
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
            RestoreOutcome::Miss(MissClass::Failure(Failure::NotRederived(
                Refuse::NotRederivable("compressed")
            )))
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

#[allow(clippy::too_many_arguments)]
fn scope_for(
    source: DurableSource,
    snapshot_source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    format: u16,
    allowlist: &store::Digest32,
) -> store::Digest32 {
    store::replay_scope_digest(
        &store::scope_digest_for(
            format,
            &scope.0,
            allowlist,
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
        crate::snapshot_sync::effective_upload_body_witness_revision(snapshot_source),
        index.active_effective_upload_body_witness_revision,
        if source == DurableSource::ClaudeCode {
            index.claude_money_birth_store.money_rule_version()
        } else {
            0
        },
        source == DurableSource::ClaudeCode && claude_request_money::e2::enabled(),
    )
}

pub(crate) fn seed_pinned_v1(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
) -> Vec<u8> {
    let checkpoint = cache.retained_checkpoint(key).unwrap();
    let ds = durable_source(source).unwrap();
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(ds).as_mut().unwrap();
    let interpretation =
        Interpretation::of(source, key, index, slot.identity_capture, &slot.namespace);
    let record = match slot.store.read(&store::key_digest(ds, key)) {
        ReadOutcome::Found(record) => record,
        other => panic!("{other:?}"),
    };
    let mut pending = record.record;
    pending.binding.scope = scope_for(
        ds,
        source,
        checkpoint.scope(),
        index,
        &interpretation,
        1,
        &pending.allowlist,
    );
    let bytes = store::tests::pinned_v1_bytes(&pending, record.index_generation);
    let name = store::key_digest(ds, key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::fs::write(slot.store.dir().join(format!("{name}.rec")), &bytes).unwrap();
    bytes
}

/// V1 envelope debt is retired, but the index remains the deadline authority.
/// Exercise real disk decode, certificate restore and acquisition decisions on
/// every layout, including two process/index reloads and a later offered debt.
#[test]
fn v1_dropped_envelope_debt_survives_in_index_without_postponement() {
    use crate::transcript_acquisition::{AuditDebt, ReadMode};
    let root = crate::test_scratch::private_dir("ottto-v1-debt-survival");
    let lock = test_locks::hold(&root);
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("debt-survival".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let now = 1_800_000_000;
    let due = now + 60;
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 3, "modified_unix_seconds": 1, "source_file_fingerprint": "debt-source"
        }))
        .unwrap(),
    );
    assert!(index.stage_sampled_audit(
        &key,
        "debt-source",
        AuditDebt {
            due_unix_seconds: due
        }
    ));
    index.save(&index_path).unwrap();
    let mut certificate = certificate(&path, &scope);
    certificate.audit_debt_unix_seconds = Some(due);
    let source = DurableSource::ClaudeCode;
    let record_key = store::key_digest(source, &key);
    // Match the production writer: debt belongs to this namespace/upload context.
    let live_context =
        store::context_digest(&scope.0, index.active_upload_context_fingerprint.as_deref());
    let pending = PendingRecord {
        binding: store::Binding {
            source,
            key: record_key,
            context: live_context,
            scope: [1; 32],
            entry: [2; 32],
        },
        certificate,
        body: crate::snapshots::durable_store_fixture_body(SnapshotSource::ClaudeCode, 0, 0),
        allowlist: codec::allowlist_digest(SnapshotSource::ClaudeCode),
    };
    let dir = store::store_dir_for_index(&index_path);
    DurableTailStore::new(dir.clone(), source)
        .write_after_save(lock, index.generation, vec![pending])
        .unwrap();
    for pass in 0..2 {
        let mut index = ScanIndex::load(&index_path).unwrap();
        let record = match DurableTailStore::new(dir.clone(), source).read(&record_key) {
            ReadOutcome::Found(record) => record,
            other => panic!("{other:?}"),
        };
        assert_eq!(record.record.certificate.audit_debt_unix_seconds, None);
        let mut held = File::open(&path).unwrap();
        let (checkpoint, _) = record
            .record
            .certificate
            .restore(&mut held, scope.clone())
            .unwrap();
        assert_eq!(checkpoint.audit_debt(), None, "no envelope fallback");
        assert_eq!(record.envelope_audit_debt, Some(due));
        assert!(audit_carrier_matches(&record, &index, &key, now + pass));
        // A decoded checkpoint has no debt, but the CURRENT index must write it.
        let current = certificate_at(&key, &checkpoint, &index, now + pass).unwrap();
        assert_eq!(current.audit_debt_unix_seconds, Some(due));
        let mut rewritten = record.record.clone();
        rewritten.certificate = current;
        let old_wire = store::tests::pinned_v1_bytes(&rewritten, index.generation);
        DurableTailStore::new(dir.clone(), source)
            .write_after_save(lock, index.generation, vec![rewritten])
            .unwrap();
        let record_path = dir.join(format!(
            "{}.rec",
            record_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        assert_eq!(std::fs::read(&record_path).unwrap(), old_wire);
        assert_eq!(
            u64::from_le_bytes(old_wire[312..320].try_into().unwrap()),
            due,
            "downgrade reader sees original obligation"
        );

        let debt = sampled_audit::debt_for_key(&index, &key, now + pass).unwrap();
        assert_eq!(debt.due_unix_seconds, due);
        let before =
            ReadPlan::prepare(&mut held, Some(&checkpoint), &scope, Some(debt), due - 1).unwrap();
        assert_eq!(before.mode(), ReadMode::Unchanged);
        let retained = before
            .commit_after_native_completion(&held, &scope, due - 1)
            .unwrap();
        assert_eq!(retained.audit_debt().unwrap().due_unix_seconds, due);
        assert!(index.stage_sampled_audit(
            &key,
            "debt-source",
            AuditDebt {
                due_unix_seconds: due + 600
            }
        ));
        index.save(&index_path).unwrap();
        let debt = sampled_audit::debt_for_key(&index, &key, due).unwrap();
        assert_eq!(debt.due_unix_seconds, due, "later offers cannot renew debt");
        let overdue =
            ReadPlan::prepare(&mut held, Some(&checkpoint), &scope, Some(debt), due).unwrap();
        assert_eq!(overdue.mode(), ReadMode::Unchanged);
        let overdue = overdue
            .commit_after_native_completion(&held, &scope, due)
            .unwrap();
        assert_eq!(overdue.audit_debt().unwrap().due_unix_seconds, due);
        assert_eq!(
            overdue.last_full_verified(),
            checkpoint.last_full_verified(),
            "no Full credit"
        );
    }
    // Third case: absent entries miss without inventing membership. Reset
    // carriers re-arm an immediate current-index audit before any source read.
    // A completed Full whose durable replacement failed has the same state.
    let saved = ScanIndex::load(&index_path).unwrap();
    // A missing entry must still reach same-context carrier classification.
    // No entry-derived binding or transcript read is available in either arm.
    // A foreign namespace supplies no scheduling authority and stays NoEntry.
    for matching_context in [true, false] {
        let mut absent = saved.clone();
        absent.files.remove(&key);
        let namespace = if matching_context {
            scope.clone()
        } else {
            Scope("foreign-debt-survival".into())
        };
        let cache = SharedCache::default();
        cache.durable_begin_pass(SnapshotSource::ClaudeCode, &index_path, &namespace, true);
        let interpretation =
            Interpretation::of(SnapshotSource::ClaudeCode, &key, &absent, true, &namespace);
        let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let record_path = dir.join(format!(
            "{}.rec",
            record_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let before = std::fs::read(&record_path).unwrap();
        let outcome = cache.durable_restore(
            SnapshotSource::ClaudeCode,
            &key,
            &path,
            &scope,
            &mut held,
            &absent,
            &interpretation,
        );
        assert!(if matching_context {
            matches!(outcome, RestoreOutcome::Miss(MissClass::AuditCarrier))
        } else {
            matches!(outcome, RestoreOutcome::Miss(MissClass::NoEntry))
        });
        assert!(!absent.files.contains_key(&key), "no invented membership");
        assert_eq!(std::fs::read(&record_path).unwrap(), before);
        let (counts, _) = cache.durable_counters(SnapshotSource::ClaudeCode).unwrap();
        assert_eq!(
            counts.ineligible.get("audit_carrier"),
            matching_context.then_some(&1)
        );
        assert_eq!(counts.durable_held, [0; 5]);
        assert_eq!(counts.restored, 0);
    }

    for reset in [false, true] {
        let mut missing = saved.clone();
        if reset {
            assert!(missing.complete_full_audit(&key, "debt-source"));
            missing.save(&index_path).unwrap(); // crash before record replacement
        } else {
            missing.files.remove(&key);
        }
        assert_eq!(
            store::context_digest(
                &scope.0,
                missing.active_upload_context_fingerprint.as_deref(),
            ),
            live_context,
            "carrier reset preserves the writer namespace/upload context"
        );
        let cache = SharedCache::default();
        cache.durable_begin_pass(SnapshotSource::ClaudeCode, &index_path, &scope, true);
        let interpretation =
            Interpretation::of(SnapshotSource::ClaudeCode, &key, &missing, true, &scope);
        let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let outcome = cache.durable_restore(
            SnapshotSource::ClaudeCode,
            &key,
            &path,
            &scope,
            &mut held,
            &missing,
            &interpretation,
        );
        if reset {
            let RestoreOutcome::Miss(class @ MissClass::AuditCarrier) = outcome else {
                panic!("reset must re-arm, not hold");
            };
            let rearmed = class.rearm_audit(&mut missing, &key, now).unwrap();
            assert_eq!(
                sampled_audit::debt_for_key(&missing, &key, now),
                Some(rearmed)
            );
            // Carrier custody re-arms scheduling debt, independently of the
            // read cause: without a checkpoint the reader is StateMissing.
            let plan = ReadPlan::prepare(&mut held, None, &scope, Some(rearmed), now).unwrap();
            assert_eq!(plan.mode(), ReadMode::Full(FullReason::StateMissing));
            assert_eq!(rearmed.due_unix_seconds, now);
            assert_eq!(plan.metrics().audit_due, Some(rearmed.due_unix_seconds));
            missing.save(&index_path).unwrap();
            let loaded = ScanIndex::load(&index_path).unwrap();
            let mut disk = DurableTailStore::new(dir.clone(), source);
            let record = match disk.read(&record_key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert!(audit_carrier_matches(&record, &loaded, &key, now));
            // The retry completes a real Full, then publishes a clean replacement.
            let mut file = File::open(&path).unwrap();
            let mut plan = ReadPlan::prepare(&mut file, None, &scope, Some(rearmed), now).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            plan.observe_complete_records(&bytes).unwrap();
            let checkpoint = plan
                .commit_after_native_completion(&file, &scope, now)
                .unwrap();
            assert_eq!(checkpoint.audit_debt(), None);
            assert!(missing.complete_full_audit(&key, "debt-source"));
            missing.save(&index_path).unwrap();
            let mut replacement = record.record;
            replacement.certificate = certificate_at(&key, &checkpoint, &missing, now).unwrap();
            assert_eq!(
                disk.write_after_save(lock, missing.generation, vec![replacement])
                    .unwrap()
                    .written,
                1,
                "completed audit must replace the debt-bearing predecessor, not memo-skip it"
            );
            let record = match DurableTailStore::new(dir.clone(), source).read(&record_key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert_eq!(record.envelope_audit_debt, None);
            assert!(audit_carrier_matches(
                &record,
                &ScanIndex::load(&index_path).unwrap(),
                &key,
                now
            ));
        } else {
            assert!(matches!(
                outcome,
                RestoreOutcome::Miss(MissClass::AuditCarrier)
            ));
            assert!(!missing.files.contains_key(&key));
        }
        assert_eq!(
            cache
                .durable_counters(SnapshotSource::ClaudeCode)
                .unwrap()
                .0
                .ineligible
                .get("audit_carrier"),
            Some(&1)
        );
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_some(),
            "record remains in custody"
        );
    }
    // A current clean index clears stale RAM debt on write, never the reverse.
    let mut held = File::open(&path).unwrap();
    let mut stale = self::certificate(&path, &scope);
    stale.audit_debt_unix_seconds = Some(due);
    let (checkpoint, _) = stale.restore(&mut held, scope.clone()).unwrap();
    assert_eq!(checkpoint.audit_debt().unwrap().due_unix_seconds, due);
    let mut clean = saved;
    clean.files.get_mut(&key).unwrap().scan_identity_version = None;
    assert_eq!(
        certificate_at(&key, &checkpoint, &clean, now)
            .unwrap()
            .audit_debt_unix_seconds,
        None
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// Contract-5 cutover (Lead B, byte-stable keys): a record a permit-era
/// permitted Claude cycle wrote (capture on, the E2 contract recorded)
/// keeps its identity interpretation byte for byte under the always-on
/// capture, so it binds and restores; nothing is refused. Codex never
/// captured and still does not.
///
/// This is a same-binary round trip: no record bytes written by the
/// previous binary are replayed. Its cross-version claim rests on the
/// pinned literal interpretation below and on the
/// sampled-scope goldens (`the_always_on_sampled_scope_keeps_the_permit_era_bytes`).
/// A restore reads only its bounded certificate and re-derivation bytes,
/// never the transcript in Full; an unsupported heap layout cannot restore
/// and says so.
#[test]
fn a_permit_era_record_restores_under_the_always_on_capture() {
    let root = crate::test_scratch::private_dir("ottto-dt-contract5");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("contract5-test".into());
    let scope = Scope("contract5-file".into());
    let index_path = root.join("index.json");
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.claude_request_identity_contract = Some(claude_request_identity::E2_GROUPING.to_owned());
    index.save(&index_path).unwrap();
    // The permit-era permitted cycle: capture followed the permit.
    let before = Interpretation::of(source, &key, &index, true, &namespace);
    assert_eq!(
        before.identity_contract,
        format!(
            "claude_code_jsonl:own_request_identity_rows:v1/e2_grouping:v1|changed=false|capture=true|attr={}",
            claude_attribution_capture_enabled()
        ),
        "the pre-cutover interpretation bytes"
    );
    let capture = claude_request_identity::captures(source);
    let after = Interpretation::of(source, &key, &index, capture, &namespace);
    assert_eq!(after.identity_contract, before.identity_contract);
    let codex = SnapshotSource::Codex;
    assert_eq!(
        Interpretation::of(codex, &key, &index, false, &namespace).identity_contract,
        Interpretation::of(
            codex,
            &key,
            &index,
            claude_request_identity::captures(codex),
            &namespace
        )
        .identity_contract
    );
    let binding = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &index,
        &before,
        None,
    )
    .unwrap()
    .binding;
    let (reduction, _) = native_record(&path, &scope);
    let mut store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    store
        .write_after_save(
            lock,
            index.generation,
            vec![PendingRecord {
                binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let restored = cache
        .durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &after,
        )
        .into_test_option();
    let supported = crate::heap_layout_bound::layout_supported();
    assert_eq!(restored.is_some(), supported);
    let (counts, disk) = cache.durable_counters(source).unwrap();
    if supported {
        assert!(counts.ineligible.is_empty(), "{:?}", counts.ineligible);
        assert_eq!(counts.refused_record, 0);
        // No Full read: re-derivation reads less than the transcript.
        let transcript = std::fs::metadata(&path).unwrap().len();
        let read = counts.rederive_head_bytes + counts.rederive_line_bytes;
        assert!(read < transcript, "re-derived {read} of {transcript} bytes");
    } else {
        std::io::Write::write_all(
            &mut std::io::stderr().lock(),
            b"a_permit_era_record_restores_under_the_always_on_capture: UNEXECUTED \
              (heap layout unsupported; restore not exercised)\n",
        )
        .unwrap();
    }
    assert_eq!(counts.restored, u64::from(supported));
    assert_eq!(disk.records_read, 1);
    drop(restored);
    let _ = std::fs::remove_dir_all(root);
}

/// Real inventory -> disk restore -> native Tail. The scaled cache keeps the
/// same admission mechanism; optional facts must lose before a usable record.
#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn header_facts_yield_to_real_durable_restore_but_not_hopeless_admission() {
    use crate::heap_layout_bound::bound;
    use crate::snapshots::codex_file_join::header_cache_tests::{page, READ_CALLS};
    use crate::snapshots::sampled_scan::{codex_cursor, STATE_BYTES};
    use crate::transcript_acquisition::ReadMode;
    use crate::transcript_cache::{FrozenCacheState, Retained, TranscriptCache};
    const INVENTORY_LIMIT: usize = 256 * 1024;
    let root = crate::test_scratch::private_dir("ottto-header-restore");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let source = SnapshotSource::Codex;
    let namespace = Scope("header-restore".into());
    let scope = Scope("header-restore-file".into());
    let path = sessions.join("target.jsonl");
    let session = "0199f7a0-0000-7000-8000-0000000d7a11";
    codex_budget_fixture(&path, session, Some(32 * 1024));
    let key = local_index_key(&path);
    let mut paths = BTreeSet::from([key.clone()]);
    for number in 0..512 {
        let header = sessions.join(format!("header-{number:04}.jsonl"));
        std::fs::write(
            &header,
            format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session}\"}}}}\n"),
        )
        .unwrap();
        paths.insert(local_index_key(&header));
    }
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
    let (reduction, checkpoint) = native_record_of(&path, &scope, source);
    assert!(reduction.supports_frozen_charge());
    let incoming = Retained {
        checkpoint,
        state: reduction,
    };
    assert!(bound(&incoming, crate::transcript_cache::ENTRY_BYTES).is_some());
    // Use the production writer's current binding construction, rather than
    // coupling this fixture to the internal expected() signature.
    let writer = SharedCache::default();
    writer.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(writer.insert_admitted(
        key.clone(),
        sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: incoming.checkpoint,
            reduction: Some(incoming.state),
            released: None,
            unsealed: false,
        },
        0
    ));
    writer.durable_note_selection(&key, "fp");
    assert_eq!(
        writer
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::Codex,
    );
    let records = || {
        std::fs::read_dir(store.dir())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), std::fs::read(path).unwrap())
            })
            .collect::<BTreeMap<_, _>>()
    };
    let saved = records();
    assert_eq!(saved.len(), 1);
    let suffix = b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\"}}\n";
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap(),
        suffix,
    )
    .unwrap();
    // Size the actual restored representation, including codec/rederive
    // capacities, rather than assuming that 256 KiB covers the native layout.
    let sizing = SharedCache::default();
    sizing.durable_begin_pass(source, &index_path, &namespace, false);
    let incoming = match sizing.durable_restore(
        source,
        &key,
        &path,
        &scope,
        &mut File::open(&path).unwrap(),
        &index,
        &interpretation,
    ) {
        RestoreOutcome::Restored(taken) => taken.retained,
        _ => panic!("unscaled sizing restore must succeed"),
    };
    let incoming_heap = bound(&incoming, crate::transcript_cache::ENTRY_BYTES).unwrap()
        - std::mem::size_of_val(&incoming);
    let incoming_slot =
        crate::transcript_cache::entry_slot_bytes::<CachedJsonlReduction>(key.capacity()).unwrap();
    let rank = crate::transcript_cache::admission_rank(
        incoming.checkpoint.modified_hint(),
        crate::transcript_cache::admission_now(),
    );
    for fits in [true, false] {
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        READ_CALLS.with(|count| count.set(0));
        let inventory =
            codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || page(&root, &paths, &cache));
        assert!(inventory.complete);
        assert_eq!(inventory.reuse_misses, paths.len());
        assert_eq!(READ_CALLS.with(std::cell::Cell::get), paths.len());
        let before = cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap();
        assert!(before > 0, "real inventory retains header facts");
        {
            let mut retained = cache.retained().unwrap();
            cache
                .with_cursor(|cursor| {
                    let headers = std::mem::take(&mut cursor.headers);
                    let cursor_bytes = bound(cursor, STATE_BYTES).unwrap();
                    let side = crate::snapshots::sampled_scan::side_ledger::SIDE_LEDGER_BYTES;
                    let empty_retained = bound(&*retained, STATE_BYTES).unwrap();
                    // The empty retained root and the incoming entry's node
                    // are both charged; the incoming inline state lives in
                    // that node, and only its heap is added separately.
                    let minimum = cursor_bytes + side + empty_retained + incoming_slot + incoming_heap;
                    assert!(minimum < STATE_BYTES);
                    let one_byte_short = TranscriptCache::with_byte_limit(minimum - 1);
                    assert!(!one_byte_short.insertion_fits(
                        &key,
                        &incoming,
                        cursor_bytes + side,
                        rank,
                        true
                    ));
                    *retained = TranscriptCache::with_byte_limit(if fits { minimum } else { 1 });
                    println!(
                        "header_restore_layout: cursor={cursor_bytes} side={side} \
                         empty_retained={empty_retained} slot={incoming_slot} \
                         incoming_heap={incoming_heap} minimum={minimum} headers={before} fits={fits}"
                    );
                    assert_eq!(
                        retained.insertion_fits(&key, &incoming, cursor_bytes + side, rank, true),
                        fits,
                        "derived minimum must discriminate the header-free arm"
                    );
                    cursor.headers = headers;
                    let reserved = bound(cursor, STATE_BYTES).unwrap() + side;
                    assert!(!retained.insertion_fits(&key, &incoming, reserved, rank, true));
                })
                .unwrap();
        }
        let restored = cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        );
        if fits {
            let taken = match restored {
                RestoreOutcome::Restored(taken) => taken,
                _ => panic!("fitting durable record must restore, never miss or hold"),
            };
            let mut parser = OwnedJsonlParser::new(
                File::open(&path).unwrap(),
                &path,
                source,
                apply_codex_line,
                None,
                None,
                None,
                false,
            )
            .unwrap();
            assert_eq!(
                parser
                    .prepare_acquisition(Some(taken.retained), &scope, None, 1_800_000_001)
                    .unwrap(),
                ReadMode::Tail
            );
            while !parser.step().unwrap() {}
            assert_eq!(parser.reader.consumed_bytes(), suffix.len() as u64);
            let next = codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || {
                page(&root, &paths, &cache)
            });
            assert!(next.complete);
            assert_eq!(next.reuse_hits, 0);
            assert_eq!(next.reuse_misses, paths.len());
            assert!(next.reuse_evictions > 0);
            assert!(next.read_bytes <= paths.len() * (64 * 1024 + 1));
        } else {
            assert!(matches!(
                restored,
                RestoreOutcome::Miss(MissClass::BudgetRefused)
            ));
            assert_eq!(
                cache
                    .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
                    .unwrap(),
                before
            );
            let next = codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || {
                page(&root, &paths, &cache)
            });
            assert!(next.reuse_hits > 0);
            assert_eq!(next.reuse_evictions, 0, "hopeless restore preserves facts");
        }
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.restored, u64::from(fits));
        assert_eq!(counts.budget_refused, u64::from(!fits));
        assert_eq!(records(), saved, "restore cannot change durable authority");
    }
    std::fs::remove_dir_all(root).unwrap();
}
