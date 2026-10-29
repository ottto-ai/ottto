//! M3 r7 resources: prepaid key-map layout, P1-1 restore-pending authority,
//! freed authorityless custody, debt outside custody, index-sized pass maps,
//! the P2 restored head budget and the Codex refused stale record. Every row
//! drives the real `Stores` owner; nothing here is a production entry point.
use super::*;
use crate::transcript_acquisition::ReadPlan;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const CLAUDE: SnapshotSource = SnapshotSource::ClaudeCode;

fn digest(key: &str) -> store::Digest32 {
    store::key_digest(DurableSource::ClaudeCode, key)
}

/// A one-line checkpoint whose file then grew by one more line.
fn grown(name: &str) -> (PathBuf, Checkpoint, File) {
    let root = crate::test_scratch::private_dir(name);
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{\"n\":1}\n").unwrap();
    let scope = Scope("r7-scope".into());
    let mut file = File::open(&path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let checkpoint = plan
        .commit_after_native_completion(&file, &scope, 1_800_000_000)
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"n\":2}\n")
        .unwrap();
    (root, checkpoint, file)
}

fn entry() -> ScanIndexEntry {
    serde_json::from_value(serde_json::json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
    }))
    .unwrap()
}

#[test]
fn r7_every_key_map_node_fits_its_prepaid_charge() {
    // r6 put the D3 hold in the A0-h node and pushed it past 1024 bytes,
    // which would refuse every Q11 grant and strict check as unfunded.
    assert!(custody_node_bytes().unwrap() <= 1024, "A0-h custody node");
    assert!(
        super::owed::key_debt_node_bytes().unwrap() <= 1024,
        "debt/hold node"
    );
    assert!(
        restore_pending_node_bytes().unwrap() <= 1024,
        "pending node"
    );
    assert_eq!(
        KEY_RESERVE_BYTES,
        2 * (RESTORE_PENDING_KEYS + 1) * 1024,
        "both M3 maps prepay a retained root"
    );
    assert_eq!(STORES_RESIDENT_BOUND, 1_978_368);
}

#[test]
fn p1_1_zero_old_byte_restore_spends_pending_never_custody() {
    let (root, checkpoint, file) = grown("r7-p1-1-pending");
    let sealed = checkpoint.sealed_offset();
    let end = file.metadata().unwrap().len();
    let cache = SharedCache::default();
    let begin = |key: &str, at| cache.begin_retail(CLAUDE, key, &checkpoint, &file, sealed, at);
    let now = Instant::now();
    let first = begin("k", now).unwrap();
    assert_eq!(first.grant(), RetailGrant::Process);
    first.finish();
    {
        let stores = cache.durable().unwrap();
        assert!(stores.retail_spent.is_empty(), "no never-evicted A0-h node");
        assert_eq!(stores.restore_pending[&digest("k")].high, end);
        assert_eq!(
            (stores.counters.retail_keys, stores.counters.retail_attempts),
            (1, 1)
        );
    }
    // The same stale certificate again re-reads behind the pending high
    // water: promoted with its original grant time, then Daily-gated.
    assert!(matches!(
        begin("k", now + Duration::from_secs(1)),
        Err(RetailHold::Exhausted)
    ));
    {
        let stores = cache.durable().unwrap();
        assert!(stores.restore_pending.is_empty());
        assert_eq!(stores.retail_spent[&digest("k")].spent, Some((end, now)));
    }
    let daily = begin("k", now + RETAIL_DAILY).unwrap();
    assert_eq!(daily.grant(), RetailGrant::Daily);
    daily.finish();
    // A write or receipt at the high water frees a pending grant; a shorter
    // certificate does not.
    begin("w", now).unwrap().finish();
    {
        let mut stores = cache.durable().unwrap();
        stores.release_restore_pending(&digest("w"), end - 1);
        assert!(stores.restore_pending.contains_key(&digest("w")));
        stores.release_restore_pending(&digest("w"), end);
        assert!(!stores.restore_pending.contains_key(&digest("w")));
        assert_eq!(stores.retail_spent.len(), 1, "only the promoted key");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn p1_1_pending_overflow_reads_through_the_paced_full_and_never_evicts() {
    let (root, checkpoint, file) = grown("r7-p1-1-overflow");
    let sealed = checkpoint.sealed_offset();
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let begin = |key: &str, at| cache.begin_retail(CLAUDE, key, &checkpoint, &file, sealed, at);
    let now = Instant::now();
    for n in 0..RESTORE_PENDING_KEYS {
        begin(&format!("p{n}"), now).unwrap().finish();
    }
    assert!(matches!(begin("new", now), Err(RetailHold::AccountingLost)));
    {
        let stores = cache.durable().unwrap();
        assert_eq!(stores.counters.ineligible["retail_pending_overflow"], 1);
        assert!(!stores
            .counters
            .ineligible
            .contains_key("retail_pending_expired"));
        assert_eq!(stores.restore_pending.len(), RESTORE_PENDING_KEYS);
        assert!(
            stores.retail_spent.is_empty(),
            "overflow never takes custody"
        );
        let slot = stores.slots[DurableSource::ClaudeCode.slot()].as_ref();
        assert!(
            slot.is_some_and(|slot| slot.store.disabled().is_none()),
            "overflow never disables the store"
        );
    }
    // The caller's existing counted Full reads the grown file instead.
    assert!(cache.retail_full("new", &file, sealed, SystemTime::now()));
    // A day later the day-old grants are reclaimed, never a younger one.
    let later = begin("new", now + RETAIL_DAILY).unwrap();
    assert_eq!(later.grant(), RetailGrant::Process);
    later.finish();
    let stores = cache.durable().unwrap();
    assert_eq!(
        stores.counters.ineligible["retail_pending_expired"],
        RESTORE_PENDING_KEYS as u64
    );
    assert_eq!(stores.restore_pending.len(), 1);
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn authorityless_custody_is_freed_and_authority_is_kept() {
    let root = crate::test_scratch::private_dir("r7-custody-free");
    let cache = SharedCache::default();
    let now = Instant::now();
    {
        let mut stores = cache.durable().unwrap();
        assert!(stores.fund_key(digest("idle")));
        assert!(stores.fund_key(digest("spent")));
        stores.retail_spent.get_mut(&digest("spent")).unwrap().spent = Some((1, now));
        stores.release_idle_custody(&digest("idle"));
        stores.release_idle_custody(&digest("spent"));
        assert!(!stores.retail_spent.contains_key(&digest("idle")));
        assert!(stores.retail_spent.contains_key(&digest("spent")));
        // A strict check funded mid-pass and left without a witness.
        assert!(stores.fund_key(digest("idle")));
    }
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_spent.len(), 1);
    assert_eq!(stores.retail_spent[&digest("spent")].spent, Some((1, now)));
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn debt_and_holds_live_outside_custody_and_overflow_stays_conservative() {
    use super::owed::OwedMark;
    let claude = DurableSource::ClaudeCode;
    let cache = SharedCache::default();
    let mut stores = cache.durable().unwrap();
    for n in 0..store::MAX_RECORDS {
        stores.set_owed(digest(&format!("d{n}")), OwedMark::Owed(claude));
    }
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.key_debt.len(), store::MAX_RECORDS);
    assert!(!stores.owed_overflow[claude.slot()]);
    // No node is free: the source-wide conservative bit, never an eviction.
    stores.set_owed(digest("late"), OwedMark::Hold(claude));
    assert!(stores.owed_overflow[claude.slot()]);
    assert_eq!(stores.owed_mark(&digest("d0")), OwedMark::Owed(claude));
    assert_eq!(stores.counters.ineligible["key_debt_unfunded"], 1);
    // A discharged key frees its node.
    stores.clear_owed(digest("d0"));
    assert_eq!(stores.key_debt.len(), store::MAX_RECORDS - 1);
    stores.clear_source_owed(claude);
    assert!(stores.key_debt.is_empty());
    assert!(!stores.owed_overflow[claude.slot()]);
}

#[test]
fn pass_maps_follow_the_committed_index_and_count_overflow() {
    let root = crate::test_scratch::private_dir("r7-pass-maps");
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    let scope = Scope("r7-file".into());
    let floor = 2 * store::MAX_RECORDS;
    for n in 0..floor {
        let key = format!("k{n}");
        cache.durable_note_scope(CLAUDE, &key, &scope);
        cache.durable_note_selection(&key, "fp");
        cache.durable_touch(&key);
    }
    let over = |cache: &SharedCache| {
        cache.durable_note_scope(CLAUDE, "over", &scope);
        cache.durable_note_selection("over", "fp");
        cache.durable_touch("over");
    };
    over(&cache);
    {
        let mut stores = cache.durable().unwrap();
        for map in ["decided", "selected", "touched"] {
            assert_eq!(
                stores.counters.ineligible[&*format!("pass_overflow.{map}")],
                1,
                "{map}"
            );
        }
        assert!(!stores.touched.contains("over"));
        // A large committed index sizes the same maps; nothing is dropped.
        let mut index = ScanIndex::default();
        for n in 0..1_000 {
            index.files.insert(format!("i{n}"), entry());
        }
        stores.note_indexed(DurableSource::ClaudeCode, &index);
    }
    over(&cache);
    let stores = cache.durable().unwrap();
    let slot = stores.slots[DurableSource::ClaudeCode.slot()]
        .as_ref()
        .unwrap();
    assert!(slot.decided.contains_key("over"));
    assert!(stores.touched.contains("over"));
    assert_eq!(stores.selected.get("over").map(String::as_str), Some("fp"));
    assert_eq!(stores.counters.ineligible["pass_overflow.touched"], 1);
    drop(stores);
    std::fs::remove_dir_all(root).unwrap();
}

fn certificate(path: &Path, scope: &Scope) -> DurableCertificate {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    plan.commit_after_native_completion(&file, scope, 1_800_000_000)
        .unwrap()
        .durable_certificate(birth_unix_nanos(&std::fs::metadata(path).unwrap()))
        .unwrap()
}

fn native_reduction(path: &Path, scope: &Scope) -> CachedJsonlReduction {
    let mut parser = OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        CLAUDE,
        apply_claude_code_line,
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
    parser.durable_test_reduction_copy()
}

/// The production restore with the enabled workspace obligation: a pass
/// whose head budget cannot cover this extent refuses before content input
/// and counts it; the next pass's budget admits and charges the exact extent.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn p2_restored_head_reread_is_bounded_per_pass_and_counted() {
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("r7-p2-head");
    let path = root.join("source.jsonl");
    std::fs::write(
        &path,
        b"{\"type\":\"progress\",\"cwd\":\"/tmp/synthetic-workspace\"}\n",
    )
    .unwrap();
    let scope = Scope("r7-content".into());
    let body = codec::encode(
        &native_reduction(&path, &scope),
        store::BODY_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    let binding = store::tests::binding("account", "scope", ("fp-a", None));
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: store::FORMAT_VERSION,
        index_generation: 1,
        record: PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(CLAUDE),
        },
    };
    let head = std::fs::metadata(&path).unwrap().len();
    let cache = SharedCache::default();
    let restore = || {
        let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(CLAUDE) else {
            panic!("owner")
        };
        let result = cache
            .durable_restore_record(
                CLAUDE,
                &record,
                &expected,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &mut lease,
            )
            .map(|(_, _, receipt)| receipt.head_bytes);
        lease.release();
        result
    };
    let slot = DurableSource::ClaudeCode.slot();
    cache.durable().unwrap().rederive_spent[slot] = REDERIVE_PASS_BYTES - head + 1;
    let before = rederive_head_bytes_total(CLAUDE);
    assert!(matches!(
        restore(),
        Err(Failure::Resource("rederive_budget"))
    ));
    assert_eq!(
        rederive_head_bytes_total(CLAUDE),
        before,
        "a refused restore reads no head byte"
    );
    assert_eq!(cache.durable().unwrap().counters.rederive_budget, [1, head]);
    assert_eq!(
        MissClass::Resource("rederive_budget").label(),
        "resource_full.rederive_budget"
    );
    cache.durable_begin_pass(
        CLAUDE,
        &root.join("index.json"),
        &Scope("r7-ns".into()),
        false,
    );
    assert_eq!(restore().ok(), Some(head));
    assert_eq!(cache.durable().unwrap().rederive_spent[slot], head);
    assert!(rederive_head_bytes_total(CLAUDE) - before >= head);
}

/// SOURCE cond. 5 carrier without a new field: a Codex selection cleared
/// over a record not proved absent (the D3 strict-rebind store is disabled)
/// counts a stale refusal and takes one paced Full under its own cause.
#[test]
fn codex_cleared_selection_over_a_surviving_record_is_refused_and_paced() {
    let root = crate::test_scratch::private_dir("r7-codex-stale-selection");
    let path = root.join("fixture.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let source = SnapshotSource::Codex;
    let key = "r7-codex-key".to_string();
    let namespace = Scope("r7-codex".into());
    let scope = Scope("r7-codex-file".into());
    let mut index = ScanIndex::default();
    index.files.insert(key.clone(), entry());
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &root.join("index.json"), &namespace, false);
    let attempt = || {
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
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
    let label = |outcome: RestoreOutcome| match outcome {
        RestoreOutcome::Miss(class) => class.label(),
        RestoreOutcome::Pending => "pending",
        _ => panic!("expected a typed miss or pending"),
    };
    // Proved absent: the plain selection-clear Miss, no refusal.
    assert_eq!(label(attempt()), "ineligible.selection_cleared");
    cache
        .durable()
        .unwrap()
        .slot(DurableSource::Codex)
        .as_mut()
        .unwrap()
        .store
        .disable("r7_strict_rebind");
    assert_eq!(
        label(attempt()),
        "ineligible.selection_cleared.stale_record"
    );
    assert_eq!(
        label(attempt()),
        "ineligible.selection_cleared.stale_record",
        "a page deferral must not spend the Full permission"
    );
    assert!(cache.start_stale_selection_full(source, &key, &File::open(&path).unwrap()));
    assert_eq!(
        label(attempt()),
        "pending",
        "paced once per actual Full start"
    );
    let (counts, disk) = cache.durable_counters(source).unwrap();
    assert_eq!(disk.stale_record_refused, 3);
    assert_eq!(counts.ineligible["selection_cleared"], 4);
    assert_eq!(counts.ineligible["selection_cleared.stale_record_full"], 1);
    assert_eq!(
        counts.ineligible["selection_cleared.stale_record_full.paced"],
        1
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_debt_reservation_refuses_before_io_and_preserves_every_funded_hold() {
    use super::owed::OwedMark;
    let cache = SharedCache::default();
    let mut stores = cache.durable().unwrap();
    for n in 0..store::MAX_RECORDS {
        let key = digest(&format!("reserved-{n}"));
        assert!(stores.fund_debt(key).is_some());
        stores.hold_key(key, Some(((1, n as u64 + 1, 3), 17)));
    }
    assert_eq!(stores.holds().count(), store::MAX_RECORDS);
    assert!(stores.fund_debt(digest("unstarted")).is_none());
    assert_eq!(stores.holds().count(), store::MAX_RECORDS);
    assert!(stores.owed_overflow.iter().all(|bit| !bit));
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.counters.ineligible["key_debt_unfunded"], 1);
    assert_eq!(
        stores.counters.d3[super::write_ahead::D3_HOLD_UNFUNDED],
        0,
        "no unfunded hold created"
    );
    // Existing-key settlement always retains its reserved node at capacity.
    let key = digest("reserved-0");
    assert!(stores.fund_debt(key).is_some());
    stores.set_owed(key, OwedMark::Hold(DurableSource::ClaudeCode));
    assert!(stores.hold(&key).is_some());
}

#[test]
fn overflow_preserves_discovery_without_forcing_quiet_keys_to_parse() {
    use super::owed::{OwedMark, OwedQuery};
    let cache = SharedCache::default();
    {
        let mut stores = cache.durable().unwrap();
        for n in 0..store::MAX_RECORDS {
            stores.set_owed(
                digest(&format!("overflow-{n}")),
                OwedMark::Owed(DurableSource::Codex),
            );
        }
        stores.set_owed(digest("unfunded"), OwedMark::Hold(DurableSource::Codex));
        assert!(stores.owed_overflow[DurableSource::Codex.slot()]);
    }
    assert!(matches!(
        cache.owed_before_skip(SnapshotSource::Codex, "quiet-unrelated"),
        OwedQuery::None
    ));
    assert!(cache.owes_discovery(SnapshotSource::Codex, "quiet-unrelated"));
    assert!(cache.owes_discovery(SnapshotSource::Codex, "unfunded"));
}

#[test]
fn native_full_debt_map_declines_before_write_and_keeps_the_emitted_body() {
    use super::owed::{OwedMark, OwedQuery};
    use crate::snapshots::{OwnedSourceScan, OwnedSourceScanStep};
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let scratch = crate::test_scratch::ScratchDir::new("m3-native-debt-cap-corpus");
    let _lock = crate::locked_state_dir::test_locks::hold(&scratch);
    let sessions = scratch.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let session = "11111111-2222-4333-8444-555555555555";
    let path = sessions.join(format!("{session}.jsonl"));
    std::fs::write(
        &path,
        serde_json::json!({"type":"assistant", "sessionId":session,
        "timestamp":"2026-10-07T10:00:00Z", "requestId":"native-cap-request",
        "message":{"id":"native-cap-message", "model":"fixture-model",
            "usage":{"input_tokens":100,"output_tokens":10}}})
        .to_string()
            + "\n",
    )
    .unwrap();
    let namespace = Scope("native-debt-cap".into());
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(CLAUDE, &scratch.join("index.json"), &namespace, false);
    {
        let mut stores = cache.durable().unwrap();
        for n in 0..store::MAX_RECORDS {
            stores.set_owed(
                digest(&format!("already-owed-{n}")),
                OwedMark::Hold(DurableSource::ClaudeCode),
            );
        }
    }
    let run = |cache: Arc<SharedCache>| {
        let mut scan = OwnedSourceScan::new(
            CLAUDE,
            std::slice::from_ref(&sessions),
            ScanIndex::default(),
            "2026-10-20T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        for _ in 0..1000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { scan, .. } => return scan.snapshots,
            }
        }
        panic!("bounded native cap corpus did not finish");
    };
    let actual = run(cache.clone());
    let cold = run(Arc::new(SharedCache::default()));
    assert_eq!(
        actual.len(),
        1,
        "capacity cannot turn money into a held empty page"
    );
    assert_eq!(cold.len(), 1);
    assert_eq!(
        snapshot_upload_body_witness(&actual[0]),
        snapshot_upload_body_witness(&cold[0])
    );
    let (counts, disk) = cache.durable_counters(CLAUDE).unwrap();
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(counts.not_persisted.get("wa.pass_budget"), Some(&1));
    } else {
        assert_eq!(
            counts.ineligible["native_stage_skipped.layout_unsupported.claude"],
            1
        );
    }
    assert_eq!(disk.records_written, 0, "unfunded write never starts");
    assert_eq!(disk.receipt_pending_records, 0);
    assert_eq!(disk.store_faults, 0);
    assert!(matches!(
        cache.owed_before_skip(CLAUDE, &local_index_key(&path)),
        OwedQuery::None
    ));
    let stores = cache.durable().unwrap();
    assert_eq!(stores.key_debt.len(), store::MAX_RECORDS);
    assert!(stores.retail_spent.is_empty());
}

/// Persisted post-read class flags survive begin_pass without another class
/// encoding. These are the existing canonical protected-history carriers.
#[test]
fn protected_history_refuses_singleton_restore_across_passes_before_record_io() {
    for field in [
        "codex_protected_owner",
        "codex_joined_member_set",
        "codex_captured_joined_member_set",
        "codex_applied_tier_receipt_required",
        "codex_captured_tier_receipt_required",
        "codex_captured_uncommitted",
    ] {
        let (root, _, _) = grown("m3-protected-history");
        let path = root.join("source.jsonl");
        let key = local_index_key(&path);
        let cache = SharedCache::default();
        let namespace = Scope("post-read-class".into());
        cache.durable_begin_pass(
            SnapshotSource::Codex,
            &root.join("index.json"),
            &namespace,
            false,
        );
        // Must return before even dispatching this deliberately unreadable
        // record. Unknown record protection is never relaxed by the class gate.
        let dir = store::store_dir_for_index(&root.join("index.json"));
        std::fs::create_dir_all(&dir).unwrap();
        let filename = store::key_digest(DurableSource::Codex, &key)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(dir.join(format!("{filename}.rec")), b"unreadable sentinel").unwrap();
        let mut index = ScanIndex::default();
        let mut row = serde_json::to_value(entry()).unwrap();
        row[field] = if field.ends_with("required") || field.ends_with("uncommitted") {
            serde_json::json!(true)
        } else {
            serde_json::json!("a".repeat(64))
        };
        let row: ScanIndexEntry = serde_json::from_value(row).unwrap();
        assert!(
            row.codex_history_is_protected(),
            "{field}: canonical class carrier"
        );
        index.files.insert(key.clone(), row);
        // A fresh pass/process has no previous Slot.decided entry.
        cache.durable_begin_pass(
            SnapshotSource::Codex,
            &root.join("index.json"),
            &namespace,
            false,
        );
        // Refusal must also survive the optional per-pass map being full.
        {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(DurableSource::Codex).as_mut().unwrap();
            for n in 0..2 * store::MAX_RECORDS {
                slot.decided.insert(
                    format!("other-{n}"),
                    ScopeDecision::Scope(Scope("ordinary".into())),
                );
            }
        }
        let interpretation =
            Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace);
        let before = cache.durable_counters(SnapshotSource::Codex).unwrap().1;
        assert!(matches!(
            cache.durable_restore(
                SnapshotSource::Codex,
                &key,
                &path,
                &Scope("singleton".into()),
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation
            ),
            RestoreOutcome::Miss(MissClass::ExcludedClass)
        ));
        let (counts, after) = cache.durable_counters(SnapshotSource::Codex).unwrap();
        assert_eq!(after.bytes_read, before.bytes_read);
        assert_eq!(after.guard_header_bytes, before.guard_header_bytes);
        assert_eq!(after.records_read, before.records_read);
        assert_eq!(counts.ineligible["wa.class_changed.restore_refused"], 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn layout_unavailability_preserves_future_audit_and_state_missing_selection_cause() {
    let (root, _, mut file) = grown("m3-layout-future-audit");
    let now = 1_800_000_000;
    let future = now + 3600;
    let key = "already-selected";
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), entry());
    assert!(index.stage_sampled_audit(
        key,
        "fp",
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: future
        }
    ));
    let debt = MissClass::LayoutUnavailable(Some(future)).rearm_audit(&mut index, key, now);
    assert_eq!(index.files[key].unverified_deadline(), Some(future));
    let plan = ReadPlan::prepare(&mut file, None, &Scope("selected".into()), debt, now).unwrap();
    assert!(
        matches!(
            plan.mode(),
            crate::transcript_acquisition::ReadMode::Full(FullReason::StateMissing)
        ),
        "a missing restore shortcut cannot mint an AuditDue Full"
    );
    drop(plan);
    drop(file);
    std::fs::remove_dir_all(root).unwrap();
}
