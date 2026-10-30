//! M3 r7 resources: prepaid key-map layout, P1-1 restore-pending authority,
//! freed authorityless custody, debt outside custody, index-sized pass maps,
//! the P2 restored head budget and the Codex refused stale record. Every row
//! drives the real `Stores` owner; nothing here is a production entry point.
use super::*;
use crate::transcript_acquisition::ReadPlan;
use std::io::{Read, Write};

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

/// SOURCE cond. 5 carrier without a new field: a Codex selection cleared
/// over a record not proved absent (the D3 strict-rebind store is disabled)
/// counts a stale refusal and takes one paced Full under its own cause.
/// [behaviour] codex cleared selection over a surviving record is refused and paced.
#[test]
fn codex_cleared_selection_over_a_surviving_record_is_refused_and_paced() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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

/// [behaviour] native debt reservation refuses before io and preserves every funded hold.
#[test]
fn native_debt_reservation_refuses_before_io_and_preserves_every_funded_hold() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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

/// [behaviour] overflow preserves discovery without forcing quiet keys to parse.
#[test]
fn overflow_preserves_discovery_without_forcing_quiet_keys_to_parse() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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

/// [behaviour] native full debt map declines before write and keeps the emitted body.
#[test]
fn native_full_debt_map_declines_before_write_and_keeps_the_emitted_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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
/// [behaviour] protected history refuses singleton restore across passes before record io.
#[test]
fn protected_history_refuses_singleton_restore_across_passes_before_record_io() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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

/// [behaviour] layout unavailability preserves future audit and state missing selection cause.
#[test]
fn layout_unavailability_preserves_future_audit_and_state_missing_selection_cause() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
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
