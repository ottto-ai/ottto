//! M3 r7 resources: prepaid key-map layout, P1-1 restore-pending authority,
//! freed authorityless custody, debt outside custody, index-sized pass maps,
//! the P2 restored head budget and the Codex refused stale record. Every row
//! drives the real `Stores` owner; nothing here is a production entry point.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::native_cold as fixture;
use std::io::Write;

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
    let checkpoint = fixture::checkpoint(&mut file, &scope, 1_800_000_000);
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

/// [money] native full debt map declines before write and keeps the emitted body.
#[test]
fn native_full_debt_map_declines_before_write_and_keeps_the_emitted_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use super::owed::{OwedMark, OwedQuery};
    use crate::snapshots::OwnedSourceScan;
    let scratch = crate::test_scratch::ScratchDir::new("m3-native-debt-cap-corpus");
    let _lock = crate::locked_state_dir::test_locks::hold(&scratch);
    let sessions = scratch.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let session = "11111111-2222-4333-8444-555555555555";
    crate::snapshots::write_claude_reemission_list_for_test(&scratch, &[session]);
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
        let scan = OwnedSourceScan::new(
            CLAUDE,
            std::slice::from_ref(&sessions),
            ScanIndex::default(),
            "2026-10-20T12:00:00Z",
            365,
            100,
            false,
            Some(&scratch),
            &[],
            false,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        fixture::scan(scan, 1000).1.snapshots
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
/// [money] protected history refuses singleton restore across passes before record io.
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
