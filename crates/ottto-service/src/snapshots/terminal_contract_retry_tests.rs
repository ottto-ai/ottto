use super::*;
use terminal_contract_retry::with_contract;

fn terminal(source: SnapshotSource) -> SnapshotQuarantineRecord {
    let mut record = snapshot_quarantine_record(source);
    record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
    record.retry_after_unix_seconds = 0;
    record.upload_body_witness = Some("b".repeat(64));
    record
}

#[test]
fn terminal_contract_legacy_decode_and_lenient_repair_preserve_version() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-decode");
    let fingerprint = "a".repeat(64);
    for version in [None, Some(2)] {
        for repair in [false, true] {
            let path = scratch.join(format!("index-{}-{repair}.json", version.unwrap_or(0)));
            let record = terminal(SnapshotSource::ClaudeCode);
            let mut index = ScanIndex::default();
            index
                .quarantined_snapshot_fingerprints
                .insert(fingerprint.clone(), record);
            index.save(&path).unwrap();
            let mut wire = serde_json::to_value(&index).unwrap();
            let record = &mut wire["quarantined_snapshot_fingerprints"][&fingerprint];
            if let Some(version) = version {
                record["reconstruction_contract"] = json!(version);
            } else {
                record
                    .as_object_mut()
                    .unwrap()
                    .remove("reconstruction_contract");
            }
            if repair {
                record["failed_reconstruction_count"] = Value::Null;
            }
            fs::write(&path, serde_json::to_vec(&wire).unwrap()).unwrap();
            let mut loaded = ScanIndex::load(&path).unwrap();
            assert!(loaded.decode_holds.is_empty());
            assert_eq!(
                loaded.quarantined_snapshot_fingerprints[&fingerprint].reconstruction_contract,
                version.unwrap_or(1)
            );
            assert_eq!(
                loaded.quarantined_snapshot_fingerprints[&fingerprint].disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            loaded.save(&path).unwrap();
            assert_eq!(
                ScanIndex::load(&path)
                    .unwrap()
                    .quarantined_snapshot_fingerprints[&fingerprint],
                loaded.quarantined_snapshot_fingerprints[&fingerprint]
            );
        }
    }
}

#[test]
fn terminal_contract_load_is_paced_and_preserves_account_and_history_state() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-load");
    let path = scratch.join("index.json");
    let fingerprint = "a".repeat(64);
    let mut index = ScanIndex::default();
    index
        .quarantined_snapshot_fingerprints
        .insert(fingerprint.clone(), terminal(SnapshotSource::ClaudeCode));
    let binding = SessionAccountBinding {
        account_identifier_hash: "c".repeat(64),
        workspace_identifier_hash: Some("d".repeat(64)),
    };
    index
        .session_account_bindings
        .insert("owner".into(), binding.clone());
    index.claude_history_gate_loaded = true;
    index.claude_history_cutoff_unix_seconds = Some(1_790_000_000);
    index.save(&path).unwrap();
    let history_before = serde_json::to_value(&index.claude_full_rearm_progress).unwrap();
    with_contract(2, || {
        let before = sampled_scan::now_seconds();
        let mut loaded = ScanIndex::load_for_snapshot_source(
            &path,
            SnapshotSource::ClaudeCode,
            scratch.as_ref(),
        )
        .unwrap();
        let record = &loaded.quarantined_snapshot_fingerprints[&fingerprint];
        assert_eq!(record.reconstruction_contract, 2);
        assert_eq!(
            record.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        );
        assert_eq!(
            record.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert!(record.retry_after_unix_seconds >= before + SNAPSHOT_QUARANTINE_RETRY_SECONDS);
        assert!(
            record.retry_after_unix_seconds
                < sampled_scan::now_seconds() + 2 * SNAPSHOT_QUARANTINE_RETRY_SECONDS
        );
        assert_eq!(
            record.upload_body_witness.as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(loaded.session_account_bindings["owner"], binding);
        assert_eq!(
            serde_json::to_value(&loaded.claude_full_rearm_progress).unwrap(),
            history_before
        );
        assert_eq!(
            loaded.claude_history_cutoff_unix_seconds,
            index.claude_history_cutoff_unix_seconds
        );
        assert!(loaded.claude_history_gate_loaded);
        let records = loaded.quarantined_snapshot_fingerprints.clone();
        loaded.save(&path).unwrap();
        let restarted = ScanIndex::load(&path).unwrap();
        assert_eq!(
            restarted.quarantined_snapshot_fingerprints, records,
            "same-version reload never grants another attempt or postpones the due time"
        );
        assert_eq!(restarted.session_account_bindings["owner"], binding);
    });
}

#[test]
fn terminal_contract_retry_reads_only_the_owning_file() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-file-read");
    let root = scratch.join("sources");
    fs::create_dir_all(&root).unwrap();
    for name in ["held", "unrelated"] {
        fs::write(
            root.join(format!("{name}.jsonl")),
            format!(
                "{}\n",
                json!({
                    "timestamp":"2026-10-25T07:00:00Z", "type":"assistant", "sessionId":name,
                    "requestId":format!("req-{name}"), "message":{"id":format!("msg-{name}"),
                    "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}
                })
            ),
        )
        .unwrap();
    }
    let scan = |index: &mut ScanIndex| {
        scan_source_roots(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            "2026-10-25T07:01:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    };
    let mut index = ScanIndex::default();
    let initial = scan(&mut index);
    assert_eq!(initial.scanned_file_count, 2);
    let held = initial
        .snapshots
        .iter()
        .find(|item| item.source_session_id == "held")
        .unwrap();
    let fingerprint = held.snapshot_fingerprint.clone();
    let mut record = terminal(SnapshotSource::ClaudeCode);
    record.upload_body_witness = Some(snapshot_upload_body_witness(held));
    index
        .quarantined_snapshot_fingerprints
        .insert(fingerprint.clone(), record);
    assert_eq!(scan(&mut index).scanned_file_count, 0, "quiet baseline");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    with_contract(2, || {
        let mut loaded = ScanIndex::load_for_snapshot_source(
            &path,
            SnapshotSource::ClaudeCode,
            scratch.as_ref(),
        )
        .unwrap();
        assert_eq!(
            scan(&mut loaded).scanned_file_count,
            0,
            "contract bump waits for the paced deadline"
        );
        loaded
            .quarantined_snapshot_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        terminal_contract_retry::claim(
            loaded
                .quarantined_snapshot_fingerprints
                .get_mut(&fingerprint)
                .unwrap(),
        );
        loaded.save(&path).unwrap();
        loaded.activate_terminal_contract_retries(BTreeSet::from([fingerprint.clone()]));
        let due = scan(&mut loaded);
        assert_eq!(due.scanned_file_count, 1);
        assert_eq!(due.snapshots.len(), 1);
        assert_eq!(due.snapshots[0].source_session_id, "held");
        assert_eq!(due.snapshots[0].snapshot_fingerprint, fingerprint);
        // Exactly one file entered acquisition/parser and it is the held
        // file: unrelated full reads (and incremental reads) are both zero.
        let unrelated_full_reads = due.scanned_file_count
            - due
                .snapshots
                .iter()
                .filter(|s| s.source_session_id == "held")
                .count();
        assert_eq!(unrelated_full_reads, 0);
    });
}

#[test]
fn terminal_contract_valid_values_are_not_coerced_by_tolerant_decode() {
    for version in [0, 1, 2, u16::MAX] {
        let mut wire = serde_json::to_value(terminal(SnapshotSource::ClaudeCode)).unwrap();
        wire["reconstruction_contract"] = json!(version);
        let decoded: SnapshotQuarantineRecord = serde_json::from_value(wire).unwrap();
        assert_eq!(decoded.reconstruction_contract, version);
        let restarted: SnapshotQuarantineRecord =
            serde_json::from_slice(&serde_json::to_vec(&decoded).unwrap()).unwrap();
        assert_eq!(restarted, decoded);
    }
}
