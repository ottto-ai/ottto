use super::*;
use crate::snapshots::terminal_contract_retry::with_contract;

#[test]
fn terminal_contract_v1_to_v2_one_paced_attempt_then_terminal_on_failure() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-progress");
    let path = scratch.join("progress.json");
    let fingerprint = "a".repeat(64);
    let body = "b".repeat(64);
    let mut progress = test_upload_progress();
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &body);
    }
    progress.save(&path).unwrap();
    let stale_index = progress.quarantined_fingerprints.clone();
    let namespace = progress.destination_namespace_hash.clone();
    let mut same_version =
        SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
    assert!(!same_version.prepare_quarantine_retries(&stale_index));
    assert_eq!(same_version.quarantined_fingerprints, stale_index);
    with_contract(2, || {
        // Even a simultaneous witness change must wait for the paced retry.
        let mut witness = test_quarantine_witness();
        witness.collector_version = "synthetic-v2".into();
        let before = current_unix_seconds();
        let mut loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
        let record = &loaded.quarantined_fingerprints[&fingerprint];
        assert_eq!(record.reconstruction_contract, 2);
        assert_eq!(
            record.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        );
        assert_eq!(record.witness, witness);
        assert!(record.retry_after_unix_seconds >= before + SNAPSHOT_QUARANTINE_RETRY_SECONDS);
        assert!(
            loaded.prepare_quarantine_retries(&stale_index),
            "migration must be saved even before any lease is due"
        );
        assert!(loaded.active_quarantine_retries.is_empty());
        loaded.save(&path).unwrap();
        let record = loaded.quarantined_fingerprints[&fingerprint].clone();
        loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
        assert!(!loaded.prepare_quarantine_retries(&stale_index));
        assert_eq!(loaded.quarantined_fingerprints[&fingerprint], record);
        loaded
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        assert!(loaded.prepare_quarantine_retries(&stale_index));
        assert_eq!(
            loaded.active_quarantine_retries,
            BTreeSet::from([fingerprint.clone()])
        );
        loaded.save(&path).unwrap();
        // The same failed reconstruction boundary used by rejected uploads.
        loaded.quarantine_body(&fingerprint, &body);
        let terminal = &loaded.quarantined_fingerprints[&fingerprint];
        assert_eq!(terminal.reconstruction_contract, 2);
        assert_eq!(
            terminal.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        );
        assert_eq!(
            terminal.disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert_eq!(terminal.retry_after_unix_seconds, 0);
        loaded.save(&path).unwrap();
        for _ in 0..3 {
            loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
            assert!(!loaded.prepare_quarantine_retries(&stale_index));
            assert!(loaded.active_quarantine_retries.is_empty());
        }
    });
}

#[test]
fn terminal_off_on_terminal_contract_v1_to_v2_one_paced_attempt_then_terminal_on_failure() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-progress");
    let path = scratch.join("progress.json");
    let fingerprint = "a".repeat(64);
    let body = "b".repeat(64);
    let mut progress = test_upload_progress();
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &body);
    }
    progress.save(&path).unwrap();
    let stale_index = progress.quarantined_fingerprints.clone();
    let namespace = progress.destination_namespace_hash.clone();
    let mut same_version =
        SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
    assert!(!same_version.prepare_quarantine_retries(&stale_index));
    assert_eq!(same_version.quarantined_fingerprints, stale_index);
    with_contract(2, || {
        // Even a simultaneous witness change must wait for the paced retry.
        let mut witness = test_quarantine_witness();
        witness.collector_version = "synthetic-v2".into();
        let before = current_unix_seconds();
        let mut loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
        let record = &loaded.quarantined_fingerprints[&fingerprint];
        assert_eq!(record.reconstruction_contract, 2);
        assert_eq!(
            record.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        );
        assert_eq!(record.witness, witness);
        assert!(record.retry_after_unix_seconds >= before + SNAPSHOT_QUARANTINE_RETRY_SECONDS);
        assert!(
            loaded.prepare_quarantine_retries(&stale_index),
            "migration must be saved even before any lease is due"
        );
        assert!(loaded.active_quarantine_retries.is_empty());
        loaded.save(&path).unwrap();
        let record = loaded.quarantined_fingerprints[&fingerprint].clone();
        loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
        assert!(!loaded.prepare_quarantine_retries(&stale_index));
        assert_eq!(loaded.quarantined_fingerprints[&fingerprint], record);
        loaded
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        assert!(loaded.prepare_quarantine_retries(&stale_index));
        assert_eq!(
            loaded.active_quarantine_retries,
            BTreeSet::from([fingerprint.clone()])
        );
        loaded.save(&path).unwrap();
        // The same failed reconstruction boundary used by rejected uploads.
        loaded.quarantine_body(&fingerprint, &body);
        let terminal = &loaded.quarantined_fingerprints[&fingerprint];
        assert_eq!(terminal.reconstruction_contract, 2);
        assert_eq!(
            terminal.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
        );
        assert_eq!(
            terminal.disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert_eq!(terminal.retry_after_unix_seconds, 0);
        loaded.save(&path).unwrap();
        for _ in 0..3 {
            loaded = SnapshotUploadProgress::load(&path, &namespace, witness.clone()).unwrap();
            assert!(!loaded.prepare_quarantine_retries(&stale_index));
            assert!(loaded.active_quarantine_retries.is_empty());
        }
    });
}

#[test]
fn terminal_contract_current_and_future_versions_and_superseded_never_rearm() {
    let mut progress = test_upload_progress();
    let fingerprint = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &fingerprint);
    }
    for version in [1, 2] {
        progress
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .reconstruction_contract = version;
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            0
        );
    }
    progress
        .quarantined_fingerprints
        .get_mut(&fingerprint)
        .unwrap()
        .disposition = SnapshotQuarantineDisposition::SupersededTerminal;
    with_contract(3, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            0
        );
    });
}

#[test]
fn terminal_off_on_terminal_contract_current_and_future_versions_and_superseded_never_rearm() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut progress = test_upload_progress();
    let fingerprint = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &fingerprint);
    }
    for version in [1, 2] {
        progress
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .reconstruction_contract = version;
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            0
        );
    }
    progress
        .quarantined_fingerprints
        .get_mut(&fingerprint)
        .unwrap()
        .disposition = SnapshotQuarantineDisposition::SupersededTerminal;
    with_contract(3, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            0
        );
    });
}

#[test]
fn terminal_contract_newer_index_assessment_dominates_stale_progress() {
    let mut progress = test_upload_progress();
    let fingerprint = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &fingerprint);
    }
    let mut upgraded = progress.quarantined_fingerprints.clone();
    with_contract(2, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut upgraded,
                progress.active_quarantine_witness.as_ref()
            ),
            1
        );
        assert!(progress.prepare_quarantine_retries(&upgraded));
        assert_eq!(progress.quarantined_fingerprints, upgraded);
        assert!(progress.active_quarantine_retries.is_empty());
    });
}

#[test]
fn terminal_off_on_terminal_contract_newer_index_assessment_dominates_stale_progress() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut progress = test_upload_progress();
    let fingerprint = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fingerprint, &fingerprint);
    }
    let mut upgraded = progress.quarantined_fingerprints.clone();
    with_contract(2, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut upgraded,
                progress.active_quarantine_witness.as_ref()
            ),
            1
        );
        assert!(progress.prepare_quarantine_retries(&upgraded));
        assert_eq!(progress.quarantined_fingerprints, upgraded);
        assert!(progress.active_quarantine_retries.is_empty());
    });
}

#[test]
fn terminal_contract_permanent_refusal_keeps_its_existing_gate() {
    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-permanent");
    let path = scratch.join("progress.json");
    let fingerprint = "a".repeat(64);
    let body = "b".repeat(64);
    let mut progress = test_upload_progress();
    progress.quarantine_permanent_body(&fingerprint, &body, "usage_accounting_authority_downgrade");
    let namespace = progress.destination_namespace_hash.clone();
    progress.save(&path).unwrap();
    let mut index_records = progress.quarantined_fingerprints.clone();
    with_contract(2, || {
        crate::snapshots::terminal_contract_retry::rearm(
            &mut index_records,
            progress.active_quarantine_witness.as_ref(),
        );
        let mut loaded =
            SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
        assert_eq!(
            loaded.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert!(
            loaded.prepare_quarantine_retries(&index_records),
            "persist the newer assessment inherited from the index"
        );
        assert!(loaded.active_quarantine_retries.is_empty());
        assert_eq!(
            loaded.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert_eq!(loaded.permanent_rejections, progress.permanent_rejections);
    });
}

#[test]
fn terminal_off_on_terminal_contract_permanent_refusal_keeps_its_existing_gate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-permanent");
    let path = scratch.join("progress.json");
    let fingerprint = "a".repeat(64);
    let body = "b".repeat(64);
    let mut progress = test_upload_progress();
    progress.quarantine_permanent_body(&fingerprint, &body, "usage_accounting_authority_downgrade");
    let namespace = progress.destination_namespace_hash.clone();
    progress.save(&path).unwrap();
    let mut index_records = progress.quarantined_fingerprints.clone();
    with_contract(2, || {
        crate::snapshots::terminal_contract_retry::rearm(
            &mut index_records,
            progress.active_quarantine_witness.as_ref(),
        );
        let mut loaded =
            SnapshotUploadProgress::load(&path, &namespace, test_quarantine_witness()).unwrap();
        assert_eq!(
            loaded.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert!(
            loaded.prepare_quarantine_retries(&index_records),
            "persist the newer assessment inherited from the index"
        );
        assert!(loaded.active_quarantine_retries.is_empty());
        assert_eq!(
            loaded.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert_eq!(loaded.permanent_rejections, progress.permanent_rejections);
    });
}

// Round 2 uses both real checkpoint writers/readers. The retained identity
// fields live in ScanIndex; exact ACK/cache/refusal evidence lives in progress.
struct RetainedRetryFixture {
    scratch: crate::test_scratch::ScratchDir,
    index_path: PathBuf,
    progress_path: PathBuf,
    namespace: String,
    index_guard: serde_json::Value,
    progress_guard: serde_json::Value,
}

fn held_fingerprint() -> String {
    "1".repeat(64)
}
fn retained_ack() -> String {
    "2".repeat(64)
}
fn retained_refusal() -> String {
    "3".repeat(64)
}
fn held_body() -> String {
    "4".repeat(64)
}
fn retained_ack_body() -> String {
    "5".repeat(64)
}
fn retained_body(fingerprint: &str) -> String {
    if fingerprint == held_fingerprint() {
        held_body()
    } else if fingerprint == retained_ack() {
        retained_ack_body()
    } else {
        fingerprint.to_owned()
    }
}

impl RetainedRetryFixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("terminal-contract-retained");
        let index_path = scratch.join("index.json");
        let progress_path = scratch.join("progress.json");
        let namespace = "c".repeat(64);
        let mut progress = SnapshotUploadProgress::new(
            namespace.clone(),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        );
        for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
            progress.quarantine_body(&held_fingerprint(), &held_body());
        }
        progress.record_body(&retained_ack(), &retained_ack_body());
        progress
            .accepted_cache_heads
            .insert("6".repeat(64), "7".repeat(64));
        progress
            .accepted_cache_states
            .insert("6".repeat(64), serde_json::json!({"observations": []}));
        progress.quarantine_permanent_body(
            &retained_refusal(),
            &retained_refusal(),
            "usage_accounting_authority_downgrade",
        );
        progress.historical_replay_generation = Some("retained-replay".into());
        progress.save(&progress_path).unwrap();
        let progress_guard = serde_json::to_value(&progress).unwrap();
        let mut index = ScanIndex::default();
        for fingerprint in [held_fingerprint(), retained_ack(), retained_refusal()] {
            index.file_snapshot_fingerprints.insert(
                format!("{fingerprint}.jsonl"),
                BTreeSet::from([fingerprint.clone()]),
            );
            index
                .snapshot_activity_at
                .insert(fingerprint, Some("2026-10-25T07:00:00Z".into()));
        }
        index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
        index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        index.save(&index_path).unwrap();
        let mut index_guard = serde_json::to_value(&index).unwrap();
        index_guard["session_account_bindings"] = serde_json::json!({"a".repeat(64): {
            "account_identifier_hash": "8".repeat(64), "workspace_identifier_hash": "9".repeat(64)}});
        index_guard["claude_request_identity_contract"] =
            serde_json::json!("retained-own-request-contract");
        index_guard["claude_request_identity_contract_changed"] = serde_json::json!(true);
        index_guard["claude_history_gate_loaded"] = serde_json::json!(true);
        index_guard["claude_history_cutoff_unix_seconds"] = serde_json::json!(1_790_000_000_u64);
        std::fs::write(&index_path, serde_json::to_vec(&index_guard).unwrap()).unwrap();
        Self {
            scratch,
            index_path,
            progress_path,
            namespace,
            index_guard,
            progress_guard,
        }
    }

    fn load(&self) -> (ScanIndex, SnapshotUploadProgress) {
        let index = ScanIndex::load_for_snapshot_source_with_origin(
            &self.index_path,
            SnapshotSource::ClaudeCode,
            self.scratch.as_ref(),
        )
        .unwrap()
        .0;
        let progress = SnapshotUploadProgress::load(
            &self.progress_path,
            &self.namespace,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        self.assert_retained(&index, &progress);
        (index, progress)
    }

    fn assert_retained(&self, index: &ScanIndex, progress: &SnapshotUploadProgress) {
        let value = serde_json::to_value(index).unwrap();
        for field in [
            "session_account_bindings",
            "claude_request_identity_contract",
            "claude_request_identity_contract_changed",
            "claude_history_gate_loaded",
            "claude_history_cutoff_unix_seconds",
        ] {
            assert_eq!(
                value[field], self.index_guard[field],
                "retained index {field}"
            );
        }
        assert!(index.accepted_snapshot_fingerprint_recorded(&retained_ack()));
        assert!(
            !index.decode_holds_entity(&held_fingerprint()),
            "non-identity damage must not become opaque held debt"
        );
        assert_eq!(progress.destination_namespace_hash, self.namespace);
        assert!(progress.generation >= 1, "no reset to Self::new");
        assert!(progress.accepted_fingerprints.contains(&retained_ack()));
        assert_eq!(
            progress.accepted_body_witnesses[&retained_ack()],
            retained_ack_body()
        );
        let value = serde_json::to_value(progress).unwrap();
        for field in [
            "historical_replay_generation",
            "accepted_cache_heads",
            "accepted_cache_states",
            "permanent_rejections",
        ] {
            assert_eq!(
                value[field], self.progress_guard[field],
                "retained progress {field}"
            );
        }
        assert!(self.index_path.exists() && self.progress_path.exists());
        assert_eq!(
            std::fs::read_dir(self.scratch.as_ref())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("corrupt"))
                .count(),
            0,
            "neither whole checkpoint may be quarantined"
        );
    }
}

#[test]
fn terminal_contract_malformed_values_keep_both_checkpoints_and_one_paced_debt() {
    let malformed = [
        serde_json::Value::Null,
        serde_json::json!("2"),
        serde_json::json!(-1),
        serde_json::json!(65536),
        serde_json::json!(1.5),
        serde_json::json!(false),
        serde_json::json!([1, {"nested": true}]),
        serde_json::json!({"nested": [1, 2]}),
    ];
    for bad in malformed {
        for repair_count in [false, true] {
            for pending in [false, true] {
                let fixture = RetainedRetryFixture::new();
                for (path, field) in [
                    (&fixture.index_path, "quarantined_snapshot_fingerprints"),
                    (&fixture.progress_path, "quarantined_fingerprints"),
                ] {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    let record = &mut value[field][held_fingerprint()];
                    record["reconstruction_contract"] = bad.clone();
                    if pending {
                        record["disposition"] = serde_json::json!("retry_pending");
                        record["failed_reconstruction_count"] = serde_json::json!(1);
                    }
                    // Force ScanIndex's separate scalar-repair representation.
                    if repair_count && field == "quarantined_snapshot_fingerprints" {
                        record["failed_reconstruction_count"] = serde_json::Value::Null;
                    }
                    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                let before = current_unix_seconds();
                let (mut index, mut progress) = fixture.load();
                for record in [
                    &index.quarantined_snapshot_fingerprints[&held_fingerprint()],
                    &progress.quarantined_fingerprints[&held_fingerprint()],
                ] {
                    assert_eq!(
                        record.reconstruction_contract,
                        crate::snapshots::terminal_contract_retry::current_contract()
                    );
                    assert_eq!(
                        record.failed_reconstruction_count,
                        MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
                    );
                    assert_eq!(
                        record.disposition,
                        SnapshotQuarantineDisposition::RetryPending
                    );
                    assert_eq!(
                        record.upload_body_witness.as_deref(),
                        Some(held_body().as_str())
                    );
                    assert!(
                        record.retry_after_unix_seconds
                            >= before + SNAPSHOT_QUARANTINE_RETRY_SECONDS
                    );
                    assert!(
                        record.retry_after_unix_seconds
                            < current_unix_seconds() + 2 * SNAPSHOT_QUARANTINE_RETRY_SECONDS
                    );
                }
                assert!(
                    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints)
                );
                assert!(
                    progress.active_quarantine_retries.is_empty(),
                    "unknown waits for pacing"
                );
                index.save(&fixture.index_path).unwrap();
                progress.save(&fixture.progress_path).unwrap();
                let (restarted_index, mut restarted_progress) = fixture.load();
                assert_eq!(
                    restarted_index.quarantined_snapshot_fingerprints[&held_fingerprint()],
                    index.quarantined_snapshot_fingerprints[&held_fingerprint()]
                );
                assert_eq!(
                    restarted_progress.quarantined_fingerprints[&held_fingerprint()],
                    progress.quarantined_fingerprints[&held_fingerprint()]
                );
                assert!(!restarted_progress.prepare_quarantine_retries(
                    &restarted_index.quarantined_snapshot_fingerprints
                ));
                assert!(restarted_progress.active_quarantine_retries.is_empty());
                fixture.assert_retained(&restarted_index, &restarted_progress);
            }
        }
    }
}

#[test]
fn terminal_off_on_terminal_contract_malformed_values_keep_both_checkpoints_and_one_paced_debt() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let malformed = [
        serde_json::Value::Null,
        serde_json::json!("2"),
        serde_json::json!(-1),
        serde_json::json!(65536),
        serde_json::json!(1.5),
        serde_json::json!(false),
        serde_json::json!([1, {"nested": true}]),
        serde_json::json!({"nested": [1, 2]}),
    ];
    for bad in malformed {
        for repair_count in [false, true] {
            for pending in [false, true] {
                let fixture = RetainedRetryFixture::new();
                for (path, field) in [
                    (&fixture.index_path, "quarantined_snapshot_fingerprints"),
                    (&fixture.progress_path, "quarantined_fingerprints"),
                ] {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    let record = &mut value[field][held_fingerprint()];
                    record["reconstruction_contract"] = bad.clone();
                    if pending {
                        record["disposition"] = serde_json::json!("retry_pending");
                        record["failed_reconstruction_count"] = serde_json::json!(1);
                    }
                    // Force ScanIndex's separate scalar-repair representation.
                    if repair_count && field == "quarantined_snapshot_fingerprints" {
                        record["failed_reconstruction_count"] = serde_json::Value::Null;
                    }
                    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
                }
                let before = current_unix_seconds();
                let (mut index, mut progress) = fixture.load();
                for record in [
                    &index.quarantined_snapshot_fingerprints[&held_fingerprint()],
                    &progress.quarantined_fingerprints[&held_fingerprint()],
                ] {
                    assert_eq!(
                        record.reconstruction_contract,
                        crate::snapshots::terminal_contract_retry::current_contract()
                    );
                    assert_eq!(
                        record.failed_reconstruction_count,
                        MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
                    );
                    assert_eq!(
                        record.disposition,
                        SnapshotQuarantineDisposition::RetryPending
                    );
                    assert_eq!(
                        record.upload_body_witness.as_deref(),
                        Some(held_body().as_str())
                    );
                    assert!(
                        record.retry_after_unix_seconds
                            >= before + SNAPSHOT_QUARANTINE_RETRY_SECONDS
                    );
                    assert!(
                        record.retry_after_unix_seconds
                            < current_unix_seconds() + 2 * SNAPSHOT_QUARANTINE_RETRY_SECONDS
                    );
                }
                assert!(
                    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints)
                );
                assert!(
                    progress.active_quarantine_retries.is_empty(),
                    "unknown waits for pacing"
                );
                index.save(&fixture.index_path).unwrap();
                progress.save(&fixture.progress_path).unwrap();
                let (restarted_index, mut restarted_progress) = fixture.load();
                assert_eq!(
                    restarted_index.quarantined_snapshot_fingerprints[&held_fingerprint()],
                    index.quarantined_snapshot_fingerprints[&held_fingerprint()]
                );
                assert_eq!(
                    restarted_progress.quarantined_fingerprints[&held_fingerprint()],
                    progress.quarantined_fingerprints[&held_fingerprint()]
                );
                assert!(!restarted_progress.prepare_quarantine_retries(
                    &restarted_index.quarantined_snapshot_fingerprints
                ));
                assert!(restarted_progress.active_quarantine_retries.is_empty());
                fixture.assert_retained(&restarted_index, &restarted_progress);
            }
        }
    }
}

fn successful_contract_retry(restart_after_selection: bool) {
    let fixture = RetainedRetryFixture::new();
    with_contract(2, || {
        let (mut index, mut progress) = fixture.load();
        assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
        assert!(progress.active_quarantine_retries.is_empty());
        index.save(&fixture.index_path).unwrap();
        progress.save(&fixture.progress_path).unwrap();
        let stale_index_records = index.quarantined_snapshot_fingerprints.clone();
        progress
            .quarantined_fingerprints
            .get_mut(&held_fingerprint())
            .unwrap()
            .retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&stale_index_records));
        assert_eq!(
            progress.active_quarantine_retries,
            BTreeSet::from([held_fingerprint()])
        );
        progress.save(&fixture.progress_path).unwrap();
        let selected = progress.quarantined_fingerprints[&held_fingerprint()].clone();
        assert_eq!(selected.reconstruction_contract, 2);
        assert_eq!(
            selected.failed_reconstruction_count,
            MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
        );
        assert_eq!(
            selected.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert!(
            selected.retry_after_unix_seconds
                >= current_unix_seconds() + SNAPSHOT_QUARANTINE_RETRY_SECONDS - 1
        );
        fixture.assert_retained(&index, &progress);
        if restart_after_selection {
            drop(progress);
            drop(index);
            (index, progress) = fixture.load();
            assert!(
                progress.active_quarantine_retries.is_empty(),
                "runtime lease must not survive restart"
            );
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()],
                selected
            );
            assert!(
                !progress.prepare_quarantine_retries(&stale_index_records),
                "saved lease cannot be consumed early again"
            );
            assert!(progress.contains_body(&held_fingerprint(), &held_body()));
            fixture.assert_retained(&index, &progress);
            // Advance the synthetic persisted deadline; no outcome was received.
            progress
                .quarantined_fingerprints
                .get_mut(&held_fingerprint())
                .unwrap()
                .retry_after_unix_seconds = 0;
            progress.save(&fixture.progress_path).unwrap();
            (index, progress) = fixture.load();
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].failed_reconstruction_count,
                selected.failed_reconstruction_count
            );
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].reconstruction_contract,
                selected.reconstruction_contract
            );
            assert!(
                progress.prepare_quarantine_retries(&stale_index_records),
                "interrupted attempt remains owed after pacing"
            );
            assert_eq!(
                progress.active_quarantine_retries,
                BTreeSet::from([held_fingerprint()])
            );
            progress.save(&fixture.progress_path).unwrap();
        }
        // The unrelated permanent refusal remains in the durable fixture,
        // outside this attempt's frozen input. Including it would correctly
        // report the whole input as Rejected despite accepting the retry.
        let items = vec![held_fingerprint()];
        let mut accepted = 0;
        let mut offered = Vec::new();
        let result = upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |fp| retained_body(fp),
            |batch| {
                assert_eq!(
                    batch,
                    vec![held_fingerprint()],
                    "pre-existing ACK and refusal must not be uploaded"
                );
                offered.extend(batch.clone());
                let response = entity_ack_batch(&batch, &[], &[]);
                response.validate_entity_ack_identities(
                    batch
                        .iter()
                        .map(|fp| (format!("session-{fp}"), fp.clone()))
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|(id, fp)| (id.as_str(), fp.as_str())),
                )?;
                Ok(response)
            },
            |state| state.save(&fixture.progress_path),
        )
        .unwrap();
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(accepted, 1);
        assert_eq!(offered, vec![held_fingerprint()]);
        assert!(!progress
            .quarantined_fingerprints
            .contains_key(&held_fingerprint()));
        assert_eq!(
            progress.accepted_body_witnesses[&held_fingerprint()],
            held_body()
        );
        assert!(
            !progress.prepare_quarantine_retries(&stale_index_records),
            "exact ACK dominates stale index after successful retry"
        );
        index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
        index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        assert!(index.accepted_snapshot_fingerprint_recorded(&held_fingerprint()));
        index.save(&fixture.index_path).unwrap();
        progress.save(&fixture.progress_path).unwrap();
        (index, progress) = fixture.load();
        assert!(index.accepted_snapshot_fingerprint_recorded(&held_fingerprint()));
        assert!(!index
            .quarantined_snapshot_fingerprints
            .contains_key(&held_fingerprint()));
        assert!(!progress.prepare_quarantine_retries(&stale_index_records));
        assert!(progress.active_quarantine_retries.is_empty());
        let mut duplicate_uploads = 0;
        let mut duplicate_accepted = 0;
        let duplicate_result = upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut duplicate_accepted,
            String::as_str,
            |fp| retained_body(fp),
            |batch| {
                duplicate_uploads += 1;
                Ok(entity_ack_batch(&batch, &[], &[]))
            },
            |state| state.save(&fixture.progress_path),
        )
        .unwrap();
        assert_eq!(duplicate_result, ResumableUploadResult::Completed);
        assert_eq!(
            (duplicate_uploads, duplicate_accepted),
            (0, 0),
            "settles exactly once across restart"
        );
        fixture.assert_retained(&index, &progress);
    });
}

#[test]
fn terminal_contract_bump_successful_ack_settles_once_with_stale_index() {
    successful_contract_retry(false);
}

#[test]
fn terminal_off_on_terminal_contract_bump_successful_ack_settles_once_with_stale_index() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    successful_contract_retry(false);
}

#[test]
fn terminal_contract_restart_after_saved_lease_keeps_owed_attempt_and_identity() {
    successful_contract_retry(true);
}

#[test]
fn terminal_off_on_terminal_contract_restart_after_saved_lease_keeps_owed_attempt_and_identity() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    successful_contract_retry(true);
}

// Every pass uses the real source scanner on two unchanged synthetic files.
// The parser acquisition observer counts actual opened source inputs, including
// unrelated files, rather than inferring reads from selected fingerprints.
struct ReadBudgetFixture {
    retained: RetainedRetryFixture,
    root: PathBuf,
    fingerprint: String,
    body: String,
}
impl ReadBudgetFixture {
    fn new() -> Self {
        let mut retained = RetainedRetryFixture::new();
        let root = retained.scratch.join("sources");
        std::fs::create_dir_all(&root).unwrap();
        for name in ["held", "unrelated"] {
            std::fs::write(
                root.join(format!("{name}.jsonl")),
                format!(
                    "{}\n",
                    serde_json::json!({
                        "timestamp":"2026-10-25T07:00:00Z", "type":"assistant", "sessionId":name,
                        "requestId":format!("req-{name}"), "message":{"id":format!("msg-{name}"),
                        "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}
                    })
                ),
            )
            .unwrap();
        }
        let mut seeded = ScanIndex::default();
        let initial = Self::scan_root(&root, &mut seeded);
        assert_eq!(initial.scanned_file_count, 2);
        let held = initial
            .snapshots
            .iter()
            .find(|s| s.source_session_id == "held")
            .unwrap();
        let fingerprint = held.snapshot_fingerprint.clone();
        let body = snapshot_upload_body_witness(held);
        let (mut index, mut progress) = retained.load();
        progress
            .quarantined_fingerprints
            .remove(&held_fingerprint());
        for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
            progress.quarantine_body(&fingerprint, &body);
        }
        // Keep the scanner's complete settled baseline (roots, family census
        // and current identity contract). A deliberately stale identity token
        // would independently and correctly request history reconstruction.
        let old = serde_json::to_value(&index).unwrap();
        let mut settled = serde_json::to_value(&seeded).unwrap();
        retained.index_guard["claude_request_identity_contract"] =
            settled["claude_request_identity_contract"].clone();
        for field in [
            "generation",
            "session_account_bindings",
            "claude_request_identity_contract_changed",
            "claude_history_gate_loaded",
            "claude_history_cutoff_unix_seconds",
            "accepted_snapshot_fingerprints",
            "accepted_snapshot_fingerprint_ledger_version",
        ] {
            settled[field] = old[field].clone();
        }
        let old_incidence = index.file_snapshot_fingerprints.clone();
        index = serde_json::from_value(settled).unwrap();
        index.file_snapshot_fingerprints.extend(old_incidence);
        index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
        index.save(&retained.index_path).unwrap();
        progress.save(&retained.progress_path).unwrap();
        Self {
            retained,
            root,
            fingerprint,
            body,
        }
    }

    fn scan_root(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return Self::terminal_off_on_scan_root(root, index);
        }
        crate::snapshots::scan_source_roots(
            SnapshotSource::ClaudeCode,
            &[root.to_owned()],
            index,
            "2026-10-25T07:01:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    }

    fn terminal_off_on_scan_root(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
        let mut scan = crate::snapshots::scan_source_roots_with_attribution_and_hints(
            SnapshotSource::ClaudeCode,
            &[root.to_owned()],
            index,
            "2026-10-25T07:01:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            true,
            None,
            &std::fs::read_dir(root)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect::<Vec<_>>(),
            false,
        )
        .unwrap();
        crate::snapshots::finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, index);
        scan
    }

    fn scan(&self, index: &ScanIndex) -> BTreeMap<PathBuf, usize> {
        let (scan, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
            Self::scan_root(&self.root, &mut index.clone())
        });
        assert_eq!(scan.scanned_file_count, reads.values().sum::<usize>());
        assert_eq!(
            reads.get(&self.root.join("unrelated.jsonl")),
            None,
            "unrelated full and incremental source acquisitions stay zero"
        );
        assert!(scan.snapshots.iter().all(|s| s.source_session_id == "held"));
        reads
    }

    fn due_claim(&self) -> (ScanIndex, SnapshotUploadProgress) {
        let (mut index, mut progress) = self.retained.load();
        progress
            .quarantined_fingerprints
            .get_mut(&self.fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
        progress.save(&self.retained.progress_path).unwrap();
        save_terminal_contract_claims_for_scan(&mut index, &progress, &self.retained.index_path)
            .unwrap();
        (index, progress)
    }
}

#[derive(Clone, Copy, Debug)]
enum InterruptedOutcome {
    Restart,
    Conflict,
    SaveFailure,
}

fn contract_read_cap(outcome: InterruptedOutcome, unbound_body: bool) {
    let fixture = ReadBudgetFixture::new();
    if unbound_body {
        let (mut index, mut progress) = fixture.retained.load();
        index
            .quarantined_snapshot_fingerprints
            .get_mut(&fixture.fingerprint)
            .unwrap()
            .upload_body_witness = None;
        progress
            .quarantined_fingerprints
            .get_mut(&fixture.fingerprint)
            .unwrap()
            .upload_body_witness = None;
        index.save(&fixture.retained.index_path).unwrap();
        progress.save(&fixture.retained.progress_path).unwrap();
    }
    with_contract(2, || {
        let (mut index, mut progress) = fixture.retained.load();
        assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
        assert!(progress.active_quarantine_retries.is_empty());
        progress.save(&fixture.retained.progress_path).unwrap();
        index.save(&fixture.retained.index_path).unwrap();
        assert!(fixture.scan(&index).is_empty(), "bump alone never reads");
        let stale_index = index.quarantined_snapshot_fingerprints.clone();
        let mut total_reads = 0;
        let exhausted_before = crate::snapshots::terminal_contract_retry::exhausted_count();
        for cycle in 0..7 {
            (index, progress) = fixture.due_claim();
            let reads = fixture.scan(&index);
            let expected = if cycle < 2 { 1 } else { 0 };
            assert_eq!(
                reads.values().sum::<usize>(),
                expected,
                "{outcome:?} cycle {cycle}"
            );
            total_reads += reads.values().sum::<usize>();
            let record = &progress.quarantined_fingerprints[&fixture.fingerprint];
            assert_eq!(record.reconstruction_contract, 2);
            assert_eq!(
                record.contract_retry_claims,
                Some((cycle + 1).min(2) as u16)
            );
            assert_eq!(
                index.quarantined_snapshot_fingerprints[&fixture.fingerprint].contract_retry_claims,
                record.contract_retry_claims,
                "index claim saved before acquisition"
            );
            if expected == 0 {
                assert_eq!(
                    record.disposition,
                    SnapshotQuarantineDisposition::UnprovenTerminal
                );
                assert_eq!(
                    record.failed_reconstruction_count,
                    MAX_SNAPSHOT_RECONSTRUCTION_FAILURES
                );
                assert!(progress.active_quarantine_retries.is_empty());
                assert!(!progress.prepare_quarantine_retries(&stale_index));
                fixture.retained.assert_retained(&index, &progress);
                continue;
            }
            assert_eq!(
                record.failed_reconstruction_count,
                MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
            );
            match outcome {
                InterruptedOutcome::Restart => {} // Lose all volatile state before any outcome.
                InterruptedOutcome::Conflict | InterruptedOutcome::SaveFailure => {
                    let mut accepted = 0;
                    // ACK lifetime is independent of this incremental input.
                    // Keep the sibling out of the delta to exercise retention.
                    let items = vec![fixture.fingerprint.clone()];
                    let temp = fixture
                        .retained
                        .progress_path
                        .with_extension(format!("json.{}.tmp", std::process::id()));
                    if matches!(outcome, InterruptedOutcome::SaveFailure) {
                        std::fs::create_dir(&temp).unwrap(); // Fail the actual checkpoint create, after reading.
                    }
                    let result = upload_resumable_batches_with_body_witness(
                        &items,
                        &unique_poison_scope(),
                        &mut progress,
                        &mut accepted,
                        String::as_str,
                        |fp| {
                            if fp == &fixture.fingerprint {
                                fixture.body.clone()
                            } else {
                                retained_body(fp)
                            }
                        },
                        |batch| {
                            assert_eq!(
                                batch,
                                vec![fixture.fingerprint.clone()],
                                "the retained exact ACK must never be offered again"
                            );
                            Ok(entity_ack_batch(&[], &[], &batch))
                        },
                        |state| state.save(&fixture.retained.progress_path),
                    );
                    if matches!(outcome, InterruptedOutcome::SaveFailure) {
                        assert!(result.is_err(), "real outcome persistence must fail");
                        std::fs::remove_dir(&temp).unwrap();
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            ResumableUploadResult::Deferred { count: 1 }
                        );
                    }
                    assert_eq!(accepted, 0);
                }
            }
            drop(progress);
            drop(index);
            (index, progress) = fixture.retained.load();
            let saved = progress.quarantined_fingerprints[&fixture.fingerprint].clone();
            assert_eq!(saved.contract_retry_claims, Some(cycle as u16 + 1));
            assert_eq!(saved.reconstruction_contract, 2);
            assert!(!index.decode_holds_entity(&fixture.fingerprint));
            // Reload never restores a volatile lease; the next attempt waits.
            progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
            assert!(progress.active_quarantine_retries.is_empty());
            assert!(fixture.scan(&index).is_empty());
            if cycle == 0 {
                assert_eq!(
                    saved.disposition,
                    SnapshotQuarantineDisposition::RetryPending
                );
                assert_eq!(
                    saved.failed_reconstruction_count,
                    MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1
                );
                assert!(
                    saved.retry_after_unix_seconds
                        >= current_unix_seconds() + SNAPSHOT_QUARANTINE_RETRY_SECONDS - 1
                );
            }
            fixture.retained.assert_retained(&index, &progress);
        }
        assert_eq!(
            total_reads, 2,
            "{outcome:?}: actual owning-file acquisitions across all cycles"
        );
        assert!(crate::snapshots::terminal_contract_retry::exhausted_count() > exhausted_before);
    });
}

#[test]
fn terminal_contract_restart_before_outcome_allows_one_more_paced_source_read() {
    contract_read_cap(InterruptedOutcome::Restart, false);
}

#[test]
fn terminal_off_on_terminal_contract_restart_before_outcome_allows_one_more_paced_source_read() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_read_cap(InterruptedOutcome::Restart, false);
}
#[test]
fn terminal_contract_repeated_conflicts_cap_actual_source_reads_at_two() {
    contract_read_cap(InterruptedOutcome::Conflict, false);
}

#[test]
fn terminal_off_on_terminal_contract_repeated_conflicts_cap_actual_source_reads_at_two() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_read_cap(InterruptedOutcome::Conflict, false);
}
#[test]
fn terminal_contract_failed_outcome_save_caps_actual_source_reads_at_two() {
    contract_read_cap(InterruptedOutcome::SaveFailure, false);
}

#[test]
fn terminal_off_on_terminal_contract_failed_outcome_save_caps_actual_source_reads_at_two() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_read_cap(InterruptedOutcome::SaveFailure, false);
}

#[test]
fn terminal_contract_stale_index_and_same_generation_cas_keep_maximum_claim() {
    let fixture = ReadBudgetFixture::new();
    with_contract(2, || {
        let (_, progress) = fixture.due_claim();
        let stale = progress.quarantined_fingerprints.clone();
        let (mut index, mut progress) = fixture.due_claim();
        assert_eq!(
            progress.quarantined_fingerprints[&fixture.fingerprint].contract_retry_claims,
            Some(2)
        );
        index.retain_quarantined_fingerprints(&stale);
        assert_eq!(
            index.quarantined_snapshot_fingerprints[&fixture.fingerprint].contract_retry_claims,
            Some(2)
        );
        // Older records embedded in a current generation cannot lower either
        // CAS, including an index copy from before this contract version.
        for old_version in [2, 1] {
            let mut old = stale[&fixture.fingerprint].clone();
            old.reconstruction_contract = old_version;
            index
                .quarantined_snapshot_fingerprints
                .insert(fixture.fingerprint.clone(), old.clone());
            index.save(&fixture.retained.index_path).unwrap();
            progress
                .quarantined_fingerprints
                .insert(fixture.fingerprint.clone(), old);
            progress.save(&fixture.retained.progress_path).unwrap();
        }
        (index, progress) = fixture.retained.load();
        for record in [
            &index.quarantined_snapshot_fingerprints[&fixture.fingerprint],
            &progress.quarantined_fingerprints[&fixture.fingerprint],
        ] {
            assert_eq!(record.contract_retry_claims, Some(2));
        }
        assert!(progress.prepare_quarantine_retries(&stale)); // Exhaustion must be saved.
        assert!(progress.active_quarantine_retries.is_empty());
        progress.save(&fixture.retained.progress_path).unwrap();
        save_terminal_contract_claims_for_scan(&mut index, &progress, &fixture.retained.index_path)
            .unwrap();
        assert!(fixture.scan(&index).is_empty());
        fixture.retained.assert_retained(&index, &progress);
    });
}

#[test]
fn terminal_off_on_terminal_contract_stale_index_and_same_generation_cas_keep_maximum_claim() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = ReadBudgetFixture::new();
    with_contract(2, || {
        let (_, progress) = fixture.due_claim();
        let stale = progress.quarantined_fingerprints.clone();
        let (mut index, mut progress) = fixture.due_claim();
        assert_eq!(
            progress.quarantined_fingerprints[&fixture.fingerprint].contract_retry_claims,
            Some(2)
        );
        index.retain_quarantined_fingerprints(&stale);
        assert_eq!(
            index.quarantined_snapshot_fingerprints[&fixture.fingerprint].contract_retry_claims,
            Some(2)
        );
        // Older records embedded in a current generation cannot lower either
        // CAS, including an index copy from before this contract version.
        for old_version in [2, 1] {
            let mut old = stale[&fixture.fingerprint].clone();
            old.reconstruction_contract = old_version;
            index
                .quarantined_snapshot_fingerprints
                .insert(fixture.fingerprint.clone(), old.clone());
            index.save(&fixture.retained.index_path).unwrap();
            progress
                .quarantined_fingerprints
                .insert(fixture.fingerprint.clone(), old);
            progress.save(&fixture.retained.progress_path).unwrap();
        }
        (index, progress) = fixture.retained.load();
        for record in [
            &index.quarantined_snapshot_fingerprints[&fixture.fingerprint],
            &progress.quarantined_fingerprints[&fixture.fingerprint],
        ] {
            assert_eq!(record.contract_retry_claims, Some(2));
        }
        assert!(progress.prepare_quarantine_retries(&stale)); // Exhaustion must be saved.
        assert!(progress.active_quarantine_retries.is_empty());
        progress.save(&fixture.retained.progress_path).unwrap();
        save_terminal_contract_claims_for_scan(&mut index, &progress, &fixture.retained.index_path)
            .unwrap();
        assert!(fixture.scan(&index).is_empty());
        fixture.retained.assert_retained(&index, &progress);
    });
}

#[test]
fn terminal_contract_malformed_claims_exhaust_without_reset_or_opaque_hold() {
    for bad in [
        serde_json::Value::Null,
        serde_json::json!("1"),
        serde_json::json!(-1),
        serde_json::json!(65536),
        serde_json::json!([1]),
        serde_json::json!({"claim":1}),
    ] {
        for repair in [false, true] {
            let fixture = RetainedRetryFixture::new();
            for (path, field) in [
                (&fixture.index_path, "quarantined_snapshot_fingerprints"),
                (&fixture.progress_path, "quarantined_fingerprints"),
            ] {
                let mut wire: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                let record = &mut wire[field][held_fingerprint()];
                record["contract_retry_claims"] = bad.clone();
                record["disposition"] = serde_json::json!("retry_pending");
                record["failed_reconstruction_count"] =
                    serde_json::json!(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1);
                record["retry_after_unix_seconds"] =
                    serde_json::json!(quarantine_retry_after(&held_fingerprint()));
                if repair && field == "quarantined_snapshot_fingerprints" {
                    record["failed_reconstruction_count"] = serde_json::Value::Null;
                }
                std::fs::write(path, serde_json::to_vec(&wire).unwrap()).unwrap();
            }
            let (mut index, mut progress) = fixture.load();
            assert_eq!(
                index.quarantined_snapshot_fingerprints[&held_fingerprint()].contract_retry_claims,
                Some(2)
            );
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].contract_retry_claims,
                Some(2)
            );
            assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
            assert!(progress.active_quarantine_retries.is_empty());
            progress.save(&fixture.progress_path).unwrap();
            save_terminal_contract_claims_for_scan(&mut index, &progress, &fixture.index_path)
                .unwrap();
            let (index, mut progress) = fixture.load();
            assert!(!progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            fixture.assert_retained(&index, &progress);
        }
    }
}

#[test]
fn terminal_off_on_terminal_contract_malformed_claims_exhaust_without_reset_or_opaque_hold() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for bad in [
        serde_json::Value::Null,
        serde_json::json!("1"),
        serde_json::json!(-1),
        serde_json::json!(65536),
        serde_json::json!([1]),
        serde_json::json!({"claim":1}),
    ] {
        for repair in [false, true] {
            let fixture = RetainedRetryFixture::new();
            for (path, field) in [
                (&fixture.index_path, "quarantined_snapshot_fingerprints"),
                (&fixture.progress_path, "quarantined_fingerprints"),
            ] {
                let mut wire: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                let record = &mut wire[field][held_fingerprint()];
                record["contract_retry_claims"] = bad.clone();
                record["disposition"] = serde_json::json!("retry_pending");
                record["failed_reconstruction_count"] =
                    serde_json::json!(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1);
                record["retry_after_unix_seconds"] =
                    serde_json::json!(quarantine_retry_after(&held_fingerprint()));
                if repair && field == "quarantined_snapshot_fingerprints" {
                    record["failed_reconstruction_count"] = serde_json::Value::Null;
                }
                std::fs::write(path, serde_json::to_vec(&wire).unwrap()).unwrap();
            }
            let (mut index, mut progress) = fixture.load();
            assert_eq!(
                index.quarantined_snapshot_fingerprints[&held_fingerprint()].contract_retry_claims,
                Some(2)
            );
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].contract_retry_claims,
                Some(2)
            );
            assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
            assert!(progress.active_quarantine_retries.is_empty());
            progress.save(&fixture.progress_path).unwrap();
            save_terminal_contract_claims_for_scan(&mut index, &progress, &fixture.index_path)
                .unwrap();
            let (index, mut progress) = fixture.load();
            assert!(!progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
            assert_eq!(
                progress.quarantined_fingerprints[&held_fingerprint()].disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            fixture.assert_retained(&index, &progress);
        }
    }
}

#[test]
fn terminal_contract_next_version_starts_a_distinct_paced_budget() {
    let mut progress = test_upload_progress();
    let fp = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fp, &fp);
    }
    with_contract(2, || {
        crate::snapshots::terminal_contract_retry::rearm(
            &mut progress.quarantined_fingerprints,
            progress.active_quarantine_witness.as_ref(),
        );
        let record = progress.quarantined_fingerprints.get_mut(&fp).unwrap();
        record.retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
        assert_eq!(
            progress.quarantined_fingerprints[&fp].contract_retry_claims,
            Some(1)
        );
    });
    with_contract(3, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            1
        );
        let record = &progress.quarantined_fingerprints[&fp];
        assert_eq!(record.reconstruction_contract, 3);
        assert_eq!(record.contract_retry_claims, Some(0));
        assert!(
            record.retry_after_unix_seconds
                >= current_unix_seconds() + SNAPSHOT_QUARANTINE_RETRY_SECONDS - 1
        );
        assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
        assert!(progress.active_quarantine_retries.is_empty());
    });
}

#[test]
fn terminal_off_on_terminal_contract_next_version_starts_a_distinct_paced_budget() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let mut progress = test_upload_progress();
    let fp = "a".repeat(64);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES {
        progress.quarantine_body(&fp, &fp);
    }
    with_contract(2, || {
        crate::snapshots::terminal_contract_retry::rearm(
            &mut progress.quarantined_fingerprints,
            progress.active_quarantine_witness.as_ref(),
        );
        let record = progress.quarantined_fingerprints.get_mut(&fp).unwrap();
        record.retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
        assert_eq!(
            progress.quarantined_fingerprints[&fp].contract_retry_claims,
            Some(1)
        );
    });
    with_contract(3, || {
        assert_eq!(
            crate::snapshots::terminal_contract_retry::rearm(
                &mut progress.quarantined_fingerprints,
                progress.active_quarantine_witness.as_ref()
            ),
            1
        );
        let record = &progress.quarantined_fingerprints[&fp];
        assert_eq!(record.reconstruction_contract, 3);
        assert_eq!(record.contract_retry_claims, Some(0));
        assert!(
            record.retry_after_unix_seconds
                >= current_unix_seconds() + SNAPSHOT_QUARANTINE_RETRY_SECONDS - 1
        );
        assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
        assert!(progress.active_quarantine_retries.is_empty());
    });
}

#[test]
fn terminal_contract_legacy_unknown_body_conflicts_keep_the_two_source_read_cap() {
    contract_read_cap(InterruptedOutcome::Conflict, true);
}

#[test]
fn terminal_off_on_terminal_contract_legacy_unknown_body_conflicts_keep_the_two_source_read_cap() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_read_cap(InterruptedOutcome::Conflict, true);
}

// SOURCE's post-ACK/pre-index crash seam: the scanner's actual next delta
// omits the accepted retry. Both checkpoints must retain the evidence until
// index settlement is durably adopted. No ACK body is added to uploader input.
fn contract_ack_saved_before_index_restart(unrelated: bool) {
    let fixture = ReadBudgetFixture::new();
    with_contract(2, || {
        let (index, mut progress) = fixture.due_claim();
        let mut scan_index = index.clone();
        let first = ReadBudgetFixture::scan_root(&fixture.root, &mut scan_index);
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first.snapshots[0].snapshot_fingerprint, fixture.fingerprint);
        assert!(!index.accepted_snapshot_fingerprint_recorded(&fixture.fingerprint));
        let items = vec![fixture.fingerprint.clone()];
        let mut accepted = 0;
        let result = upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| fixture.body.clone(),
            |batch| {
                assert_eq!(batch, vec![fixture.fingerprint.clone()]);
                let response = entity_ack_batch(&batch, &[], &[]);
                let identities: Vec<_> = batch
                    .iter()
                    .map(|fp| (format!("session-{fp}"), fp.clone()))
                    .collect();
                response.validate_entity_ack_identities(
                    identities.iter().map(|(id, fp)| (id.as_str(), fp.as_str())),
                )?;
                Ok(response)
            },
            |state| state.save(&fixture.retained.progress_path),
        )
        .unwrap();
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(accepted, 1);
        assert_eq!(
            progress.accepted_body_witnesses.get(&fixture.fingerprint),
            Some(&fixture.body)
        );
        fixture.retained.assert_retained(&index, &progress);

        // Crash after the actual uploader's ACK checkpoint, with no index
        // settlement/save. Index still owns the first contract claim.
        drop(scan_index);
        drop(index);
        drop(progress);
        let (mut index, mut progress) = fixture.retained.load();
        assert!(progress
            .accepted_fingerprints
            .contains(&fixture.fingerprint));
        assert!(!index.accepted_snapshot_fingerprint_recorded(&fixture.fingerprint));
        if progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints) {
            progress.save(&fixture.retained.progress_path).unwrap();
        }
        assert!(progress.active_quarantine_retries.is_empty());
        save_terminal_contract_claims_for_scan(&mut index, &progress, &fixture.retained.index_path)
            .unwrap();
        if unrelated {
            std::fs::write(fixture.root.join("later.jsonl"), format!("{}\n", serde_json::json!({
                "timestamp":"2026-10-25T07:00:00Z", "type":"assistant", "sessionId":"later",
                "requestId":"req-later", "message":{"id":"msg-later", "model":"claude-haiku-4-5",
                "usage":{"input_tokens":20,"output_tokens":2}}
            }))).unwrap();
        }
        let committed_index = index.clone();
        let (next, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
            ReadBudgetFixture::scan_root(&fixture.root, &mut index)
        });
        assert_eq!(next.snapshots.len(), usize::from(unrelated));
        assert!(next
            .snapshots
            .iter()
            .all(|s| s.source_session_id == "later"));
        assert_eq!(
            reads.get(&fixture.root.join("held.jsonl")),
            None,
            "durably ACKed retry receives no source lease after restart"
        );
        assert_eq!(reads.get(&fixture.root.join("unrelated.jsonl")), None);
        assert_eq!(reads.values().sum::<usize>(), usize::from(unrelated));
        // Pass the scanner's ACTUAL empty or unrelated-only delta.
        let delta: Vec<String> = next
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect();
        assert!(!delta.contains(&fixture.fingerprint));
        assert!(!delta.contains(&retained_ack()));
        let bodies: BTreeMap<_, _> = next
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect();
        let mut delta_accepted = 0;
        let mut posts = 0;
        let result = upload_resumable_batches_with_body_witness(
            &delta,
            &unique_poison_scope(),
            &mut progress,
            &mut delta_accepted,
            String::as_str,
            |fp| bodies[fp].clone(),
            |batch| {
                assert!(unrelated, "empty delta must not POST");
                assert_eq!(batch, delta);
                posts += 1;
                Ok(entity_ack_batch(&batch, &[], &[]))
            },
            |state| state.save(&fixture.retained.progress_path),
        )
        .unwrap();
        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(posts, usize::from(unrelated));
        assert_eq!(delta_accepted, u64::from(unrelated));
        progress.save(&fixture.retained.progress_path).unwrap();
        // Reload both durable checkpoints before index adoption: the ACK must
        // still be in progress; keep the scanner's tentative index for settlement.
        let mut selected = index.clone();
        (index, progress) = fixture.retained.load();
        assert!(progress
            .accepted_fingerprints
            .contains(&fixture.fingerprint));
        assert_eq!(
            progress.accepted_body_witnesses.get(&fixture.fingerprint),
            Some(&fixture.body)
        );
        assert!(!index.accepted_snapshot_fingerprint_recorded(&fixture.fingerprint));
        settle_index_after_upload(&mut selected, &committed_index, &progress);
        selected.save(&fixture.retained.index_path).unwrap();
        let (index, progress) = fixture.retained.load();
        assert!(index.accepted_snapshot_fingerprint_recorded(&fixture.fingerprint));
        assert!(progress
            .accepted_fingerprints
            .contains(&fixture.fingerprint));
        assert_eq!(
            progress.accepted_body_witnesses.get(&fixture.fingerprint),
            Some(&fixture.body)
        );
        assert!(!index
            .quarantined_snapshot_fingerprints
            .contains_key(&fixture.fingerprint));
        assert!(!progress
            .quarantined_fingerprints
            .contains_key(&fixture.fingerprint));
        for fp in &delta {
            assert!(index.accepted_snapshot_fingerprint_recorded(fp));
        }
        fixture.retained.assert_retained(&index, &progress);
        // A later cycle cannot regrant the accepted retry from its old claim.
        let mut restarted = progress;
        assert!(!restarted
            .prepare_quarantine_retries(&committed_index.quarantined_snapshot_fingerprints));
        assert!(restarted.active_quarantine_retries.is_empty());
        let value = serde_json::to_value(&index).unwrap();
        for field in [
            "session_account_bindings",
            "claude_request_identity_contract",
            "claude_request_identity_contract_changed",
        ] {
            assert_eq!(value[field], fixture.retained.index_guard[field]);
        }
    });
}

#[test]
fn terminal_contract_ack_saved_before_index_restart_survives_empty_delta() {
    contract_ack_saved_before_index_restart(false);
}

#[test]
fn terminal_off_on_terminal_contract_ack_saved_before_index_restart_survives_empty_delta() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_ack_saved_before_index_restart(false);
}
#[test]
fn terminal_contract_ack_saved_before_index_restart_survives_unrelated_only_delta() {
    contract_ack_saved_before_index_restart(true);
}

#[test]
fn terminal_off_on_terminal_contract_ack_saved_before_index_restart_survives_unrelated_only_delta() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    contract_ack_saved_before_index_restart(true);
}
