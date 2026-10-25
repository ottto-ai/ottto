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
        let items = vec![held_fingerprint(), retained_ack()];
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
fn terminal_contract_restart_after_saved_lease_keeps_owed_attempt_and_identity() {
    successful_contract_retry(true);
}
