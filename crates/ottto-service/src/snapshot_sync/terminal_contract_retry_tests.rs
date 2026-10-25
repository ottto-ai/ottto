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
