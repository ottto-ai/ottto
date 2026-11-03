use super::*;
use crate::snapshot_client::{SnapshotBatchResponse, SnapshotEntityRejection};

const STALE: &str = "accepted_log_stale_older_upload";
const MIXED: &str = "accepted_log_stale_older_mixed";
fn ledger(source: SnapshotSource) -> SnapshotUploadProgress {
    SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source))
}
fn fp(n: u64) -> String {
    format!("{n:064x}")
}
fn response(item: &SnapshotItem, reason: &str) -> SnapshotBatchResponse {
    SnapshotBatchResponse {
        conflict_rescans: Default::default(),
        accepted: 0,
        sessions_reconciled: 0,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: vec![],
        unchanged_entities: vec![],
        conflict_entities: vec![],
        rejected_entities: vec![SnapshotEntityRejection {
            source_session_id: item.source_session_id.clone(),
            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
            reason: reason.into(),
            detail: String::new(),
            permanent: reason != MIXED,
            occurrence_count: 1,
        }],
    }
}
fn offer(
    item: &SnapshotItem,
    source: SnapshotSource,
    reason: &str,
    progress: &mut SnapshotUploadProgress,
) -> usize {
    let mut calls = 0;
    upload_resumable_batches_with_body_witness(
        std::slice::from_ref(item),
        "synthetic-stale",
        progress,
        &mut 0,
        |i| i.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            calls += 1;
            let reply = response(&batch[0], reason);
            reply.validate_entity_ack(&SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: source.api_slug().into(),
                machine_id: "synthetic".into(),
                collector_version: None,
                snapshots: batch,
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            })?;
            Ok(reply)
        },
        |_| Ok(()),
    )
    .unwrap();
    calls
}
/// [regress] Legacy timestamp refusals stay owed through exhaustion; exact
/// revisions stay suppressed while a changed body receives one offer.
#[test]
#[serial_test::serial(client_report)]
fn stale_refusals_stay_owed_and_only_changed_bytes_retry() {
    let source = SnapshotSource::ClaudeCode;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.cache_observations = None;
    item.session_account_evidence = None;
    item.snapshot_fingerprint = fp(1);
    let mut progress = ledger(source);
    assert_eq!(offer(&item, source, STALE, &mut progress), 1);
    // Represent the retained pre-exposure record, not a fresh server answer.
    progress
        .permanent_rejections
        .get_mut(&item.snapshot_fingerprint)
        .unwrap()
        .exposure = None;
    let old_body = snapshot_upload_body_witness(&item);
    assert!(!RejectedUsageReason::AcceptedLogStaleOlderUpload.is_dominated());
    assert_eq!(PermanentRefusalCounts::of(&progress).dominated, 0);
    for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES + 1 {
        progress.quarantine_body(&item.snapshot_fingerprint, &old_body);
    }
    progress.hold_unstored_body(&item.snapshot_fingerprint, &old_body);
    progress.prepare_quarantine_retries(&BTreeMap::new());
    assert_eq!(
        progress.quarantined_fingerprints[&item.snapshot_fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert!(progress.active_quarantine_retries.is_empty());
    assert_eq!(offer(&item, source, STALE, &mut progress), 0);
    let scratch = crate::test_scratch::ScratchDir::new("stale-refusal-restart");
    let path = scratch.join("progress.json");
    progress.save(&path).unwrap();
    let mut restored =
        SnapshotUploadProgress::load(&path, &"a".repeat(64), snapshot_quarantine_witness(source))
            .unwrap();
    assert!(restored
        .permanent_rejections
        .contains_key(&item.snapshot_fingerprint));
    item.tool_usage_truncated = !item.tool_usage_truncated;
    assert_eq!(offer(&item, source, STALE, &mut restored), 1);
    assert_eq!(offer(&item, source, STALE, &mut restored), 0);
    assert!(restored.contains_body(&item.snapshot_fingerprint, &old_body));
    assert!(restored.accepted_fingerprints.is_empty());
    let new_body = snapshot_upload_body_witness(&item);
    restored.record_body(&item.snapshot_fingerprint, &new_body);
    assert!(restored.owed_stale_body(&item.snapshot_fingerprint, &old_body));
    restored.record_body(&item.snapshot_fingerprint, &old_body);
    assert!(!restored.owed_stale_body(&item.snapshot_fingerprint, &old_body));
    // Mixed uses ordinary non-permanent custody, never permanent Other.
    let mut mixed = ledger(source);
    assert_eq!(offer(&item, source, MIXED, &mut mixed), 1);
    assert!(mixed.permanent_rejections.is_empty());
    assert_eq!(
        mixed.quarantined_fingerprints[&item.snapshot_fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
}
/// [format] Old exact JSON is unchanged; an invalid optional observation is
/// isolated from the refusal, just like the existing re-offer extension.
#[test]
fn old_state_decode_keeps_canonical_bytes_and_legacy_unknowns() {
    let old = serde_json::json!({"body_witness": fp(2), "reason": STALE});
    let refusal: PermanentSnapshotRejection = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(&refusal).unwrap(), old);
    assert!(refusal.exposure.is_none());
    assert!(refusal.owed());
    let progress = ledger(SnapshotSource::ClaudeCode);
    let old_progress = serde_json::to_value(&progress).unwrap();
    let decoded: SnapshotUploadProgress = serde_json::from_value(old_progress.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), old_progress);
    let mut invalid = old.clone();
    invalid["exposure"] = serde_json::json!({"requests": "invalid"});
    let decoded: PermanentSnapshotRejection = serde_json::from_value(invalid).unwrap();
    assert!(decoded.owed());
    assert_eq!(serde_json::to_value(decoded).unwrap(), old);
}

/// [behaviour] Unchanged stale debt never acquires a retry lease or reads the
/// transcript across passes, even after a contract change or legacy terminal
/// disposition. Real appended input remains ordinary acquisition authority.
#[test]
#[serial_test::serial(client_report)]
fn unchanged_stale_debt_never_reads_on_automatic_retry_passes() {
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};
    use std::io::Write;
    let scratch = crate::test_scratch::ScratchDir::new("stale-unchanged-input");
    let root = scratch.join("sources");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("session-example.jsonl");
    let line = |n| {
        format!(
            "{}\n",
            serde_json::json!({
                "timestamp":"2026-10-25T07:00:00Z", "type":"assistant", "sessionId":"session-example",
                "requestId":format!("req-{n}"), "message":{"id":format!("msg-{n}"), "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}
            })
        )
    };
    std::fs::write(&path, line(1)).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let collected = "2026-10-25T07:01:00Z";
    let scan = |index: &mut ScanIndex| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            source,
            std::slice::from_ref(&root),
            index,
            collected,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            8,
            std::slice::from_ref(&path),
        )
        .unwrap()
    };
    let mut index = ScanIndex::default();
    let mut first = scan(&mut index);
    crate::snapshots::finalize_scan_after_policy(source, &mut first, &mut index);
    assert_eq!(first.snapshots.len(), 1);
    let item = &first.snapshots[0];
    let fp = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(item);
    let mut progress = ledger(source);
    assert_eq!(offer(item, source, STALE, &mut progress), 1);
    progress.permanent_rejections.get_mut(&fp).unwrap().exposure = None;
    let legacy = progress.quarantined_fingerprints.get_mut(&fp).unwrap();
    legacy.disposition = SnapshotQuarantineDisposition::RetryPending;
    legacy.failed_reconstruction_count = 1;
    for pass in 0..3 {
        let record = progress.quarantined_fingerprints.get_mut(&fp).unwrap();
        record.retry_after_unix_seconds = 0;
        record.witness.contract.push_str("-older");
        if pass == 2 {
            record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
            record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
        }
        let disposition = record.disposition;
        index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
        index.snapshot_activity_at.remove(&fp);
        progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
        assert!(progress.active_quarantine_retries.is_empty());
        assert!(progress.active_reason_reoffers.is_empty());
        assert_eq!(
            progress.quarantined_fingerprints[&fp].disposition,
            disposition
        );
        assert!(save_terminal_contract_claims_for_scan(
            &mut index,
            &progress,
            &scratch.join("index.json")
        )
        .unwrap()
        .is_empty());
        index.activate_reason_reoffer_cooldowns(
            progress.reason_reoffer_cooldowns(current_unix_seconds()),
        );
        let (mut quiet, reads) =
            crate::snapshots::terminal_contract_retry::source_acquisitions(|| scan(&mut index));
        crate::snapshots::finalize_scan_after_policy(source, &mut quiet, &mut index);
        assert!(reads.is_empty(), "pass {pass} read an unchanged transcript");
        assert!(quiet.snapshots.is_empty());
        assert_eq!(
            progress
                .refusal_exposure(current_unix_seconds())
                .owed_entities,
            1
        );
        assert!(progress.contains_body(&fp, &body));
        assert_eq!(offer(item, source, STALE, &mut progress), 0);
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(line(2).as_bytes())
        .unwrap();
    index.activate_reason_reoffer_cooldowns(
        progress.reason_reoffer_cooldowns(current_unix_seconds()),
    );
    let (mut changed, reads) =
        crate::snapshots::terminal_contract_retry::source_acquisitions(|| scan(&mut index));
    crate::snapshots::finalize_scan_after_policy(source, &mut changed, &mut index);
    assert_eq!(reads.values().sum::<usize>(), 1);
    assert_eq!(changed.snapshots.len(), 1);
    assert_eq!(changed.snapshots[0].request_count, 2);
    let mut cold_index = ScanIndex::default();
    let mut cold = scan(&mut cold_index);
    crate::snapshots::finalize_scan_after_policy(source, &mut cold, &mut cold_index);
    let route = |mode, items: &[SnapshotItem]| {
        let request = snapshot_batch_request(
            source,
            "synthetic",
            items.to_vec(),
            SnapshotUploadPolicy::default(),
            crate::client_report::ClientReport::empty(),
        );
        RouteResult::emitted(
            mode,
            source,
            vec![serde_json::to_vec(&request).unwrap()],
            items,
        )
    };
    money_oracle::assert_equivalent(
        &route(Mode::ColdFull, &cold.snapshots),
        &route(Mode::Restart, &changed.snapshots),
    );
    assert_eq!(
        offer(&changed.snapshots[0], source, STALE, &mut progress),
        1
    );
    assert_eq!(
        offer(&changed.snapshots[0], source, STALE, &mut progress),
        0
    );
}
