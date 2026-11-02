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

/// [regress] The observed timestamp refusal remains owed through exhaustion;
/// exact revisions stay suppressed, while a changed body receives one offer.
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
    let mut restored: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    restored.active_quarantine_witness = Some(snapshot_quarantine_witness(source));
    item.tool_usage_truncated = !item.tool_usage_truncated;
    assert_eq!(offer(&item, source, STALE, &mut restored), 1);
    assert_eq!(offer(&item, source, STALE, &mut restored), 0);
    assert!(restored.contains_body(&item.snapshot_fingerprint, &old_body));
    assert!(restored.accepted_fingerprints.is_empty());
    let new_body = snapshot_upload_body_witness(&item);
    restored.record_body(&item.snapshot_fingerprint, &new_body);
    assert!(restored.stale_body(&item.snapshot_fingerprint, &old_body));
    restored.record_body(&item.snapshot_fingerprint, &old_body);
    assert!(!restored.stale_body(&item.snapshot_fingerprint, &old_body));
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
    let progress = ledger(SnapshotSource::ClaudeCode);
    let old_progress = serde_json::to_value(&progress).unwrap();
    let decoded: SnapshotUploadProgress = serde_json::from_value(old_progress.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), old_progress);
    let mut invalid = old.clone();
    invalid["exposure"] = serde_json::json!({"requests": "invalid"});
    let decoded: PermanentSnapshotRejection = serde_json::from_value(invalid).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), old);
    assert_eq!(
        entity_hash("claude_code", "machine-example", "session-example"),
        "2fe67006"
    );
}

/// [regress] Receipt-covered entities supersede without acquisition. Only the
/// explicitly owed entities get one paced Full; native results use the shared
/// money oracle. No input, unlisted input, restart and a later trigger conserve debt.
#[test]
#[serial_test::serial(client_report)]
fn receipt_covered_supersedes_without_read_and_only_owed_acquires() {
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};
    let scratch = crate::test_scratch::ScratchDir::new("stale-head-compare");
    let path = scratch.join("progress.json");
    let root = scratch.join("sources");
    std::fs::create_dir_all(&root).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let collected = "2026-10-25T07:01:00Z";
    for n in 0..67 {
        let session = format!("session-{n:02}");
        std::fs::write(root.join(format!("{session}.jsonl")), format!("{}\n", serde_json::json!({
            "timestamp":"2026-10-25T07:00:00Z", "type":"assistant", "sessionId":session,
            "requestId":format!("req-{n}"), "message":{"id":format!("msg-{n}"), "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}
        }))).unwrap();
    }
    let mut index = ScanIndex::default();
    let mut first = crate::snapshots::scan_source_roots(
        source,
        &[root.clone()],
        &mut index,
        collected,
        crate::snapshots::BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    crate::snapshots::finalize_scan_after_policy(source, &mut first, &mut index);
    assert_eq!(first.snapshots.len(), 67);
    let mut progress = ledger(source);
    let mut entries = Vec::new();
    let mut owed_items = Vec::new();
    for item in &first.snapshots {
        let n: usize = item
            .source_session_id
            .strip_prefix("session-")
            .unwrap()
            .parse()
            .unwrap();
        let fp = &item.snapshot_fingerprint;
        let body = snapshot_upload_body_witness(item);
        progress.quarantine_permanent_body(fp, &body, STALE);
        progress.permanent_rejections.get_mut(fp).unwrap().exposure = None;
        progress
            .quarantined_fingerprints
            .get_mut(fp)
            .unwrap()
            .disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
        if n == 66 {
            continue;
        }
        if n >= 63 {
            owed_items.push(item.clone());
        }
        entries.push(serde_json::json!({"entity_hash":entity_hash(source.api_slug(), "synthetic", &item.source_session_id),
            "source_session_id":item.source_session_id, "snapshot_fingerprint":fp, "body_witness":body,
            "verdict":if n < 63 {"covered"} else {"owed"}}));
    }
    index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
    let before = serde_json::to_value(&progress).unwrap();
    assert!(!progress
        .reopen_stale_once(&path, source, "synthetic", &mut index)
        .unwrap());
    assert_eq!(serde_json::to_value(&progress).unwrap(), before);
    assert_eq!(
        progress
            .refusal_exposure(current_unix_seconds())
            .owed_entities,
        67
    );
    let marker = path.with_extension("stale-older-reopen-once");
    let mut request = serde_json::json!({"nonce":"first", "entities":entries});
    std::fs::write(&marker, serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(progress
        .reopen_stale_once(&path, source, "synthetic", &mut index)
        .unwrap());
    assert_eq!(index.snapshot_superseded_terminal_count(), 63);
    assert_eq!(
        progress
            .refusal_exposure(current_unix_seconds())
            .owed_entities,
        4
    );
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert!(
        progress.active_quarantine_retries.is_empty(),
        "ordinary pacing"
    );
    for r in progress.quarantined_fingerprints.values_mut() {
        r.retry_after_unix_seconds = 0;
    }
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert_eq!(progress.active_quarantine_retries.len(), 3);
    let hints =
        save_terminal_contract_claims_for_scan(&mut index, &progress, &scratch.join("index.json"))
            .unwrap();
    assert_eq!(hints.len(), 3);
    assert!(progress.record_stale_acquisitions(&index));
    progress.save(&path).unwrap();
    let (mut fresh, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            source,
            &[root.clone()],
            &mut index,
            collected,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            67,
            true,
            &hints,
        )
        .unwrap()
    });
    crate::snapshots::finalize_scan_after_policy(source, &mut fresh, &mut index);
    assert_eq!(reads.len(), 3);
    assert_eq!(reads.values().sum::<usize>(), 3);
    assert_eq!(fresh.snapshots.len(), 3);
    let route = |mode, items: &[SnapshotItem]| {
        let mut ordered = items.to_vec();
        ordered.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        let request = snapshot_batch_request(
            source,
            "synthetic",
            ordered,
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
        &route(Mode::ColdFull, &owed_items),
        &route(Mode::Restart, &fresh.snapshots),
    );
    for item in &fresh.snapshots {
        assert_eq!(offer(item, source, STALE, &mut progress), 0);
    }
    let mut restored =
        SnapshotUploadProgress::load(&path, &"a".repeat(64), snapshot_quarantine_witness(source))
            .unwrap();
    assert!(!restored
        .reopen_stale_once(&path, source, "synthetic", &mut index)
        .unwrap());
    restored.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    assert!(
        restored.active_quarantine_retries.is_empty(),
        "recorded attempt cannot renew itself"
    );
    request["nonce"] = "later-explicit-action".into();
    std::fs::write(&marker, serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(restored
        .reopen_stale_once(&path, source, "synthetic", &mut index)
        .unwrap());
    assert_eq!(
        restored
            .refusal_exposure(current_unix_seconds())
            .owed_entities,
        4
    );
}
