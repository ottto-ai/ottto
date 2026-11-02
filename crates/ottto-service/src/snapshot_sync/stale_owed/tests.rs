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

/// [regress] Older activity and mixed usage are owed for every source; exact
/// refused bytes are suppressed even after exhaustion and a quiet restart.
/// A changed body has one offer and acquires its own suppression, never an ACK.
#[test]
#[serial_test::serial(client_report)]
fn stale_refusals_stay_owed_and_only_changed_bytes_retry() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for reason in [STALE, MIXED] {
            let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
            item.cache_observations = None;
            item.session_account_evidence = None;
            item.snapshot_fingerprint = fp(1);
            let mut progress = ledger(source);
            assert_eq!(offer(&item, source, reason, &mut progress), 1);
            let body = snapshot_upload_body_witness(&item);
            assert!(progress.stale_body(&item.snapshot_fingerprint, &body));
            assert_eq!(PermanentRefusalCounts::of(&progress).dominated, 0);
            assert!(!RejectedUsageReason::AcceptedLogStaleOlderUpload.is_dominated());
            for _ in 0..MAX_SNAPSHOT_RECONSTRUCTION_FAILURES + 1 {
                progress.quarantine_body(&item.snapshot_fingerprint, &body);
            }
            progress.hold_unstored_body(&item.snapshot_fingerprint, &body);
            progress.prepare_quarantine_retries(&BTreeMap::new());
            assert_eq!(
                progress.quarantined_fingerprints[&item.snapshot_fingerprint].disposition,
                SnapshotQuarantineDisposition::RetryPending
            );
            assert!(progress.active_quarantine_retries.is_empty());
            assert_eq!(offer(&item, source, reason, &mut progress), 0);
            let encoded = serde_json::to_vec(&progress).unwrap();
            let mut restored: SnapshotUploadProgress = serde_json::from_slice(&encoded).unwrap();
            restored.active_quarantine_witness = Some(snapshot_quarantine_witness(source));
            restored.prepare_quarantine_retries(&BTreeMap::new());
            assert_eq!(offer(&item, source, reason, &mut restored), 0);
            item.tool_usage_truncated = !item.tool_usage_truncated;
            assert_eq!(offer(&item, source, reason, &mut restored), 1);
            assert_eq!(offer(&item, source, reason, &mut restored), 0);
            assert!(restored.accepted_fingerprints.is_empty());
            let rows = census(&ScanIndex::default(), &restored, current_unix_seconds());
            assert_eq!(rows.values().map(|c| c.entities).sum::<usize>(), 2);
            assert_eq!(rows.values().map(|c| c.unknown_requests).sum::<usize>(), 0);
            assert_eq!(
                rows.values().map(|c| c.known_requests).sum::<u64>(),
                item.request_count * 2
            );
            assert_eq!(
                rows.values().map(|c| c.known_tokens).sum::<u64>(),
                (item.input_tokens + item.output_tokens + item.unattributed_total_tokens) * 2
            );
            let encoded = serde_json::to_vec(&restored).unwrap();
            restored = serde_json::from_slice(&encoded).unwrap();
            restored.active_quarantine_witness = Some(snapshot_quarantine_witness(source));
            let old_body = body;
            assert!(restored.contains_body(&item.snapshot_fingerprint, &old_body));
            let mut returned = item.clone();
            returned.tool_usage_truncated = !returned.tool_usage_truncated;
            assert_eq!(offer(&returned, source, reason, &mut restored), 0);
            assert!(cache_head_probe_held(
                &restored,
                &cache_head_probe(&returned)
            ));
            let new_body = snapshot_upload_body_witness(&item);
            restored.record_body(&item.snapshot_fingerprint, &new_body);
            assert!(restored.stale_body(&item.snapshot_fingerprint, &old_body));
            restored.record_body(&item.snapshot_fingerprint, &old_body);
            assert!(!restored.stale_body(&item.snapshot_fingerprint, &old_body));
        }
    }
}

/// [format] Pre-extension state round-trips without adding defaults or changing
/// enum vocabulary; mixed classification is additive and never a daily Other offer.
#[test]
fn old_state_decode_keeps_canonical_bytes_and_legacy_unknowns() {
    let old =
        serde_json::json!({"body_witness": fp(2), "reason": "accepted_log_stale_older_upload"});
    let refusal: PermanentSnapshotRejection = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(&refusal).unwrap(), old);
    assert!(refusal.is_stale());
    assert!(refusal.exposure.is_none());
    let mut progress = ledger(SnapshotSource::Pi);
    let old_progress = serde_json::to_value(&progress).unwrap();
    assert!(old_progress.get("stale_reopen_consumed").is_none());
    let decoded: SnapshotUploadProgress = serde_json::from_value(old_progress.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), old_progress);
    progress.permanent_rejections.insert(fp(1), refusal);
    let rows = census(&ScanIndex::default(), &progress, current_unix_seconds());
    let row = rows.get(&(STALE.into(), "unknown")).unwrap();
    assert_eq!(
        (
            row.entities,
            row.unknown_requests,
            row.unknown_tokens,
            row.unknown_age
        ),
        (1, 1, 1, 1)
    );
    progress.quarantine_permanent_body(&fp(3), &fp(4), MIXED);
    let mixed = &progress.permanent_rejections[&fp(3)];
    assert_eq!(mixed.reason, RejectedUsageReason::Other);
    assert_eq!(
        mixed.reoffer,
        Some(reason_reoffer::RefusalReoffer::Classified)
    );
    assert!(mixed.is_stale());
}

/// [regress] Legacy terminal and progress-only refusals remain unchanged without
/// the explicit action. A persisted action gives one paced acquisition, consumes
/// before I/O, survives restart and never grants permission to resend the body.
#[test]
#[serial_test::serial(client_report)]
fn reopen_is_explicit_paced_and_durably_once() {
    let root = std::env::temp_dir().join(format!(
        "ottto-stale-once-{}-{}",
        std::process::id(),
        fp(current_unix_seconds())
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    let input = root.join("source");
    std::fs::create_dir(&input).unwrap();
    let session_path = input.join("session.jsonl");
    std::fs::write(&session_path, concat!(
        "{\"type\":\"session\",\"id\":\"fixture-session\",\"timestamp\":\"2026-08-31T08:00:00Z\"}\n",
        "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1788163201000,\"usage\":{\"input\":12,\"output\":4}}}\n",
    )).unwrap();
    let mut index = ScanIndex::default();
    let collected = "2026-09-01T03:27:03Z";
    let mut first = crate::snapshots::scan_source_roots(
        SnapshotSource::Pi,
        std::slice::from_ref(&input),
        &mut index,
        collected,
        crate::snapshots::BACKFILL_WINDOW_DAYS,
    )
    .unwrap();
    crate::snapshots::finalize_scan_after_policy(SnapshotSource::Pi, &mut first, &mut index);
    let entity = first.snapshots[0].snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&first.snapshots[0]);
    let mut progress = ledger(SnapshotSource::Pi);
    for (key, refused_body) in [(&entity, &body), (&fp(2), &fp(12))] {
        progress.permanent_rejections.insert(
            key.clone(),
            PermanentSnapshotRejection {
                body_witness: refused_body.clone(),
                reason: RejectedUsageReason::AcceptedLogStaleOlderUpload,
                reoffer: None,
                exposure: None,
            },
        );
    }
    progress.quarantine_permanent_body(&entity, &fp(99), STALE);
    progress.quarantine_body(&entity, &body);
    let record = progress.quarantined_fingerprints.get_mut(&entity).unwrap();
    record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
    let before = serde_json::to_value(&progress).unwrap();
    assert!(!progress.reopen_stale_once(&path).unwrap());
    progress.prepare_quarantine_retries(&BTreeMap::new());
    assert_eq!(serde_json::to_value(&progress).unwrap(), before);
    std::fs::write(path.with_extension("stale-older-reopen-once"), b"").unwrap();
    assert!(progress.reopen_stale_once(&path).unwrap());
    progress.save(&path).unwrap();
    progress.prepare_quarantine_retries(&BTreeMap::new());
    assert!(
        progress.active_quarantine_retries.is_empty(),
        "existing pacing applies"
    );
    for record in progress.quarantined_fingerprints.values_mut() {
        record.retry_after_unix_seconds = 0;
    }
    progress.save(&path).unwrap();
    let mut restored = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .unwrap();
    assert!(!restored.reopen_stale_once(&path).unwrap());
    assert!(restored.prepare_quarantine_retries(&BTreeMap::new()));
    restored.save(&path).unwrap();
    assert_eq!(restored.active_quarantine_retries.len(), 2);
    assert!(restored.contains_body(&entity, &body));
    assert!(restored.contains_body(&fp(2), &fp(12)));
    let hints =
        save_terminal_contract_claims_for_scan(&mut index, &restored, &root.join("index.json"))
            .unwrap();
    assert_eq!(hints, vec![session_path.clone()]);
    let (mut fresh, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::Pi,
            std::slice::from_ref(&input),
            &mut index,
            collected,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            1,
            true,
            &hints,
        )
        .unwrap()
    });
    crate::snapshots::finalize_scan_after_policy(SnapshotSource::Pi, &mut fresh, &mut index);
    assert_eq!(reads.get(&session_path), Some(&1), "one fresh acquisition");
    assert_eq!(reads.values().sum::<usize>(), 1);
    assert_eq!(fresh.snapshots.len(), 1);
    assert_eq!(
        offer(
            &fresh.snapshots[0],
            SnapshotSource::Pi,
            STALE,
            &mut restored
        ),
        0
    );
    let mut again = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .unwrap();
    assert!(!again.reopen_stale_once(&path).unwrap());
    again.prepare_quarantine_retries(&BTreeMap::new());
    assert!(
        again.active_quarantine_retries.is_empty(),
        "crash cannot renew the claim"
    );
    assert_eq!(again.quarantined_fingerprints.len(), 2);
    index.activate_reason_reoffer_cooldowns(again.reason_reoffer_cooldowns(current_unix_seconds()));
    index.activate_terminal_contract_retries(BTreeSet::new());
    index.activate_stale_reopen_retries(BTreeSet::new());
    let (_, reads) = crate::snapshots::terminal_contract_retry::source_acquisitions(|| {
        crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::Pi,
            std::slice::from_ref(&input),
            &mut index,
            collected,
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            1,
            true,
            &[],
        )
        .unwrap()
    });
    assert!(reads.is_empty(), "no timer renewal after the one-shot");
    std::fs::remove_dir_all(root).unwrap();
}
