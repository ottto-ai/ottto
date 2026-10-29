use super::*;

/// Actual uploader/ACK-recording seam, with synthetic validated responses only.
pub(crate) fn exact_acks(
    source: SnapshotSource,
    items: &[SnapshotItem],
) -> BTreeMap<String, String> {
    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        items,
        "synthetic-context-receipt",
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let response = crate::snapshot_client::SnapshotBatchResponse {
                accepted: batch.len() as u64,
                sessions_reconciled: batch.len() as u64,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
                accepted_entities:
                    batch
                        .iter()
                        .map(|item| crate::snapshot_client::SnapshotEntityRef {
                            source_session_id: item.source_session_id.clone(),
                            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                            occurrence_count: 1,
                            body_witness_version:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap(),
                            body_witness_digest:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap()
                                    .map(|_| snapshot_upload_body_witness(item)),
                            head_etag: batch
                                .iter()
                                .any(|item| item.cache_observations.is_some())
                                .then(|| "e".repeat(64)),
                            head_challenge: None,
                            unchanged_basis: None,
                        })
                        .collect(),
                unchanged_entities: Vec::new(),
                rejected_entities: Vec::new(),
                conflict_entities: Vec::new(),
            };
            response
                .validate_entity_ack(&SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: source.api_slug().into(),
                    machine_id: "synthetic".into(),
                    collector_version: None,
                    snapshots: batch,
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                })
                .unwrap();
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    progress.fresh_context_body_acks
}

#[test]
fn upload_context_transport_resume_keeps_body_acks_without_receipt_authority() {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let entity = "b".repeat(64);
    let body = "c".repeat(64);
    progress.record_body(&entity, &body);
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    assert!(restored.fresh_context_body_acks.is_empty());
    assert!(
        restored.contains_body(&entity, &body),
        "resume never resends this exact body"
    );
    progress.quarantine_permanent_body(&entity, &body, "synthetic_refusal");
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
}

#[test]
fn upload_context_prepare_preserves_resume_but_clears_prior_context_receipt_authority() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut index = ScanIndex::default();
        let mut progress = SnapshotUploadProgress::new(
            "a".repeat(64),
            crate::snapshots::snapshot_quarantine_witness_for_context(source, &"c".repeat(64)),
        );
        let entity = "b".repeat(64);
        let body = "d".repeat(64);
        progress.record_body(&entity, &body);
        progress
            .fresh_context_body_acks
            .insert(entity.clone(), body.clone());
        activate_source_upload_context(source, "e".repeat(64), &mut index, &mut progress);
        assert_eq!(
            progress.active_quarantine_witness,
            Some(crate::snapshots::snapshot_quarantine_witness_for_context(
                source,
                &"e".repeat(64)
            ))
        );
        assert!(
            progress.contains_body(&entity, &body),
            "transport ACK survives"
        );
        assert!(
            progress.fresh_context_body_acks.is_empty(),
            "old-context ACK cannot mint"
        );
        assert!(progress.context_receipt_candidates.is_empty());
    }
}

#[test]
fn upload_context_receipt_count_only_ack_refused() {
    let items = vec!["a".repeat(64)];
    let mut progress = SnapshotUploadProgress::new(
        "b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &items,
        "synthetic-count-only",
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| "c".repeat(64),
        |_| {
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                accepted: 1,
                sessions_reconciled: 1,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: None,
                accepted_entities: Vec::new(),
                unchanged_entities: Vec::new(),
                rejected_entities: Vec::new(),
                conflict_entities: Vec::new(),
            })
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(progress.accepted_fingerprints.len(), 1);
    assert!(progress.fresh_context_body_acks.is_empty());
}

pub(crate) fn partial_context_checkpoint(
    source: SnapshotSource,
    index: &ScanIndex,
    previous: &ScanIndex,
    items: &[SnapshotItem],
    fresh: bool,
) -> ScanIndex {
    let scratch = crate::test_scratch::ScratchDir::new("context-partial-checkpoint");
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &"d".repeat(64)),
    );
    progress.context_receipt_candidates = index.file_upload_context_ack_candidates(items);
    let exact = exact_acks(source, items);
    for (entity, body) in &exact {
        progress.record_body(entity, body);
    }
    if fresh {
        progress.fresh_context_body_acks = exact;
    }
    let progress_path = scratch.join("progress.json");
    let index_path = scratch.join("index.json");
    progress.save(&progress_path).unwrap();
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&std::fs::read(&progress_path).unwrap()).unwrap();
    assert!(restored.context_receipt_candidates.is_empty());
    assert!(restored.fresh_context_body_acks.is_empty());
    let selected = checkpoint_partial_snapshot_index(
        index,
        previous,
        &progress,
        items,
        None,
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&selected.files).unwrap(),
        serde_json::to_value(&loaded.files).unwrap()
    );
    selected
}

pub(crate) fn reproject_context_refusal(
    source: SnapshotSource,
    context: &str,
    quarantine: BTreeMap<String, SnapshotQuarantineRecord>,
    items: &[SnapshotItem],
) -> BTreeMap<String, SnapshotQuarantineRecord> {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(source, context),
    );
    progress.quarantined_fingerprints = quarantine;
    assert!(progress.note_reprojected_context_refusals(items));
    assert!(progress.fresh_context_body_acks.is_empty());
    assert!(progress.accepted_fingerprints.is_empty());
    progress.quarantined_fingerprints
}

#[test]
fn upload_context_pending_refusal_preserves_cooldown_through_prepare_and_reprojection() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&item);
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(body.clone());
    record.retry_after_unix_seconds = current_unix_seconds() + 3600;
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record.clone());
    assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
    assert_eq!(progress.quarantined_fingerprints[&entity], record);
    assert!(progress.active_quarantine_retries.is_empty());
    assert!(progress.note_reprojected_context_refusals(std::slice::from_ref(&item)));
    let rebound = &progress.quarantined_fingerprints[&entity];
    assert_eq!(
        rebound.retry_after_unix_seconds,
        record.retry_after_unix_seconds
    );
    assert_eq!(
        rebound.failed_reconstruction_count,
        record.failed_reconstruction_count
    );
    assert_eq!(rebound.contract_retry_claims, record.contract_retry_claims);
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
}
#[test]
fn upload_context_due_refusal_still_uses_existing_retry_lease() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&item);
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(body.clone());
    record.retry_after_unix_seconds = current_unix_seconds().saturating_sub(1);
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record);
    assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
    assert!(progress.active_quarantine_retries.contains(&entity));
    assert!(!progress.contains_body(&entity, &body));
}
#[test]
fn upload_context_changed_body_can_correct_pending_refusal() {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(snapshot_upload_body_witness(&item));
    record.retry_after_unix_seconds = current_unix_seconds() + 3600;
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record);
    assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
    item.tool_usage_truncated = !item.tool_usage_truncated;
    let corrected = snapshot_upload_body_witness(&item);
    assert!(!progress.note_reprojected_context_refusals(&[item]));
    assert!(!progress.contains_body(&entity, &corrected));
}
