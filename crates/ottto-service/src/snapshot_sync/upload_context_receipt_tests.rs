use super::*;

/// Actual uploader/ACK-recording seam, with synthetic validated responses only.
pub(crate) fn exact_acks(
    source: SnapshotSource,
    items: &[SnapshotItem],
) -> BTreeMap<String, String> {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
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
                            head_etag: None,
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
fn upload_context_rearm_bypasses_old_body_ack_but_preserves_refusal_backoff() {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let entity = "b".repeat(64);
    let body = "c".repeat(64);
    progress.record_body(&entity, &body);
    progress.context_rearm_entities.insert(entity.clone());
    assert!(!progress.contains_body(&entity, &body));
    progress
        .fresh_context_body_acks
        .insert(entity.clone(), body.clone());
    assert!(progress.contains_body(&entity, &body));
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    assert!(restored.fresh_context_body_acks.is_empty());
    progress.fresh_context_body_acks.clear();
    progress.quarantine_permanent_body(&entity, &body, "synthetic_refusal");
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
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
