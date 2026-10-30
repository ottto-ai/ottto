// Offline canonical ACK adapter shared by the remaining native retry tests.
fn integrated_ack(
    request: &SnapshotBatchRequest,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    // Synthetic bounded fixture response, not a proposed production response limit.
    let entities = request
        .snapshots
        .iter()
        .map(|item| {
            serde_json::json!({
                "source_session_id":item.source_session_id,
                "snapshot_fingerprint":item.snapshot_fingerprint,
                "occurrence_count":1,"body_witness_version":match crate::snapshots::snapshot_upload_body_witness_version(item) {
                Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_CONTEXT_CURVE_VERSION) =>
                    Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_CONTEXT_CURVE_VERSION),
                Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_CONTEXT_CURVE_VERSION) =>
                    Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_EXCLUSIVE_CONTEXT_CURVE_VERSION),
                None | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION)
                    | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION) => None,
                other => panic!("unexpected retained ordinary fixture witness: {other:?}"),
            },
                "body_witness_digest":snapshot_upload_body_witness(item)
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "accepted":entities.len(),"sessions_reconciled":entities.len(),"session_ids":[],
        "disabled":false,"disabled_reason":null,
        "entity_ack_contract":crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities":entities
    }))?;
    assert!(bytes.len() < crate::retry_retention_bound::PROOF_RESERVE);
    let response: crate::snapshot_client::SnapshotBatchResponse = serde_json::from_slice(&bytes)?;
    response.validate_entity_ack_with_head_cas(request, false)?;
    Ok(response)
}
