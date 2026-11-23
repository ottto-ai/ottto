fn integrated_ack(
    request: &SnapshotBatchRequest<impl std::borrow::Borrow<SnapshotItem>>,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let entities = request
        .items()
        .map(|item| {
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item)?;
            if version.is_none() {
                // Ordinary fixtures have no witness domain, as on the backend.
                let retained_version = crate::snapshots::snapshot_upload_body_witness_version(item);
                assert!(
                    matches!(
                        retained_version,
                        None | Some(
                            crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION
                                | crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION
                        )
                    ),
                    "unexpected retained ordinary fixture witness: {retained_version:?}"
                );
            }
            // Additive evidence uses the production public ACK version; the
            // digest travels only with that version.
            Ok(serde_json::json!({
                "source_session_id":item.source_session_id,
                "snapshot_fingerprint":item.snapshot_fingerprint,
                "occurrence_count":1,"body_witness_version":version,
                "body_witness_digest":version.map(|_| snapshot_upload_body_witness(item))
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "accepted":entities.len(),"sessions_reconciled":entities.len(),"session_ids":[],
        "disabled":false,"disabled_reason":null,
        "entity_ack_contract":crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities":entities
    }))?;
    let response: crate::snapshot_client::SnapshotBatchResponse = serde_json::from_slice(&bytes)?;
    response.validate_entity_ack_with_head_cas(request, false)?;
    Ok(response)
}
