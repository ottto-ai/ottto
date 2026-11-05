//! Validation of a snapshot batch request before upload: schema version,
//! source, fingerprints, and the per-item and per-batch wire sizes.
use super::content_hash::{
    snapshot_fingerprint_from_component_hashes, snapshot_semantic_component_hashes,
    snapshot_semantic_envelope,
};
use super::{SnapshotBatchRequest, SnapshotItemWire};
use crate::snapshots::{
    snapshot_source_from_api_slug, validate_snapshot_item, MAX_SEMANTIC_ENVELOPE_BYTES,
    MAX_SNAPSHOT_BATCH_WIRE_BYTES, MAX_SNAPSHOT_ITEM_WIRE_BYTES, SNAPSHOT_SCHEMA_VERSION,
};

pub fn validate_snapshot_batch_request(request: &SnapshotBatchRequest) -> Result<(), String> {
    validate_snapshot_batch_request_with_item_limit(request, MAX_SNAPSHOT_ITEM_WIRE_BYTES)
}

pub(crate) fn validate_snapshot_batch_request_with_item_limit(
    request: &SnapshotBatchRequest,
    item_limit: usize,
) -> Result<(), String> {
    if request.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "schema_version {} does not match daemon SNAPSHOT_SCHEMA_VERSION {}",
            request.schema_version, SNAPSHOT_SCHEMA_VERSION
        ));
    }
    if request.snapshots.is_empty() {
        return Err("snapshots must not be empty".to_string());
    }
    let source = snapshot_source_from_api_slug(&request.source)
        .ok_or_else(|| "unsupported snapshot source".to_string())?;
    for (index, item) in request.snapshots.iter().enumerate() {
        validate_snapshot_item(index, item)?;
        let component_hashes = snapshot_semantic_component_hashes(source, item);
        let expected_fingerprint = snapshot_fingerprint_from_component_hashes(
            source,
            &item.source_session_id,
            &component_hashes,
        );
        if item.snapshot_fingerprint != expected_fingerprint {
            return Err(format!(
                "snapshot[{index}] fingerprint does not match semantic components"
            ));
        }
        let envelope = snapshot_semantic_envelope(source, item, request.upload_policy);
        let envelope_size = serde_json::to_vec(&envelope)
            .map_err(|error| format!("snapshot[{index}] semantic_envelope: {error}"))?
            .len();
        if envelope_size > MAX_SEMANTIC_ENVELOPE_BYTES {
            return Err(format!(
                "snapshot[{index}] semantic_envelope is {envelope_size} bytes; maximum is {MAX_SEMANTIC_ENVELOPE_BYTES}"
            ));
        }
        let item_size = serde_json::to_vec(&SnapshotItemWire {
            snapshot: item,
            semantic_envelope: envelope,
        })
        .map_err(|error| format!("snapshot[{index}] wire encoding: {error}"))?
        .len();
        if item_size > item_limit && item_size > MAX_SNAPSHOT_ITEM_WIRE_BYTES {
            return Err(format!(
                "snapshot[{index}] wire body is {item_size} bytes; maximum is {item_limit}"
            ));
        }
    }
    let batch_size = serde_json::to_vec(request)
        .map_err(|error| format!("snapshot batch wire encoding: {error}"))?
        .len();
    if batch_size > MAX_SNAPSHOT_BATCH_WIRE_BYTES {
        return Err(format!(
            "snapshot batch wire body is {batch_size} bytes; maximum is {MAX_SNAPSHOT_BATCH_WIRE_BYTES}"
        ));
    }
    Ok(())
}
