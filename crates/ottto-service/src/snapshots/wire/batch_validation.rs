//! Validation of a snapshot batch request before upload: schema version,
//! source, fingerprints, and the per-item and per-batch wire sizes.
use std::collections::{BTreeMap, BTreeSet};

use super::content_hash::{
    snapshot_fingerprint_from_component_hashes, snapshot_semantic_component_hashes,
    snapshot_semantic_envelope,
};
use super::{SnapshotBatchRequest, SnapshotItem, SnapshotItemWire};
use crate::snapshots::{
    row_key_from_model_usage, snapshot_source_from_api_slug, usage_totals_equal,
    usage_totals_from_item, usage_totals_from_model_usage, usage_totals_has_usage, RowKey,
    UsageTotals, MAX_COMPACTION_TIMESTAMPS, MAX_MODEL_USAGE_ROWS, MAX_SEMANTIC_ENVELOPE_BYTES,
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

pub(in crate::snapshots) fn validate_snapshot_item(
    index: usize,
    item: &SnapshotItem,
) -> Result<(), String> {
    if item.model_usage.len() > MAX_MODEL_USAGE_ROWS {
        return Err(format!(
            "snapshot[{index}] has more than {MAX_MODEL_USAGE_ROWS} model_usage rows"
        ));
    }
    if item.compaction_timestamps.len() > MAX_COMPACTION_TIMESTAMPS {
        return Err(format!(
            "snapshot[{index}] has more than {MAX_COMPACTION_TIMESTAMPS} compaction_timestamps"
        ));
    }
    if item.compaction_events.len() > MAX_COMPACTION_TIMESTAMPS {
        return Err(format!(
            "snapshot[{index}] has more than {MAX_COMPACTION_TIMESTAMPS} compaction_events"
        ));
    }
    crate::session_attribution::validate_fact_limits(&item.attribution_facts)
        .map_err(|error| format!("snapshot[{index}] {error}"))?;
    let expected = usage_totals_from_item(item);
    let expected_has_usage = usage_totals_has_usage(&expected);
    if expected_has_usage && item.usage_buckets.is_empty() {
        return Err(format!(
            "snapshot[{index}] has usage totals but no usage_buckets"
        ));
    }

    let mut top_rows: BTreeMap<RowKey, UsageTotals> = BTreeMap::new();
    for row in &item.model_usage {
        let row_key = row_key_from_model_usage(row);
        if top_rows
            .insert(row_key, usage_totals_from_model_usage(row))
            .is_some()
        {
            return Err(format!(
                "snapshot[{index}] has duplicate top-level model_usage rows"
            ));
        }
    }

    let mut bucket_totals = UsageTotals::default();
    let mut bucket_rows: BTreeMap<RowKey, UsageTotals> = BTreeMap::new();
    for (bucket_index, bucket) in item.usage_buckets.iter().enumerate() {
        if bucket.model_usage.len() > MAX_MODEL_USAGE_ROWS {
            return Err(format!(
                "snapshot[{index}].usage_buckets[{bucket_index}] has more than {MAX_MODEL_USAGE_ROWS} model_usage rows"
            ));
        }
        if bucket.model_usage.is_empty() {
            return Err(format!(
                "snapshot[{index}].usage_buckets[{bucket_index}] has no model_usage rows"
            ));
        }
        let mut seen_bucket_rows = BTreeSet::new();
        for row in &bucket.model_usage {
            let row_key = row_key_from_model_usage(row);
            if !seen_bucket_rows.insert(row_key.clone()) {
                return Err(format!(
                    "snapshot[{index}].usage_buckets[{bucket_index}] has duplicate model_usage rows"
                ));
            }
            let totals = usage_totals_from_model_usage(row);
            if !bucket_totals.add(&totals) || !bucket_rows.entry(row_key).or_default().add(&totals)
            {
                return Err(format!(
                    "snapshot[{index}] usage_buckets counters overflow wire bounds"
                ));
            }
        }
    }

    if !usage_totals_equal(&bucket_totals, &expected) {
        return Err(format!(
            "snapshot[{index}] usage_buckets totals do not match snapshot totals"
        ));
    }

    if !bucket_rows.is_empty() {
        if top_rows.keys().collect::<Vec<_>>() != bucket_rows.keys().collect::<Vec<_>>() {
            return Err(format!(
                "snapshot[{index}] usage_buckets model rows do not match top-level model_usage rows"
            ));
        }
        for (row_key, top_totals) in &top_rows {
            let bucket_row = bucket_rows.get(row_key).expect("checked key set");
            if !usage_totals_equal(bucket_row, top_totals) {
                return Err(format!(
                    "snapshot[{index}] usage_buckets model row totals do not match top-level model_usage"
                ));
            }
        }
    }

    Ok(())
}
