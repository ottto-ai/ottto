//! Codex usage readers for one rollout line: the cumulative and last-response
//! token totals of a `token_count` event, the model context window, the line's
//! envelope time and its usage event identity.

use serde_json::Value;

use crate::snapshots::cache_observations::{self, OwnedRequest};
use crate::snapshots::scan::json_fields::{string_at, u64_at};
use crate::snapshots::scan_index::file_set_digest::sha256_hex;
use crate::snapshots::{
    raw_value_at, timestamp_is_after, usage_object_has_numeric_field, SnapshotAccumulator,
    UsageCosts, UsageTotals,
};

pub(in crate::snapshots) fn codex_total_usage(value: &Value) -> Option<UsageTotals> {
    let root = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))?;
    codex_usage_from_root(root, true)
}

pub(in crate::snapshots) fn codex_last_usage(value: &Value) -> Option<UsageTotals> {
    codex_usage_from_root(codex_last_usage_root(value)?, false)
}

/// The one `last_token_usage` root the parser admits (shared with the group
/// proof, S10).
pub(in crate::snapshots) fn codex_last_usage_root(value: &Value) -> Option<&Value> {
    value
        .pointer("/token_count/info/last_token_usage")
        .or_else(|| value.pointer("/payload/info/last_token_usage"))
        .or_else(|| value.pointer("/payload/last_token_usage"))
        .or_else(|| value.pointer("/last_token_usage"))
}

pub(in crate::snapshots) fn codex_model_context_window(value: &Value) -> Option<u64> {
    raw_value_at(value, &["token_count", "info", "model_context_window"])
        .or_else(|| raw_value_at(value, &["payload", "info", "model_context_window"]))
        .or_else(|| raw_value_at(value, &["info", "model_context_window"]))
        .and_then(Value::as_u64)
        .filter(|window| *window > 0)
}

/// A Codex line's own envelope time, the same on every read route.
pub(in crate::snapshots) fn codex_line_timestamp(value: &Value) -> Option<String> {
    string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["time"]))
        .or_else(|| string_at(value, &["created_at"]))
}

pub(in crate::snapshots) fn codex_usage_event_identity(value: &Value) -> Option<String> {
    // The digest is never uploaded; it is persisted only in the local
    // durable-tail store. Hash the complete
    // content-free token_count record so an exact duplicated physical line is
    // idempotent without pretending that equal cumulative counters identify a
    // provider response. Native ordinals naturally participate when present.
    codex_last_usage(value)?;
    let event = value.to_string();
    Some(sha256_hex(&["codex_usage_event:v1", event.as_str()]))
}

fn codex_usage_from_root(root: &Value, cumulative: bool) -> Option<UsageTotals> {
    if !usage_object_has_numeric_field(
        root,
        &[
            "input_tokens",
            "inputTokens",
            "output_tokens",
            "outputTokens",
            "cache_read_tokens",
            "cached_input_tokens",
            "cachedInputTokens",
            "cache_write_tokens",
            "cache_write_input_tokens",
            "cacheWriteTokens",
            "cache_creation_tokens",
            "cacheCreationInputTokens",
            "reasoning_output_tokens",
            "request_count",
            "requests",
        ],
    ) {
        return None;
    }
    let input_details = root
        .get("input_tokens_details")
        .or_else(|| root.get("prompt_tokens_details"));
    // Keep Codex input inclusive here. Snapshot provenance declares
    // `input_token_scope=inclusive_cached`, and backend ingest subtracts the
    // observed read/write subsets exactly once. Normalizing in both places
    // would undercount fresh input.
    let mut usage = UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens: u64_at(root, &["output_tokens"])
            .or_else(|| u64_at(root, &["outputTokens"]))
            .unwrap_or_default(),
        cache_read_tokens: u64_at(root, &["cache_read_tokens"])
            .or_else(|| u64_at(root, &["cached_input_tokens"]))
            .or_else(|| u64_at(root, &["cachedInputTokens"]))
            .or_else(|| input_details.and_then(|details| u64_at(details, &["cached_tokens"])))
            .unwrap_or_default(),
        // Current Codex JSONL exposes reads but not writes. Accept OpenAI's
        // newer cache-write aliases now so a future CLI can become complete
        // without another wire-contract change.
        cache_creation_5m_tokens: u64_at(root, &["cache_write_tokens"])
            .or_else(|| u64_at(root, &["cache_write_input_tokens"]))
            .or_else(|| u64_at(root, &["cacheWriteTokens"]))
            .or_else(|| u64_at(root, &["cache_creation_tokens"]))
            .or_else(|| u64_at(root, &["cacheCreationInputTokens"]))
            .or_else(|| {
                input_details.and_then(|details| {
                    u64_at(details, &["cache_write_tokens"])
                        .or_else(|| u64_at(details, &["cache_write_input_tokens"]))
                })
            })
            .unwrap_or_default(),
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: u64_at(root, &["reasoning_output_tokens"]).unwrap_or_default(),
        unattributed_total_tokens: 0,
        request_count: u64_at(root, &["request_count"])
            .or_else(|| u64_at(root, &["requests"]))
            .unwrap_or_default(),
        costs: UsageCosts::default(),
    };
    if usage.request_count == 0 && (cumulative || !usage.is_zero()) {
        usage.request_count = 1;
    }
    Some(usage)
}

/// This response's effective input context from a Codex `token_count` event:
/// `last_token_usage.input_tokens`, the usage of the single API response the
/// event reports (the sibling `total_token_usage` is the session-wide running
/// sum). Already includes the cached prefix — `cached_input_tokens` is a subset
/// of `input_tokens`, not an addend — so it is the window-comparable context on
/// its own. `None` for lines carrying no per-response usage, and 0 for the
/// zero-usage event Codex emits at a compaction.
///
/// Pointer fallbacks mirror `codex_total_usage` so both survive the same
/// rollout-shape variations.
pub(in crate::snapshots) fn codex_last_turn_input_context(value: &Value) -> Option<u64> {
    let root = value
        .pointer("/token_count/info/last_token_usage")
        .or_else(|| value.pointer("/payload/info/last_token_usage"))
        .or_else(|| value.pointer("/payload/last_token_usage"))
        .or_else(|| value.pointer("/last_token_usage"))?;
    u64_at(root, &["input_tokens"]).or_else(|| u64_at(root, &["inputTokens"]))
}

pub(in crate::snapshots) fn codex_total_usage_has_request_count(value: &Value) -> bool {
    let Some(root) = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))
    else {
        return false;
    };
    u64_at(root, &["request_count"])
        .or_else(|| u64_at(root, &["requests"]))
        .is_some()
}

pub(in crate::snapshots) fn codex_cache_request(
    value: &Value,
    accumulator: &SnapshotAccumulator,
) -> Option<OwnedRequest> {
    let slot = cache_observations::codex_slot(
        value,
        accumulator.latest_model.clone(),
        accumulator.latest_reasoning_effort.clone(),
    )?;
    let compaction_before = accumulator
        .compaction_timestamps
        .last()
        .is_some_and(|timestamp| {
            accumulator.cache_requests.last().map_or(true, |prior| {
                timestamp_is_after(timestamp, &prior.slot.occurred_at)
            })
        });
    Some(OwnedRequest {
        slot,
        ordering: if accumulator.cache_active_turns.len() > 1 {
            "ambiguous"
        } else {
            "sequential"
        }
        .into(),
        compaction_before,
        configuration_changed: false,
        configuration_witness: accumulator.cache_configuration_witness.clone(),
        idle_seconds: accumulator.cache_pending_idle,
    })
}
