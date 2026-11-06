//! Codex usage readers for one rollout line: the cumulative and last-response
//! token totals of a `token_count` event, the model context window, the line's
//! envelope time and its usage event identity.

use serde_json::Value;

use crate::snapshots::cache_observations::{self, OwnedRequest};
use crate::snapshots::scan::json_fields::{string_at, u64_at};
use crate::snapshots::scan_index::file_set_digest::sha256_hex;
use crate::snapshots::*;
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

pub(in crate::snapshots) fn apply_codex_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    apply_codex_envelope_line(value, accumulator);
    if string_eq_at(value, &["type"], "session_meta") {
        accumulator.session_start.note_codex_session_meta(value);
    }
    accumulator.configure_codex_ownership(value);
    if !accumulator.codex_record_is_owned(value) {
        return;
    }
    let bootstrap = std::mem::take(&mut accumulator.codex_legacy_bootstrap_buffer);
    for bootstrap_value in &bootstrap {
        apply_codex_owned_line(bootstrap_value, accumulator);
    }
    apply_codex_owned_line(value, accumulator);
}

fn apply_codex_owned_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    codex_opening_content(value, accumulator);
    if string_eq_at(value, &["type"], "turn_context") {
        if let Some(payload) = value.get("payload").and_then(Value::as_object) {
            let metadata = payload
                .iter()
                .filter(|(field, _)| {
                    !matches!(
                        field.as_str(),
                        "turn_id" | "root_turn_id" | "summary" | "timestamp" | "usage"
                    )
                })
                .map(|(field, value)| (field.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>();
            if !metadata.is_empty() {
                // Domain-separated SHA-256 (an H value in the durable store).
                accumulator.cache_configuration_witness = Some(sha256_hex(&[
                    "ottto-cache-configuration-witness:v1",
                    Value::Object(metadata).to_string().as_str(),
                ]));
            }
        }
    }
    if string_eq_at(value, &["payload", "type"], "task_complete") {
        accumulator.cache_task_complete_at = string_at(value, &["timestamp"]);
        if let Some(turn) = string_at(value, &["payload", "turn_id"]) {
            accumulator.cache_active_turns.remove(&turn);
        }
    }
    if string_eq_at(value, &["payload", "type"], "task_started") {
        codex_user_turn_content(value, accumulator);
        if let Some(turn) = string_at(value, &["payload", "turn_id"]) {
            accumulator.codex_dictionary_slots.active_turns.note(&turn);
            accumulator.cache_active_turns.insert(turn);
        }
        accumulator.cache_pending_idle = accumulator
            .cache_task_complete_at
            .as_deref()
            .zip(value.get("timestamp").and_then(Value::as_str))
            .and_then(|(end, start)| cache_observations::elapsed_seconds(end, start));
    }
    if let Some(request) = codex_cache_request(value, accumulator) {
        accumulator.cache_requests.push(request);
        accumulator.cache_pending_idle = None;
    }
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = resolve_codex_identity_option(
            codex_identity_at(value, &["session_meta", "payload", "id"])
                .or_else(|| codex_identity_at(value, &["payload", "id"]))
                .or_else(|| codex_identity_at(value, &["session_id"]))
                .or_else(|| codex_identity_at(value, &["sessionId"])),
        );
    }
    // Raw session-origin (siblings of `id` in session_meta.payload). The
    // session_meta line carries these; other lines yield None, so first-seen
    // (guarded by is_none) keeps the authoritative session_meta values.
    if accumulator.origin.thread_source.is_none() {
        accumulator.origin.thread_source =
            string_at(value, &["session_meta", "payload", "thread_source"])
                .or_else(|| string_at(value, &["payload", "thread_source"]));
    }
    if accumulator.origin.source.is_none() && accumulator.origin.source_subagent.is_none() {
        if let Some(src) = raw_value_at(value, &["session_meta", "payload", "source"])
            .or_else(|| raw_value_at(value, &["payload", "source"]))
        {
            if let Some(text) = src.as_str() {
                accumulator.origin.source = Some(text.to_string());
            } else if src.is_object() {
                // Codex subagent form: source = { "subagent": { "thread_spawn": .. } }.
                accumulator.origin.source_subagent = Some(src.get("subagent").is_some());
                accumulator.origin.parent_session_ref = resolve_codex_identity_option(
                    codex_identity_at(src, &["subagent", "thread_spawn", "parent_thread_id"]),
                );
            }
        }
    }
    if accumulator.origin.originator.is_none() {
        accumulator.origin.originator =
            string_at(value, &["session_meta", "payload", "originator"])
                .or_else(|| string_at(value, &["payload", "originator"]));
    }
    if accumulator.origin.agent_role.is_none() {
        accumulator.origin.agent_role =
            string_at(value, &["session_meta", "payload", "agent_role"])
                .or_else(|| string_at(value, &["payload", "agent_role"]));
    }
    let timestamp = codex_line_timestamp(value);
    accumulator.note_time(timestamp.clone());
    codex_prompt_content(value, accumulator);
    accumulator.set_model(
        string_at(value, &["turn_context", "payload", "model"])
            .or_else(|| string_at(value, &["payload", "model"]))
            .or_else(|| string_at(value, &["model"])),
    );
    codex_workspace_content(value, accumulator);
    let selector = codex_selector_from_line(value);
    accumulator.set_selector(selector.clone());
    accumulator.note_codex_thread_settings(value, timestamp.as_deref());
    if let Some(effort) = codex_reasoning_effort(value) {
        accumulator.latest_reasoning_effort = Some(effort);
    }
    // Track the running turn id from `turn_context` (the token_count event that
    // emits usage carries none). It joins each usage row to its `logs_2`
    // fast-mode signal. Lines without a turn id leave the running value intact.
    if let Some(turn_id) = string_at(value, &["turn_context", "payload", "turn_id"])
        .or_else(|| string_at(value, &["payload", "turn_id"]))
    {
        accumulator.latest_turn_id = Some(turn_id);
    }
    // Codex compaction (auto or manual `/compact`) writes a top-level
    // `type=compacted` rollout record carrying the `replacement_history` that
    // supersedes the compacted turns. Codex also emits an
    // `event_msg`/`context_compacted` UI event for the same compaction a few
    // milliseconds later; the two are strictly paired, so count the rollout
    // record only — counting both would double every compaction. The rollout
    // record is the state mutation itself, which makes it the Codex analogue of
    // the `isCompactSummary` record the Claude parser counts.
    if string_eq_at(value, &["type"], "compacted") {
        accumulator.compaction_count += 1;
        if let Some(timestamp) = timestamp.clone() {
            // `before` is the session's current "last" value: the last owned
            // non-zero request before this marker, in the posture measure.
            accumulator
                .codex_compaction_sizes
                .note_marker(&timestamp, accumulator.last_turn_context_tokens);
            accumulator.compaction_timestamps.push(timestamp);
        }
    }
    // Context posture watermarks for this response. Codex states the per-turn
    // usage directly in `last_token_usage`, so read it off the event rather
    // than reusing the cumulative delta computed below. The delta agrees with
    // `last_token_usage` on a healthy sequence, but not on the two cases that
    // matter here: a duplicated `token_count` event (Codex emits these) yields
    // a zero delta while `last_token_usage` still states the turn's true
    // context, and a non-monotonic cumulative (session restart) makes the delta
    // the whole session's input rather than one turn's — which would post a
    // wildly inflated peak.
    //
    // The value needs no cache adjustment: unlike Claude's `message.usage`,
    // Codex `input_tokens` is INCLUSIVE of `cached_input_tokens` (hence
    // `input_token_scope=inclusive_cached` in this snapshot's provenance), so
    // it already IS the prompt volume the model saw. Adding cache reads on top
    // — the Claude-side `effective_input_context()` formula — would nearly
    // double a cache-heavy turn and report a long session as filling more than
    // its own context window.
    if let Some(context_tokens) = codex_last_turn_input_context(value) {
        // The `token_count` event Codex emits at a compaction reports zero
        // usage; it observed no context, so it must not become the baseline.
        if context_tokens > 0 {
            // The window that bounded THIS prompt, read off the same record,
            // so each watermark keeps its own window when Codex changes it
            // mid-session. One lookup on the already parsed record.
            let window = codex_model_context_window(value);
            if accumulator.first_turn_context_tokens.is_none() {
                accumulator.first_turn_context_tokens = Some(context_tokens);
                accumulator.first_turn_context_window_tokens = window;
            }
            // Peak ties: the first record that reached the peak keeps its
            // window; a later equal record only fills a window that is still
            // missing, and never replaces a known one.
            if context_tokens > accumulator.peak_context_fill_tokens
                || (context_tokens == accumulator.peak_context_fill_tokens
                    && accumulator.peak_context_fill_window_tokens.is_none())
            {
                accumulator.peak_context_fill_window_tokens = window;
            }
            accumulator.peak_context_fill_tokens =
                accumulator.peak_context_fill_tokens.max(context_tokens);
            accumulator.last_turn_context_tokens = Some(context_tokens);
            // As-is, including None: a later record without a window must not
            // keep an older record's window under its own watermark.
            accumulator.last_turn_context_window_tokens = window;
            accumulator
                .local_context_points
                .push(timestamp.as_deref(), context_tokens);
        }
    }
    // Usage-counting V2 (configured parsers only): version decision on the
    // first owned record, turn lifecycle and native `token_usage_record`s.
    accumulator.observe_codex_counting_line(value, timestamp.as_deref(), &selector);
    if let Some(usage) = codex_total_usage(value) {
        // Codex cumulative totals carry request_count as a session-wide count.
        // When the field is missing the parser defaults it to 1 so deltas
        // would yield 0 requests. Track the implicit case and override the
        // delta's request_count to 1 so the bucket row reflects "one turn
        // observed at this hour" — matching v5's note_activity behavior.
        let implicit_request_count = if codex_total_usage_has_request_count(value) {
            None
        } else {
            Some(1)
        };
        // Stamp the fast-mode tier onto THIS turn's usage row only — passed as
        // the per-line selector, never merged into current_selector — so a fast
        // turn prices at the priority rate without leaking into later standard
        // turns of the same session.
        let mut usage_selector = selector;
        if accumulator.current_turn_is_priority() {
            usage_selector.insert(
                "service_tier",
                "priority".to_string(),
                "derived_from_logs_2",
            );
        }
        let model = string_at(value, &["token_count", "info", "model"])
            .or_else(|| string_at(value, &["payload", "info", "model"]))
            .or_else(|| string_at(value, &["turn_context", "payload", "model"]))
            .or_else(|| string_at(value, &["payload", "model"]));
        let applied_tier = accumulator.codex_tier_replay.as_mut().and_then(|replay| {
            replay.selector(
                value,
                &mut usage_selector,
                &accumulator.current_selector,
                model.as_deref().or(accumulator.latest_model.as_deref()),
                accumulator.latest_reasoning_effort.as_deref(),
                accumulator.latest_turn_id.as_deref(),
            )
        });
        accumulator.stamp_codex_thread_tier(&mut usage_selector, timestamp.as_deref());
        // Stamp this response's long-context price bucket on the same per-line
        // selector, after the tier replay key above (which must not change): a
        // prompt over the model's provider line bills the whole request at the
        // long rate. The size is the already-parsed per-response
        // `last_token_usage.input_tokens`; no price line, no stamp.
        if !usage_selector.context.contains_key("context_bucket") {
            let bucket = model
                .as_deref()
                .or(accumulator.latest_model.as_deref())
                .zip(codex_last_turn_input_context(value))
                .and_then(|(model, prompt_tokens)| {
                    provider_context_bucket(model, prompt_tokens, timestamp.as_deref())
                });
            if let Some(bucket) = bucket {
                usage_selector.insert(
                    "context_bucket",
                    bucket.to_string(),
                    "derived_from_last_token_usage",
                );
            }
        }
        let last_usage = codex_last_usage(value);
        let usage_event_identity = codex_usage_event_identity(value);
        let admitted = accumulator.set_cumulative_usage_with_selector(
            model.clone(),
            usage,
            last_usage.clone(),
            usage_event_identity.clone(),
            usage_selector,
            timestamp.as_deref(),
            implicit_request_count,
            accumulator.latest_reasoning_effort.clone(),
        );
        if admitted.is_some() {
            let v2 = codex_file_join::group_counting_is_v2(accumulator);
            if let Some(replay) = accumulator.codex_tier_replay.as_mut() {
                replay.admitted(applied_tier);
                // S10: the group proof sees only actually admitted usage.
                replay.admitted_usage(
                    value,
                    last_usage.is_some(),
                    usage_event_identity.as_deref(),
                    accumulator.latest_turn_id.as_deref(),
                    v2,
                );
            }
        }
        if let (Some(_), Some(last_usage)) = (admitted.as_ref(), last_usage.as_ref()) {
            accumulator.session_start.note_codex_request(last_usage);
        }
        // A compaction's "after" is the first COUNTED request after it: exact
        // duplicates and re-emissions are not admitted. Same measure as
        // `before` (the posture read of `last_token_usage`).
        if admitted.is_some() {
            if let Some(context_tokens) = codex_last_turn_input_context(value) {
                accumulator
                    .codex_compaction_sizes
                    .note_counted_request(context_tokens);
            }
        }
    }
    if string_eq_at(value, &["type"], "response_item") {
        let payload_type = string_at(value, &["payload", "type"]);
        if matches!(
            payload_type.as_deref(),
            Some("function_call" | "custom_tool_call")
        ) {
            if let Some(name) = string_at(value, &["payload", "name"]) {
                let is_function_call = payload_type.as_deref() == Some("function_call");
                let call_id = is_function_call
                    .then(|| string_at(value, &["payload", "call_id"]))
                    .flatten();
                let mcp_tool = is_function_call
                    .then(|| codex_namespaced_mcp_tool(value, &name))
                    .flatten();
                if call_id
                    .as_ref()
                    .is_some_and(|call_id| accumulator.activity_mcp_call_ids.contains_key(call_id))
                {
                    // Already counted as MCP by its completion event.
                } else if let Some((server, tool)) = mcp_tool {
                    accumulator.activity_mcp_calls += 1;
                    accumulator.note_activity_mcp_tool(&server, &tool);
                    if let Some(call_id) = call_id {
                        accumulator.codex_dictionary_slots.open_calls.note(&call_id);
                        accumulator.activity_mcp_call_ids.insert(call_id, false);
                    }
                } else {
                    accumulator.note_activity_tool(&name);
                    if let Some(call_id) = call_id {
                        accumulator.codex_dictionary_slots.open_calls.note(&call_id);
                        accumulator
                            .activity_call_tools
                            .insert(ActivityCallId { id: call_id }, ActivityCallTool { name });
                    }
                }
            }
            if let Some(material) = string_at(value, &["payload", "arguments"])
                .or_else(|| string_at(value, &["payload", "input"]))
            {
                accumulator.note_activity_tools(&material);
                accumulator.note_activity_skills(&material);
            }
        }
        if payload_type.as_deref() == Some("function_call_output") {
            if let Some(call_id) = string_at(value, &["payload", "call_id"]) {
                accumulator.activity_call_tools.remove(call_id.as_str());
                accumulator.activity_mcp_call_ids.remove(&call_id);
            }
        }
    }
    if matches!(
        string_at(value, &["type"]).as_deref(),
        Some("event_msg" | "response_item")
    ) {
        match string_at(value, &["payload", "type"]).as_deref() {
            Some("patch_apply_end") => {
                accumulator.activity_patch_operations += 1;
                if let Some(changes) =
                    raw_value_at(value, &["payload", "changes"]).and_then(Value::as_object)
                {
                    for (path, change) in changes {
                        accumulator
                            .activity_changed_file_hashes
                            .insert(sha256_hex(&["ottto-activity-changed-file:v1", path]));
                        if let Some(diff) = change.get("unified_diff").and_then(Value::as_str) {
                            for line in diff.lines() {
                                if line.starts_with('+') && !line.starts_with("+++") {
                                    accumulator.activity_lines_added += 1;
                                } else if line.starts_with('-') && !line.starts_with("---") {
                                    accumulator.activity_lines_deleted += 1;
                                }
                            }
                        }
                    }
                }
            }
            Some("web_search_end") => accumulator.activity_web_searches += 1,
            Some("mcp_tool_call_end") => {
                let call_id = string_at(value, &["payload", "call_id"]);
                let prior = call_id
                    .as_ref()
                    .and_then(|call_id| accumulator.activity_mcp_call_ids.get(call_id).copied());
                // `Some(true)`: a repeated completion event for a counted call.
                if prior != Some(true) {
                    if let Some((capability_id, raw_origin)) = codex_tool_surface_capability(value)
                    {
                        accumulator.note_capability_call(
                            timestamp.as_deref(),
                            capability_id,
                            raw_origin,
                        );
                    }
                    if let Some(call_id) = &call_id {
                        accumulator.codex_dictionary_slots.open_calls.note(call_id);
                        accumulator
                            .activity_mcp_call_ids
                            .insert(call_id.clone(), true);
                    }
                }
                // `Some(false)`: the namespaced function_call already counted it.
                if prior.is_none() {
                    if let Some(call_id) = &call_id {
                        accumulator.reclassify_activity_call_as_mcp(call_id);
                    }
                    accumulator.activity_mcp_calls += 1;
                    let server = string_at(value, &["payload", "app_name"])
                        .or_else(|| string_at(value, &["payload", "invocation", "server"]));
                    let tool = string_at(value, &["payload", "action_name"])
                        .or_else(|| string_at(value, &["payload", "invocation", "tool"]));
                    if let (Some(server), Some(tool)) = (server, tool) {
                        accumulator.note_activity_mcp_tool(&server, &tool);
                    }
                }
            }
            Some("sub_agent_activity") if string_eq_at(value, &["payload", "kind"], "started") => {
                accumulator.activity_subagent_spawns += 1;
            }
            _ => {}
        }
    }
    // Per-turn latency from the rollout `task_complete` event. Codex emits
    // `duration_ms` + `time_to_first_token_ms` only here (never over OTLP), so
    // accumulate them per session for the session-level latency average.
    if string_eq_at(value, &["payload", "type"], "task_complete") {
        if let Some(duration_ms) = u64_at(value, &["payload", "duration_ms"]) {
            accumulator.latency_duration_ms_sum = accumulator
                .latency_duration_ms_sum
                .saturating_add(duration_ms);
            accumulator.latency_duration_ms_count += 1;
            accumulator.latency_duration_ms_max =
                accumulator.latency_duration_ms_max.max(duration_ms);
        }
        if let Some(ttft_ms) = u64_at(value, &["payload", "time_to_first_token_ms"]) {
            accumulator.latency_ttft_ms_sum =
                accumulator.latency_ttft_ms_sum.saturating_add(ttft_ms);
            accumulator.latency_ttft_ms_count += 1;
            accumulator.latency_ttft_ms_max = accumulator.latency_ttft_ms_max.max(ttft_ms);
        }
    }
}

/// The explicit MCP server and tool of a Codex `function_call` that names its
/// server in `payload.namespace` (`mcp__<server>`), as current Codex writes for
/// MCP tools (for example `js` under `mcp__cua_repl`). The server comes only
/// from that field: a bare name, a non-MCP namespace or a malformed one yields
/// `None`, and so does a name already qualified for a different server.
fn codex_namespaced_mcp_tool(value: &Value, name: &str) -> Option<(String, String)> {
    let namespace = string_at(value, &["payload", "namespace"])?;
    let server = namespace.strip_prefix("mcp__")?;
    if server.is_empty() || server.contains("__") {
        return None;
    }
    let tool = match name.strip_prefix("mcp__") {
        Some(qualified) => qualified.strip_prefix(server)?.strip_prefix("__")?,
        None => name
            .strip_prefix(server)
            .and_then(|rest| rest.strip_prefix("__"))
            .unwrap_or(name),
    };
    let qualified = format!("mcp__{server}__{tool}");
    (!tool.is_empty()
        && qualified.len() <= MAX_TOOL_USAGE_NAME_LENGTH
        && bounded_tool_usage_name(&qualified).is_some())
    .then(|| (server.to_string(), tool.to_string()))
}

fn codex_tool_surface_capability(value: &Value) -> Option<(&'static str, &'static str)> {
    let meta = value
        .pointer("/payload/result/Ok/_meta")
        .or_else(|| value.pointer("/result/Ok/_meta"))?;
    let surface = meta.get("codex/toolSurface")?;
    match (
        surface.get("kind").and_then(Value::as_str),
        surface.get("backend").and_then(Value::as_str),
    ) {
        (Some("browserUse"), Some("chrome")) => Some(("browser.chrome", "browser:chrome")),
        (Some("browserUse"), Some("iab")) => Some(("browser.in_app", "browser:iab")),
        (Some("computerUse"), _) => Some(("computer.use", "computer-use")),
        _ => None,
    }
}

pub(in crate::snapshots) fn codex_plan_window_bucket(value: &Value) -> Option<u64> {
    let rate_limit_paths: &[&[&str]] = &[
        &["payload", "rate_limits"],
        &["token_count", "info", "rate_limits"],
    ];
    for path in rate_limit_paths {
        if let Some(rate_limits) = raw_value_at(value, path) {
            if let Some(resets_at) = u64_at(rate_limits, &["secondary", "resets_at"]) {
                return Some(resets_at / 86_400);
            }
        }
    }
    None
}

pub(in crate::snapshots) fn codex_extract_quota_window_selectors(
    value: &Value,
    selector: &mut SelectorCapture,
) {
    let rate_limits = raw_value_at(value, &["payload", "rate_limits"])
        .or_else(|| raw_value_at(value, &["token_count", "info", "rate_limits"]));
    let Some(rate_limits) = rate_limits else {
        return;
    };
    for window_name in &["primary", "secondary"] {
        let Some(window) = raw_value_at(rate_limits, &[*window_name]) else {
            continue;
        };
        for (field_suffix, source_key, raw) in [
            (
                "used_percent",
                "used_percent",
                window.get("used_percent").cloned(),
            ),
            (
                "window_minutes",
                "window_minutes",
                window.get("window_minutes").cloned(),
            ),
            ("resets_at", "resets_at", window.get("resets_at").cloned()),
        ] {
            let Some(raw) = raw else {
                continue;
            };
            let field = format!("agent_quota_{window_name}_{field_suffix}");
            let source = format!("payload.rate_limits.{window_name}.{source_key}");
            insert_selector_raw(selector, field.as_str(), source.as_str(), &raw);
        }
    }
    if let Some(credits) = raw_value_at(rate_limits, &["credits"]) {
        for (field_suffix, source_key) in [
            ("has_credits", "has_credits"),
            ("unlimited", "unlimited"),
            ("balance", "balance"),
        ] {
            let Some(raw) = credits.get(source_key) else {
                continue;
            };
            let field = format!("agent_quota_credits_{field_suffix}");
            let source = format!("payload.rate_limits.credits.{source_key}");
            insert_selector_raw(selector, field.as_str(), source.as_str(), raw);
        }
    }
}

pub(in crate::snapshots) fn codex_transcript_title(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "thread_name_updated") {
        return string_at(value, &["payload", "thread_name"])
            .or_else(|| string_at(value, &["payload", "name"]))
            .or_else(|| string_at(value, &["payload", "title"]));
    }
    if string_eq_at(value, &["type"], "thread_name_updated") {
        return string_at(value, &["thread_name"])
            .or_else(|| string_at(value, &["name"]))
            .or_else(|| string_at(value, &["title"]));
    }
    string_at(value, &["thread_name_updated", "payload", "name"])
        .or_else(|| string_at(value, &["thread_name_updated", "name"]))
}

pub(in crate::snapshots) fn codex_first_user_prompt(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "user_message") {
        return string_at(value, &["payload", "message"])
            .or_else(|| string_at(value, &["payload", "text"]))
            .or_else(|| prompt_text_from_array(value.pointer("/payload/text_elements")));
    }
    if string_eq_at(value, &["type"], "user_message") {
        return string_at(value, &["message"])
            .or_else(|| string_at(value, &["text"]))
            .or_else(|| prompt_text_from_array(value.get("text_elements")));
    }
    if string_eq_at(value, &["payload", "type"], "message")
        && string_eq_at(value, &["payload", "role"], "user")
    {
        return prompt_text_from_array(value.pointer("/payload/content"));
    }
    None
}

fn prompt_text_from_array(value: Option<&Value>) -> Option<String> {
    let Value::Array(items) = value? else {
        return None;
    };
    let parts = items.iter().filter_map(|item| {
        let text = match item {
            Value::String(text) => Some(text.as_str()),
            Value::Object(_) => item
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| item.get("input_text").and_then(Value::as_str)),
            _ => None,
        }?;
        let text = crate::session_attribution::prompt_without_injected_scaffolding(text);
        (!text.is_empty()).then_some(text)
    });
    normalize_title(parts.collect::<Vec<_>>().join("\n"))
}
