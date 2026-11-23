//! Claude Code usage-field readers for one transcript record: the response
//! dedup key, the usage root and counters, `iterations[]`, the cache-write
//! split and the effective input context.

use serde_json::Value;

use crate::snapshots::cache_observations::RequestSlot;
use crate::snapshots::claude_request_money;
use crate::snapshots::scan::json_fields::{string_at, u64_at};
use crate::snapshots::*;
use crate::snapshots::{usage_object_has_numeric_field, UsageCosts, UsageTotals};

/// Identity of the API response behind one Claude Code JSONL record, used to
/// count `message.usage` once per response instead of once per content-block
/// record. Keyed on the (`message.id`, `requestId`) PAIR when both exist —
/// conservative: if either differs, the line is treated as a distinct
/// response — falling back to whichever is present alone. `None` (neither id)
/// means no dedup is possible and the caller counts the line.
pub(in crate::snapshots) fn claude_code_usage_dedup_key(value: &Value) -> Option<String> {
    let message_id = string_at(value, &["message", "id"]);
    let request_id = string_at(value, &["requestId"]).or_else(|| string_at(value, &["request_id"]));
    match (message_id, request_id) {
        (Some(message_id), Some(request_id)) => {
            Some(format!("p\u{1f}{message_id}\u{1f}{request_id}"))
        }
        (Some(message_id), None) => Some(format!("m\u{1f}{message_id}")),
        (None, Some(request_id)) => Some(format!("r\u{1f}{request_id}")),
        (None, None) => None,
    }
}

pub(in crate::snapshots) fn claude_code_usage_root(value: &Value) -> Option<&Value> {
    value
        .pointer("/message/usage")
        .or_else(|| value.pointer("/usage"))
        .or_else(|| value.pointer("/payload/usage"))
}

pub(in crate::snapshots) fn claude_code_delta_usage(value: &Value) -> Option<UsageTotals> {
    let root = claude_code_usage_root(value)?;
    if !usage_object_has_numeric_field(
        root,
        &[
            "input_tokens",
            "inputTokens",
            "output_tokens",
            "outputTokens",
            "cache_read_input_tokens",
            "cache_read_tokens",
            "cache_creation_input_tokens",
            "reasoning_output_tokens",
        ],
    ) {
        return None;
    }
    // Claude Code can state part of a response's usage only in
    // `usage.iterations[]`, one entry per API call: an all-zero top level
    // beside a carrying iteration, or a top level restating only the last of
    // several calls. The top level never exceeds the iterations' sum and
    // equals it on almost every line, so each billed kind takes the larger of
    // the two, never both. Cache writes are normalized per entry first and
    // keep their 5m and 1h buckets apart.
    let mut usage = claude_code_usage_fields(root);
    let mut summed = UsageTotals::default();
    for iteration in claude_code_usage_iterations(root)
        .iter()
        .map(claude_code_usage_fields)
    {
        summed.input_tokens = summed.input_tokens.saturating_add(iteration.input_tokens);
        summed.output_tokens = summed.output_tokens.saturating_add(iteration.output_tokens);
        summed.cache_read_tokens = summed
            .cache_read_tokens
            .saturating_add(iteration.cache_read_tokens);
        summed.cache_creation_5m_tokens = summed
            .cache_creation_5m_tokens
            .saturating_add(iteration.cache_creation_5m_tokens);
        summed.cache_creation_1h_tokens = summed
            .cache_creation_1h_tokens
            .saturating_add(iteration.cache_creation_1h_tokens);
    }
    usage.input_tokens = usage.input_tokens.max(summed.input_tokens);
    usage.output_tokens = usage.output_tokens.max(summed.output_tokens);
    usage.cache_read_tokens = usage.cache_read_tokens.max(summed.cache_read_tokens);
    usage.cache_creation_5m_tokens = usage
        .cache_creation_5m_tokens
        .max(summed.cache_creation_5m_tokens);
    usage.cache_creation_1h_tokens = usage
        .cache_creation_1h_tokens
        .max(summed.cache_creation_1h_tokens);
    Some(usage)
}

/// Numeric keys a usage object (top level or iteration) may carry that
/// `claude_code_usage_fields` does not read, plus those in its `cache_creation`
/// and `output_tokens_details`. Every numeric key seen at these levels in local
/// transcripts is read, so this reads zero today.
pub(in crate::snapshots) fn claude_code_unknown_usage_keys(root: &Value) -> u64 {
    const USAGE: &[&str] = &[
        "input_tokens",
        "inputTokens",
        "output_tokens",
        "outputTokens",
        "cache_read_input_tokens",
        "cache_read_tokens",
        "cache_creation_input_tokens",
        "cache_creation_tokens",
        "reasoning_output_tokens",
    ];
    const CACHE_CREATION: &[&str] = &[
        "ephemeral_5m_input_tokens",
        "ephemeral5mInputTokens",
        "ephemeral_1h_input_tokens",
        "ephemeral1hInputTokens",
    ];
    let unknown = |object: Option<&Value>, known: &[&str]| {
        object.and_then(Value::as_object).map_or(0, |object| {
            object
                .iter()
                .filter(|(key, value)| value.is_number() && !known.contains(&key.as_str()))
                .count() as u64
        })
    };
    std::iter::once(root)
        .chain(claude_code_usage_iterations(root))
        .map(|usage| {
            let cache_creation = usage
                .get("cache_creation")
                .or_else(|| usage.get("cacheCreation"));
            unknown(Some(usage), USAGE)
                + unknown(cache_creation, CACHE_CREATION)
                + unknown(usage.get("output_tokens_details"), &["thinking_tokens"])
        })
        .sum()
}

pub(in crate::snapshots) fn claude_code_usage_iterations(root: &Value) -> &[Value] {
    root.get("iterations")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// One usage object's own counters: a response's top level or one of its
/// `iterations[]` entries.
fn claude_code_usage_fields(root: &Value) -> UsageTotals {
    let (cache_5m, cache_1h) = claude_code_cache_creation_split(root);
    let output_tokens = u64_at(root, &["output_tokens"])
        .or_else(|| u64_at(root, &["outputTokens"]))
        .unwrap_or_default();
    // Claude Code writes the thinking count as
    // `output_tokens_details.thinking_tokens`, a part of `output_tokens`.
    // Early streamed rows can briefly report more thinking than output, so
    // clamp to the record's own output.
    let reasoning_output_tokens = u64_at(root, &["reasoning_output_tokens"])
        .or_else(|| u64_at(root, &["output_tokens_details", "thinking_tokens"]))
        .unwrap_or_default()
        .min(output_tokens);
    UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens,
        cache_read_tokens: u64_at(root, &["cache_read_input_tokens"])
            .or_else(|| u64_at(root, &["cache_read_tokens"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens,
        unattributed_total_tokens: 0,
        request_count: 1,
        costs: UsageCosts::default(),
    }
}

// Anthropic exposes prompt-cache writes as `usage.cache_creation.ephemeral_5m_input_tokens`
// and `ephemeral_1h_input_tokens` (the 5m / 1h TTL split). The pricing page rates those
// at 1.25x and 2x base input respectively, so the split is load-bearing for cost. If only
// the flat `cache_creation_input_tokens` is present (older transcripts), default to the
// 5m bucket which is Anthropic's default TTL.
pub(in crate::snapshots) fn claude_code_cache_creation_split(root: &Value) -> (u64, u64) {
    use claude_request_money::CacheCreation;
    let (cache_5m, cache_1h) = root
        .get("cache_creation")
        .or_else(|| root.get("cacheCreation"))
        .map(|nested| {
            (
                u64_at(nested, &["ephemeral_5m_input_tokens"])
                    .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
                    .unwrap_or_default(),
                u64_at(nested, &["ephemeral_1h_input_tokens"])
                    .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
                    .unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let flat = u64_at(root, &["cache_creation_input_tokens"])
        .or_else(|| u64_at(root, &["cache_creation_tokens"]))
        .unwrap_or_default();
    // The transcript reading: a stated split wins over the flat total even
    // when they disagree; a flat-only write is the default (5m) TTL.
    match claude_request_money::claude_cache_creation(flat, cache_5m, cache_1h) {
        CacheCreation::Split { five_m, one_h } => (five_m, one_h),
        CacheCreation::Unattributed(flat) => (flat, 0),
        CacheCreation::Contradictory => (cache_5m, cache_1h),
    }
}

/// This response's effective input context — the largest single prompt the model
/// saw — reconciled against `usage.iterations[]`.
///
/// Claude Code now writes an `iterations[]` array on nearly every assistant
/// record (103,579 of 104,020 in the 2026-08-14 local corpus), one entry per API
/// call made while producing the response. The top-level fields normally restate
/// that call's usage and agree with it, so this reads through as a no-op. Two
/// observed shapes disagree:
///
///   * a resumed session's first response reports all-zero top-level prompt
///     fields while `iterations[0]` carries the real prompt. `cache_creation`
///     still states the write, so the top-level formula returns a small POSITIVE
///     value (1,684 against a true 896,597) — positive enough to be accepted as
///     the session's first-turn baseline, 532x too low.
///   * a multi-iteration response, where the top level tracks only one of the
///     calls (observed: the last) and the largest prompt is another iteration.
///
/// Rare but concentrated: re-parsing the whole local corpus moves 5 of 616
/// sessions, and every one of them is a ~900K-1M context session — the sessions
/// a context-pressure product exists to describe.
///
/// Take the MAX, never the sum: each iteration is its own API call with its own
/// prompt, so the watermark these values feed (`first_turn_context_tokens`,
/// `peak_context_fill_tokens`, and the 1M-window `context_bucket` threshold)
/// models one prompt. One local response iterates prompts of 879,891 and
/// 708,526; summing would post 1,588,417 for a response whose largest prompt was
/// 879,891 — past the model window. Maxing against the top level rather than
/// replacing it also keeps the reverse case honest: another local record reports
/// 104,266 top-level over iterations of 82,241 and 82,222, and the larger figure
/// is the one to keep.
///
/// Billing differs on purpose: `claude_code_delta_usage` takes, per kind, the
/// larger of the top level and the iterations' sum. This watermark reads the
/// raw top level and single iterations, never that billing fold.
pub(in crate::snapshots) fn claude_code_effective_input_context(root: &Value) -> u64 {
    claude_code_usage_iterations(root)
        .iter()
        .map(|iteration| claude_code_usage_fields(iteration).effective_input_context())
        .fold(
            claude_code_usage_fields(root).effective_input_context(),
            u64::max,
        )
}

pub(in crate::snapshots) fn claude_cache_request_slot(
    value: &Value,
    model: Option<String>,
    effort: Option<String>,
    timestamp: Option<String>,
) -> RequestSlot {
    let usage = claude_code_usage_root(value);
    let field = |name: &str| {
        usage
            .and_then(|usage| usage.get(name))
            .and_then(Value::as_u64)
    };
    let uncached = field("input_tokens");
    let read = field("cache_read_input_tokens");
    let write = field("cache_creation_input_tokens");
    RequestSlot {
        request_ref: string_at(value, &["requestId"])
            .or_else(|| string_at(value, &["request_id"]))
            .unwrap_or_default(),
        occurred_at: timestamp.unwrap_or_default(),
        model,
        effort,
        prompt_tokens: uncached
            .zip(read)
            .zip(write)
            .and_then(|((u, r), w)| u.checked_add(r)?.checked_add(w)),
        cache_read_tokens: read,
        cache_creation_tokens: write,
        uncached_tokens: uncached,
        output_tokens: field("output_tokens"),
    }
}

/// First-user-prompt candidate from one Claude Code transcript record — the
/// Claude analogue of `codex_first_user_prompt`, feeding the shared
/// `first_prompt` fallback when no real title exists anywhere (pure-CLI
/// sessions never opened in the desktop app).
///
/// Only genuine human-authored prompts qualify: `type=user` records whose
/// `message.role` is `user`, skipping `isMeta` records, `tool_result` content
/// blocks (which also ride `type=user` records), and harness wrappers
/// (slash-command envelopes, injected system reminders).
pub(in crate::snapshots) fn claude_first_user_prompt(value: &Value) -> Option<String> {
    if !string_eq_at(value, &["type"], "user")
        || value.get("isMeta").and_then(Value::as_bool) == Some(true)
        || !string_eq_at(value, &["message", "role"], "user")
    {
        return None;
    }
    match value.pointer("/message/content") {
        Some(Value::String(text)) => {
            if claude_prompt_is_harness_wrapper(text) {
                return None;
            }
            normalize_title(text.clone())
        }
        Some(content @ Value::Array(_)) => claude_prompt_text_from_content(content),
        _ => None,
    }
}

fn claude_prompt_text_from_content(content: &Value) -> Option<String> {
    let Value::Array(items) = content else {
        return None;
    };
    let mut parts = Vec::new();
    for item in items {
        if !string_eq_at(item, &["type"], "text") {
            continue;
        }
        if let Some(text) = item.get("text").and_then(Value::as_str) {
            if !claude_prompt_is_harness_wrapper(text) {
                parts.push(text);
            }
        }
    }
    normalize_title(parts.join("\n"))
}

/// True for text the Claude Code harness writes into `type=user` records that
/// is not a human prompt: slash-command envelopes, local command output,
/// injected system reminders, and background-task notifications.
fn claude_prompt_is_harness_wrapper(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with("<command-")
        || trimmed.starts_with("<local-command")
        || trimmed.starts_with("<system-reminder")
        || trimmed.starts_with("<task-notification")
        || trimmed.starts_with("[SYSTEM NOTIFICATION")
        || trimmed.starts_with("[Request interrupted")
        || trimmed.starts_with("Caveat: the messages below were generated")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum ClaudeForkLineProvenance {
    None,
    Inherited,
    Invalid,
}

/// Classify Claude's provider-authored branch provenance. Current branch,
/// `--fork-session`, SDK fork, and rewind writers stamp every copied record
/// with both the direct source session and original message UUID. A malformed
/// marker is not safe to count or skip, so it quarantines the file instead.
pub(in crate::snapshots) fn claude_fork_line_provenance(value: &Value) -> ClaudeForkLineProvenance {
    let Some(forked_from) = value.get("forkedFrom") else {
        return ClaudeForkLineProvenance::None;
    };
    let Some(forked_from) = forked_from.as_object() else {
        return ClaudeForkLineProvenance::Invalid;
    };
    let session_id = forked_from
        .get("sessionId")
        .or_else(|| forked_from.get("session_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let message_uuid = forked_from
        .get("messageUuid")
        .or_else(|| forked_from.get("message_uuid"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if session_id.is_some() && message_uuid.is_some() {
        ClaudeForkLineProvenance::Inherited
    } else {
        ClaudeForkLineProvenance::Invalid
    }
}

/// `/branch` (Claude Code 2.1.309+) writes one `fork-context-ref` line naming
/// the session it copied. Only a session-id-shaped name is kept; a second,
/// different name (or an invalid one) leaves no single original (empty).
fn note_claude_fork_parent(parent: &mut Option<String>, named: Option<&str>) {
    let named = named.filter(|named| codex_identity_is_uuid_shaped(named));
    match (parent.as_deref(), named) {
        (None, Some(named)) => *parent = Some(named.to_owned()),
        (Some(kept), Some(named)) if kept == named => {}
        _ => *parent = Some(String::new()),
    }
}

pub(in crate::snapshots) fn apply_claude_code_line(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    // Before the fork-provenance return: the lineage window includes copied
    // history.
    if let Some(at) = value
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(rfc3339_unix_nanos)
    {
        let (first, last) = accumulator.claude_line_clocks.get_or_insert((at, at));
        *first = (*first).min(at);
        *last = (*last).max(at);
    }
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = string_at(value, &["sessionId"])
            .or_else(|| string_at(value, &["session_id"]))
            .or_else(|| string_at(value, &["conversation_id"]));
    }
    match claude_fork_line_provenance(value) {
        ClaudeForkLineProvenance::Inherited => {
            // The copied record belongs to the source session. Returning here
            // excludes its usage, lifecycle, activity, title, model, context,
            // compaction, and artifacts from the child while leaving graph
            // attribution untouched (that is path/sidecar-derived later).
            accumulator.claude_context_curve_owned_start_proven = true;
            accumulator.session_start.note_inherited_prefix();
            return;
        }
        ClaudeForkLineProvenance::Invalid => {
            accumulator.note_dropped_usage();
            return;
        }
        ClaudeForkLineProvenance::None => {}
    }
    if string_eq_at(value, &["type"], "fork-context-ref") {
        note_claude_fork_parent(
            &mut accumulator.claude_fork_parent,
            value.get("parentSessionId").and_then(Value::as_str),
        );
    }
    if accumulator.claude_request_identity_capture {
        claude_request_identity::note_marker_line(
            &mut accumulator.claude_org_markers,
            value,
            accumulator.claude_response_sequence,
        );
    }
    if let Some(owned_id) = string_at(value, &["sessionId"])
        .or_else(|| string_at(value, &["session_id"]))
        .or_else(|| string_at(value, &["conversation_id"]))
    {
        accumulator.claude_owned_session_id_observed = true;
        accumulator.claude_owned_session_id_conflicted |=
            accumulator.source_session_id.as_deref() != Some(owned_id.as_str());
    }
    // Raw session-origin from the Claude JSONL header/lines. entrypoint +
    // sessionKind are first-seen; isSidechain is per-line so any true marks the
    // whole session a subagent (Task tool sidechain).
    if accumulator.origin.entrypoint.is_none() {
        accumulator.origin.entrypoint = string_at(value, &["entrypoint"]);
    }
    if accumulator.origin.session_kind.is_none() {
        accumulator.origin.session_kind = string_at(value, &["sessionKind"]);
    }
    if let Some(sidechain) = value.get("isSidechain").and_then(Value::as_bool) {
        accumulator.origin.is_sidechain =
            Some(accumulator.origin.is_sidechain.unwrap_or(false) || sidechain);
    }
    accumulator.note_provider_skill(string_at(value, &["attributionSkill"]));
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["created_at"]))
        .or_else(|| string_at(value, &["message", "created_at"]));
    accumulator
        .claude_file_birth
        .observe_line(timestamp.as_deref(), accumulator.claude_response_sequence);
    note_claude_capability_calls(value, timestamp.as_deref(), accumulator);
    // Current Claude transcripts write both of these shapes for one compaction.
    // Keep the raw observations here; `claude_compaction_summary` pairs a
    // summary with the boundary its `parentUuid` chain leads to, falls back to
    // a short time window only for a summary with no `parentUuid`, and
    // preserves either shape when it appears alone.
    let is_legacy_compaction = string_eq_at(value, &["type"], "user")
        && value.get("isCompactSummary").and_then(Value::as_bool) == Some(true);
    let is_current_compaction = string_eq_at(value, &["type"], "system")
        && string_eq_at(value, &["subtype"], "compact_boundary");
    let extends_compaction_link =
        accumulator
            .claude_compaction_link_tip
            .as_ref()
            .is_some_and(|(_, tip)| {
                value.get("parentUuid").and_then(Value::as_str) == Some(tip.as_str())
            });
    if extends_compaction_link && string_eq_at(value, &["type"], "attachment") {
        accumulator.claude_compaction_link_tip = accumulator
            .claude_compaction_link_tip
            .take()
            .and_then(|(key, _)| Some((key, string_at(value, &["uuid"])?)));
    }
    if is_legacy_compaction {
        let pair_key = if extends_compaction_link {
            accumulator
                .claude_compaction_link_tip
                .take()
                .map(|(key, _)| key)
        } else {
            None
        };
        accumulator
            .claude_compaction_observations
            .push(ClaudeCompactionObservation {
                kind: ClaudeCompactionKind::LegacySummary,
                timestamp: timestamp.clone(),
                pre_tokens: None,
                post_tokens: None,
                cumulative_dropped_tokens: None,
                duration_ms: None,
                response_count_before: accumulator.claude_response_sequence,
                pair_key,
                has_parent_link: value.get("parentUuid").and_then(Value::as_str).is_some(),
                trigger: None,
                id_less_before: false,
                id_less_after: false,
            });
    }
    if is_current_compaction {
        let pre_tokens = value
            .pointer("/compactMetadata/preTokens")
            .and_then(Value::as_u64);
        let post_tokens = value
            .pointer("/compactMetadata/postTokens")
            .and_then(Value::as_u64);
        let cumulative_dropped_tokens = value
            .pointer("/compactMetadata/cumulativeDroppedTokens")
            .and_then(Value::as_u64);
        let duration_ms = value
            .pointer("/compactMetadata/durationMs")
            .and_then(Value::as_u64);
        let pair_key = accumulator.claude_compaction_observations.len() as u64;
        accumulator.claude_compaction_link_tip =
            string_at(value, &["uuid"]).map(|uuid| (pair_key, uuid));
        accumulator
            .claude_compaction_observations
            .push(ClaudeCompactionObservation {
                kind: ClaudeCompactionKind::CurrentBoundary,
                timestamp: timestamp.clone(),
                pre_tokens,
                post_tokens,
                cumulative_dropped_tokens,
                duration_ms,
                response_count_before: accumulator.claude_response_sequence,
                pair_key: Some(pair_key),
                has_parent_link: value.get("parentUuid").and_then(Value::as_str).is_some(),
                trigger: ClaudeCompactionTrigger::from_marker(
                    value
                        .pointer("/compactMetadata/trigger")
                        .and_then(Value::as_str),
                ),
                id_less_before: false,
                id_less_after: false,
            });
    }
    accumulator.note_time(timestamp.clone());
    // Remember the latest user-input moment so the next assistant response can
    // derive its turn duration. A `type=user` record is either a real prompt or
    // a tool_result; both are "model input available" instants and neither
    // carries `message.usage`, so this never collides with the usage path below.
    if string_eq_at(value, &["type"], "user") {
        if let Some(user_ts) = timestamp.clone() {
            accumulator.claude_last_user_ts = Some(user_ts);
        }
    }
    claude_prompt_content(value, accumulator);
    accumulator.set_model(
        string_at(value, &["message", "model"])
            .or_else(|| string_at(value, &["model"]))
            .or_else(|| string_at(value, &["payload", "model"])),
    );
    claude_workspace_content(value, accumulator);
    // Defer the whole response. Sidechain content-block rows progressively
    // increase cumulative output and may add selectors late; neither the first
    // nor an arbitrary line is an authoritative complete response.
    if let Some((usage, root)) = claude_code_delta_usage(value).zip(claude_code_usage_root(value)) {
        // Reconciled against `usage.iterations[]`: on a resumed session's first
        // response the top-level prompt fields read all-zero while the real
        // prompt sits in the iterations, and the small non-zero remainder would
        // otherwise be accepted as this session's baseline.
        let effective_input_context = claude_code_effective_input_context(root);
        if claude_code_usage_iterations(root).len() > 1 {
            // Each iteration is a distinct model request, but the containing
            // response exposes only one stable request id and one terminal
            // timestamp. Keep the response-level peak watermarks, but never
            // claim this collapsed shape is an exact request-indexed curve.
            accumulator.claude_context_curve_request_index_complete = false;
        }
        let selector = claude_code_selector_from_line(value);
        let model = string_at(value, &["message", "model"])
            .or_else(|| string_at(value, &["model"]))
            .or_else(|| string_at(value, &["payload", "model"]));
        // A call naming another model (a refusal fallback's declined first
        // attempt) is billed here at the response's model; count it.
        if claude_code_usage_iterations(root).iter().any(|iteration| {
            iteration
                .get("model")
                .and_then(Value::as_str)
                .is_some_and(|other| Some(other) != model.as_deref())
        }) {
            crate::local_resource_diagnostics::claude_usage_iteration_model_differs();
        }
        // A new numeric field would leave money unseen; count it.
        crate::local_resource_diagnostics::claude_usage_unknown_numeric_keys(
            claude_code_unknown_usage_keys(root),
        );
        // The derived context bucket is attached only after all content-block
        // records for this response are canonically resolved. Early progressive
        // records may still have zero input/cache counters; classifying those
        // rows here would manufacture a short->long selector conflict. An
        // explicit transcript-supplied bucket remains authoritative.
        // Current Claude Code stamps the applied tier on the assistant record
        // itself (`"effort":"high"`), so the transcript is authoritative and no
        // OTLP is required: the tier is already on the record whose usage this
        // is, in the parent and sidechain transcripts alike.
        //
        // A record without the field stays effort-unknown, which is the honest
        // answer: the local OTLP sidecar no longer carries effort at all.
        let reasoning_effort = claude_transcript_effort(value);
        accumulator.observe_claude_response(
            value,
            usage,
            model,
            selector,
            timestamp,
            reasoning_effort,
            Some(effective_input_context),
        );
    }
    accumulator.session_start.observe_claude_line(
        value,
        accumulator.claude_response_sequence,
        accumulator.workspace_path.as_deref(),
    );
    // Local collection never depends on a toggle: `apply_upload_policy` decides
    // what leaves the machine.
    let text = claude_code_scannable_text(value);
    crate::local_resource_diagnostics::claude_reread::link_scrape_bytes(text.len() as u64);
    let artifacts = extract_session_artifacts(&text);
    if !artifacts.is_empty() {
        accumulator.add_artifacts(artifacts);
    }
}

fn claude_capability_from_tool_name(name: &str) -> Option<(&'static str, &'static str)> {
    let normalized = name.to_ascii_lowercase();
    if normalized.starts_with("mcp__claude-in-chrome__") {
        return Some(("browser.chrome", "claude-in-chrome"));
    }
    if normalized.starts_with("mcp__claude_browser__") {
        return Some(("browser.claude_browser", "Claude_Browser"));
    }
    if normalized.starts_with("mcp__computer-use__") {
        return Some(("computer.use", "computer-use"));
    }
    None
}

pub(in crate::snapshots) fn claude_response_tool_uses(value: &Value) -> BTreeMap<String, String> {
    if !string_eq_at(value, &["message", "role"], "assistant") {
        return BTreeMap::new();
    }
    let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
        return BTreeMap::new();
    };
    blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| string_eq_at(block, &["type"], "tool_use"))
        .filter_map(|(index, block)| {
            let name =
                string_at(block, &["name"]).and_then(|name| bounded_tool_usage_name(&name))?;
            let occurrence =
                string_at(block, &["id"]).unwrap_or_else(|| format!("anonymous:{index}:{name}"));
            Some((occurrence, name))
        })
        .collect()
}

/// Skill evidence from one Claude tool call: a `Skill` invocation (provider
/// native, like the `attributionSkill` marker) or a SKILL.md reference read by
/// `Read`/`Bash` (provider artifact). Never counts tools: Claude's tool totals
/// come from its own classifier.
fn note_claude_skill_signal(
    name: &str,
    input: Option<&Value>,
    accumulator: &mut SnapshotAccumulator,
) {
    let Some(input) = input else {
        return;
    };
    match name {
        "Skill" => accumulator.note_provider_skill(string_at(input, &["skill"])),
        "Read" => {
            if let Some(path) = input.get("file_path").and_then(Value::as_str) {
                accumulator.note_activity_skills(path);
            }
        }
        "Bash" => {
            if let Some(command) = input.get("command").and_then(Value::as_str) {
                accumulator.note_activity_skills(command);
            }
        }
        _ => {}
    }
}

fn note_claude_capability_calls(
    value: &Value,
    timestamp: Option<&str>,
    accumulator: &mut SnapshotAccumulator,
) {
    if !string_eq_at(value, &["message", "role"], "assistant") {
        return;
    }
    let Some(blocks) = value.pointer("/message/content").and_then(Value::as_array) else {
        return;
    };
    for block in blocks {
        if !string_eq_at(block, &["type"], "tool_use") {
            continue;
        }
        let Some(name) = string_at(block, &["name"]) else {
            continue;
        };
        note_claude_skill_signal(&name, block.get("input"), accumulator);
        let Some((capability_id, raw_origin)) = claude_capability_from_tool_name(&name) else {
            continue;
        };
        let occurrence = string_at(block, &["id"])
            .unwrap_or_else(|| format!("{name}:{}", timestamp.unwrap_or_default()));
        if accumulator
            .seen_claude_capability_tool_uses
            .insert(occurrence, ())
            .is_some()
        {
            continue;
        }
        accumulator.note_capability_call(timestamp, capability_id, raw_origin);
    }
}

/// Gather tool-output text from one Claude Code transcript line (tool_result
/// content + ``toolUseResult`` stdout/stderr) for artifact scraping. Prompt text
/// and assistant prose are deliberately excluded.
fn claude_code_scannable_text(value: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(tool_use_result) = value.get("toolUseResult") {
        collect_tool_text(tool_use_result, &mut parts);
    }
    if let Some(content) = value.pointer("/message/content").and_then(Value::as_array) {
        for block in content {
            if string_eq_at(block, &["type"], "tool_result") {
                if let Some(inner) = block.get("content") {
                    collect_tool_text(inner, &mut parts);
                }
            }
        }
    }
    parts.join("\n")
}

fn collect_tool_text(value: &Value, parts: &mut Vec<String>) {
    match value {
        Value::String(text) => parts.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_tool_text(item, parts);
            }
        }
        Value::Object(map) => {
            for key in ["stdout", "stderr", "text", "content", "output"] {
                if let Some(child) = map.get(key) {
                    collect_tool_text(child, parts);
                }
            }
        }
        _ => {}
    }
}

/// Scrape canonical, content-free VCS artifacts (PR / issue / commit) from free
/// text. Only clean values survive: clean authority, no credentials, query, or
/// percent-encoding, and the path truncated at the numeric id — so the backend
/// accepts them unchanged and a malformed match can never reject the batch.
pub(in crate::snapshots) fn extract_session_artifacts(text: &str) -> Vec<SessionArtifact> {
    let mut out: Vec<SessionArtifact> = Vec::new();
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '<' | '>' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | '\\' | '|'
            )
    }) {
        if let Some(artifact) = parse_artifact_url(token) {
            push_unique_artifact(&mut out, artifact);
        }
    }
    for line in text.lines() {
        if let Some(sha) = parse_commit_sha_line(line) {
            push_unique_artifact(
                &mut out,
                SessionArtifact {
                    kind: "commit".to_string(),
                    value: sha,
                },
            );
        }
    }
    out
}

fn push_unique_artifact(out: &mut Vec<SessionArtifact>, artifact: SessionArtifact) {
    if out.len() >= MAX_SESSION_ARTIFACTS {
        return;
    }
    if !out.iter().any(|existing| existing == &artifact) {
        out.push(artifact);
    }
}

/// Parse one token as a PR/issue/MR URL, returning its canonical form
/// (`scheme://authority/<repo path>/<marker>/<id>`) or None.
pub(in crate::snapshots) fn parse_artifact_url(token: &str) -> Option<SessionArtifact> {
    let token = token.trim_end_matches(['.', ';', ':', '!', '?']);
    let (scheme, rest) = if let Some(rest) = token.strip_prefix("https://") {
        ("https", rest)
    } else {
        let rest = token.strip_prefix("http://")?;
        ("http", rest)
    };
    let slash = rest.find('/')?;
    let authority = &rest[..slash];
    if !is_clean_authority(authority) {
        return None;
    }
    // Drop any query string / fragment before segmenting the path.
    let path = &rest[slash..];
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let (kind, id_index) = find_artifact_marker(&segments)?;
    if !segments[..=id_index]
        .iter()
        .all(|segment| is_clean_path_segment(segment))
    {
        return None;
    }
    let canonical_path = segments[..=id_index].join("/");
    Some(SessionArtifact {
        kind: kind.to_string(),
        value: format!("{scheme}://{authority}/{canonical_path}"),
    })
}

/// Locate the first PR/issue/MR marker in path segments, returning its kind and
/// the index of the numeric-id segment. A marker needs at least one repository
/// segment before it (contract: backend agent_session_snapshots.py
/// `_ISSUE_PATH_RE`/`_PR_PATH_RE`), so `https://host/issues/1` is not an issue.
fn find_artifact_marker(segments: &[&str]) -> Option<(&'static str, usize)> {
    for i in 1..segments.len() {
        if segments[i] == "-"
            && i + 2 < segments.len()
            && segments[i + 1] == "merge_requests"
            && is_numeric(segments[i + 2])
        {
            return Some(("pull_request", i + 2));
        }
        if (segments[i] == "pull" || segments[i] == "pull-requests")
            && i + 1 < segments.len()
            && is_numeric(segments[i + 1])
        {
            return Some(("pull_request", i + 1));
        }
        if segments[i] == "issues" && i + 1 < segments.len() && is_numeric(segments[i + 1]) {
            return Some(("issue", i + 1));
        }
    }
    None
}

/// Extract a lowercase-hex commit SHA from a `git commit` summary line of the
/// form `[branch sha] message` (or `[branch (root-commit) sha] message`).
fn parse_commit_sha_line(line: &str) -> Option<String> {
    let inner = line.trim_start().strip_prefix('[')?;
    let close = inner.find(']')?;
    let token = inner[..close].split_whitespace().last()?;
    // Require lowercase hex AND at least one a-f letter. Real git short SHAs are
    // virtually always mixed hex; demanding a letter rejects all-numeric log
    // lines like `[INFO 1234567] starting` that would otherwise look like a SHA.
    let is_hex = token.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
    let has_hex_letter = token.chars().any(|c| matches!(c, 'a'..='f'));
    if (7..=40).contains(&token.len()) && is_hex && has_hex_letter {
        Some(token.to_string())
    } else {
        None
    }
}

fn is_clean_authority(authority: &str) -> bool {
    if authority.is_empty() {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return false;
    }
    match port {
        Some(port) => !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()),
        None => true,
    }
}

fn is_clean_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn is_numeric(segment: &str) -> bool {
    !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit())
}
