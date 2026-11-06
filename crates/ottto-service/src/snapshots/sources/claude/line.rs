//! Claude Code usage-field readers for one transcript record: the response
//! dedup key, the usage root and counters, `iterations[]`, the cache-write
//! split and the effective input context.

use serde_json::Value;

use crate::snapshots::cache_observations::RequestSlot;
use crate::snapshots::claude_request_money::{self, CacheCreation};
use crate::snapshots::scan::json_fields::{string_at, u64_at};
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
    let (cache_5m, cache_1h, cache_creation) = claude_code_cache_creation(root);
    match cache_creation {
        CacheCreation::Split { five_m, one_h } => (five_m, one_h),
        CacheCreation::Unattributed(flat) => (flat, 0),
        CacheCreation::Contradictory => (cache_5m, cache_1h),
    }
}

/// One usage object's stated 5m and 1h writes and their reading against the
/// flat write total.
fn claude_code_cache_creation(root: &Value) -> (u64, u64, CacheCreation) {
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
    let reading = claude_request_money::claude_cache_creation(flat, cache_5m, cache_1h);
    (cache_5m, cache_1h, reading)
}

/// Content-free counts for one usage record. Per record: an `iterations[]`
/// call naming another model than the record's, and numeric keys the parser
/// does not read. Once per response (`first_record`): a cache write with no
/// 5m/1h split (read as 5m), and thinking tokens stated only on
/// `iterations[]` entries.
pub(in crate::snapshots) fn claude_code_usage_diagnostics(
    root: &Value,
    model: Option<&str>,
    first_record: bool,
    session: Option<&str>,
) {
    let iterations = claude_code_usage_iterations(root);
    // A refusal fallback's declined first attempt is billed at the record's model.
    if iterations.iter().any(|iteration| {
        let other = iteration.get("model").and_then(Value::as_str);
        other.is_some_and(|other| Some(other) != model)
    }) {
        crate::local_resource_diagnostics::claude_usage_iteration_model_differs();
    }
    // A new numeric field would leave money unseen.
    crate::local_resource_diagnostics::claude_usage_unknown_numeric_keys(
        claude_code_unknown_usage_keys(root),
    );
    if !first_record {
        return;
    }
    let unsplit = |usage: &Value| {
        let reading = claude_code_cache_creation(usage).2;
        matches!(reading, CacheCreation::Unattributed(flat) if flat > 0)
    };
    let thinking = |usage: &Value| {
        u64_at(usage, &["output_tokens_details", "thinking_tokens"]).is_some_and(|n| n > 0)
    };
    crate::local_resource_diagnostics::claude_usage_gaps(
        [
            std::iter::once(root).chain(iterations).any(unsplit),
            !thinking(root) && iterations.iter().any(thinking),
        ],
        session,
    );
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
