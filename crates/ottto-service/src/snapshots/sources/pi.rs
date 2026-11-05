//! Pi: reducing one session line into the accumulator, the usage records
//! and their timestamps, and the dedup and fork ledgers that count each
//! response once.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::snapshots::scan::json_fields::{string_at, string_eq_at, u64_at};
use crate::snapshots::scan_index::file_set_digest::update_length_prefixed;
use crate::snapshots::{
    bounded_rfc3339_millis, pi_prompt_content, pi_selector_from_custom,
    pi_selector_from_usage_message, pi_usage_costs_with_observations, text_from_array,
    usage_object_has_numeric_field, PiFork, PiLedger, PiUsageDedupState, SelectorCapture,
    SnapshotAccumulator, UsageTotals,
};

pub(in crate::snapshots) fn apply_pi_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    // Count per observed usage line, before response deduplication and timestamp
    // drops; rereads count again. Usage-shape probes remain side-effect-free.
    if pi_usage_event(value) {
        if let Some(usage) = pi_usage_value(value) {
            let (_, observations) = pi_usage_costs_with_observations(usage);
            crate::local_resource_diagnostics::pi_cost_observations(
                observations.refused,
                observations.rounded,
            );
        }
    }
    let event_type = string_at(value, &["type"]);
    match event_type.as_deref() {
        Some("custom") => {
            if let Some(selector) = pi_selector_from_custom(value) {
                accumulator.set_selector(selector);
            }
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("session") => {
            if accumulator.source_session_id.is_none() {
                accumulator.seen_pi_usage_keys.note_header(value);
                accumulator.source_session_id = string_at(value, &["id"])
                    .or_else(|| string_at(value, &["session_id"]))
                    .or_else(|| string_at(value, &["sessionId"]));
            }
            accumulator.set_workspace_hash(string_at(value, &["cwd"]));
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("message") => {
            // Pi user prompts use both legacy top-level `role` and current
            // nested `message.role`. This is the only chance to capture prompt
            // text for a title fallback.
            let role = pi_message_role(value);
            pi_prompt_content(value, role.as_deref(), accumulator);
            let timestamp = pi_usage_record_timestamp(value);
            if role.as_deref() == Some("assistant") {
                apply_pi_usage_record(
                    value,
                    accumulator,
                    timestamp.as_deref(),
                    PiUsageRecordShape::Message,
                );
            }
            accumulator.note_time(timestamp);
        }
        Some("message_end") => {
            let timestamp = pi_usage_record_timestamp(value);
            apply_pi_usage_record(
                value,
                accumulator,
                timestamp.as_deref(),
                PiUsageRecordShape::MessageEnd,
            );
            accumulator.note_time(timestamp);
        }
        Some("model_change") => {
            accumulator
                .set_model(string_at(value, &["modelId"]).or_else(|| string_at(value, &["model"])));
            accumulator.note_time(pi_timestamp_field(value));
        }
        // Pi 0.81.0+ bills summary generation on these entries and 0.86.0+
        // writes `usage` entries (e.g. cache warming); Pi's session totals add
        // each exactly once and no assistant message repeats them.
        Some("compaction" | "branch_summary" | "usage") => {
            apply_pi_entry_usage(value, accumulator);
            accumulator.note_time(pi_timestamp_field(value));
        }
        _ => {}
    }
}

/// Usage carried on a Pi entry rather than an assistant message. It has no
/// response id, so every occurrence counts and the dedup ledger is untouched.
/// `usage` entries name their model; summaries run on the session's current
/// model, which `place_usage` falls back to when `model` is None.
fn apply_pi_entry_usage(value: &Value, accumulator: &mut SnapshotAccumulator) {
    let clock = value.get("timestamp");
    let timestamp = pi_timestamp_value(clock);
    if !pi_usage_gate(value, accumulator, &["model"], clock, timestamp.as_deref()) {
        return;
    }
    let Some(usage) = pi_message_usage(value) else {
        return;
    };
    let mut selector = accumulator.current_selector.clone();
    selector.merge(pi_selector_from_usage_message(value));
    accumulator.add_usage_with_selector(
        string_at(value, &["model"]),
        usage,
        selector,
        timestamp.as_deref(),
        None,
    );
}

fn pi_message_role(value: &Value) -> Option<String> {
    string_at(value, &["message", "role"]).or_else(|| string_at(value, &["role"]))
}

pub(in crate::snapshots) fn pi_usage_event(value: &Value) -> bool {
    string_eq_at(value, &["type"], "message_end")
        || pi_entry_carries_usage(value)
        || (string_eq_at(value, &["type"], "message")
            && pi_message_role(value).as_deref() == Some("assistant"))
}

fn pi_entry_carries_usage(value: &Value) -> bool {
    matches!(
        string_at(value, &["type"]).as_deref(),
        Some("compaction" | "branch_summary" | "usage")
    )
}

pub(in crate::snapshots) fn pi_usage_value(value: &Value) -> Option<&Value> {
    if pi_entry_carries_usage(value) {
        value.get("usage")
    } else {
        value.pointer("/message/usage")
    }
}

fn pi_usage_dedup_key(value: &Value) -> Option<String> {
    string_at(value, &["message", "responseId"])
        .or_else(|| string_at(value, &["message", "response_id"]))
        .or_else(|| string_at(value, &["responseId"]))
        .or_else(|| string_at(value, &["response_id"]))
        .map(|id| pi_usage_hash("ottto-pi-usage-key:v1", &[&id]))
}

fn apply_pi_usage_line(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
    timestamp: Option<&str>,
    shape: PiUsageRecordShape,
) {
    let model = string_at(value, &["message", "model"]);
    accumulator.set_model(model.clone());
    if let Some(usage) = pi_message_usage(value) {
        let mut selector = accumulator.current_selector.clone();
        selector.merge(pi_selector_from_usage_message(value));
        let occurrence_digest =
            pi_usage_occurrence_digest(model.as_deref(), &usage, &selector, timestamp);
        let is_new_occurrence = match pi_usage_dedup_key(value) {
            Some(key) => accumulator
                .seen_pi_usage_keys
                .usage_keys_mut()
                .entry(key)
                .or_default()
                .record(shape, occurrence_digest),
            None => true,
        };
        if is_new_occurrence {
            accumulator.add_usage_with_selector(
                model, usage, selector, timestamp,
                // Pi does not emit a per-turn reasoning effort tier.
                None,
            );
        }
    }
}

/// Domain and parts share the length-prefixed snapshot hash convention.
fn pi_usage_hash(domain: &str, parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        update_length_prefixed(&mut hash, part.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn pi_usage_occurrence_digest(
    model: Option<&str>,
    usage: &UsageTotals,
    selector: &SelectorCapture,
    timestamp: Option<&str>,
) -> String {
    let selector_context = serde_json::to_string(&selector.context).unwrap_or_default();
    pi_usage_hash(
        "ottto-pi-usage-occurrence:v1",
        &[
            model.unwrap_or(""),
            &timestamp
                .and_then(pi_usage_timestamp_identity)
                .unwrap_or_default(),
            &usage.input_tokens.to_string(),
            &usage.output_tokens.to_string(),
            &usage.cache_read_tokens.to_string(),
            &usage.cache_creation_5m_tokens.to_string(),
            &usage.cache_creation_1h_tokens.to_string(),
            &usage.reasoning_output_tokens.to_string(),
            &usage.unattributed_total_tokens.to_string(),
            &usage.request_count.to_string(),
            &usage.costs.observed.to_string(),
            &usage.costs.reported.to_string(),
            &format!("{:?}", usage.costs.total),
            &format!("{:?}", usage.costs.input),
            &format!("{:?}", usage.costs.output),
            &format!("{:?}", usage.costs.cache_read),
            &format!("{:?}", usage.costs.cache_creation),
            &selector_context,
        ],
    )
}

pub(in crate::snapshots) fn pi_message_text(value: &Value) -> Option<String> {
    string_at(value, &["content"])
        .or_else(|| string_at(value, &["text"]))
        .or_else(|| string_at(value, &["message", "content"]))
        .or_else(|| text_from_array(value.get("content")))
        .or_else(|| text_from_array(value.pointer("/message/content")))
}

fn pi_timestamp_field(value: &Value) -> Option<String> {
    pi_timestamp_value(value.get("timestamp"))
        .or_else(|| pi_timestamp_value(value.pointer("/message/timestamp")))
}

/// The rule every Pi usage line passes first. A fork copy is the parent's
/// spend: it only leaves its model (at `model_path`) as context. A present but
/// invalid `clock` drops positive usage. True when the usage applies at
/// `timestamp` (None when the clock is absent).
fn pi_usage_gate(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
    model_path: &[&str],
    clock: Option<&Value>,
    timestamp: Option<&str>,
) -> bool {
    if accumulator.seen_pi_usage_keys.skip_fork_copy(value) {
        accumulator.set_model(string_at(value, model_path));
        false
    } else if timestamp.is_none() && clock.is_some() {
        if pi_message_usage(value).is_some_and(|usage| !usage.is_zero()) {
            accumulator.note_dropped_usage();
        }
        false
    } else {
        true
    }
}

/// One usage record (an assistant `message` or a `message_end`), through the
/// shared gate, then the dedup ledger.
fn apply_pi_usage_record(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
    timestamp: Option<&str>,
    shape: PiUsageRecordShape,
) {
    let clock = pi_usage_record_clock(value);
    if pi_usage_gate(value, accumulator, &["message", "model"], clock, timestamp) {
        apply_pi_usage_line(value, accumulator, timestamp, shape);
    }
}

/// A usage record's occurrence clock. Current and transitional Pi records may
/// carry a later envelope write time at the top level; provider response time
/// is the usage occurrence clock and is also what historical `message_end`
/// records use. Present-but-invalid provider evidence is loss: falling back
/// to the envelope would turn a malformed occurrence clock into a different,
/// often later, billable hour.
fn pi_usage_record_clock(value: &Value) -> Option<&Value> {
    value
        .pointer("/message/timestamp")
        .or_else(|| value.get("timestamp"))
}

fn pi_usage_record_timestamp(value: &Value) -> Option<String> {
    pi_timestamp_value(pi_usage_record_clock(value))
}

fn pi_timestamp_value(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(text) = value.as_str() {
        if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
            if (1..=9999).contains(&parsed.year()) {
                return Some(text.to_string());
            }
        }
    }
    pi_ms_timestamp(Some(value))
}

fn pi_timestamp_nanos(value: &str) -> Option<i128> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp_nanos)
}

fn pi_usage_timestamp_identity(value: &str) -> Option<String> {
    pi_timestamp_nanos(value).map(|n| n.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiUsageRecordShape {
    Message,
    MessageEnd,
}

/// Counts only: the occurrence digests are unkeyed hashes.
impl std::fmt::Debug for PiUsageDedupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiUsageDedupState")
            .field("message", &self.message.len())
            .field("message_end", &self.message_end.len())
            .field("paired_digests", &self.paired_digests.len())
            .finish()
    }
}

crate::durable_tail_codec::durable_struct!(PiUsageDedupState {
    H message: BTreeMap<String, usize>,
    H message_end: BTreeMap<String, usize>,
    H paired_digests: BTreeSet<String>,
});

impl PiUsageDedupState {
    /// Returns true when this record is a new billable occurrence. An exact
    /// opposite-shape occurrence consumes one unmatched digest and is the
    /// compatibility duplicate of the occurrence already counted.
    fn record(&mut self, shape: PiUsageRecordShape, digest: String) -> bool {
        let (same_shape, opposite_shape) = match shape {
            PiUsageRecordShape::Message => (&mut self.message, &mut self.message_end),
            PiUsageRecordShape::MessageEnd => (&mut self.message_end, &mut self.message),
        };
        if let Some(count) = opposite_shape.get_mut(&digest) {
            self.paired_digests.insert(digest.clone());
            *count -= 1;
            if *count == 0 {
                opposite_shape.remove(&digest);
            }
            return false;
        }
        *same_shape.entry(digest).or_default() += 1;
        true
    }

    pub(in crate::snapshots) fn has_cross_shape_conflict(&self) -> bool {
        (!self.message.is_empty() && !self.message_end.is_empty())
            || (!self.paired_digests.is_empty()
                && self
                    .message
                    .keys()
                    .chain(self.message_end.keys())
                    .any(|digest| !self.paired_digests.contains(digest)))
    }
}

/// Never prints the local header time or `parentSession`.
/// Counts only: the usage keys are unkeyed hashes.
impl std::fmt::Debug for PiLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiLedger")
            .field("usage_keys", &self.usage_keys.len())
            .field("has_parent", &self.fork_parts().0)
            .finish()
    }
}

impl std::fmt::Debug for PiFork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiFork").finish_non_exhaustive()
    }
}

impl PiFork {
    /// Usage on an entry stamped strictly before the fork header time is the
    /// parent's copied spend: skip it, counted. An entry without a valid
    /// time counts normally. The envelope time comes first, as Pi copies it.
    fn copied_usage(&self, value: &Value) -> Option<UsageTotals> {
        let header = self.header_nanos?;
        // A present invalid envelope is not evidence for skipping. Only an
        // absent envelope falls back to the provider clock.
        let at = pi_timestamp_value(
            value
                .get("timestamp")
                .or_else(|| value.pointer("/message/timestamp")),
        )
        .as_deref()
        .and_then(pi_timestamp_nanos)?;
        if at < header {
            pi_message_usage(value)
        } else {
            None
        }
    }
}

impl PiLedger {
    pub(crate) fn usage_keys(&self) -> &BTreeMap<String, PiUsageDedupState> {
        &self.usage_keys
    }

    pub(crate) fn usage_keys_mut(&mut self) -> &mut BTreeMap<String, PiUsageDedupState> {
        &mut self.usage_keys
    }

    /// No ledger key and no fork state: what Claude and Codex hold, since a
    /// fork state is as non-empty as a key.
    pub(crate) fn is_empty(&self) -> bool {
        self.usage_keys.is_empty() && self.fork.is_none()
    }

    /// The persisted fork values: (the header named a parent, header time).
    pub(crate) fn fork_parts(&self) -> (bool, Option<i128>) {
        self.fork
            .as_deref()
            .map_or((false, None), |fork| (true, fork.header_nanos))
    }

    /// The ledger a Pi Tail head restores: no keys yet (its pages follow)
    /// and the stored fork values.
    pub(crate) fn from_parts(
        usage_keys: BTreeMap<String, PiUsageDedupState>,
        has_parent: bool,
        header_nanos: Option<i128>,
    ) -> Self {
        Self {
            usage_keys,
            fork: has_parent.then(|| Box::new(PiFork { header_nanos })),
        }
    }

    /// The first header that names a parent marks the file a fork. Pi writes
    /// one header, as the first line.
    pub(in crate::snapshots) fn note_header(&mut self, value: &Value) {
        if !string_at(value, &["parentSession"]).is_some_and(|p| !p.is_empty()) {
            return;
        }
        self.fork = Some(Box::new(PiFork {
            header_nanos: pi_timestamp_value(value.get("timestamp"))
                .as_deref()
                .and_then(pi_timestamp_nanos),
        }));
    }

    pub(in crate::snapshots) fn is_fork_copy(&self, value: &Value) -> bool {
        self.fork
            .as_deref()
            .is_some_and(|fork| fork.copied_usage(value).is_some())
    }

    fn skip_fork_copy(&mut self, value: &Value) -> bool {
        let Some(fork) = self.fork.as_deref_mut() else {
            return false;
        };
        let Some(usage) = fork.copied_usage(value) else {
            return false;
        };
        use crate::local_resource_diagnostics::cache_lifecycle::{add, Event};
        add(Event::PiForkCopiesSkippedEntries, 1);
        add(Event::PiForkCopiesSkippedTokens, usage.total_tokens());
        true
    }
}

fn pi_ms_timestamp(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let ms = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    }?;
    bounded_rfc3339_millis(ms)
}

pub(in crate::snapshots) fn pi_message_usage(value: &Value) -> Option<UsageTotals> {
    let usage = pi_usage_value(value)?;
    if !usage_object_has_numeric_field(
        usage,
        &[
            "input",
            "output",
            "cacheRead",
            "cache_read",
            "cacheWrite",
            "cache_write",
            "cacheWrite1h",
            "cache_write_1h",
            "reasoning",
        ],
    ) {
        return None;
    }
    // Pi is multi-provider (Anthropic / OpenAI / Gemini). When the underlying
    // model is Anthropic and Pi exposes the nested `cacheCreation` object with
    // ephemeral_5m / ephemeral_1h, prefer that. Otherwise the flat `cacheWrite`
    // total routes to the 5m bucket (Anthropic default TTL, and the safer guess
    // for non-Anthropic providers where the distinction does not apply).
    let (cache_5m, cache_1h) = pi_cache_creation_split(usage);
    let totals = UsageTotals {
        input_tokens: u64_at(usage, &["input"]).unwrap_or_default(),
        output_tokens: u64_at(usage, &["output"]).unwrap_or_default(),
        cache_read_tokens: u64_at(usage, &["cacheRead"])
            .or_else(|| u64_at(usage, &["cache_read"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: u64_at(usage, &["reasoning"]).unwrap_or_default(),
        unattributed_total_tokens: 0,
        request_count: 1,
        costs: pi_usage_costs_with_observations(usage).0,
    };
    Some(totals)
}

fn pi_cache_creation_split(usage: &Value) -> (u64, u64) {
    if let Some(nested) = usage
        .get("cacheCreation")
        .or_else(|| usage.get("cache_creation"))
    {
        let cache_5m = u64_at(nested, &["ephemeral_5m_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
            .unwrap_or_default();
        let cache_1h = u64_at(nested, &["ephemeral_1h_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
            .unwrap_or_default();
        if cache_5m > 0 || cache_1h > 0 {
            return (cache_5m, cache_1h);
        }
    }
    let flat = u64_at(usage, &["cacheWrite"])
        .or_else(|| u64_at(usage, &["cache_write"]))
        .unwrap_or_default();
    let cache_1h = u64_at(usage, &["cacheWrite1h"])
        .or_else(|| u64_at(usage, &["cache_write_1h"]))
        .unwrap_or_default()
        .min(flat);
    (flat.saturating_sub(cache_1h), cache_1h)
}
