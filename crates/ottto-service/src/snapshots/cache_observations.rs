//! Content-free owned-request cache evidence. Accounting remains in the usage owner.
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) fn event_id(session_ref: &str, request_ref: &str) -> String {
    use sha2::{Digest, Sha256};
    let identity = serde_json::to_vec(&("session_cache_observation:v1", session_ref, request_ref))
        .expect("identity tuple serializes");
    format!("cache:{:x}", Sha256::digest(identity))
}

// Server-enforced bounds (the backend's cache observation schema): at most
// MAX_OPERATIONS operations and MAX_PATCH_BYTES per uploaded patch, and
// MAX_ROWS rows and MAX_STATE_BYTES per session's accepted state. The
// detector itself keeps every row; the upload sends what these bounds admit.
pub const MAX_OPERATIONS: usize = 64;
pub const MAX_PATCH_BYTES: usize = 128 * 1024;
pub const MAX_ROWS: usize = 512;
pub const MAX_STATE_BYTES: usize = 640 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RequestSlot {
    pub request_ref: String,
    pub occurred_at: String,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_creation_tokens: Option<u64>,
    pub uncached_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub event_id: String,
    pub affected_request_ref: String,
    pub episode_anchor_request_ref: Option<String>,
    pub baseline_request_ref: Option<String>,
    pub occurred_at: String,
    pub observation_kind: String,
    pub status: String,
    pub previous: Option<RequestSlot>,
    pub affected: RequestSlot,
    pub immediate_next: Option<RequestSlot>,
    pub ordering_confidence: String,
    pub explanation_code: String,
    pub supporting_conditions: Vec<String>,
    pub idle_seconds: Option<u64>,
    pub report_gap_seconds: Option<u64>,
    pub detector_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    Upsert { observation: Box<Observation> },
    Retract { event_id: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheObservations {
    pub schema_version: u16,
    pub operations: Vec<Operation>,
    pub coverage: String,
    pub omitted_observation_count: Option<u64>,
}

impl CacheObservations {
    /// No rows, with an exact omitted count or none when it is unknown.
    pub(crate) fn partial(omitted_observation_count: Option<u64>) -> Self {
        Self {
            schema_version: 1,
            operations: Vec::new(),
            coverage: "partial".into(),
            omitted_observation_count,
        }
    }

    pub fn validate(&self) -> bool {
        let mut ids = BTreeSet::new();
        self.schema_version == 1
            && matches!(self.coverage.as_str(), "complete" | "partial" | "unknown")
            && (self.omitted_observation_count.unwrap_or(0) == 0 || self.coverage == "partial")
            && self.operations.len() <= MAX_OPERATIONS
            && self.operations.iter().all(|operation| {
                ids.insert(match operation {
                    Operation::Upsert { observation } => &observation.event_id,
                    Operation::Retract { event_id } => event_id,
                })
            })
            && serde_json::to_value(self).is_ok_and(|value| {
                crate::canonical_json::canonicalize(&value)
                    .is_ok_and(|bytes| bytes.len() <= MAX_PATCH_BYTES)
            })
    }
}

/// Local-only metadata; request identity never depends on these mutable facts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OwnedRequest {
    pub slot: RequestSlot,
    pub ordering: String,
    pub compaction_before: bool,
    pub configuration_changed: bool,
    pub configuration_witness: Option<String>,
    pub idle_seconds: Option<u64>,
}

fn share(slot: &RequestSlot) -> Option<f64> {
    let prompt = slot.prompt_tokens?;
    let read = slot.cache_read_tokens?;
    (prompt > 0 && read <= prompt).then_some(read as f64 / prompt as f64)
}
/// The time from `from` to `to` (RFC 3339). `None` when either does not
/// parse or `to` is earlier, so a backwards clock never yields a gap.
pub(crate) fn elapsed(from: &str, to: &str) -> Option<time::Duration> {
    let from = OffsetDateTime::parse(from, &Rfc3339).ok()?;
    let to = OffsetDateTime::parse(to, &Rfc3339).ok()?;
    (to >= from).then_some(to - from)
}

/// [`elapsed`] in whole seconds.
pub(crate) fn elapsed_seconds(from: &str, to: &str) -> Option<u64> {
    u64::try_from(elapsed(from, to)?.whole_seconds()).ok()
}
fn comparable(a: &OwnedRequest, b: &OwnedRequest) -> bool {
    a.ordering != "ambiguous"
        && b.ordering != "ambiguous"
        && a.slot.model.is_some()
        && a.slot.model == b.slot.model
        && !b.compaction_before
        && !b.configuration_changed
        && a.slot.effort == b.slot.effort
        && a.configuration_witness == b.configuration_witness
        && !prompt_reduced(&a.slot, &b.slot)
}
fn prompt_reduced(previous: &RequestSlot, current: &RequestSlot) -> bool {
    previous
        .prompt_tokens
        .zip(current.prompt_tokens)
        .is_some_and(|(previous, current)| current < previous / 2)
}
fn material(baseline: &RequestSlot, current: &RequestSlot) -> bool {
    let (Some(before), Some(now), Some(prompt), Some(read), Some(prior_read)) = (
        share(baseline),
        share(current),
        current.prompt_tokens,
        current.cache_read_tokens,
        baseline.cache_read_tokens,
    ) else {
        return false;
    };
    prompt >= 20_000
        && before >= 0.8
        && (now <= 0.05
            || (before - now >= 0.5 && prior_read.min(prompt).saturating_sub(read) >= 20_000))
}

/// [`detect_unique`] keyed by event id.
#[cfg(test)]
pub(crate) fn detect(
    session_ref: &str,
    requests: &[OwnedRequest],
) -> BTreeMap<String, Observation> {
    detect_unique(session_ref, requests)
        .into_iter()
        .map(|row| (row.event_id.clone(), row))
        .collect()
}

/// Every row of the session, in session order. Input has already passed the
/// adapter's duplicate/conflict check. Replaying the same owned sequence
/// rebuilds identical rows after restart or correction. Adjacent witnesses
/// are selected before episode baselines; no later warm request is
/// substituted.
pub(crate) fn detect_unique(session_ref: &str, requests: &[OwnedRequest]) -> Vec<Observation> {
    let mut rows = Vec::new();
    let mut baseline: Option<&OwnedRequest> = None;
    let mut episode: Option<String> = None;
    for (index, request) in requests.iter().enumerate() {
        let previous = index.checked_sub(1).map(|i| &requests[i]);
        let next = requests.get(index + 1);
        let boundary = previous.is_some_and(|prior| !comparable(prior, request));
        let boundary_loss =
            boundary && previous.is_some_and(|prior| material(&prior.slot, &request.slot));
        if boundary {
            baseline = None;
            episode = None;
        }
        let cold = request.slot.prompt_tokens.is_some_and(|n| n >= 20_000)
            && share(&request.slot).is_some_and(|n| n <= 0.05);
        let loss = baseline.is_some_and(|prior| material(&prior.slot, &request.slot));
        if !loss && !cold && !boundary_loss {
            if share(&request.slot).is_some_and(|n| n >= 0.8) {
                baseline = Some(request);
                episode = None;
            }
            continue;
        }
        if loss && request.ordering != "ambiguous" && episode.is_none() {
            episode = Some(request.slot.request_ref.clone());
        }
        let model_change = previous.is_some_and(|prior| prior.slot.model != request.slot.model);
        let configuration_changed = request.configuration_changed
            || previous.is_some_and(|prior| {
                prior.slot.effort != request.slot.effort
                    || prior.configuration_witness != request.configuration_witness
            });
        let prompt_reduced =
            previous.is_some_and(|prior| prompt_reduced(&prior.slot, &request.slot));
        let report_gap = previous
            .and_then(|prior| elapsed_seconds(&prior.slot.occurred_at, &request.slot.occurred_at));
        let mut conditions = Vec::new();
        if model_change {
            conditions.push("model_changed".into());
        }
        if request.compaction_before {
            conditions.push("recorded_compaction".into());
        }
        if configuration_changed {
            conditions.push("recorded_configuration_change".into());
        }
        if request.idle_seconds.is_some_and(|seconds| seconds >= 3600) {
            conditions.push("long_task_inactivity".into());
        }
        let explanation = if model_change {
            "model_change"
        } else if request.compaction_before {
            "compaction"
        } else if configuration_changed {
            "configuration_change"
        } else if loss
            && request.configuration_witness.is_some()
            && request.idle_seconds.is_some_and(|n| n >= 3600)
        {
            "likely_expiry"
        } else {
            "unclear"
        };
        if prompt_reduced {
            conditions.push("prompt_size_reduced".into());
        }
        if report_gap.is_some_and(|seconds| seconds >= 3600) {
            conditions.push("long_report_gap".into());
        }
        let kind = if request.ordering == "ambiguous" {
            "ambiguous"
        } else if model_change
            || request.compaction_before
            || configuration_changed
            || prompt_reduced
        {
            "expected_rebuild"
        } else if loss {
            "unexpected_loss"
        } else {
            "cold_start"
        };
        // Provider identity plus existing session identity; no counter, offset or version digest.
        let event_id = event_id(session_ref, &request.slot.request_ref);
        let recovery_comparable = next.is_some_and(|next| comparable(request, next));
        let observation = Observation {
            event_id: event_id.clone(),
            affected_request_ref: request.slot.request_ref.clone(),
            episode_anchor_request_ref: episode.clone(),
            baseline_request_ref: baseline.map(|b| b.slot.request_ref.clone()),
            occurred_at: request.slot.occurred_at.clone(),
            observation_kind: kind.into(),
            status: if next.is_none() {
                "awaiting_next"
            } else if recovery_comparable {
                "complete"
            } else {
                "next_unavailable"
            }
            .into(),
            previous: previous.map(|p| p.slot.clone()),
            affected: request.slot.clone(),
            immediate_next: next.map(|n| n.slot.clone()),
            ordering_confidence: request.ordering.clone(),
            explanation_code: explanation.into(),
            supporting_conditions: conditions,
            idle_seconds: request.idle_seconds,
            report_gap_seconds: report_gap,
            detector_version: "v1".into(),
        };
        rows.push(observation);
    }
    rows
}

#[cfg(test)]
mod tests;

pub(crate) fn codex_slot(
    value: &serde_json::Value,
    model: Option<String>,
    effort: Option<String>,
) -> Option<RequestSlot> {
    if value.get("type")?.as_str()? != "token_usage_record" {
        return None;
    }
    let payload = value.get("payload")?;
    let request_ref = payload.get("response_id")?.as_str()?.to_string();
    if request_ref.is_empty() || request_ref.len() > 256 {
        return None;
    }
    let usage = payload.get("usage")?;
    let prompt = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64);
    let read = usage
        .get("cached_input_tokens")
        .and_then(serde_json::Value::as_u64);
    let write = usage
        .get("cache_write_input_tokens")
        .and_then(serde_json::Value::as_u64);
    Some(RequestSlot {
        request_ref,
        occurred_at: value.get("timestamp")?.as_str()?.to_string(),
        model,
        effort,
        prompt_tokens: prompt,
        cache_read_tokens: read,
        cache_creation_tokens: write,
        uncached_tokens: prompt
            .zip(read)
            .zip(write)
            .and_then(|((p, r), w)| p.checked_sub(r)?.checked_sub(w)),
        output_tokens: usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64),
    })
}

// Closed owned-field inventory for optional scan overlap admission.
crate::heap_layout_bound::fields!(CacheObservations; schema_version, operations, coverage, omitted_observation_count);
crate::heap_layout_bound::fields!(OwnedRequest; slot, ordering, compaction_before, configuration_changed, configuration_witness, idle_seconds);
crate::durable_tail_codec::durable_struct!(OwnedRequest {
    D slot: RequestSlot,
    N ordering: String,
    N compaction_before: bool,
    N configuration_changed: bool,
    H configuration_witness: Option<String>,
    N idle_seconds: Option<u64>,
});
crate::heap_layout_bound::fields!(RequestSlot; request_ref, occurred_at, model, effort, prompt_tokens, cache_read_tokens, cache_creation_tokens, uncached_tokens, output_tokens);
crate::durable_tail_codec::durable_struct!(RequestSlot {
    L request_ref: String,
    N occurred_at: String,
    U model: Option<String>,
    U effort: Option<String>,
    N prompt_tokens: Option<u64>,
    N cache_read_tokens: Option<u64>,
    N cache_creation_tokens: Option<u64>,
    N uncached_tokens: Option<u64>,
    N output_tokens: Option<u64>,
});

crate::heap_layout_bound::fields!(Observation; event_id, affected_request_ref, episode_anchor_request_ref, baseline_request_ref, occurred_at, observation_kind, status, previous, affected, immediate_next, ordering_confidence, explanation_code, supporting_conditions, idle_seconds, report_gap_seconds, detector_version);

impl crate::heap_layout_bound::HeapLayoutBound for Operation {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Upsert { observation } => observation.heap_bound(c),
            Self::Retract { event_id } => event_id.heap_bound(c),
        }
    }
}
