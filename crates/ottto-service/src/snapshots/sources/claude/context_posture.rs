//! Claude context posture: legacy compaction pairing, the compaction summary,
//! and the writer and clearer of an item's context and compaction scalars.

use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::snapshots::local_context_points::{local_context_points_recent, LocalContextPoints};
use crate::snapshots::wire::SnapshotItem;
use crate::snapshots::{
    compaction_events, ClaudeCompactionTrigger, ClaudeTranscriptUsageOccurrence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) enum ClaudeCompactionKind {
    LegacySummary,
    CurrentBoundary,
}
crate::durable_tail_codec::durable_enum!(ClaudeCompactionKind {
    0 => LegacySummary,
    1 => CurrentBoundary,
});

// The time fallback consumes unlinked legacy summaries greedily in
// current-boundary input order. Equal distances prefer the original legacy
// index; keep millisecond truncation and the inclusive tolerance identical for
// both callers.
fn matching_claude_legacy_compaction(
    observations: &[ClaudeCompactionObservation],
    current_millis: i128,
    matched_legacy: &BTreeSet<usize>,
) -> Option<usize> {
    observations
        .iter()
        .enumerate()
        .filter(|(index, observation)| {
            observation.kind == ClaudeCompactionKind::LegacySummary
                && !observation.has_parent_link
                && !matched_legacy.contains(index)
        })
        .filter_map(|(index, observation)| {
            let legacy_timestamp = observation
                .timestamp
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())?;
            let delta =
                (legacy_timestamp.unix_timestamp_nanos() / 1_000_000 - current_millis).abs();
            (delta <= CLAUDE_COMPACTION_PAIR_TOLERANCE_MILLISECONDS).then_some((delta, index))
        })
        .min()
        .map(|(_, index)| index)
}

/// Legacy summaries folded into a current boundary, shared by the count and
/// the curve so both see one event list. A summary pairs with the boundary it
/// structurally descends from first; only boundaries left unlinked then fall
/// back to the nearest summary inside the time tolerance that names no parent.
pub(in crate::snapshots) fn paired_claude_legacy_compactions(
    observations: &[ClaudeCompactionObservation],
) -> BTreeSet<usize> {
    let mut boundary_by_key = BTreeMap::new();
    for (index, observation) in observations.iter().enumerate() {
        if observation.kind == ClaudeCompactionKind::CurrentBoundary {
            if let Some(key) = observation.pair_key {
                boundary_by_key.entry(key).or_insert(index);
            }
        }
    }
    let mut matched_legacy = BTreeSet::new();
    let mut linked_boundaries = BTreeSet::new();
    for (index, observation) in observations.iter().enumerate() {
        if observation.kind != ClaudeCompactionKind::LegacySummary {
            continue;
        }
        let Some(&boundary) = observation
            .pair_key
            .and_then(|key| boundary_by_key.get(&key))
        else {
            continue;
        };
        if linked_boundaries.insert(boundary) {
            matched_legacy.insert(index);
        }
    }
    for (index, current) in observations.iter().enumerate() {
        if current.kind != ClaudeCompactionKind::CurrentBoundary
            || linked_boundaries.contains(&index)
        {
            continue;
        }
        let Some(current_timestamp) = current
            .timestamp
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        else {
            continue;
        };
        let current_millis = current_timestamp.unix_timestamp_nanos() / 1_000_000;
        if let Some(legacy_index) =
            matching_claude_legacy_compaction(observations, current_millis, &matched_legacy)
        {
            matched_legacy.insert(legacy_index);
        }
    }
    matched_legacy
}

pub(in crate::snapshots) fn claude_compaction_summary(
    observations: &[ClaudeCompactionObservation],
) -> (u64, Vec<String>, CompactionMetrics) {
    claude_compaction_summary_paired(
        observations,
        &paired_claude_legacy_compactions(observations),
    )
}

/// `claude_compaction_summary` with the pairing already computed, so the fold
/// can share one pairing between the summary and the compaction sizes.
fn claude_compaction_summary_paired(
    observations: &[ClaudeCompactionObservation],
    matched_legacy: &BTreeSet<usize>,
) -> (u64, Vec<String>, CompactionMetrics) {
    let mut metrics = CompactionMetrics::default();

    for current in observations
        .iter()
        .filter(|observation| observation.kind == ClaudeCompactionKind::CurrentBoundary)
    {
        if current
            .timestamp
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .is_none()
        {
            continue;
        }
        if let Some(pre_tokens) = current.pre_tokens {
            metrics.total_pre_tokens = metrics.total_pre_tokens.saturating_add(pre_tokens);
        }
        if let Some(post_tokens) = current.post_tokens {
            metrics.total_post_tokens = metrics.total_post_tokens.saturating_add(post_tokens);
        }
        if let Some(cumulative_dropped_tokens) = current.cumulative_dropped_tokens {
            metrics.total_cumulative_dropped_tokens = metrics
                .total_cumulative_dropped_tokens
                .saturating_add(cumulative_dropped_tokens);
        }
        if let Some(duration_ms) = current.duration_ms {
            metrics.total_duration_ms = metrics.total_duration_ms.saturating_add(duration_ms);
        }
        if current.pre_tokens.is_some()
            || current.post_tokens.is_some()
            || current.cumulative_dropped_tokens.is_some()
            || current.duration_ms.is_some()
        {
            metrics.metrics_count = metrics.metrics_count.saturating_add(1);
        }
    }

    let timestamps = observations
        .iter()
        .enumerate()
        .filter(|(index, observation)| {
            observation.kind == ClaudeCompactionKind::CurrentBoundary
                || !matched_legacy.contains(index)
        })
        .filter_map(|(_, observation)| observation.timestamp.clone())
        .collect();
    (
        observations.len() as u64 - matched_legacy.len() as u64,
        bounded_compaction_timestamps(timestamps),
        metrics,
    )
}

pub(in crate::snapshots) fn clear_claude_context_posture(item: &mut SnapshotItem) {
    item.claude_file_birth_verdict = None;
    item.session_start = item
        .session_start
        .take()
        .and_then(|start| (*start).inherited())
        .map(Box::new);
    item.peak_context_fill_tokens = None;
    item.first_turn_context_tokens = None;
    item.last_turn_context_tokens = None;
    item.compaction_count = None;
    item.compaction_timestamps.clear();
    item.compaction_events.clear();
    item.first_own_request_at = None;
    item.local_context_points.clear();
    item.compaction_total_pre_tokens = None;
    item.compaction_total_post_tokens = None;
    item.compaction_total_cumulative_dropped_tokens = None;
    item.compaction_total_duration_ms = None;
}

/// The compaction tuple (count, timestamps, four totals), the compaction
/// sizes and the Mac-local context points of a Claude Code item, all from one
/// owned set: `owned_observations` and the requests of `occurrences` that
/// `is_own` accepts (the requests behind first/peak/last, any order). Both
/// posture writers call this, so the two paths cannot drift;
/// `clear_claude_context_posture` clears the same fields and `finish()` never
/// builds Claude sizes or points.
///
/// Legacy pairing runs once for the summary and the sizes. Points are built
/// only when the item's last activity is within the 75-minute output gate,
/// in request order without collecting the requests. Returns how many
/// shipped events sit next to an id-less response, and whether LOCAL points
/// exceeded their work budget, for local counters only. `sequence_ordered`
/// is true only for the strict fold's already sorted slice.
pub(in crate::snapshots) fn set_claude_compaction_scalars<'a, I>(
    item: &mut SnapshotItem,
    owned_observations: &[ClaudeCompactionObservation],
    occurrences: I,
    sequence_ordered: bool,
    is_own: impl Fn(&ClaudeTranscriptUsageOccurrence) -> bool,
) -> (compaction_events::ClaudeIdLessNeighbours, bool)
where
    I: ExactSizeIterator<Item = &'a ClaudeTranscriptUsageOccurrence> + Clone,
{
    let paired = paired_claude_legacy_compactions(owned_observations);
    let (count, timestamps, metrics) =
        claude_compaction_summary_paired(owned_observations, &paired);
    item.compaction_count = Some(count);
    item.compaction_timestamps = timestamps;
    let (events, id_less) = compaction_events::claude_compaction_events(
        owned_observations,
        &paired,
        occurrences.clone().filter(|occurrence| is_own(occurrence)),
    );
    item.compaction_events = events;
    item.compaction_total_pre_tokens =
        (metrics.metrics_count > 0).then_some(metrics.total_pre_tokens);
    item.compaction_total_post_tokens =
        (metrics.metrics_count > 0).then_some(metrics.total_post_tokens);
    item.compaction_total_cumulative_dropped_tokens =
        (metrics.metrics_count > 0).then_some(metrics.total_cumulative_dropped_tokens);
    item.compaction_total_duration_ms =
        (metrics.metrics_count > 0).then_some(metrics.total_duration_ms);
    let mut points_refused = false;
    item.local_context_points =
        if local_context_points_recent(item.source_last_activity_at.as_deref(), &item.collected_at)
        {
            let point = |occurrence: &'a ClaudeTranscriptUsageOccurrence| {
                is_own(occurrence).then_some((
                    occurrence.timestamp.as_deref(),
                    occurrence.effective_input_context,
                ))
            };
            if sequence_ordered {
                LocalContextPoints::from_ordered_requests(occurrences, point)
            } else {
                LocalContextPoints::from_requests_by_sequence(
                    occurrences,
                    |occurrence| occurrence.sequence,
                    point,
                )
                .unwrap_or_else(|| {
                    points_refused = true;
                    Vec::new()
                })
            }
        } else {
            Vec::new()
        };
    (id_less, points_refused)
}

pub(crate) const MAX_COMPACTION_TIMESTAMPS: usize = 64;

pub(crate) fn bounded_compaction_timestamps(mut timestamps: Vec<String>) -> Vec<String> {
    timestamps.sort();
    timestamps.dedup();
    if timestamps.len() > MAX_COMPACTION_TIMESTAMPS {
        timestamps.split_off(timestamps.len() - MAX_COMPACTION_TIMESTAMPS)
    } else {
        timestamps
    }
}

// Fallback only: a legacy summary normally pairs through its `parentUuid`
// chain. Since mid-October 2026 the two records land up to ~1.2 s apart, so an
// unlinked pair still needs a window wider than that spread.
const CLAUDE_COMPACTION_PAIR_TOLERANCE_MILLISECONDS: i128 = 2_000;
#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct CompactionMetrics {
    pub(in crate::snapshots) total_pre_tokens: u64,
    pub(in crate::snapshots) total_post_tokens: u64,
    pub(in crate::snapshots) total_cumulative_dropped_tokens: u64,
    pub(in crate::snapshots) total_duration_ms: u64,
    pub(in crate::snapshots) metrics_count: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaudeCompactionObservation {
    pub(in crate::snapshots) kind: ClaudeCompactionKind,
    pub(in crate::snapshots) timestamp: Option<String>,
    pub(in crate::snapshots) pre_tokens: Option<u64>,
    pub(in crate::snapshots) post_tokens: Option<u64>,
    pub(in crate::snapshots) cumulative_dropped_tokens: Option<u64>,
    pub(in crate::snapshots) duration_ms: Option<u64>,
    /// Number of provider responses first observed before this boundary. This
    /// stays local and lets the post-census ownership pass attach the boundary
    /// to exact owned request ordinals without uploading provider identities.
    pub(in crate::snapshots) response_count_before: u64,
    /// Local parse-order key of a current boundary. A legacy summary carries
    /// its boundary's key when its `parentUuid` chain (through `attachment`
    /// records) leads to that boundary, and `None` otherwise.
    pub(in crate::snapshots) pair_key: Option<u64>,
    /// Whether the record named a `parentUuid`. Read only for a legacy summary:
    /// one that names a parent outside its boundary's chain is its own event,
    /// so only a summary without any link may pair by time.
    pub(in crate::snapshots) has_parent_link: bool,
    /// `compactMetadata.trigger` of a current boundary; `None` for a legacy
    /// summary or an unknown value. Fits the struct's existing padding.
    pub(in crate::snapshots) trigger: Option<ClaudeCompactionTrigger>,
    /// The response just before / just after this compaction had no request
    /// id, so it is never its size. Set when responses are resolved; read only
    /// by the fold's local id-less counters, never uploaded. Padding too.
    pub(in crate::snapshots) id_less_before: bool,
    pub(in crate::snapshots) id_less_after: bool,
}
crate::heap_layout_bound::fields!(ClaudeCompactionObservation; kind, timestamp, pre_tokens, post_tokens, cumulative_dropped_tokens, duration_ms, response_count_before, pair_key, has_parent_link, trigger, id_less_before, id_less_after);
crate::durable_tail_codec::durable_struct!(ClaudeCompactionObservation {
    N kind: ClaudeCompactionKind,
    N timestamp: Option<String>,
    N pre_tokens: Option<u64>,
    N post_tokens: Option<u64>,
    N cumulative_dropped_tokens: Option<u64>,
    N duration_ms: Option<u64>,
    N response_count_before: u64,
    N pair_key: Option<u64>,
    N has_parent_link: bool,
    N trigger: Option<ClaudeCompactionTrigger>,
    N id_less_before: bool,
    N id_less_after: bool,
});
