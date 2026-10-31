//! Context sizes around each compaction, for the snapshot upload and the
//! local Sessions list.
//!
//! `SnapshotCompactionEvent` rides `SnapshotItem.compaction_events`, one entry
//! per entry of `compaction_timestamps` with `at` byte-identical to it. Sizes
//! are prompt sizes in the same measure as first/peak/last (Codex: inclusive
//! `input_tokens`), never billed tokens. `before` is the last owned non-zero
//! request before the compaction; `after` is the first counted non-zero
//! request after it and stays absent until one is seen.
//!
//! The list is additive evidence only. It is deliberately outside the
//! `context_posture` component, the content hash and the body witness, so it
//! never re-mints session identity and needs no parser or scan identity bump.
//!
//! Codex builds its list at finish from sizes noted during the parse. Claude
//! Code builds it only in the ownership fold (`claude_compaction_events`),
//! from the same owned boundaries and requests as the session's
//! first/peak/last, so a copied request is never a size.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    ClaudeCompactionKind, ClaudeCompactionObservation, ClaudeTranscriptUsageOccurrence,
    MAX_COMPACTION_TIMESTAMPS,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SnapshotCompactionEvent {
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    /// Closed values `auto`, `manual` or `idle` (Claude Code only). Codex
    /// states no trigger, so its events never carry one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
}

crate::heap_layout_bound::fields!(SnapshotCompactionEvent; at, before, after, trigger);

/// The same set and order `bounded_compaction_timestamps` yields for the
/// events' `at` values: sorted by `at`, one event per distinct `at` (the first
/// in parse order wins), newest `MAX_COMPACTION_TIMESTAMPS` kept.
pub(crate) fn bounded_compaction_events(
    mut events: Vec<SnapshotCompactionEvent>,
) -> Vec<SnapshotCompactionEvent> {
    // Stable sort, so equal timestamps keep parse order for the dedup below.
    events.sort_by(|left, right| left.at.cmp(&right.at));
    events.dedup_by(|later, earlier| later.at == earlier.at);
    if events.len() > MAX_COMPACTION_TIMESTAMPS {
        events.split_off(events.len() - MAX_COMPACTION_TIMESTAMPS)
    } else {
        events
    }
}

/// Gap between a Claude Code automatic compaction and the last owned request
/// before it that marks the compaction idle. Claude Code compacts an idle
/// session shortly before its one-hour prompt cache expires (about 54 minutes
/// observed); a transcript marker saying `idle` wins when present.
const CLAUDE_IDLE_COMPACTION_GAP_SECONDS: i64 = 50 * 60;

/// `compactMetadata.trigger` of a Claude Code `compact_boundary`, read on the
/// boundary line only. Unknown values stay `None`. Local: never uploaded
/// except where the upload contract already carries it (the closed string
/// from `wire`); persisted only in the local durable-tail store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeCompactionTrigger {
    Auto,
    Manual,
    Idle,
}
crate::durable_tail_codec::durable_enum!(ClaudeCompactionTrigger {
    0 => Auto,
    1 => Manual,
    2 => Idle,
});

impl ClaudeCompactionTrigger {
    pub(super) fn from_marker(value: Option<&str>) -> Option<Self> {
        match value? {
            "auto" => Some(Self::Auto),
            "manual" => Some(Self::Manual),
            "idle" => Some(Self::Idle),
            _ => None,
        }
    }

    fn wire(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Manual => "manual",
            Self::Idle => "idle",
        }
    }
}

crate::heap_layout_bound::no_heap!(true; ClaudeCompactionTrigger);

/// Sizes and trigger for exactly the events `claude_compaction_summary`
/// lists for the same `owned_observations`: every boundary plus every legacy
/// summary #676's pairing leaves unpaired, each with a timestamp, bounded like
/// `bounded_compaction_timestamps`, so `at` matches `compaction_timestamps`
/// entry for entry. `own_requests` are the owned requests behind the item's
/// first/peak/last, in any order; only requests with a request id have one.
/// - `before`: prompt size of the last owned request with a request id before
///   the compaction. Responses without a request id are skipped, so this can
///   come from an earlier request than the true last one (usually smaller).
///   NULL when there is none. Exactly: the owned non-zero request with the
///   largest sequence below the boundary's `response_count_before`.
/// - `after`: prompt size of the first owned request with a request id after
///   the compaction. Responses without a request id are skipped, so this can
///   come from a later request (usually larger). NULL until seen. Exactly:
///   the owned non-zero request with the smallest sequence at or above it.
///
/// `paired` is `paired_claude_legacy_compactions(owned_observations)`, the
/// set the summary already built, so the fold pairs once. One pass over the
/// observations and one over the requests; everything this builds is bounded
/// by the (at most 64) events, never by the marker or request count, and an
/// item without an owned boundary does no request work. Called only by the
/// fold's posture writers through `set_claude_compaction_scalars`, never by
/// `finish()`. Also returns how many of these events sit next to an id-less
/// response (local counters only).
pub(super) fn claude_compaction_events<'a>(
    owned_observations: &[ClaudeCompactionObservation],
    paired: &BTreeSet<usize>,
    own_requests: impl Iterator<Item = &'a ClaudeTranscriptUsageOccurrence>,
) -> (Vec<SnapshotCompactionEvent>, ClaudeIdLessNeighbours) {
    let mut candidates = NewestDistinctAt::default();
    for (index, observation) in owned_observations.iter().enumerate() {
        if observation.kind == ClaudeCompactionKind::CurrentBoundary || !paired.contains(&index) {
            if let Some(at) = observation.timestamp.as_deref() {
                candidates.note(at, observation);
            }
        }
    }
    let candidates = candidates.entries;
    if candidates.is_empty() {
        return (Vec::new(), ClaudeIdLessNeighbours::default());
    }
    let mut id_less = ClaudeIdLessNeighbours::default();
    for (_, observation) in &candidates {
        id_less.before += u64::from(observation.id_less_before);
        id_less.after += u64::from(observation.id_less_after);
    }

    // Cut points between requests, ascending. Gap `g` holds the requests with
    // `cuts[g - 1] <= sequence < cuts[g]`; gap 0 is before the first cut.
    let mut cuts = candidates
        .iter()
        .map(|(_, observation)| observation.response_count_before)
        .collect::<Vec<_>>();
    cuts.sort_unstable();
    cuts.dedup();
    debug_assert!(candidates.len() <= MAX_COMPACTION_TIMESTAMPS);
    debug_assert!(cuts.len() <= MAX_COMPACTION_TIMESTAMPS);
    let mut gaps = vec![ClaudeRequestGap::default(); cuts.len() + 1];
    for request in own_requests {
        if request.effective_input_context == 0 {
            continue;
        }
        let gap = &mut gaps[cuts.partition_point(|cut| *cut <= request.sequence)];
        if !matches!(gap.last, Some((sequence, ..)) if sequence >= request.sequence) {
            gap.last = Some((
                request.sequence,
                request.effective_input_context,
                request.timestamp.as_deref(),
            ));
        }
        if !matches!(gap.first, Some((sequence, _)) if sequence <= request.sequence) {
            gap.first = Some((request.sequence, request.effective_input_context));
        }
    }
    // before[k]: the latest request at or before gap k; after[k]: the earliest
    // request in gap k + 1 or later.
    let mut before = Vec::with_capacity(cuts.len());
    let mut latest = None;
    for gap in &gaps[..cuts.len()] {
        latest = gap.last.or(latest);
        before.push(latest);
    }
    let mut after = vec![None; cuts.len()];
    let mut earliest = None;
    for (index, gap) in gaps.iter().enumerate().skip(1).rev() {
        earliest = gap.first.or(earliest);
        after[index - 1] = earliest;
    }

    let events = candidates
        .into_iter()
        .map(|(at, observation)| {
            let cut = cuts.partition_point(|cut| *cut < observation.response_count_before);
            let before = before[cut];
            let trigger = match observation.trigger {
                Some(ClaudeCompactionTrigger::Auto)
                    if idle_gap(before.and_then(|(_, _, timestamp)| timestamp), at) =>
                {
                    Some(ClaudeCompactionTrigger::Idle)
                }
                trigger => trigger,
            };
            SnapshotCompactionEvent {
                at: at.to_string(),
                before: before.map(|(_, context, _)| context),
                after: after[cut].map(|(_, context)| context),
                trigger: trigger.map(|trigger| trigger.wire().to_string()),
            }
        })
        .collect();
    (events, id_less)
}

/// Shipped Claude compactions whose response just before (or just after) had
/// no request id. That response is never a size, so `before` came from an
/// earlier request (or `after` from a later one). Local log counters only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ClaudeIdLessNeighbours {
    pub(super) before: u64,
    pub(super) after: u64,
}

/// The newest `MAX_COMPACTION_TIMESTAMPS` distinct `at` values seen so far,
/// sorted by the string order of `bounded_compaction_timestamps`, each with
/// the first entry in input order that carried it. Equal to collecting every
/// entry, stable-sorting by `at`, deduplicating and keeping the newest 64,
/// but length and capacity never pass 64: once full, the cutoff (the oldest
/// kept `at`) only rises, so a rejected or evicted `at` can never come back
/// and a kept one has been kept since its first entry. The 5a Codex sizes use
/// the same rule.
#[derive(Debug)]
struct NewestDistinctAt<'a, T> {
    entries: Vec<(&'a str, T)>,
}

impl<T> Default for NewestDistinctAt<'_, T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<'a, T> NewestDistinctAt<'a, T> {
    fn note(&mut self, at: &'a str, value: T) {
        let Err(mut index) = self.entries.binary_search_by(|(kept, _)| (*kept).cmp(at)) else {
            return;
        };
        if self.entries.len() == MAX_COMPACTION_TIMESTAMPS {
            if index == 0 {
                return;
            }
            self.entries.remove(0);
            index -= 1;
        }
        if self.entries.len() == self.entries.capacity() {
            let target = (self.entries.capacity() * 2).clamp(4, MAX_COMPACTION_TIMESTAMPS);
            self.entries.reserve_exact(target - self.entries.len());
        }
        self.entries.insert(index, (at, value));
    }
}

/// The owned requests of one gap between compactions that the sizes need:
/// the last one (with its time, for the idle rule) and the first one.
#[derive(Debug, Clone, Copy, Default)]
struct ClaudeRequestGap<'a> {
    last: Option<(u64, u64, Option<&'a str>)>,
    first: Option<(u64, u64)>,
}

fn idle_gap(last_request_at: Option<&str>, compaction_at: &str) -> bool {
    let parse = |value: &str| OffsetDateTime::parse(value, &Rfc3339).ok();
    last_request_at
        .and_then(parse)
        .zip(parse(compaction_at))
        .is_some_and(|(last, compaction)| {
            (compaction - last).whole_seconds() >= CLAUDE_IDLE_COMPACTION_GAP_SECONDS
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CodexCompactionSize {
    before: Option<NonZeroU64>,
    after: Option<NonZeroU64>,
}
crate::durable_tail_codec::durable_struct!(CodexCompactionSize {
    N before: Option<NonZeroU64>,
    N after: Option<NonZeroU64>,
});

/// Sizes for the newest distinct Codex marker timestamps, sorted by the same
/// string order as `bounded_compaction_timestamps`. Pruned during parsing:
/// both length and vector capacity stay at most `MAX_COMPACTION_TIMESTAMPS`.
/// The existing count and timestamp accumulator are independent and unchanged.
#[derive(Debug, Clone, Default)]
pub(super) struct CodexCompactionSizes {
    entries: Vec<(String, CodexCompactionSize)>,
    pending_after: bool,
}
crate::durable_tail_codec::durable_struct!(CodexCompactionSizes {
    N entries: Vec<(String, CodexCompactionSize)>,
    N pending_after: bool,
});

impl CodexCompactionSizes {
    /// Keep the first marker at each timestamp. Once a timestamp falls below
    /// the newest-64 cutoff it can never return: that cutoff only increases.
    pub(super) fn note_marker(&mut self, at: &str, before: Option<u64>) {
        let Err(mut index) = self
            .entries
            .binary_search_by(|(timestamp, _)| timestamp.as_str().cmp(at))
        else {
            return;
        };
        if self.entries.len() == MAX_COMPACTION_TIMESTAMPS {
            if index == 0 {
                return;
            }
            self.entries.remove(0);
            index -= 1;
        }
        if self.entries.len() == self.entries.capacity() {
            // Cloning retained state can leave an odd capacity. Plain Vec
            // growth could then overshoot the cap even though length cannot.
            let target = (self.entries.capacity() * 2).clamp(4, MAX_COMPACTION_TIMESTAMPS);
            self.entries.reserve_exact(target - self.entries.len());
        }
        self.entries.insert(
            index,
            (
                at.to_owned(),
                CodexCompactionSize {
                    before: before.and_then(NonZeroU64::new),
                    after: None,
                },
            ),
        );
        self.pending_after = true;
    }

    /// Every retained marker still waiting takes the next counted non-zero
    /// request. Timestamp order need not be parse order, so check every entry
    /// (at most 64), only when a marker has been admitted since the last fill.
    pub(super) fn note_counted_request(&mut self, context_tokens: u64) {
        if !self.pending_after {
            return;
        }
        let Some(context_tokens) = NonZeroU64::new(context_tokens) else {
            return;
        };
        for (_, entry) in &mut self.entries {
            entry.after.get_or_insert(context_tokens);
        }
        self.pending_after = false;
    }

    /// Already sorted, distinct and bounded: allocate only the surviving
    /// events, moving their keys rather than cloning the timestamp accumulator.
    pub(super) fn into_events(self) -> Vec<SnapshotCompactionEvent> {
        self.entries
            .into_iter()
            .map(|(at, size)| SnapshotCompactionEvent {
                at,
                before: size.before.map(NonZeroU64::get),
                after: size.after.map(NonZeroU64::get),
                trigger: None,
            })
            .collect()
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for CodexCompactionSizes {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(
            self.entries
                .capacity()
                .checked_mul(std::mem::size_of::<(String, CodexCompactionSize)>())?,
        )?;
        for (at, _) in &self.entries {
            c.add(at.capacity())?;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{
        bounded_compaction_timestamps, claude_compaction_summary,
        local_context_points::{LocalContextPoints, LOCAL_CONTEXT_POINT_ORDER_WINDOW},
        paired_claude_legacy_compactions,
    };
    use std::collections::BTreeMap;

    fn at(index: usize) -> String {
        format!("2026-10-21T10:{:02}:{:02}Z", index / 60, index % 60)
    }

    /// Round 2's `claude_compaction_events`, kept as the oracle: collect every
    /// candidate, stable-sort by `at`, dedup (first in parse order wins), keep
    /// the newest 64, then the same gap walk.
    fn round_two_claude_compaction_events<'a>(
        owned_observations: &[ClaudeCompactionObservation],
        own_requests: impl Iterator<Item = &'a ClaudeTranscriptUsageOccurrence>,
    ) -> (Vec<SnapshotCompactionEvent>, ClaudeIdLessNeighbours) {
        let paired = paired_claude_legacy_compactions(owned_observations);
        let mut candidates = owned_observations
            .iter()
            .enumerate()
            .filter(|(index, observation)| {
                observation.kind == ClaudeCompactionKind::CurrentBoundary || !paired.contains(index)
            })
            .filter_map(|(_, observation)| Some((observation.timestamp.as_deref()?, observation)))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return (Vec::new(), ClaudeIdLessNeighbours::default());
        }
        candidates.sort_by(|left, right| left.0.cmp(right.0));
        candidates.dedup_by(|later, earlier| later.0 == earlier.0);
        if candidates.len() > MAX_COMPACTION_TIMESTAMPS {
            candidates = candidates.split_off(candidates.len() - MAX_COMPACTION_TIMESTAMPS);
        }
        let mut id_less = ClaudeIdLessNeighbours::default();
        for (_, observation) in &candidates {
            id_less.before += u64::from(observation.id_less_before);
            id_less.after += u64::from(observation.id_less_after);
        }
        let cuts = candidates
            .iter()
            .map(|(_, observation)| observation.response_count_before)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut gaps = vec![ClaudeRequestGap::default(); cuts.len() + 1];
        for request in own_requests {
            if request.effective_input_context == 0 {
                continue;
            }
            let gap = &mut gaps[cuts.partition_point(|cut| *cut <= request.sequence)];
            if !matches!(gap.last, Some((sequence, ..)) if sequence >= request.sequence) {
                gap.last = Some((
                    request.sequence,
                    request.effective_input_context,
                    request.timestamp.as_deref(),
                ));
            }
            if !matches!(gap.first, Some((sequence, _)) if sequence <= request.sequence) {
                gap.first = Some((request.sequence, request.effective_input_context));
            }
        }
        let mut before = Vec::new();
        let mut latest = None;
        for gap in &gaps[..cuts.len()] {
            latest = gap.last.or(latest);
            before.push(latest);
        }
        let mut after = vec![None; cuts.len()];
        let mut earliest = None;
        for (index, gap) in gaps.iter().enumerate().skip(1).rev() {
            earliest = gap.first.or(earliest);
            after[index - 1] = earliest;
        }
        let events = candidates
            .into_iter()
            .map(|(at, observation)| {
                let cut = cuts.partition_point(|cut| *cut < observation.response_count_before);
                let before = before[cut];
                let trigger = match observation.trigger {
                    Some(ClaudeCompactionTrigger::Auto)
                        if idle_gap(before.and_then(|(_, _, timestamp)| timestamp), at) =>
                    {
                        Some(ClaudeCompactionTrigger::Idle)
                    }
                    trigger => trigger,
                };
                SnapshotCompactionEvent {
                    at: at.to_string(),
                    before: before.map(|(_, context, _)| context),
                    after: after[cut].map(|(_, context)| context),
                    trigger: trigger.map(|trigger| trigger.wire().to_string()),
                }
            })
            .collect();
        (events, id_less)
    }

    fn claude_at(seconds: i64) -> String {
        OffsetDateTime::from_unix_timestamp(1_792_576_800 + seconds)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    #[test]
    fn claude_streaming_selection_matches_round_two_on_a_long_stream() {
        // 5,000 owned markers in parse order: boundaries at out-of-order
        // times with many duplicates (2,003 distinct values), legacy
        // summaries paired by link, by time, or left as their own event, and
        // some without a timestamp. 20,000 requests in a request-id map, so
        // map order is not request order: every 5th is copied (not own),
        // every 11th has size zero, every 13th is id-less (absent), and a
        // few have no usable timestamp.
        let mut observations = Vec::new();
        for index in 0..5_000_u64 {
            let at = (index % 97 != 0).then(|| claude_at((index * 7_919 % 2_003) as i64 * 15));
            let boundary = ClaudeCompactionObservation {
                kind: ClaudeCompactionKind::CurrentBoundary,
                timestamp: at.clone(),
                pre_tokens: Some(100_000 + index),
                post_tokens: None,
                cumulative_dropped_tokens: None,
                duration_ms: None,
                response_count_before: index * 4,
                pair_key: Some(index),
                has_parent_link: true,
                trigger: [
                    Some(ClaudeCompactionTrigger::Auto),
                    Some(ClaudeCompactionTrigger::Manual),
                    Some(ClaudeCompactionTrigger::Idle),
                    None,
                ][(index % 4) as usize],
                id_less_before: index % 6 == 0,
                id_less_after: index % 10 == 0,
            };
            observations.push(boundary.clone());
            if index % 9 == 0 {
                // Linked legacy summary (paired away), or every 27th an
                // unlinked one 1 s later (paired by time), or every 45th one
                // with a foreign parent (its own event).
                let mut legacy = boundary;
                legacy.kind = ClaudeCompactionKind::LegacySummary;
                legacy.trigger = None;
                if index % 45 == 0 {
                    legacy.pair_key = None;
                    legacy.timestamp = Some(claude_at(40_000 + index as i64));
                } else if index % 27 == 0 {
                    legacy.pair_key = None;
                    legacy.has_parent_link = false;
                    legacy.timestamp =
                        at.map(|_| claude_at((index * 7_919 % 2_003) as i64 * 15 + 1));
                }
                observations.push(legacy);
            }
        }
        let observations = observations.into_iter().take(5_000).collect::<Vec<_>>();
        let mut occurrences = BTreeMap::new();
        for sequence in 0..20_000_u64 {
            if sequence % 13 == 0 {
                continue;
            }
            let timestamp = (sequence % 1_009 != 0).then(|| claude_at(sequence as i64 * 3 / 2));
            occurrences.insert(
                format!(
                    "req_{:08x}",
                    sequence.wrapping_mul(2_654_435_761) % (1 << 32)
                ),
                ClaudeTranscriptUsageOccurrence {
                    sequence,
                    telemetry_attached: false,
                    e2_inherited: None,
                    usage: Default::default(),
                    model: None,
                    selector: Default::default(),
                    reasoning_effort: None,
                    timestamp,
                    event_clock_complete: true,
                    desktop_request: false,
                    effective_input_context: if sequence % 11 == 0 {
                        0
                    } else {
                        10_000 + sequence * 7 % 190_000
                    },
                },
            );
        }
        fn is_own(occurrence: &ClaudeTranscriptUsageOccurrence) -> bool {
            occurrence.sequence % 5 != 0
        }
        assert!(occurrences
            .values()
            .zip(occurrences.values().skip(1))
            .any(|(left, right)| left.sequence > right.sequence));

        // The streaming selection never holds more than 64 entries.
        let paired = paired_claude_legacy_compactions(&observations);
        let mut selection = NewestDistinctAt::default();
        for (index, observation) in observations.iter().enumerate() {
            if observation.kind == ClaudeCompactionKind::CurrentBoundary || !paired.contains(&index)
            {
                if let Some(at) = observation.timestamp.as_deref() {
                    selection.note(at, index);
                    assert!(selection.entries.len() <= MAX_COMPACTION_TIMESTAMPS);
                    assert!(selection.entries.capacity() <= MAX_COMPACTION_TIMESTAMPS);
                }
            }
        }
        assert_eq!(selection.entries.len(), MAX_COMPACTION_TIMESTAMPS);

        let own = || occurrences.values().filter(|occurrence| is_own(occurrence));
        let streamed = claude_compaction_events(&observations, &paired, own());
        let oracle = round_two_claude_compaction_events(&observations, own());
        assert_eq!(streamed, oracle);
        let (events, _) = &streamed;
        assert_eq!(events.len(), MAX_COMPACTION_TIMESTAMPS);
        assert_eq!(
            events
                .iter()
                .map(|event| event.at.clone())
                .collect::<Vec<_>>(),
            claude_compaction_summary(&observations).1
        );
        assert!(events.iter().any(|event| event.before.is_some()));
        assert!(events.iter().any(|event| event.after.is_some()));
        assert!(events.iter().any(|event| event.trigger.is_none()));

        // Points: round 2 collected the own requests, sorted them by
        // sequence and pushed them in that order, which is exactly the
        // in-order path (a plain push loop, checked against `push` in
        // `local_context_points`). The map is not in request order, so the
        // bounded path runs several windows.
        assert!(occurrences.len() > 4 * LOCAL_CONTEXT_POINT_ORDER_WINDOW);
        let mut ordered = own().collect::<Vec<_>>();
        ordered.sort_by_key(|occurrence| occurrence.sequence);
        let round_two =
            LocalContextPoints::from_ordered_requests(ordered.iter().copied(), |occurrence| {
                Some((
                    occurrence.timestamp.as_deref(),
                    occurrence.effective_input_context,
                ))
            });
        fn point(occurrence: &ClaudeTranscriptUsageOccurrence) -> Option<(Option<&str>, u64)> {
            is_own(occurrence).then_some((
                occurrence.timestamp.as_deref(),
                occurrence.effective_input_context,
            ))
        }
        let from_map = LocalContextPoints::from_requests_by_sequence(
            occurrences.values(),
            |occurrence| occurrence.sequence,
            point,
        )
        .expect("within the work budget");
        assert!(!from_map.is_empty());
        assert!(from_map.len() <= 64);
        assert_eq!(from_map, round_two);
        // The strict fold passes a slice already in sequence order.
        let mut sorted = occurrences.values().cloned().collect::<Vec<_>>();
        sorted.sort_by_key(|occurrence| occurrence.sequence);
        let from_slice = LocalContextPoints::from_ordered_requests(sorted.iter(), point);
        assert_eq!(from_slice, round_two);
    }

    #[test]
    fn codex_size_entry_is_sixteen_bytes() {
        assert_eq!(std::mem::size_of::<CodexCompactionSize>(), 16);
    }

    #[test]
    fn markers_without_a_request_between_share_one_after() {
        let mut sizes = CodexCompactionSizes::default();
        sizes.note_counted_request(10);
        sizes.note_marker(&at(1), Some(240_000));
        sizes.note_marker(&at(2), Some(240_000));
        sizes.note_counted_request(0);
        sizes.note_counted_request(59_000);
        sizes.note_counted_request(61_000);
        sizes.note_marker(&at(3), Some(61_000));
        sizes.note_marker(&at(4), None);
        let events = sizes.into_events();
        let pairs = events
            .iter()
            .map(|event| (event.before, event.after))
            .collect::<Vec<_>>();
        assert_eq!(
            pairs,
            [
                (Some(240_000), Some(59_000)),
                (Some(240_000), Some(59_000)),
                (Some(61_000), None),
                (None, None),
            ]
        );
        assert!(events.iter().all(|event| event.trigger.is_none()));
    }

    #[test]
    fn bounded_events_match_bounded_timestamps() {
        // The old finish-time algorithm is the oracle: keep every marker,
        // fill the waiting parse-order suffix, then stable-sort/dedup/truncate.
        // Most of these 10,000 markers are duplicates and out of order; the
        // final new key intentionally stays pending at end of input.
        let mut old_events: Vec<SnapshotCompactionEvent> = Vec::new();
        let mut timestamps = Vec::new();
        let mut sizes = CodexCompactionSizes::default();
        let mut tail: Option<CodexCompactionSizes> = None;
        for index in 0..10_000 {
            let timestamp = at(if index == 9_999 {
                300
            } else {
                index * 37 % 257
            });
            let before = (index % 13 != 0).then_some(1_000 + index as u64);
            timestamps.push(timestamp.clone());
            old_events.push(SnapshotCompactionEvent {
                at: timestamp.clone(),
                before,
                after: None,
                trigger: None,
            });
            sizes.note_marker(&timestamp, before);
            if let Some(tail) = tail.as_mut() {
                tail.note_marker(&timestamp, before);
            }
            // Zero requests leave pending markers alone; the first positive
            // request fills them, later requests must never overwrite it.
            let request = if index % 17 == 0 {
                Some(50_000 + index as u64)
            } else if index % 7 == 0 {
                Some(0)
            } else {
                None
            };
            if let Some(request) = request {
                sizes.note_counted_request(request);
                if let Some(tail) = tail.as_mut() {
                    tail.note_counted_request(request);
                }
                if request > 0 {
                    for event in old_events.iter_mut().rev() {
                        if event.after.is_some() {
                            break;
                        }
                        event.after = Some(request);
                    }
                }
            }
            // Resume while some entries are pending, with clone capacity 33
            // rather than a power of two. Continue through eviction and dedup.
            if index == 32 {
                tail = Some(sizes.clone());
            }
            for state in std::iter::once(&sizes).chain(tail.iter()) {
                assert!(state.entries.len() <= MAX_COMPACTION_TIMESTAMPS);
                assert!(state.entries.capacity() <= MAX_COMPACTION_TIMESTAMPS);
                assert!(state.entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
            }
        }
        let events = sizes.into_events();
        assert_eq!(events, tail.unwrap().into_events());
        assert_eq!(events, bounded_compaction_events(old_events));
        assert_eq!(events.len(), MAX_COMPACTION_TIMESTAMPS);
        assert_eq!(
            events
                .iter()
                .map(|event| event.at.clone())
                .collect::<Vec<_>>(),
            bounded_compaction_timestamps(timestamps)
        );
        assert_eq!(events.last().unwrap().at, at(300));
        assert_eq!(events.last().unwrap().after, None);
    }

    #[test]
    fn event_wire_omits_unknown_sizes_and_trigger() {
        let event = SnapshotCompactionEvent {
            at: at(1),
            before: Some(240_000),
            after: None,
            trigger: None,
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"at":"2026-10-21T10:00:01Z","before":240000}"#
        );
    }
}
