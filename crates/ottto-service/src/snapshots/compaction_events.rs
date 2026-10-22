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
    paired_claude_legacy_compactions, ClaudeCompactionKind, ClaudeCompactionObservation,
    ClaudeTranscriptUsageOccurrence, MAX_COMPACTION_TIMESTAMPS,
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
    events: Vec<SnapshotCompactionEvent>,
) -> Vec<SnapshotCompactionEvent> {
    bounded_by_at(events, |event| &event.at)
}

fn bounded_by_at<T>(mut entries: Vec<T>, at: impl Fn(&T) -> &str) -> Vec<T> {
    // Stable sort, so equal timestamps keep parse order for the dedup below.
    entries.sort_by(|left, right| at(left).cmp(at(right)));
    entries.dedup_by(|later, earlier| at(later) == at(earlier));
    if entries.len() > MAX_COMPACTION_TIMESTAMPS {
        entries.split_off(entries.len() - MAX_COMPACTION_TIMESTAMPS)
    } else {
        entries
    }
}

/// Gap between a Claude Code automatic compaction and the last owned request
/// before it that marks the compaction idle. Claude Code compacts an idle
/// session shortly before its one-hour prompt cache expires (about 54 minutes
/// observed); a transcript marker saying `idle` wins when present.
const CLAUDE_IDLE_COMPACTION_GAP_SECONDS: i64 = 50 * 60;

/// `compactMetadata.trigger` of a Claude Code `compact_boundary`, read on the
/// boundary line only. Unknown values stay `None`. Local, never serialized;
/// the upload carries the closed string from `wire`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaudeCompactionTrigger {
    Auto,
    Manual,
    Idle,
}

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

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeCompactionTrigger {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// Sizes and trigger for exactly the events `claude_compaction_summary`
/// lists for the same `owned_observations`: every boundary plus every legacy
/// summary #676's pairing leaves unpaired, each with a timestamp, bounded like
/// `bounded_compaction_timestamps`, so `at` matches `compaction_timestamps`
/// entry for entry. `own_requests` are the owned requests behind the item's
/// first/peak/last, in any order:
/// - `before` = the owned non-zero request with the largest sequence below
///   the boundary's `response_count_before`;
/// - `after` = the owned non-zero request with the smallest sequence at or
///   above it, absent until one is seen.
///
/// One pass over the requests, memory bounded by the (at most 64) events, and
/// no work at all for an item without an owned boundary. Called only by the
/// fold's posture writers through `set_claude_compaction_scalars`, never by
/// `finish()`.
pub(super) fn claude_compaction_events<'a>(
    owned_observations: &[ClaudeCompactionObservation],
    own_requests: impl Iterator<Item = &'a ClaudeTranscriptUsageOccurrence>,
) -> Vec<SnapshotCompactionEvent> {
    let paired = paired_claude_legacy_compactions(owned_observations);
    let candidates = owned_observations
        .iter()
        .enumerate()
        .filter(|(index, observation)| {
            observation.kind == ClaudeCompactionKind::CurrentBoundary || !paired.contains(index)
        })
        .filter_map(|(_, observation)| Some((observation.timestamp.as_deref()?, observation)))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Vec::new();
    }
    let candidates = bounded_by_at(candidates, |(at, _)| at);

    // Cut points between requests, ascending. Gap `g` holds the requests with
    // `cuts[g - 1] <= sequence < cuts[g]`; gap 0 is before the first cut.
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

    candidates
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
        .collect()
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

/// Sizes for the newest distinct Codex marker timestamps, sorted by the same
/// string order as `bounded_compaction_timestamps`. Pruned during parsing:
/// both length and vector capacity stay at most `MAX_COMPACTION_TIMESTAMPS`.
/// The existing count and timestamp accumulator are independent and unchanged.
#[derive(Debug, Clone, Default)]
pub(super) struct CodexCompactionSizes {
    entries: Vec<(String, CodexCompactionSize)>,
    pending_after: bool,
}

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
    use crate::snapshots::bounded_compaction_timestamps;

    fn at(index: usize) -> String {
        format!("2026-10-21T10:{:02}:{:02}Z", index / 60, index % 60)
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
