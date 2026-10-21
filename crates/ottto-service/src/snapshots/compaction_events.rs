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

use std::num::NonZeroU64;

use serde::Serialize;

use super::MAX_COMPACTION_TIMESTAMPS;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CodexCompactionSize {
    before: Option<NonZeroU64>,
    after: Option<NonZeroU64>,
}

/// Sizes for each Codex `compacted` marker, index-aligned with the
/// accumulator's `compaction_timestamps`: exactly one entry is noted with each
/// timestamp pushed there, so entry `i` belongs to timestamp `i`. Bounded at
/// finish together with the timestamps. Every entry is 16 bytes and owns no
/// heap. Callers see only `note_marker`, `note_counted_request` and
/// `into_events`, so a swap to a bounded map keyed by `at` stays local.
#[derive(Debug, Clone, Default)]
pub(super) struct CodexCompactionSizes {
    entries: Vec<CodexCompactionSize>,
}

impl CodexCompactionSizes {
    /// A marker was recorded at `at`; `before` is the session's last owned
    /// request size at that moment. `_at` is reserved for a possible keyed-map
    /// implementation; the current vector uses timestamp index alignment.
    pub(super) fn note_marker(&mut self, _at: &str, before: Option<u64>) {
        self.entries.push(CodexCompactionSize {
            before: before.and_then(NonZeroU64::new),
            after: None,
        });
    }

    /// A counted (non-duplicate) request saw `context_tokens`. Every marker
    /// still waiting for its next request takes it; zero-size requests are
    /// skipped. Waiting markers are always the newest ones, so the backward
    /// walk stops at the first filled entry (amortized O(1)).
    pub(super) fn note_counted_request(&mut self, context_tokens: u64) {
        let Some(context_tokens) = NonZeroU64::new(context_tokens) else {
            return;
        };
        for entry in self.entries.iter_mut().rev() {
            if entry.after.is_some() {
                break;
            }
            entry.after = Some(context_tokens);
        }
    }

    /// Pairs each size with the timestamp noted beside it, then bounds the
    /// list exactly as the timestamps are bounded.
    pub(super) fn into_events(self, timestamps: Vec<String>) -> Vec<SnapshotCompactionEvent> {
        debug_assert_eq!(timestamps.len(), self.entries.len());
        let events = timestamps
            .into_iter()
            .zip(self.entries)
            .map(|(at, size)| SnapshotCompactionEvent {
                at,
                before: size.before.map(NonZeroU64::get),
                after: size.after.map(NonZeroU64::get),
                trigger: None,
            })
            .collect();
        bounded_compaction_events(events)
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for CodexCompactionSizes {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(
            self.entries
                .capacity()
                .checked_mul(std::mem::size_of::<CodexCompactionSize>())?,
        )
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
        let events = sizes.into_events(vec![at(1), at(2), at(3), at(4)]);
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
        // 70 markers, two sharing one timestamp and two out of order.
        let mut timestamps = (0..70).map(at).collect::<Vec<_>>();
        timestamps[40] = at(39);
        timestamps.swap(10, 11);
        let mut sizes = CodexCompactionSizes::default();
        for (index, timestamp) in timestamps.iter().enumerate() {
            sizes.note_marker(timestamp, Some(1_000 + index as u64));
        }
        let events = sizes.into_events(timestamps.clone());
        let bounded = bounded_compaction_timestamps(timestamps);
        assert_eq!(events.len(), MAX_COMPACTION_TIMESTAMPS);
        assert_eq!(
            events
                .iter()
                .map(|event| event.at.clone())
                .collect::<Vec<_>>(),
            bounded
        );
        // The duplicate keeps the first marker in parse order (index 39).
        let duplicate = events.iter().find(|event| event.at == at(39)).unwrap();
        assert_eq!(duplicate.before, Some(1_039));
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
