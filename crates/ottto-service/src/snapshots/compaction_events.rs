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
