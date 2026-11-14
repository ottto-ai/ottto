//! First-read order: while a source's first read (destination bootstrap or
//! replay) is pending, each root-walk end stably reorders the queued non-hint
//! entries in the positions they already hold. Order only: nothing is added,
//! dropped, capped or delayed, hint entries keep their slots and every
//! selection tier still picks by predicate, so retry, fresh, audit, hint and
//! census precedence are unchanged.
//!
//! Codex and Pi opt into newest mtime first in the durable source table;
//! Claude keeps FIFO. An unknown mtime counts as newest.
//!
//! The keys are one `stat` per queued non-hint entry at each root-walk end,
//! held in a transient vector freed before return (about 5k Codex entries
//! on a large install). Walk metadata is local to each directory entry;
//! queued paths do not retain it. No metadata cache is added.
//! The sort is stable and idempotent while mtimes stay unchanged.

use crate::snapshots::*;
use std::cmp::Reverse;

pub(in crate::snapshots) fn order_for(source: SnapshotSource) -> bool {
    durable_sources::DurableSource::from_snapshot(source)
        .is_some_and(|row| row.properties().first_read_newest_first)
}

/// Hint entries keep their positions; non-hint entries are permuted among
/// their existing slots when the source opts into newest-first ordering.
pub(in crate::snapshots) fn sort(
    queue: &mut VecDeque<ScanTraversalPath>,
    first_read_newest_first: bool,
) {
    if !first_read_newest_first {
        return;
    }
    let slots = queue
        .iter()
        .enumerate()
        .filter(|(_, entry)| !entry.watcher_hint)
        .map(|(slot, _)| slot)
        .collect::<Vec<_>>();
    if slots.len() < 2 {
        return;
    }
    let keyed = slots
        .iter()
        .map(|&slot| {
            let metadata = fs::metadata(&queue[slot].path).ok();
            Keys {
                slot,
                // Unknown counts as newest: it moves first.
                mtime: metadata
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .map_or(u128::MAX, nanos),
            }
        })
        .collect::<Vec<_>>();
    let ordered = newest_first(keyed);
    let entries = ordered
        .iter()
        .map(|keys| queue[keys.slot].clone())
        .collect::<Vec<_>>();
    for (slot, entry) in slots.into_iter().zip(entries) {
        queue[slot] = entry;
    }
}

struct Keys {
    slot: usize,
    mtime: u128,
}

fn nanos(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn newest_first(mut keyed: Vec<Keys>) -> Vec<Keys> {
    // Stable: equal mtimes keep their queue order.
    keyed.sort_by_key(|keys| Reverse(keys.mtime));
    keyed
}

/// Newest member mtime of a Codex join group, the last admission key while
/// the first read is pending (descending: newest groups admit first).
pub(in crate::snapshots) fn newest_member(members: &[CandidateFile]) -> Reverse<u64> {
    Reverse(
        members
            .iter()
            .map(|member| member.modified_unix_nanos)
            .max()
            .unwrap_or_default(),
    )
}
