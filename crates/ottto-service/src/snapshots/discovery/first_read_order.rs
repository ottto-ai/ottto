//! First-read order: while a source's first read (destination bootstrap or
//! replay) is pending, each root-walk end stably reorders the queued non-hint
//! entries in the positions they already hold. Order only: nothing is added,
//! dropped, capped or delayed, hint entries keep their slots and every
//! selection tier still picks by predicate, so retry, fresh, audit, hint and
//! census precedence are unchanged.
//!
//! Each source picks its order in the durable source table:
//! - `NewestFirst`: newest mtime first; an unknown mtime counts as newest.
//! - `NewestFolderFirst`: folders that already have read evidence (any
//!   indexed file in that folder) keep their place, first and in their
//!   current order. Other folders follow, newest file mtime first, then path.
//!   Inside such a folder files go oldest birth first, unknown birth first,
//!   so a copied session meets its earlier-born original already read and
//!   its copy-prefix wait has nothing to wait for. The pins come from the
//!   saved index, so a restart derives the same order.
//!
//! The keys are one `stat` per moved entry, held in a transient vector that
//! is freed before the call returns. The sort is idempotent: a second call
//! with unchanged files and index keeps the queue as it is.

use crate::snapshots::*;
use std::cmp::Reverse;

/// How a source orders its queued history during its first read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirstReadOrder {
    /// Walk order (directory order, then name order inside a directory).
    Fifo,
    NewestFirst,
    NewestFolderFirst,
}

pub(in crate::snapshots) fn order_for(source: SnapshotSource) -> FirstReadOrder {
    durable_sources::DurableSource::from_snapshot(source).map_or(FirstReadOrder::Fifo, |row| {
        row.properties().first_read_order
    })
}

/// Reorders `queue` in place per `order`. Hint entries keep their positions;
/// the non-hint entries are permuted among the slots they already hold.
pub(in crate::snapshots) fn sort(
    queue: &mut VecDeque<ScanTraversalPath>,
    order: FirstReadOrder,
    index: &ScanIndex,
) {
    if order == FirstReadOrder::Fifo {
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
                // Unknown birth may hold anything: it reads first in its folder.
                birth: metadata
                    .as_ref()
                    .and_then(|m| m.created().ok())
                    .map_or(0, nanos),
            }
        })
        .collect::<Vec<_>>();
    let ordered = match order {
        FirstReadOrder::Fifo => return,
        FirstReadOrder::NewestFirst => newest_first(keyed),
        FirstReadOrder::NewestFolderFirst => newest_folder_first(keyed, queue, index),
    };
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
    birth: u128,
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

fn newest_folder_first(
    keyed: Vec<Keys>,
    queue: &VecDeque<ScanTraversalPath>,
    index: &ScanIndex,
) -> Vec<Keys> {
    let parent_of = |keys: &Keys| queue[keys.slot].path.parent();
    let queued = keyed.iter().filter_map(parent_of).collect::<BTreeSet<_>>();
    // Saved read evidence: an indexed file in a queued folder.
    let pinned = index
        .files
        .iter()
        .filter_map(|(key, _)| Path::new(key).parent())
        .filter(|parent| queued.contains(parent))
        .map(Path::to_path_buf)
        .collect::<BTreeSet<_>>();
    // Entries of pinned folders (and parentless paths) keep their exact
    // relative queue order and go first; the rest group by folder in
    // first-seen order, entries in queue order.
    let mut kept = Vec::new();
    let mut moved: Vec<(&Path, Vec<Keys>)> = Vec::new();
    let mut positions = BTreeMap::new();
    for keys in keyed {
        match parent_of(&keys).filter(|parent| !pinned.contains(*parent)) {
            None => kept.push(keys),
            Some(parent) => {
                let position = *positions.entry(parent).or_insert_with(|| {
                    moved.push((parent, Vec::new()));
                    moved.len() - 1
                });
                moved[position].1.push(keys);
            }
        }
    }
    moved.sort_by(|(left_path, left), (right_path, right)| {
        let newest = |entries: &[Keys]| entries.iter().map(|keys| keys.mtime).max();
        newest(right)
            .cmp(&newest(left))
            .then_with(|| left_path.cmp(right_path))
    });
    for (_, entries) in &mut moved {
        // Stable: equal births keep their queue order.
        entries.sort_by_key(|keys| keys.birth);
    }
    kept.into_iter()
        .chain(moved.into_iter().flat_map(|(_, entries)| entries))
        .collect()
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
