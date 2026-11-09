//! Stable Tail page slots for Codex's current-state dictionaries. A key takes
//! the next slot the first time the native reducer sees it and keeps that slot
//! for good; a removal leaves a tombstone (the key is absent from its native
//! map), and a reinsertion uses the same slot. Pages therefore never shift, and
//! membership counts tombstones. The index rebuilds from the pages at load.
use crate::durable_tail_codec::durable_enum;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::owned_heap::OwnedMap;

/// One dictionary's first-seen order: key to slot, as the response book keeps it.
pub(in crate::snapshots) struct StableSlots<K> {
    index: OwnedMap<K, usize>,
}
impl<K> Default for StableSlots<K> {
    fn default() -> Self {
        Self {
            index: OwnedMap::default(),
        }
    }
}
impl<K: Ord + Clone + HeapLayoutBound> Clone for StableSlots<K> {
    fn clone(&self) -> Self {
        Self {
            index: self.index.clone(),
        }
    }
}
impl<K: HeapLayoutBound> HeapLayoutBound for StableSlots<K> {
    fn stable_heap(&self) -> bool {
        self.index.stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.index.heap_bound(c)
    }
}
impl<K: Ord + Clone + HeapLayoutBound> StableSlots<K> {
    /// The native reducer inserted `key`: it keeps its slot, or takes the next.
    pub(in crate::snapshots) fn note(&mut self, key: &K) {
        if !self.index.contains_key(key) {
            self.adopt(key.clone());
        }
    }
}
impl<K: Ord + HeapLayoutBound> StableSlots<K> {
    /// A decoded slot, in stored order. False: the key is a duplicate.
    pub(in crate::snapshots) fn adopt(&mut self, key: K) -> bool {
        let slot = self.index.len();
        if self.index.contains_key(&key) {
            return false;
        }
        self.index.insert(key, slot);
        true
    }
    /// Every slot, tombstones included.
    pub(in crate::snapshots) fn len(&self) -> usize {
        self.index.len()
    }
    pub(in crate::snapshots) fn contains(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }
    /// The keys in slot order: the index inverted.
    pub(in crate::snapshots) fn ordered(&self) -> Vec<&K> {
        let mut keys: Vec<(usize, &K)> =
            self.index.iter().map(|(key, slot)| (*slot, key)).collect();
        keys.sort_unstable_by_key(|(slot, _)| *slot);
        keys.into_iter().map(|(_, key)| key).collect()
    }
}

/// Which of Codex's three name-count maps a name belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) enum CodexCountMap {
    Tool,
    McpActivity,
    McpUsage,
}
durable_enum!(CodexCountMap {
    0 => Tool,
    1 => McpActivity,
    2 => McpUsage,
});
crate::heap_layout_bound::no_heap!(true; CodexCountMap);

/// The slots of `cache_active_turns`; `activity_call_tools` with
/// `activity_mcp_call_ids`; the three name-count maps; and the priority
/// decisions by turn, which only ever insert (a slot per turn, first seen).
#[derive(Clone, Default)]
pub(in crate::snapshots) struct CodexDictionarySlots {
    pub(in crate::snapshots) active_turns: StableSlots<String>,
    pub(in crate::snapshots) open_calls: StableSlots<String>,
    pub(in crate::snapshots) name_counts: StableSlots<(CodexCountMap, String)>,
    pub(in crate::snapshots) priority_turns: StableSlots<String>,
}
crate::heap_layout_bound::fields!(CodexDictionarySlots; active_turns, open_calls, name_counts,
    priority_turns);
