//! Stable Tail page slots for Codex's current-state dictionaries. A key takes
//! the next slot the first time the native reducer sees it and keeps that slot
//! for good; a removal leaves a tombstone (the key is absent from its native
//! map), and a reinsertion uses the same slot. Pages therefore never shift, and
//! membership counts tombstones. The index rebuilds from the pages at load.
use crate::durable_tail_codec::durable_enum;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::owned_heap::OwnedMap;

/// One dictionary's first-seen order: key to slot, as the response book keeps it.
pub(super) struct StableSlots<K> {
    index: OwnedMap<K, u32>,
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
    pub(super) fn note(&mut self, key: &K) {
        if !self.index.contains_key(key) {
            self.adopt(key.clone());
        }
    }
}
#[cfg_attr(not(test), allow(dead_code))] // Read by the Codex codec, activated by the shared dispatch.
impl<K: Ord + HeapLayoutBound> StableSlots<K> {
    /// A decoded slot, in stored order. False: the key is a duplicate, or the
    /// slot space is spent.
    pub(super) fn adopt(&mut self, key: K) -> bool {
        let Ok(slot) = u32::try_from(self.index.len()) else {
            return false;
        };
        if self.index.contains_key(&key) {
            return false;
        }
        self.index.insert(key, slot);
        true
    }
    /// Every slot, tombstones included.
    pub(super) fn len(&self) -> usize {
        self.index.len()
    }
    pub(super) fn contains(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }
    /// The keys in slot order: the index inverted.
    pub(super) fn ordered(&self) -> Vec<&K> {
        let mut keys: Vec<(u32, &K)> = self.index.iter().map(|(key, slot)| (*slot, key)).collect();
        keys.sort_unstable_by_key(|(slot, _)| *slot);
        keys.into_iter().map(|(_, key)| key).collect()
    }
}

/// Which of Codex's three name-count maps a name belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum CodexCountMap {
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
/// `activity_mcp_call_ids`; and the three name-count maps.
#[derive(Clone, Default)]
pub(super) struct CodexDictionarySlots {
    pub(super) active_turns: StableSlots<String>,
    pub(super) open_calls: StableSlots<String>,
    pub(super) name_counts: StableSlots<(CodexCountMap, String)>,
}
crate::heap_layout_bound::fields!(CodexDictionarySlots; active_turns, open_calls, name_counts);
