//! Optional process-owned reduction cache. Losing an entry never clears the
//! file index's audit debt. The caller owns both active scans and durable ACKs.
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use crate::transcript_acquisition::Checkpoint;
use std::collections::BTreeMap;

pub(crate) const CACHE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const ENTRY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const CACHE_ENTRIES: usize = 256;

pub(crate) struct Retained<S> {
    pub(crate) checkpoint: Checkpoint,
    pub(crate) state: S,
}
impl<S: HeapLayoutBound> HeapLayoutBound for Retained<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self { checkpoint, state } = self;
        checkpoint.heap_bound(c)?;
        state.heap_bound(c)
    }
}
struct Entry<S> {
    retained: Retained<S>,
    used: u64,
}
impl<S: HeapLayoutBound> HeapLayoutBound for Entry<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self { retained, used } = self;
        retained.heap_bound(c)?;
        used.heap_bound(c)
    }
}

/// One common admission/eviction mechanism for compatible native states. Uses
/// the existing fail-closed layout accounting, including strings, maps and Arc
/// payloads; it never estimates memory from the source file's size.
pub(crate) struct TranscriptCache<S> {
    entries: BTreeMap<String, Entry<S>>,
    clock: u64,
    byte_limit: usize,
    entry_limit: usize,
    count_limit: usize,
}
impl<S: HeapLayoutBound> HeapLayoutBound for TranscriptCache<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            entries,
            clock,
            byte_limit,
            entry_limit,
            count_limit,
        } = self;
        entries.heap_bound(c)?;
        clock.heap_bound(c)?;
        byte_limit.heap_bound(c)?;
        entry_limit.heap_bound(c)?;
        count_limit.heap_bound(c)
    }
}
impl<S: HeapLayoutBound> Default for TranscriptCache<S> {
    fn default() -> Self {
        Self::new(CACHE_BYTES, ENTRY_BYTES, CACHE_ENTRIES)
    }
}
impl<S: HeapLayoutBound> TranscriptCache<S> {
    fn new(byte_limit: usize, entry_limit: usize, count_limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            clock: 0,
            byte_limit,
            entry_limit,
            count_limit,
        }
    }
    pub(crate) fn with_byte_limit(byte_limit: usize) -> Self {
        Self::new(byte_limit, ENTRY_BYTES, CACHE_ENTRIES)
    }
    /// Moves state into the existing active frame: there is no cached duplicate
    /// while the provider mutates it. The active frame must count this allocation
    /// through its own existing HeapLayoutBound admission.
    pub(crate) fn take(&mut self, key: &str) -> Option<Retained<S>> {
        self.entries.remove(key).map(|entry| entry.retained)
    }
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
    #[cfg(test)]
    pub(crate) fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
    #[cfg(test)]
    pub(crate) fn resident_bound(&self) -> Option<usize> {
        heap_layout_bound::bound(self, self.byte_limit)
    }
    /// Includes active scans / native finalization copies / parked proof frames.
    /// Caller checks before allocating a bounded clone and again on actual
    /// resulting state. Unsupported layouts or traversal exhaustion bypass reuse.
    #[cfg(test)]
    pub(crate) fn bound_with<A: HeapLayoutBound>(&self, active: &A) -> Option<usize> {
        let resident = self.resident_bound()?;
        let active = heap_layout_bound::bound(active, self.byte_limit.checked_sub(resident)?)?;
        resident.checked_add(active)
    }
    /// Admission transfers ownership. Refusal drops transient state only; it
    /// cannot mutate the authoritative file index or settle upload progress.
    #[cfg(test)]
    pub(crate) fn insert(&mut self, key: String, retained: Retained<S>) -> bool {
        self.insert_reserving(key, retained, 0)
    }
    /// `live_bytes` is an actual checked native-layout charge, not file size.
    /// Native output/active copies keep this room while entries are admitted.
    pub(crate) fn insert_reserving(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
    ) -> bool {
        self.entries.remove(&key);
        let Some(resident_limit) = self.byte_limit.checked_sub(live_bytes) else {
            return false;
        };
        let Some(next) = self.clock.checked_add(1) else {
            // A safe local reset; no durable debt is owned here.
            self.entries.clear();
            self.clock = 0;
            return false;
        };
        if self.count_limit == 0 || !heap_layout_bound::layout_supported() {
            return false;
        }
        let entry = Entry {
            retained,
            used: next,
        };
        let Some(state_bytes) = heap_layout_bound::bound(&entry, self.entry_limit) else {
            return false;
        };
        if heap_layout_bound::bound(&key, self.entry_limit.saturating_sub(state_bytes)).is_none() {
            return false;
        }
        self.clock = next;
        self.entries.insert(key.clone(), entry);
        loop {
            if self.entries.len() <= self.count_limit
                && heap_layout_bound::bound(self, resident_limit).is_some()
            {
                return true;
            }
            let victim = self
                .entries
                .iter()
                .filter(|(candidate, _)| *candidate != &key)
                .min_by_key(|(_, entry)| entry.used)
                .map(|(candidate, _)| candidate.clone());
            let Some(victim) = victim else {
                self.entries.remove(&key);
                return false;
            };
            self.entries.remove(&victim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test states use the same accounting as production native accumulator
    // fields. Provider-native states are also exercised in the adapter fixtures.
    #[test]
    fn sampled_cache_accounts_private_capacity_and_active_copies() {
        let cache = TranscriptCache::<String>::default();
        let small = String::from("private");
        let mut large = small.clone();
        large.reserve(1024 * 1024);
        if heap_layout_bound::layout_supported() {
            assert!(
                cache.bound_with(&large).unwrap()
                    >= cache.bound_with(&small).unwrap() + 1024 * 1024
            );
            assert!(cache.bound_with(&vec![0_u8; CACHE_BYTES]).is_none());
            let copies = (large.clone(), large);
            assert!(
                cache.bound_with(&copies).unwrap() >= copies.0.capacity() + copies.1.capacity()
            );
        } else {
            assert!(cache.bound_with(&small).is_none());
        }
    }
    fn retained(text: String) -> Retained<String> {
        use crate::transcript_acquisition::{ReadPlan, Scope};
        use std::fs::{self, OpenOptions};
        use std::io::{Read, Write};
        let path = std::env::temp_dir().join(format!(
            "ottto-cache-fixture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{}\n").unwrap();
        let scope = Scope("synthetic-cache".into());
        let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 100).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&file, &scope, 100)
            .unwrap();
        fs::remove_file(path).unwrap();
        Retained {
            checkpoint,
            state: text,
        }
    }
    #[test]
    fn sampled_cache_count_eviction_moves_state_and_refuses_oversized_replacement() {
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 2);
        if !heap_layout_bound::layout_supported() {
            assert!(!cache.insert("a".into(), retained("private".into())));
            assert!(cache.take("a").is_none());
            return;
        }
        for key in ["a", "b", "c"] {
            assert!(cache.insert(key.into(), retained(key.into())));
        }
        assert!(cache.take("a").is_none());
        assert!(cache.take("b").is_some());
        assert!(cache.take("b").is_none());
        assert!(!cache.insert("c".into(), retained("x".repeat(256 * 1024))));
        assert!(cache.take("c").is_none());
    }
    #[test]
    fn sampled_cache_total_bytes_and_clock_overflow_fail_closed() {
        let mut cache = TranscriptCache::new(80 * 1024, 40 * 1024, 256);
        if !heap_layout_bound::layout_supported() {
            return;
        }
        for n in 0..20 {
            assert!(cache.insert(n.to_string(), retained("x".repeat(16 * 1024))));
            assert!(cache.resident_bound().unwrap() <= 80 * 1024);
        }
        assert!(cache.entries.len() < 20);
        cache.clock = u64::MAX;
        assert!(!cache.insert("overflow".into(), retained("private".into())));
        assert!(cache.entries.is_empty());
    }
    #[test]
    fn sampled_cache_reserves_actual_live_copy_and_overlap_room_at_admission() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let mut cache = TranscriptCache::with_byte_limit(32 * 1024 * 1024);
        let overlap = 32 * 1024 * 1024;
        let live = vec![0_u8; 14 * 1024 * 1024];
        let live_bytes = heap_layout_bound::bound(&live, 16 * 1024 * 1024).unwrap();
        for n in 0..8 {
            assert!(cache.insert_reserving(
                n.to_string(),
                retained("x".repeat(4 * 1024 * 1024)),
                live_bytes
            ));
            assert!(cache.resident_bound().unwrap() + live_bytes + overlap <= CACHE_BYTES);
        }
        assert!(
            cache.entries.len() < 8,
            "admission evicts instead of consuming live/overlap reservation"
        );
        assert!(!cache.insert_reserving("no-room".into(), retained("x".into()), 33 * 1024 * 1024));
    }
}
