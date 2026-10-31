//! Optional process-owned reduction cache. Losing an entry never clears the
//! file index's audit debt. The caller owns both active scans and durable ACKs.
//! Entries leave on take, capacity eviction, clear or restart; idle age alone
//! never drops one, so a resume after a long idle gap can still reuse state.
use crate::heap_layout_bound::{self, Counter, HeapLayoutBound};
use crate::local_resource_diagnostics::cache_lifecycle::{add, record, Event};
use crate::transcript_acquisition::Checkpoint;
use std::collections::BTreeMap;

pub(crate) const CACHE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const ENTRY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const CACHE_ENTRIES: usize = 256;

/// Explicit adapter opt-in: a retained graph must have no externally mutable
/// allocation. HeapLayoutBound alone also supports Arc/Mutex graphs, whose
/// measured capacities could change without transferring ownership back out.
pub(crate) trait FrozenCacheState: HeapLayoutBound {
    fn supports_frozen_charge(&self) -> bool;
}
impl FrozenCacheState for String {
    fn supports_frozen_charge(&self) -> bool {
        true
    }
}
impl<T: FrozenCacheState> FrozenCacheState for Vec<T> {
    fn supports_frozen_charge(&self) -> bool {
        self.iter().all(FrozenCacheState::supports_frozen_charge)
    }
}

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
    // Validated once at admission; private retained state is immutable until
    // take transfers it out. Reinsertion always measures the mutated graph.
    heap_bytes: usize,
    modified_hint: (i64, i64),
    /// The finalization copy's charge reserved beside this entry at its
    /// admission (P1-RETAIN R0, Q-PR13(iii) β). Inline; it charges no heap.
    finalization_charge: usize,
    /// Read eligibility only, owned by this resident and lost on take. Never
    /// persisted or exposed to delivery/census authority readers. The B-tree
    /// node layout charges this inline flag, including any padding.
    e2_held_new_file: bool,
}
impl<S: HeapLayoutBound> HeapLayoutBound for Entry<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            retained: _,
            used: _,
            heap_bytes,
            modified_hint: _,
            finalization_charge: _,
            e2_held_new_file: _,
        } = self;
        c.add(*heap_bytes)
    }
}

/// Why `release_until_for` evicts; each cause keeps its own content-free
/// counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Release {
    /// Room for a paused cursor job's admission (K6).
    CursorReservation,
    /// A copy refusal fitting the residents beside the active file (M1).
    CopyRefusal,
    /// Room for a tail's own copy, from entries ranked strictly older than
    /// the tailed file only: a non-F tail's zero-budget step start (M1 Path
    /// A), and a shape-F completion's exact prefix ranked below its copy's
    /// re-admission rank after every non-budget gate (P1-RETAIN R0, through
    /// the same `release_older_until`).
    CopyAdmission,
}

/// A retained copy moved out of the cache, with the admission facts the
/// caller's completion needs (P1-RETAIN R0).
pub(crate) struct Taken<S> {
    pub(crate) retained: Retained<S>,
    /// The entry's victim-order hint as admitted: the source mtime, clipped
    /// to admission time.
    pub(crate) modified_hint: (i64, i64),
    /// The finalization charge reserved beside the entry at its admission.
    pub(crate) finalization_charge: usize,
    pub(crate) e2_held_new_file: bool,
}

/// The victim-order hint an entry modified at `modified` is admitted at,
/// at `now`: future source timestamps are clipped to admission time, so they
/// cannot rank an entry ahead of later live work. Every admission ranks
/// through this; P1-RETAIN R0 ranks a completed copy once with it and carries
/// that value to its release and its insert.
pub(crate) fn admission_rank(modified: (i64, i64), now: std::time::Duration) -> (i64, i64) {
    modified.min((
        i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        i64::from(now.subsec_nanos()),
    ))
}

/// The wall clock an admission ranks against (`admission_rank`).
pub(crate) fn admission_now() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

/// Exactly what one entry under a key of `key_capacity` adds to the cache's
/// bound beyond its own `heap_bytes`, and exactly what removing it frees
/// beyond them: one B-tree node (`tree_nodes` charges `(len + 1)` nodes,
/// linear in `len`) plus the key's heap. `Entry` (inline in the node) stays
/// private.
pub(crate) fn entry_slot_bytes<S>(key_capacity: usize) -> Option<usize> {
    heap_layout_bound::tree_node_bytes::<String, Entry<S>>()?.checked_add(key_capacity)
}

/// The inline bytes `Entry` adds around a retained state and its checkpoint.
/// The insert's entry bound charges them; a caller's own admission does not.
pub(crate) fn entry_overhead<S>() -> usize {
    std::mem::size_of::<Entry<S>>()
        .saturating_sub(std::mem::size_of::<S>() + std::mem::size_of::<Checkpoint>())
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
impl<S: FrozenCacheState> Default for TranscriptCache<S> {
    fn default() -> Self {
        Self::new(CACHE_BYTES, ENTRY_BYTES, CACHE_ENTRIES)
    }
}
impl<S: FrozenCacheState> TranscriptCache<S> {
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
    pub(crate) fn take(&mut self, key: &str) -> Option<Taken<S>> {
        let taken = self.entries.remove(key).map(|entry| Taken {
            retained: entry.retained,
            modified_hint: entry.modified_hint,
            finalization_charge: entry.finalization_charge,
            e2_held_new_file: entry.e2_held_new_file,
        });
        record(if taken.is_some() {
            Event::TakeHit
        } else {
            Event::TakeAbsent
        });
        taken
    }
    /// Allocation-free update of inline eligibility on existing residents.
    /// `None` leaves an unvisited resident alone; no new registry or entry.
    pub(crate) fn update_e2_held(&mut self, mut update: impl FnMut(&str) -> Option<bool>) {
        for (key, entry) in &mut self.entries {
            if let Some(held) = update(key) {
                entry.e2_held_new_file = held;
            }
        }
    }
    pub(crate) fn clear(&mut self) {
        add(Event::ClearEntriesReleased, self.entries.len() as u64);
        self.entries.clear();
    }
    /// Evict in admission victim order (oldest source, then least recently
    /// used) until the resident state fits `limit`. False when even an empty
    /// cache does not fit. The cursor makes room for a paused job this way.
    pub(crate) fn release_until(&mut self, limit: usize) -> bool {
        self.release_until_for(limit, Release::CursorReservation)
    }
    /// `release_until`, counting each eviction under `cause`.
    pub(crate) fn release_until_for(&mut self, limit: usize, cause: Release) -> bool {
        self.evict_until(limit, cause, None)
    }
    /// M1 Path A: `release_until_for` restricted to entries ranked strictly
    /// below `rank` (their `modified_hint`), in the same victim order, counted
    /// under `Release::CopyAdmission`. Evicts nothing, and returns false,
    /// unless evicting all of them fits `limit` by their stored `heap_bytes`
    /// alone, a lower bound on what each eviction frees.
    pub(crate) fn release_older_until(&mut self, limit: usize, rank: (i64, i64)) -> bool {
        self.older_release_fits(limit, rank)
            && self.evict_until(limit, Release::CopyAdmission, Some(rank))
    }
    /// `release_older_until`'s fit-or-nothing test, evicting nothing: the
    /// cache fits `limit` already, or evicting every entry ranked strictly
    /// below `rank` fits it by their stored `heap_bytes` alone (U1a-2a
    /// D6(e): a suspended proof is retired only where Path A can fit).
    pub(crate) fn older_release_fits(&self, limit: usize, rank: (i64, i64)) -> bool {
        if heap_layout_bound::bound(self, limit).is_some() {
            return true;
        }
        let older = self
            .entries
            .values()
            .filter(|entry| entry.modified_hint < rank)
            .fold(0usize, |sum, entry| sum.saturating_add(entry.heap_bytes));
        heap_layout_bound::bound(self, usize::MAX)
            .is_some_and(|resident| resident.saturating_sub(older) <= limit)
    }
    /// M-a's churn bound: `release_older_until`, refusing (evicting nothing)
    /// unless at most `max_victims` entries ranked strictly below `rank` fit
    /// `limit` by their stored `heap_bytes` (`older_prefix_len`). The exact
    /// eviction stops at the first fit, so it never evicts more than that.
    pub(crate) fn release_older_until_at_most(
        &mut self,
        limit: usize,
        rank: (i64, i64),
        max_victims: usize,
    ) -> bool {
        self.older_prefix_len(limit, rank)
            .is_some_and(|victims| victims <= max_victims)
            && self.evict_until(limit, Release::CopyAdmission, Some(rank))
    }
    /// How many entries ranked strictly below `rank`, taken in victim order,
    /// fit `limit` by their stored `heap_bytes` alone: `Some(0)` when the
    /// cache fits already, `None` when all of them do not. Allocation-free
    /// (one ordered pass per victim, as `evict_until` selects them).
    pub(crate) fn older_prefix_len(&self, limit: usize, rank: (i64, i64)) -> Option<usize> {
        if heap_layout_bound::bound(self, limit).is_some() {
            return Some(0);
        }
        let mut resident = heap_layout_bound::bound(self, usize::MAX)?;
        let mut last = None;
        let mut victims = 0usize;
        while resident > limit {
            let (order, entry) = self
                .entries
                .values()
                .filter(|entry| entry.modified_hint < rank)
                .map(|entry| ((entry.modified_hint, entry.used), entry))
                .filter(|(order, _)| last.map_or(true, |last| *order > last))
                .min_by_key(|(order, _)| *order)?;
            resident = resident.saturating_sub(entry.heap_bytes);
            last = Some(order);
            victims = victims.checked_add(1)?;
        }
        Some(victims)
    }
    /// Evict in victim order, only entries ranked strictly below `below`
    /// when given, until the resident state fits `limit`.
    fn evict_until(&mut self, limit: usize, cause: Release, below: Option<(i64, i64)>) -> bool {
        loop {
            if heap_layout_bound::bound(self, limit).is_some() {
                return true;
            }
            let Some(victim) = self
                .entries
                .iter()
                .filter(|(_, entry)| below.map_or(true, |rank| entry.modified_hint < rank))
                .min_by_key(|(_, entry)| (entry.modified_hint, entry.used))
                .map(|(key, _)| key.clone())
            else {
                return false;
            };
            let Some(entry) = self.entries.remove(&victim) else {
                return false;
            };
            match cause {
                Release::CursorReservation => record(Event::CursorReservationEntriesEvicted),
                Release::CopyRefusal => {
                    record(Event::CopyRefusalEntriesEvicted);
                    add(Event::CopyRefusalBytesReleased, entry.heap_bytes as u64);
                }
                Release::CopyAdmission => {
                    record(Event::CopyRefusalAdmissionEvicted);
                    add(Event::CopyRefusalBytesReleased, entry.heap_bytes as u64);
                }
            }
        }
    }
    /// Resident entries (tests only).
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }
    /// Sealed offset of a retained entry without taking it, so a page budget
    /// can plan a tail read before the frame consumes retained state.
    pub(crate) fn sealed_offset(&self, key: &str) -> Option<u64> {
        self.entries
            .get(key)
            .map(|entry| entry.retained.checkpoint.sealed_offset())
    }
    /// A retained entry without taking it (M1 durable write after an index
    /// save encodes it in place under the retained lock).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn peek(&self, key: &str) -> Option<&Retained<S>> {
        self.entries.get(key).map(|entry| &entry.retained)
    }
    #[cfg(test)]
    pub(crate) fn checkpoint(&self, key: &str) -> Option<Checkpoint> {
        self.entries
            .get(key)
            .map(|entry| entry.retained.checkpoint.clone())
    }
    /// Resident keys in victim order, with each admitted hint and the exact
    /// bytes its removal frees.
    #[cfg(test)]
    pub(crate) fn victims(&self) -> Vec<(String, (i64, i64), usize)> {
        let mut order = self
            .entries
            .iter()
            .map(|(key, entry)| {
                let freed = entry_slot_bytes::<S>(key.capacity()).unwrap() + entry.heap_bytes;
                ((entry.modified_hint, entry.used), key.clone(), freed)
            })
            .collect::<Vec<_>>();
        order.sort_unstable_by_key(|(rank, _, _)| *rank);
        order
            .into_iter()
            .map(|((hint, _), key, freed)| (key, hint, freed))
            .collect()
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
        self.insert_reserving(key, retained, 0, 0)
    }
    /// `live_bytes` is an actual checked native-layout charge, not file size.
    /// Native output/active copies keep this room while entries are admitted.
    /// `finalization_charge` (within `live_bytes`) is this entry's own
    /// finalization copy, carried to its next take (P1-RETAIN β). Production
    /// admits through `insert_reserving_at_rank`.
    #[cfg(test)]
    pub(crate) fn insert_reserving(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        finalization_charge: usize,
    ) -> bool {
        self.insert_reserving_at_rank(key, retained, live_bytes, finalization_charge, None)
    }
    /// `insert_reserving`, admitting the entry at `rank` when one was computed
    /// before (P1-RETAIN R0: the rank its completion's release ran against,
    /// `admission_rank` of this checkpoint's mtime), so the entry's hint is
    /// exactly the one its release ranked residents against and no later clock
    /// read moves it. `None` ranks it now, as every other admission does.
    pub(crate) fn insert_reserving_at_rank(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        finalization_charge: usize,
        rank: Option<(i64, i64)>,
    ) -> bool {
        match rank {
            Some(rank) => self.admit_at_rank(key, retained, live_bytes, finalization_charge, rank),
            None => self.admit(
                key,
                retained,
                live_bytes,
                finalization_charge,
                admission_now(),
            ),
        }
    }
    #[cfg(test)]
    fn insert_at(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        now: std::time::Duration,
    ) -> bool {
        self.admit(key, retained, live_bytes, 0, now)
    }
    /// `live_bytes` is the whole reservation kept beside the entries;
    /// `finalization_charge` is the part of it owned by this entry's own
    /// finalization copy, kept on the entry for its next take (β).
    fn admit(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        finalization_charge: usize,
        now: std::time::Duration,
    ) -> bool {
        let rank = admission_rank(retained.checkpoint.modified_hint(), now);
        self.admit_at_rank(key, retained, live_bytes, finalization_charge, rank)
    }
    /// Read-only admission preflight: the same entry/key/layout gates and
    /// victim rank as `admit_at_rank`. With `victims`, count only residents
    /// that outlive the incoming entry; equal-rank residents are older uses.
    pub(crate) fn insertion_fits(
        &self,
        key: &String,
        retained: &Retained<S>,
        reserved: usize,
        rank: (i64, i64),
        victims: bool,
    ) -> bool {
        (|| {
            if self.count_limit == 0
                || self.clock == u64::MAX
                || !retained.state.supports_frozen_charge()
            {
                return None;
            }
            let heap = heap_layout_bound::bound(retained, self.entry_limit)?
                .checked_sub(std::mem::size_of_val(retained))?;
            let entry = std::mem::size_of::<Entry<S>>().checked_add(heap)?;
            heap_layout_bound::bound(key, self.entry_limit.checked_sub(entry)?)?;
            let limit = self.byte_limit.checked_sub(reserved)?;
            let mut bytes = heap_layout_bound::bound(&Self::new(0, 0, 0), limit)?
                .checked_add(entry_slot_bytes::<S>(key.capacity())?)?
                .checked_add(heap)?;
            let mut count = 1_usize;
            for (other, entry) in &self.entries {
                if other == key || (victims && entry.modified_hint <= rank) {
                    continue;
                }
                count = count.checked_add(1)?;
                bytes = bytes
                    .checked_add(entry_slot_bytes::<S>(other.capacity())?)?
                    .checked_add(entry.heap_bytes)?;
            }
            // Header eviction can relieve bytes, never retained-entry count.
            ((!victims || count <= self.count_limit) && bytes <= limit).then_some(())
        })()
        .is_some()
    }
    /// `admit` with the entry's victim-order hint already ranked
    /// (`admission_rank`).
    fn admit_at_rank(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        finalization_charge: usize,
        rank: (i64, i64),
    ) -> bool {
        self.entries.remove(&key);
        let Some(resident_limit) = self.byte_limit.checked_sub(live_bytes) else {
            record(Event::InsertLiveReservationRefused);
            return false;
        };
        let Some(next) = self.clock.checked_add(1) else {
            // A safe local reset; no durable debt is owned here. Unreachable
            // in practice (`u64` admissions), but it does clear the cache.
            self.entries.clear();
            self.clock = 0;
            record(Event::InsertClockReset);
            return false;
        };
        // A zero count limit, or a toolchain whose layouts are not validated.
        // Neither evicts; a P1-RETAIN R0 release needs a supported layout, so
        // it never precedes this refusal.
        if self.count_limit == 0 || !heap_layout_bound::layout_supported() {
            record(Event::InsertDisabledOrLayoutRefused);
            return false;
        }
        let Some(heap_bytes) = heap_layout_bound::bound(&retained, self.entry_limit)
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of_val(&retained)))
        else {
            record(Event::InsertEntryBoundRefused);
            return false;
        };
        if !retained.state.supports_frozen_charge() {
            record(Event::InsertFrozenChargeRefused);
            return false;
        }
        // Only the count/byte caps and the victim order below decide
        // residency, never idle age: under pressure, older-modified work loses
        // to newer resident state. Neither decision suppresses a native full
        // read or audit.
        let entry = Entry {
            modified_hint: rank,
            retained,
            used: next,
            heap_bytes,
            finalization_charge,
            e2_held_new_file: false,
        };
        let Some(state_bytes) = heap_layout_bound::bound(&entry, self.entry_limit) else {
            record(Event::InsertEntryBoundRefused);
            return false;
        };
        if heap_layout_bound::bound(&key, self.entry_limit.saturating_sub(state_bytes)).is_none() {
            record(Event::InsertKeyBoundRefused);
            return false;
        }
        self.clock = next;
        self.entries.insert(key.clone(), entry);
        let mut admitted = true;
        loop {
            if self.entries.len() <= self.count_limit
                && heap_layout_bound::bound(self, resident_limit).is_some()
            {
                record(if admitted {
                    Event::InsertAdmitted
                } else {
                    Event::InsertSelfEvicted
                });
                return admitted;
            }
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| (entry.modified_hint, entry.used))
                .map(|(candidate, _)| candidate.clone());
            let Some(victim) = victim else {
                self.entries.remove(&key);
                record(Event::InsertNoVictimRefused);
                return false;
            };
            let count_pressure = self.entries.len() > self.count_limit;
            self.entries.remove(&victim);
            record(Event::InsertEntriesEvicted);
            crate::local_resource_diagnostics::claude_reread::cache_capacity_eviction(
                count_pressure,
            );
            if victim == key {
                // Even a rejected new entry must release enough older state
                // for the caller's live allocation reservation.
                admitted = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux")),
        ignore = "needs macOS heap layout"
    )]
    fn insertion_preflight_matches_real_rank_and_reservation_outcomes() {
        for reserved in [0, 32 * 1024, 96 * 1024, 128 * 1024] {
            for rank in [(9, 0), (10, 0), (20, 0), (30, 0)] {
                let mut cache = TranscriptCache::new(128 * 1024, 8192, 2);
                for (key, rank) in [("old", (10, 0)), ("newer", (20, 0))] {
                    assert!(cache.insert_reserving_at_rank(
                        key.into(),
                        retained("state".into()),
                        0,
                        0,
                        Some(rank)
                    ));
                }
                let incoming = retained("incoming".into());
                let key = String::from("new");
                if reserved == 0 {
                    assert!(
                        cache.insertion_fits(&key, &incoming, reserved, rank, false),
                        "count pressure alone must not evict optional headers"
                    );
                }
                let predicted = cache.insertion_fits(&key, &incoming, reserved, rank, true);
                assert_eq!(
                    predicted,
                    cache.insert_reserving_at_rank(key, incoming, reserved, 0, Some(rank)),
                    "{reserved} {rank:?}"
                );
            }
        }
    }
    #[test]
    fn cache_lifecycle_counts_real_transfers_refusals_and_eviction_causes() {
        use crate::local_resource_diagnostics::cache_lifecycle::observe;
        let (_, counts) = observe(|| {
            let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 2);
            assert!(cache.take("never-retained").is_none());
            if !heap_layout_bound::layout_supported() {
                assert!(!cache.insert("a".into(), retained("a".into())));
                return;
            }
            let at = std::time::Duration::from_secs(100);
            for (key, modified) in [("a", 90), ("b", 80)] {
                assert!(cache.insert_at(
                    key.into(),
                    retained_at(key.into(), Some(modified)),
                    0,
                    at
                ));
            }
            let moved = cache.take("a").unwrap().retained;
            assert_eq!(moved.state, "a");
            assert!(cache.insert_at("a".into(), moved, 0, at));
            assert!(!cache.insert_at("older".into(), retained_at("old".into(), Some(1)), 0, at));
            assert!(cache.insert_at("newer".into(), retained_at("new".into(), Some(95)), 0, at));
            assert!(cache.take("b").is_none());
            assert!(!cache.insert("huge".into(), retained("x".repeat(256 * 1024))));
            assert!(!cache.insert_reserving(
                "no-room".into(),
                retained("x".into()),
                2 * 1024 * 1024,
                0
            ));
            // Cursor reservation still uses the same victim order. Leave room
            // for the empty map; no policy or byte limit is changed.
            let empty = TranscriptCache::<String>::new(1024 * 1024, 128 * 1024, 2);
            let empty_bound = heap_layout_bound::bound(&empty, 1024 * 1024).unwrap();
            assert!(cache.release_until(empty_bound));
            assert!(cache.entries.is_empty());
            assert!(cache.insert("clear".into(), retained("x".into())));
            cache.clear();
            assert!(cache.entries.is_empty());
        });
        assert_eq!(counts.take_poisoned_lock, 0);
        if heap_layout_bound::layout_supported() {
            assert_eq!(counts.take_hit, 1);
            assert_eq!(counts.take_absent, 2);
            assert_eq!(counts.insert_admitted, 5);
            assert_eq!(counts.insert_self_evicted, 1);
            assert_eq!(counts.insert_entries_evicted, 2);
            assert_eq!(counts.cursor_reservation_entries_evicted, 2);
            assert_eq!(counts.insert_entry_bound_refused, 1);
            assert_eq!(counts.insert_live_reservation_refused, 1);
            assert_eq!(counts.clear_entries_released, 1);
        } else {
            assert_eq!(counts.take_absent, 1);
            assert_eq!(counts.insert_disabled_or_layout_refused, 1);
            assert_eq!(counts.insert_admitted, 0);
        }
    }

    #[test]
    fn claude_page_cache_evictions_partition_real_count_and_byte_pressure() {
        use crate::local_resource_diagnostics::claude_reread::Scope;
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let scope = Scope::begin(true);
        let mut count_limited = TranscriptCache::new(1024 * 1024, 128 * 1024, 1);
        assert!(count_limited.insert("a".into(), retained("a".into())));
        assert!(count_limited.insert("b".into(), retained("b".into())));
        assert!(count_limited.take("a").is_none());
        let counts = scope.finish().retained_cache_page_events;
        assert_eq!(counts.events.insert_entries_evicted, 1);
        assert_eq!(counts.insert_count_entries_evicted, 1);
        assert_eq!(counts.insert_byte_entries_evicted, 0);
        let scope = Scope::begin(true);
        let mut byte_limited = TranscriptCache::new(80 * 1024, 40 * 1024, 256);
        for n in 0..20 {
            assert!(byte_limited.insert(n.to_string(), retained("x".repeat(16 * 1024))));
        }
        let counts = scope.finish().retained_cache_page_events;
        assert!(counts.events.insert_entries_evicted > 0);
        assert_eq!(counts.insert_count_entries_evicted, 0);
        assert_eq!(
            counts.insert_byte_entries_evicted,
            counts.events.insert_entries_evicted
        );
        assert_eq!(counts.events.insert_admitted, 20);
    }

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
        retained_at(text, None)
    }
    fn retained_at(text: String, modified: Option<u64>) -> Retained<String> {
        use crate::transcript_acquisition::{ReadPlan, Scope};
        use std::fs::{self, OpenOptions};
        use std::io::{Read, Write};
        // Clock reads can repeat; the counter keeps `create_new` names unique.
        static FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ottto-cache-fixture-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"{}\n").unwrap();
        if let Some(modified) = modified {
            file.set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified)),
            )
            .unwrap();
        }
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
    fn e2_held_eligibility_lives_only_with_resident_and_is_inline_charged() {
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 1);
        if !heap_layout_bound::layout_supported() {
            assert!(!cache.insert("a".into(), retained("private".into())));
            return;
        }
        assert!(cache.insert("a".into(), retained("private".into())));
        let charge = cache.resident_bound().unwrap();
        cache.update_e2_held(|_| Some(true));
        assert_eq!(cache.resident_bound(), Some(charge));
        let taken = cache.take("a").unwrap();
        assert!(taken.e2_held_new_file);
        assert!(cache.take("a").is_none());
        assert!(cache.insert("a".into(), taken.retained));
        assert!(
            !cache.take("a").unwrap().e2_held_new_file,
            "reinsertion never inherits eligibility; finish_page must stamp it anew"
        );
        assert!(cache.insert("a".into(), retained("private".into())));
        cache.update_e2_held(|_| Some(true));
        assert!(cache.insert("b".into(), retained("other".into())));
        assert!(
            cache.take("a").is_none(),
            "count eviction loses eligibility"
        );
        assert!(!cache.take("b").unwrap().e2_held_new_file);
        assert!(cache.insert("a".into(), retained("private".into())));
        cache.update_e2_held(|_| Some(true));
        cache.clear();
        assert!(cache.take("a").is_none());
        assert!(TranscriptCache::<String>::default().take("a").is_none());
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
                live_bytes,
                0
            ));
            assert!(cache.resident_bound().unwrap() + live_bytes + overlap <= CACHE_BYTES);
        }
        assert!(
            cache.entries.len() < 8,
            "admission evicts instead of consuming live/overlap reservation"
        );
        assert!(!cache.insert_reserving(
            "no-room".into(),
            retained("x".into()),
            33 * 1024 * 1024,
            0
        ));
    }
    #[test]
    fn sampled_cache_frozen_charges_survive_aggregate_walk_pressure_and_remeasure_mutation() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let mut cache = TranscriptCache::new(8 * 1024 * 1024, 512 * 1024, 32);
        for n in 0..24 {
            let checkpoint = retained("synthetic".into()).checkpoint;
            let state = vec![String::from("synthetic"); 1024];
            let expected = heap_layout_bound::bound(&state, 512 * 1024).unwrap();
            assert!(cache.insert(n.to_string(), Retained { checkpoint, state }));
            assert!(cache.resident_bound().unwrap() >= expected * (n + 1));
        }
        assert_eq!(cache.entries.len(), 24);
        let mut moved = cache.take("0").unwrap().retained;
        assert_eq!(cache.entries.len(), 23);
        moved.state[0].reserve(1024 * 1024);
        assert!(!cache.insert("0".into(), moved));
        assert!(cache.take("0").is_none());
        assert_eq!(cache.entries.len(), 23);
        cache.clear();
        assert!(cache.entries.is_empty());
        assert!(cache.resident_bound().unwrap() < 64 * 1024);
    }
    #[test]
    fn sampled_cache_idle_reuse_pressure_and_ambiguous_time_are_bounded() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 2);
        let at = |n| std::time::Duration::from_secs(n);
        assert!(cache.insert_at(
            "recent".into(),
            retained_at("x".into(), Some(90)),
            0,
            at(100)
        ));
        assert!(cache.insert_at("old".into(), retained_at("x".into(), Some(10)), 0, at(100)));
        assert!(!cache.insert_at("older".into(), retained_at("x".into(), Some(1)), 0, at(100)));
        assert!(cache.take("recent").is_some());
        // Equal/future timestamps fall back to finite admission order. A
        // future timestamp is clipped once, and cannot block a later live file.
        cache.clear();
        for key in ["a", "b", "c"] {
            assert!(cache.insert_at(
                key.into(),
                retained_at("x".into(), Some(999999)),
                0,
                at(100)
            ));
        }
        assert!(cache.take("a").is_none());
        assert!(cache.insert_at(
            "live".into(),
            retained_at("x".into(), Some(101)),
            0,
            at(101)
        ));
        assert!(cache.take("live").is_some());
        // Idle age drops nothing: admissions 2h and 5h later leave reusable
        // state in place. Capacity and the victim order still decide.
        assert!(cache.insert_at(
            "live".into(),
            retained_at("x".into(), Some(101)),
            0,
            at(101)
        ));
        // Backdated work is the oldest candidate at the count cap: it is
        // refused instead of displacing newer idle state.
        assert!(!cache.insert_at(
            "backdated".into(),
            retained_at("x".into(), Some(1)),
            0,
            at(101 + 2 * 3600)
        ));
        assert!(cache.take("backdated").is_none());
        assert_eq!(cache.entries.len(), 2);
        // Newer work still evicts the oldest resident, not the idle entry.
        let five_hours = 101 + 5 * 3600;
        assert!(cache.insert_at(
            "newer".into(),
            retained_at("x".into(), Some(five_hours)),
            0,
            at(five_hours)
        ));
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.take("c").is_none());
        assert!(cache.take("live").is_some());
        let mut restarted = TranscriptCache::<String>::default();
        assert!(restarted.take("backdated").is_none());
    }
    #[test]
    fn sampled_cache_rejected_old_admission_still_releases_live_reservation() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let mut cache = TranscriptCache::new(128 * 1024, 64 * 1024, 8);
        let at = std::time::Duration::from_secs(100);
        for (key, modified) in [("a", 90), ("b", 80)] {
            assert!(cache.insert_at(
                key.into(),
                retained_at("x".repeat(32 * 1024), Some(modified)),
                0,
                at
            ));
        }
        assert!(!cache.insert_at(
            "older".into(),
            retained_at("x".into(), Some(1)),
            120 * 1024,
            at
        ));
        assert!(cache.resident_bound().unwrap() + 120 * 1024 <= 128 * 1024);
        assert!(cache.take("older").is_none());
    }
    #[test]
    fn sampled_cache_adapter_refuses_externally_mutable_charge() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        struct Shared {
            value: std::sync::Arc<std::sync::Mutex<String>>,
        }
        crate::heap_layout_bound::fields!(Shared; value);
        impl FrozenCacheState for Shared {
            fn supports_frozen_charge(&self) -> bool {
                false
            }
        }
        let value = std::sync::Arc::new(std::sync::Mutex::new(String::from("synthetic")));
        let state = Shared {
            value: value.clone(),
        };
        assert!(heap_layout_bound::bound(&state, ENTRY_BYTES).is_some());
        let mut cache = TranscriptCache::default();
        assert!(!cache.insert(
            "shared".into(),
            Retained {
                checkpoint: retained("x".into()).checkpoint,
                state
            }
        ));
        value.lock().unwrap().reserve(1024 * 1024);
        assert!(cache.take("shared").is_none());
    }

    /// P1-RETAIN R0: `entry_slot_bytes` is exactly what one entry adds to the
    /// cache's bound beyond its `heap_bytes`, and what removing it frees.
    #[test]
    fn entry_slot_bytes_equals_the_measured_bound_delta_of_one_insert_and_one_remove() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let at = std::time::Duration::from_secs(100);
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 8);
        assert!(cache.insert_at("resident".into(), retained_at("r".into(), Some(10)), 0, at));
        for key in ["k", "a-much-longer-key-with-more-heap"] {
            let before = cache.resident_bound().unwrap();
            let key = String::from(key);
            let capacity = key.capacity();
            assert!(cache.insert_at(key.clone(), retained_at("x".repeat(300), Some(20)), 0, at));
            let heap_bytes = cache.entries[&key].heap_bytes;
            let slot = entry_slot_bytes::<String>(capacity).unwrap();
            let after = cache.resident_bound().unwrap();
            assert_eq!(after - before, slot + heap_bytes, "insert {key}");
            cache.remove(&key);
            assert_eq!(cache.resident_bound().unwrap(), before, "remove {key}");
        }
        assert!(entry_overhead::<String>() > 0);
        assert_eq!(
            entry_overhead::<String>(),
            std::mem::size_of::<Entry<String>>()
                - std::mem::size_of::<String>()
                - std::mem::size_of::<Checkpoint>()
        );
    }

    /// P1-RETAIN R0 releases through M1's `release_older_until` (c22 integ1
    /// ruling 6): only entries ranked strictly below the rank leave, in victim
    /// order, the shortest prefix that fits; an unreachable fit evicts
    /// nothing; equal and newer hints never leave.
    #[test]
    fn release_older_until_is_fit_or_nothing_and_strictly_older() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let at = std::time::Duration::from_secs(100);
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 8);
        for (key, modified) in [("old", 10), ("mid", 20), ("same", 30), ("new", 40)] {
            assert!(cache.insert_at(
                key.into(),
                retained_at(key.repeat(5_000), Some(modified)),
                0,
                at
            ));
        }
        let freed = |key: &str| {
            entry_slot_bytes::<String>(key.len()).unwrap() + cache.entries[key].heap_bytes
        };
        let (old, mid) = (freed("old"), freed("mid"));
        let hint = cache.entries["same"].modified_hint;
        assert_eq!(hint, (30, 0));
        let resident = cache.resident_bound().unwrap();
        // Already fitting evicts nothing.
        assert!(cache.older_release_fits(resident, hint));
        // `same` and `new` are never candidates: an unreachable fit evicts
        // nothing.
        let unreachable = resident - old - mid - 1;
        assert!(!cache.older_release_fits(unreachable, hint));
        assert!(!cache.release_older_until(unreachable, hint));
        assert_eq!(cache.resident_bound().unwrap(), resident);
        assert_eq!(cache.entry_count(), 4);
        // The release frees exactly the shortest prefix, under `CopyAdmission`.
        let (_, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            assert!(cache.release_older_until(resident - old - 1, hint));
        });
        assert_eq!(counts.copy_refusal_admission_evicted, 2);
        assert!(counts.copy_refusal_bytes_released > 0);
        assert_eq!(counts.insert_entries_evicted, 0);
        assert_eq!(counts.cursor_reservation_entries_evicted, 0);
        assert_eq!(cache.resident_bound().unwrap(), resident - old - mid);
        assert!(cache.entries.contains_key("same") && cache.entries.contains_key("new"));
    }

    /// Every admission ranks through `admission_rank` (a future mtime clips to
    /// the admission clock); a rank computed before (P1-RETAIN R0, the rank
    /// its release ran against) is admitted exactly, never re-ranked by a
    /// later clock read.
    #[test]
    fn admission_rank_clips_once_and_a_carried_rank_is_admitted_exactly() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let at = std::time::Duration::from_secs(100);
        assert_eq!(admission_rank((500, 7), at), (100, 0));
        assert_eq!(admission_rank((50, 7), at), (50, 7));
        assert_eq!(admission_rank((100, 0), at), (100, 0));
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 8);
        assert!(cache.insert_reserving_at_rank(
            "carried".into(),
            retained_at("c".into(), Some(500)),
            0,
            0,
            Some((90, 0))
        ));
        assert_eq!(cache.entries["carried"].modified_hint, (90, 0));
        assert!(cache.insert_reserving_at_rank(
            "ranked".into(),
            retained_at("r".into(), Some(50)),
            0,
            0,
            None
        ));
        assert_eq!(cache.entries["ranked"].modified_hint, (50, 0));
    }

    /// `Taken` carries the clipped admitted hint and the reserved finalization
    /// charge (β).
    #[test]
    fn take_carries_the_clipped_admission_hint_and_finalization_charge() {
        if !heap_layout_bound::layout_supported() {
            return;
        }
        let at = std::time::Duration::from_secs(100);
        let mut cache = TranscriptCache::new(1024 * 1024, 128 * 1024, 8);
        assert!(cache.admit(
            "future".into(),
            retained_at("f".into(), Some(500)),
            4096,
            4096,
            at
        ));
        assert!(cache.insert_at("past".into(), retained_at("p".into(), Some(50)), 0, at));
        let future = cache.take("future").unwrap();
        assert_eq!(future.modified_hint, (100, 0), "clipped to admission time");
        assert_eq!(future.finalization_charge, 4096);
        let past = cache.take("past").unwrap();
        assert_eq!(past.modified_hint, (50, 0));
        assert_eq!(past.finalization_charge, 0);
    }
}
