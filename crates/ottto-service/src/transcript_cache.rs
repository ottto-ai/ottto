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
    pub(crate) durable: crate::snapshots::DurableCustody,
    pub(crate) retained: Retained<S>,
    /// The entry's victim-order hint as admitted: the source mtime, clipped
    /// to admission time.
    pub(crate) modified_hint: (i64, i64),
    /// The finalization charge reserved beside the entry at its admission.
    pub(crate) finalization_charge: usize,
    pub(crate) e2_held_new_file: bool,
}

impl<S: HeapLayoutBound> HeapLayoutBound for Taken<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            retained,
            durable,
            modified_hint: _,
            finalization_charge: _,
            e2_held_new_file: _,
        } = self;
        retained.heap_bound(c)?;
        durable.heap_bound(c)
    }
}

// Preserve the caller's storage as well as its state on refusal. Ordinary
// optional-copy admission stays inline; the lossless caller keeps its box.
pub(crate) trait Incoming<S>: std::borrow::Borrow<Taken<S>> {
    fn into_taken(self) -> Taken<S>;
}
impl<S> Incoming<S> for Taken<S> {
    fn into_taken(self) -> Taken<S> {
        self
    }
}
impl<S> Incoming<S> for Box<Taken<S>> {
    fn into_taken(self) -> Taken<S> {
        *self
    }
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
    #[expect(
        clippy::box_collection,
        reason = "OFF allocates no custody map and retains the predecessor cache root size"
    )]
    custody: Option<Box<BTreeMap<String, Box<crate::snapshots::DurableCustody>>>>,
    clock: u64,
    byte_limit: usize,
    // Fixed cache caps fit u32; packing them preserves main's root layout
    // while the optional ON-only custody map lives outside entry nodes.
    entry_limit: u32,
    count_limit: u32,
}
impl<S: HeapLayoutBound> HeapLayoutBound for TranscriptCache<S> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            entries,
            custody,
            clock,
            byte_limit,
            entry_limit,
            count_limit,
        } = self;
        entries.heap_bound(c)?;
        custody.heap_bound(c)?;
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
            custody: None,
            clock: 0,
            byte_limit,
            entry_limit: u32::try_from(entry_limit).expect("fixed cache entry limit"),
            count_limit: u32::try_from(count_limit).expect("fixed cache count limit"),
        }
    }
    pub(crate) fn with_byte_limit(byte_limit: usize) -> Self {
        Self::new(byte_limit, ENTRY_BYTES, CACHE_ENTRIES)
    }
    fn remove_custody(&mut self, key: &str) -> crate::snapshots::DurableCustody {
        let value = self.custody.as_mut().and_then(|map| map.remove(key));
        if self.custody.as_ref().is_some_and(|map| map.is_empty()) {
            self.custody = None;
        }
        value.map_or_else(Default::default, |value| *value)
    }
    fn custody_entry_bytes(key: &String, bytes: usize) -> Option<usize> {
        if bytes == 0 {
            return Some(0);
        }
        heap_layout_bound::tree_node_bytes::<String, Box<crate::snapshots::DurableCustody>>()?
            .checked_add(key.capacity())?
            .checked_add(bytes)
    }
    fn custody_root_bytes() -> Option<usize> {
        type Map = BTreeMap<String, Box<crate::snapshots::DurableCustody>>;
        heap_layout_bound::tree_node_bytes::<String, Box<crate::snapshots::DurableCustody>>()?
            .checked_add(std::mem::size_of::<Map>() + std::mem::align_of::<Map>())
    }
    pub(crate) fn custody_extra(&self, key: &String, bytes: usize) -> Option<usize> {
        let entry = Self::custody_entry_bytes(key, bytes)?;
        if bytes > 0 && self.custody.is_none() {
            entry.checked_add(Self::custody_root_bytes()?)
        } else {
            Some(entry)
        }
    }

    /// Moves state into the existing active frame: there is no cached duplicate
    /// while the provider mutates it. The active frame must count this allocation
    /// through its own existing HeapLayoutBound admission.
    pub(crate) fn take(&mut self, key: &str) -> Option<Taken<S>> {
        let taken = self.entries.remove(key).map(|entry| Taken {
            durable: self.remove_custody(key),
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
        self.custody = None;
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
            self.remove_custody(&victim);
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
    /// The same resident's acquisition provenance, borrowed under this cache guard.
    pub(crate) fn custody(&self, key: &str) -> Option<&crate::snapshots::DurableCustody> {
        self.custody.as_ref()?.get(key).map(Box::as_ref)
    }
    /// Borrow resident keys under the existing retained lock (at most CACHE_ENTRIES).
    pub(crate) fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
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
        self.remove_custody(key);
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
    /// admits through the lossless `insert_taken_reserving` primitive.
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
    #[cfg(test)]
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
    #[cfg(test)]
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
        custody_bytes: usize,
        reserved: usize,
        rank: (i64, i64),
        victims: bool,
    ) -> bool {
        (|| {
            if (self.count_limit as usize) == 0
                || self.clock == u64::MAX
                || !retained.state.supports_frozen_charge()
            {
                return None;
            }
            let heap = heap_layout_bound::bound(retained, self.entry_limit as usize)?
                .checked_sub(std::mem::size_of_val(retained))?;
            let entry = std::mem::size_of::<Entry<S>>()
                .checked_add(heap)?
                .checked_add(custody_bytes)?;
            heap_layout_bound::bound(key, (self.entry_limit as usize).checked_sub(entry)?)?;
            let limit = self.byte_limit.checked_sub(reserved)?;
            let mut bytes = heap_layout_bound::bound(&Self::new(0, 0, 0), limit)?
                .checked_add(entry_slot_bytes::<S>(key.capacity())?)?
                .checked_add(heap)?
                .checked_add(custody_bytes)?;
            let mut custody_count = usize::from(custody_bytes > 0);
            let mut custody_charge = Self::custody_entry_bytes(key, custody_bytes)?;
            let mut count = 1_usize;
            for (other, entry) in &self.entries {
                if other == key || (victims && entry.modified_hint <= rank) {
                    continue;
                }
                count = count.checked_add(1)?;
                let other_custody = self
                    .custody(other)
                    .map_or(Some(0), |c| c.retained_bytes(limit))?;
                custody_count += usize::from(other_custody > 0);
                custody_charge =
                    custody_charge.checked_add(Self::custody_entry_bytes(other, other_custody)?)?;
                bytes = bytes
                    .checked_add(entry_slot_bytes::<S>(other.capacity())?)?
                    .checked_add(entry.heap_bytes)?;
            }
            // The cache root already includes the optional map pointer.
            bytes = bytes
                .checked_sub(custody_bytes)?
                .checked_add(custody_charge)?;
            if custody_count > 0 {
                bytes = bytes.checked_add(Self::custody_root_bytes()?)?;
            }
            // Header eviction can relieve bytes, never retained-entry count.
            ((!victims || count <= (self.count_limit as usize)) && bytes <= limit).then_some(())
        })()
        .is_some()
    }
    /// `admit` with the entry's victim-order hint already ranked
    /// (`admission_rank`).
    #[cfg(test)]
    fn admit_at_rank(
        &mut self,
        key: String,
        retained: Retained<S>,
        live_bytes: usize,
        finalization_charge: usize,
        rank: (i64, i64),
    ) -> bool {
        let taken = Taken {
            retained,
            durable: Default::default(),
            modified_hint: rank,
            finalization_charge,
            e2_held_new_file: false,
        };
        // Ordinary optional-copy refusals have no acquisition custody.
        self.insert_taken_reserving(key, taken, live_bytes).is_ok()
    }
    /// Validate and choose victims while borrowing the original. A virtual
    /// self-eviction returns the same box; it never destroys incoming custody.
    pub(crate) fn insert_taken_reserving<I: Incoming<S>>(
        &mut self,
        key: String,
        incoming: I,
        live_bytes: usize,
    ) -> Result<(), I> {
        self.entries.remove(&key);
        self.remove_custody(&key);
        let taken: &Taken<S> = incoming.borrow();
        let refuse = |event, taken| {
            record(event);
            Err(taken)
        };
        let Some(resident_limit) = self.byte_limit.checked_sub(live_bytes) else {
            return refuse(Event::InsertLiveReservationRefused, incoming);
        };
        let Some(next) = self.clock.checked_add(1) else {
            self.entries.clear();
            self.custody = None;
            self.clock = 0;
            return refuse(Event::InsertClockReset, incoming);
        };
        if (self.count_limit as usize) == 0 || !heap_layout_bound::layout_supported() {
            return refuse(Event::InsertDisabledOrLayoutRefused, incoming);
        }
        let Some(heap_bytes) = heap_layout_bound::bound(&taken.retained, self.entry_limit as usize)
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of_val(&taken.retained)))
        else {
            return refuse(Event::InsertEntryBoundRefused, incoming);
        };
        if !taken.retained.state.supports_frozen_charge() {
            return refuse(Event::InsertFrozenChargeRefused, incoming);
        }
        let custody_bytes = taken.durable.retained_bytes(self.entry_limit as usize);
        let state_bytes = custody_bytes.and_then(|bytes| {
            std::mem::size_of::<Entry<S>>()
                .checked_add(heap_bytes)?
                .checked_add(bytes)
        });
        let Some(state_bytes) = state_bytes.filter(|n| *n <= (self.entry_limit as usize)) else {
            return refuse(Event::InsertEntryBoundRefused, incoming);
        };
        if heap_layout_bound::bound(&key, self.entry_limit as usize - state_bytes).is_none() {
            return refuse(Event::InsertKeyBoundRefused, incoming);
        }
        self.clock = next;
        let mut admitted = true;
        loop {
            let extra = entry_slot_bytes::<S>(key.len())
                .and_then(|n| n.checked_add(heap_bytes))
                .and_then(|n| n.checked_add(self.custody_extra(&key, custody_bytes?)?));
            let fits = self.entries.len() + usize::from(admitted) <= (self.count_limit as usize)
                && heap_layout_bound::bound(self, usize::MAX)
                    .and_then(|n| n.checked_add(if admitted { extra? } else { 0 }))
                    .is_some_and(|n| n <= resident_limit);
            if fits {
                break;
            }
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| (entry.modified_hint, entry.used));
            let own = admitted
                && victim.map_or(true, |(_, entry)| {
                    (taken.modified_hint, next) < (entry.modified_hint, entry.used)
                });
            let count_pressure =
                self.entries.len() + usize::from(admitted) > (self.count_limit as usize);
            if own {
                admitted = false;
            } else if let Some((victim, _)) = victim {
                let victim = victim.clone();
                self.entries.remove(&victim);
                self.remove_custody(&victim);
            } else {
                return refuse(Event::InsertNoVictimRefused, incoming);
            }
            record(Event::InsertEntriesEvicted);
            crate::local_resource_diagnostics::claude_reread::cache_capacity_eviction(
                count_pressure,
            );
        }
        if !admitted {
            return refuse(Event::InsertSelfEvicted, incoming);
        }
        let Taken {
            retained,
            durable,
            modified_hint,
            finalization_charge,
            e2_held_new_file,
        } = incoming.into_taken();
        self.entries.insert(
            key.clone(),
            Entry {
                retained,
                modified_hint,
                finalization_charge,
                e2_held_new_file,
                used: next,
                heap_bytes,
            },
        );
        if !durable.is_empty() {
            self.custody
                .get_or_insert_with(Default::default)
                .insert(key, Box::new(durable));
        }
        record(Event::InsertAdmitted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [money] attached retail guard survives virtual self eviction and real admission.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(not(target_os = "macos"), ignore = "validated native cache layout")]
    fn attached_retail_guard_survives_virtual_self_eviction_and_real_admission() {
        let _on = crate::snapshots::RestartRestoreForTest::enabled();
        use crate::snapshots::{sampled_scan::SharedCache, SnapshotSource};
        use crate::transcript_acquisition::{ReadPlan, Scope};
        assert!(heap_layout_bound::layout_supported());
        let root = crate::test_scratch::ScratchDir::new("cache-retail-original");
        let path = root.join("synthetic.jsonl");
        std::fs::write(&path, b"{}\n").unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let scope = Scope("cache-retail".into());
        let mut plan = ReadPlan::prepare(&mut file, None, &scope, None, 100).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
        assert_eq!(bytes, b"{}\n");
        plan.observe_complete_records(&bytes).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&file, &scope, 100)
            .unwrap();
        let owner = SharedCache::default();
        let guard = owner
            .begin_retail(
                SnapshotSource::ClaudeCode,
                "synthetic",
                &checkpoint,
                &file,
                3,
                std::time::Instant::now(),
            )
            .unwrap();
        let mut taken: Box<Taken<String>> = Box::new(Taken {
            retained: Retained {
                checkpoint,
                state: "guarded graph".into(),
            },
            durable: Default::default(),
            modified_hint: (17, 19),
            finalization_charge: 23,
            e2_held_new_file: true,
        });
        taken.durable.put_retail(guard);
        let pointer = &*taken as *const _ as usize;
        let guard_pointer = taken.durable.retail_mut().unwrap() as *mut _ as usize;
        let allocation = taken.retained.state.as_ptr() as usize;
        let mut cache = TranscriptCache::<String>::default();
        cache.byte_limit = heap_layout_bound::bound(&cache, usize::MAX).unwrap();
        let Err(mut returned) = cache.insert_taken_reserving("synthetic".into(), taken, 0) else {
            panic!("virtual self eviction");
        };
        assert_eq!(&*returned as *const _ as usize, pointer);
        assert_eq!(
            returned.durable.retail_mut().unwrap() as *mut _ as usize,
            guard_pointer
        );
        assert_eq!(returned.retained.state.as_ptr() as usize, allocation);
        cache.byte_limit = CACHE_BYTES;
        assert!(cache
            .insert_taken_reserving("synthetic".into(), returned, 0)
            .is_ok());
        let mut admitted = cache.take("synthetic").unwrap();
        assert_eq!(admitted.retained.state.as_ptr() as usize, allocation);
        assert_eq!(admitted.modified_hint, (17, 19));
        assert_eq!(admitted.finalization_charge, 23);
        assert!(admitted.e2_held_new_file);
        admitted
            .durable
            .take_retail()
            .expect("same nonclone guard")
            .finish();
        assert!(admitted.durable.take_retail().is_none());
        let make = |name: &str, rank| {
            let mut next = Box::new(Taken {
                retained: Retained {
                    checkpoint: admitted.retained.checkpoint.clone(),
                    state: "guarded graph".to_string(),
                },
                durable: Default::default(),
                modified_hint: (rank, 0),
                finalization_charge: 0,
                e2_held_new_file: false,
            });
            next.durable.put_retail(
                owner
                    .begin_retail(
                        SnapshotSource::ClaudeCode,
                        name,
                        &next.retained.checkpoint,
                        &file,
                        3,
                        std::time::Instant::now(),
                    )
                    .unwrap(),
            );
            next
        };
        let mut bounded = TranscriptCache::<String>::new(CACHE_BYTES, ENTRY_BYTES, 1);
        assert!(bounded
            .insert_taken_reserving("old".into(), make("old", 1), 0)
            .is_ok());
        bounded.byte_limit = heap_layout_bound::bound(&bounded, usize::MAX).unwrap() - 1;
        let incoming = make("new", 2);
        assert!(
            bounded
                .insert_taken_reserving("new".into(), incoming, 0)
                .is_err(),
            "evicting the last custody node must repay the recreated map root"
        );
        assert!(heap_layout_bound::bound(&bounded, bounded.byte_limit).is_some());
    }

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
                        cache.insertion_fits(&key, &incoming, 0, reserved, rank, false),
                        "count pressure alone must not evict optional headers"
                    );
                }
                let predicted = cache.insertion_fits(&key, &incoming, 0, reserved, rank, true);
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
        // origin/main Entry<String>: Retained + u64 + usize + (i64,i64)
        // + usize + bool, rounded to eight bytes. Cache root: map + four usize.
        let main_entry = std::mem::size_of::<Retained<String>>() + 48;
        assert_eq!(std::mem::size_of::<Entry<String>>(), main_entry);
        assert_eq!(std::mem::size_of::<TranscriptCache<String>>(), 56);
        assert_eq!(
            entry_slot_bytes::<String>(0),
            Some(352 + 11 * (24 + main_entry))
        );
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
}
