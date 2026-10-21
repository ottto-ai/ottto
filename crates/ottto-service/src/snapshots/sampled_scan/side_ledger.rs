//! U1a-2a: the process side-request ledger. It paces Codex parent side
//! requests across failed passes: a charge made in a pass that never saved is
//! still here, so a lost save never buys another read. Scalars only, at most
//! `MAX_SIDE_LEDGER` entries, charged as the fixed `SIDE_LEDGER_BYTES` in
//! `SharedCache::heap_bound` and in every insert reservation, never walked.
//!
//! Authority: for a key with an entry, the entry is the truth; the loaded
//! index request is overwritten with its projection. Only the side charge
//! (G7) creates entries; every other writer updates an existing one.
#![cfg_attr(not(test), allow(dead_code))] // first production callers are C14/C15 and G7

use super::SharedCache;
use crate::local_resource_diagnostics::codex_side_lifecycle::{record, Event};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::path::Path;
use std::sync::MutexGuard;

pub(in crate::snapshots) const MAX_SIDE_LEDGER: usize = 64;
const GATE_SLOTS: usize = 8;
/// Another namespace's unsaved entries may be evicted once its last saved
/// pass is this old (Q-U27 parity: the same as a process start).
const NAMESPACE_IDLE_SECONDS: u64 = 3600;

/// `(MAX_SIDE_LEDGER + 1)` full B-tree nodes: the formula `tree_nodes`
/// charges for a map of `MAX_SIDE_LEDGER` entries (one node per entry plus
/// the root; see `heap_layout_bound::tree_node_bytes`). Entries own no heap.
pub(in crate::snapshots) const SIDE_LEDGER_BYTES: usize = (MAX_SIDE_LEDGER + 1)
    * (256 + 12 * size_of::<usize>() + 11 * (size_of::<LedgerKey>() + size_of::<LedgerEntry>()));
const _: () = assert!(size_of::<LedgerKey>() == 48);
const _: () = assert!(size_of::<LedgerEntry>() <= 96);
const _: () = assert!(size_of::<Option<GateSlot>>() <= 48);

/// A content-free 128-bit name: the first 16 bytes of SHA-256.
fn h128(bytes: &[u8]) -> u128 {
    let digest = Sha256::digest(bytes);
    let mut head = [0_u8; 16];
    head.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(head)
}

/// The namespace of one destination index file. Stable across curve and
/// identity toggles, which change the scan `Scope` but not the index file.
pub(in crate::snapshots) fn namespace_of(index_path: &Path) -> u128 {
    h128(index_path.as_os_str().as_encoded_bytes())
}

/// The ledger name of P's index key.
pub(in crate::snapshots) fn parent_of(p_key: &str) -> u128 {
    h128(p_key.as_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) struct LedgerKey {
    pub(in crate::snapshots) ns: u128,
    pub(in crate::snapshots) p: u128,
    pub(in crate::snapshots) dev: u64,
    pub(in crate::snapshots) ino: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(in crate::snapshots) enum LedgerTag {
    Live,
    Evicted,
    Short,
    Lossy,
    Unsealed,
    /// A covering record removed the request; `stub_not_before` keeps its pace.
    Removed,
    /// The key's generation ended (drop, orphan sweep, replay, replace).
    Gone,
}

/// The request's persisted projection plus the ledger's own bookkeeping.
/// Scalars only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct LedgerEntry {
    pub(in crate::snapshots) tag: LedgerTag,
    pub(in crate::snapshots) attempts: u8,
    /// `SideLedger::pass_seq` of the last write (set by the ledger).
    pub(in crate::snapshots) written_pass: u32,
    /// `Short` only.
    pub(in crate::snapshots) covered: u64,
    pub(in crate::snapshots) needed_extent: u64,
    pub(in crate::snapshots) state_extent: u64,
    pub(in crate::snapshots) state_ctime: (i64, i64),
    pub(in crate::snapshots) attempt_extent: u64,
    pub(in crate::snapshots) attempt_ctime: (i64, i64),
    pub(in crate::snapshots) not_before: u64,
    /// 0 = `None`.
    pub(in crate::snapshots) needed_charge: u64,
    /// `Removed` only.
    pub(in crate::snapshots) stub_not_before: u64,
}

impl LedgerEntry {
    /// The entry for a request's state.
    pub(in crate::snapshots) fn of_request(request: &crate::snapshots::SideRequest) -> Self {
        use crate::snapshots::SideRequestState as State;
        let (tag, covered) = match request.state {
            State::Live => (LedgerTag::Live, 0),
            State::Evicted => (LedgerTag::Evicted, 0),
            State::Short { covered } => (LedgerTag::Short, covered),
            State::Lossy => (LedgerTag::Lossy, 0),
            State::Unsealed => (LedgerTag::Unsealed, 0),
        };
        Self {
            tag,
            attempts: request.attempts,
            written_pass: 0,
            covered,
            needed_extent: request.needed_extent,
            state_extent: request.state_extent,
            state_ctime: request.state_ctime,
            attempt_extent: request.attempt_extent,
            attempt_ctime: request.attempt_ctime,
            not_before: request.not_before_unix_seconds,
            needed_charge: request
                .needed_charge
                .map_or(0, |charge| charge.max(1) as u64),
            stub_not_before: 0,
        }
    }

    /// The request this entry stands for. `Removed` and `Gone` stand for no
    /// request.
    pub(in crate::snapshots) fn request(
        &self,
        dev_ino: (u64, u64),
    ) -> Option<crate::snapshots::SideRequest> {
        use crate::snapshots::SideRequestState as State;
        let state = match self.tag {
            LedgerTag::Live => State::Live,
            LedgerTag::Evicted => State::Evicted,
            LedgerTag::Short => State::Short {
                covered: self.covered,
            },
            LedgerTag::Lossy => State::Lossy,
            LedgerTag::Unsealed => State::Unsealed,
            LedgerTag::Removed | LedgerTag::Gone => return None,
        };
        Some(crate::snapshots::SideRequest {
            dev_ino,
            needed_extent: self.needed_extent,
            state,
            state_extent: self.state_extent,
            state_ctime: self.state_ctime,
            attempt_extent: self.attempt_extent,
            attempt_ctime: self.attempt_ctime,
            attempts: self.attempts,
            not_before_unix_seconds: self.not_before,
            needed_charge: (self.needed_charge > 0)
                .then(|| usize::try_from(self.needed_charge).unwrap_or(usize::MAX)),
        })
    }

    /// Equal persisted projection (every field but the ledger's own
    /// `written_pass` and `stub_not_before`): the index already holds it.
    pub(in crate::snapshots) fn same_projection(&self, other: &Self) -> bool {
        Self {
            written_pass: 0,
            stub_not_before: 0,
            ..*self
        } == Self {
            written_pass: 0,
            stub_not_before: 0,
            ..*other
        }
    }
}

/// One namespace's outage gate and save marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct GateSlot {
    ns: u128,
    /// The namespace's last pass saved (full or a partial checkpoint).
    saved: bool,
    last_pass_unix: u64,
    last_saved_unix: u64,
    /// `pass_seq` of the namespace's last full save.
    full_saved_pass: u32,
}

/// What C14 tells the pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct GateOpen {
    /// The namespace's previous pass saved (or this process never saw it):
    /// side requests may be due this pass.
    pub(in crate::snapshots) side_allowed: bool,
    /// First pass of this namespace in this process.
    pub(in crate::snapshots) first_in_process: bool,
}

/// Why the side charge could not hold an entry. Either way the request is
/// not due: 0 bytes, uncharged; main is unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum ChargeRefusal {
    /// `SIDE_LEDGER_BYTES` is proved only on the validated layout.
    LayoutUnsupported,
    /// `MAX_SIDE_LEDGER` entries and none evictable.
    Full,
}

#[derive(Debug)]
pub(in crate::snapshots) struct SideLedger {
    entries: BTreeMap<LedgerKey, LedgerEntry>,
    gate: [Option<GateSlot>; GATE_SLOTS],
    pass_seq: u32,
    /// Namespaces seen by this process (0 = empty).
    seen_ns: [u128; GATE_SLOTS],
}

impl Default for SideLedger {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            gate: [None; GATE_SLOTS],
            pass_seq: 0,
            seen_ns: [0; GATE_SLOTS],
        }
    }
}

impl SharedCache {
    /// The side ledger: a leaf lock (retained, then cursor, then side;
    /// nothing is locked under it). A poisoned lock is recovered and the
    /// ledger cleared, which is a process start for pacing (Q-U27).
    pub(in crate::snapshots) fn side_ledger(&self) -> MutexGuard<'_, SideLedger> {
        match self.side.lock() {
            Ok(ledger) => ledger,
            Err(poisoned) => {
                let mut ledger = poisoned.into_inner();
                *ledger = SideLedger::default();
                self.side.clear_poison();
                record(Event::RequestRearmed);
                ledger
            }
        }
    }
}

impl SideLedger {
    pub(in crate::snapshots) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::snapshots) fn pass_seq(&self) -> u32 {
        self.pass_seq
    }

    fn slot(&self, ns: u128) -> Option<&GateSlot> {
        self.gate.iter().flatten().find(|slot| slot.ns == ns)
    }

    fn slot_mut(&mut self, ns: u128) -> Option<&mut GateSlot> {
        self.gate.iter_mut().flatten().find(|slot| slot.ns == ns)
    }

    /// C14 step 1, at the start of a namespace's pass. A replaced slot's
    /// entries stay; only the namespace's gate memory is lost.
    pub(in crate::snapshots) fn begin_pass(&mut self, ns: u128, now: u64) -> GateOpen {
        self.pass_seq = self.pass_seq.saturating_add(1);
        let first_in_process = !self.seen_ns.contains(&ns);
        if first_in_process {
            let at = self
                .seen_ns
                .iter()
                .position(|seen| *seen == 0)
                .unwrap_or(self.pass_seq as usize % GATE_SLOTS);
            self.seen_ns[at] = ns;
        }
        let side_allowed = match self.slot_mut(ns) {
            Some(slot) => slot.saved,
            None => {
                let at = self.free_slot();
                self.gate[at] = Some(GateSlot {
                    ns,
                    saved: false,
                    last_pass_unix: now,
                    last_saved_unix: now,
                    full_saved_pass: 0,
                });
                true
            }
        };
        let slot = self.slot_mut(ns).expect("slot was just found or placed");
        slot.saved = false;
        slot.last_pass_unix = now;
        GateOpen {
            side_allowed,
            first_in_process,
        }
    }

    /// An empty slot; else the oldest saved one; else the least recently
    /// used one (counted: that namespace's outage gate is forgotten).
    fn free_slot(&self) -> usize {
        if let Some(at) = self.gate.iter().position(Option::is_none) {
            return at;
        }
        let oldest = |saved: bool| {
            self.gate
                .iter()
                .enumerate()
                .filter_map(|(at, slot)| slot.map(|slot| (at, slot)))
                .filter(|(_, slot)| !saved || slot.saved)
                .min_by_key(|(_, slot)| slot.last_pass_unix)
                .map(|(at, _)| at)
        };
        oldest(true).unwrap_or_else(|| {
            record(Event::LedgerEviction);
            oldest(false).unwrap_or(0)
        })
    }

    /// C15: the namespace's pass saved every side field. `full` only for
    /// the full save; a partial checkpoint opens the gate but proves nothing
    /// about later entries.
    pub(in crate::snapshots) fn note_saved(&mut self, ns: u128, now: u64, full: bool) {
        let pass = self.pass_seq;
        if let Some(slot) = self.slot_mut(ns) {
            slot.saved = true;
            slot.last_saved_unix = now;
            if full {
                slot.full_saved_pass = pass;
            }
        }
    }

    pub(in crate::snapshots) fn get(&self, key: &LedgerKey) -> Option<&LedgerEntry> {
        self.entries.get(key)
    }

    /// Every writer except the side charge: updates an existing entry only,
    /// in the same step as its index write. False when there is none.
    pub(in crate::snapshots) fn write_existing(
        &mut self,
        key: &LedgerKey,
        entry: LedgerEntry,
    ) -> bool {
        let pass = self.pass_seq;
        match self.entries.get_mut(key) {
            Some(slot) => {
                *slot = LedgerEntry {
                    written_pass: pass,
                    ..entry
                };
                true
            }
            None => false,
        }
    }

    /// The side charge (G7), the only creator. The layout guard comes before
    /// any entry is built, and the limit is enforced here, under the lock.
    /// When full, evicts in order: another namespace's entry its full save
    /// already holds (lossless), then one of a slotless or idle namespace.
    /// The caller's own entries are never evicted. `Ok(true)` if created.
    pub(in crate::snapshots) fn charge(
        &mut self,
        key: LedgerKey,
        entry: LedgerEntry,
        now: u64,
    ) -> Result<bool, ChargeRefusal> {
        if !crate::heap_layout_bound::layout_supported() {
            return Err(ChargeRefusal::LayoutUnsupported);
        }
        let entry = LedgerEntry {
            written_pass: self.pass_seq,
            ..entry
        };
        if let Some(slot) = self.entries.get_mut(&key) {
            *slot = entry;
            return Ok(false);
        }
        if self.entries.len() >= MAX_SIDE_LEDGER && !self.evict_one(key.ns, now) {
            return Err(ChargeRefusal::Full);
        }
        self.entries.insert(key, entry);
        Ok(true)
    }

    fn evict_one(&mut self, caller: u128, now: u64) -> bool {
        let lossless = self
            .entries
            .iter()
            .find(|(key, entry)| {
                key.ns != caller
                    && self
                        .slot(key.ns)
                        .is_some_and(|slot| entry.written_pass <= slot.full_saved_pass)
            })
            .map(|(key, _)| *key);
        if let Some(key) = lossless {
            self.entries.remove(&key);
            record(Event::LedgerEviction);
            return true;
        }
        let idle = self
            .entries
            .keys()
            .find(|key| {
                key.ns != caller
                    && self.slot(key.ns).map_or(true, |slot| {
                        now.saturating_sub(slot.last_saved_unix) >= NAMESPACE_IDLE_SECONDS
                    })
            })
            .copied();
        if let Some(key) = idle {
            self.entries.remove(&key);
            record(Event::RequestRearmed);
            return true;
        }
        false
    }

    pub(in crate::snapshots) fn has_namespace(&self, ns: u128) -> bool {
        self.namespace(ns).next().is_some()
    }

    pub(in crate::snapshots) fn namespace(
        &self,
        ns: u128,
    ) -> impl Iterator<Item = (&LedgerKey, &LedgerEntry)> {
        let start = LedgerKey {
            ns,
            p: 0,
            dev: 0,
            ino: 0,
        };
        self.entries
            .range(start..)
            .take_while(move |(key, _)| key.ns == ns)
    }

    /// C14 prune: drops this namespace's entries that `drop` selects.
    pub(in crate::snapshots) fn prune(
        &mut self,
        ns: u128,
        mut remove: impl FnMut(&LedgerKey, &LedgerEntry) -> bool,
    ) {
        self.entries
            .retain(|key, entry| key.ns != ns || !remove(key, entry));
    }
}

/// A record of the entry's object whose seal covers what the entry's
/// children need. (dev, ino) equality is the identity part only; coverage is
/// the seal's sealed offset against `needed_extent`.
fn covers(
    record: &crate::snapshots::CodexParentSide,
    key: &LedgerKey,
    entry: &LedgerEntry,
) -> bool {
    record.parsed.dev_ino() == (key.dev, key.ino)
        && record.seal.sealed_offset() >= entry.needed_extent
}

impl SideLedger {
    /// C14 (Codex only), right after the index load and against the index
    /// exactly as loaded: the gate slot, then prune and eager hydrate of this
    /// namespace's entries. Touches only side requests and a covering side
    /// record's `pace`. With no entry for
    /// the namespace it builds nothing.
    pub(in crate::snapshots) fn begin_index_pass(
        &mut self,
        ns: u128,
        now: u64,
        index: &mut crate::snapshots::ScanIndex,
    ) -> GateOpen {
        let gate = self.begin_pass(ns, now);
        if !self.has_namespace(ns) {
            return gate;
        }
        // The entries' parents, by digest: at most one H128 per file key.
        let wanted = self
            .namespace(ns)
            .map(|(key, _)| key.p)
            .collect::<std::collections::BTreeSet<_>>();
        let keys = index
            .files
            .keys()
            .filter_map(|key| {
                let p = parent_of(key);
                wanted.contains(&p).then(|| (p, key.clone()))
            })
            .collect::<BTreeMap<u128, String>>();
        let requests = &index.codex_parent_side_requests;
        let records = &index.codex_parent_side;
        self.prune(ns, |key, entry| {
            // (c) P left the index.
            let Some(p_key) = keys.get(&key.p) else {
                return true;
            };
            let record = records.get(p_key);
            // (c) the saved record is for another object.
            if record.is_some_and(|record| record.parsed.dev_ino() != (key.dev, key.ino)) {
                return true;
            }
            match requests.get(p_key) {
                // (c) the saved request is for another object.
                Some(loaded) if loaded.dev_ino != (key.dev, key.ino) => true,
                // (a) the index already holds this entry.
                Some(loaded) => LedgerEntry::of_request(loaded).same_projection(entry),
                // (c) the generation ended and the index agrees.
                None if entry.tag == LedgerTag::Gone => true,
                // (b) the covering record's save carried the stub.
                None => {
                    entry.tag == LedgerTag::Removed
                        && record.is_some_and(|record| {
                            covers(record, key, entry)
                                && record.pace.is_some_and(|pace| {
                                    pace.not_before_unix_seconds >= entry.stub_not_before
                                        && pace.attempts_floor >= 6
                                })
                        })
                }
            }
        });
        let survivors = self
            .namespace(ns)
            .map(|(key, entry)| (*key, *entry))
            .collect::<Vec<_>>();
        for (key, entry) in survivors {
            let Some(p_key) = keys.get(&key.p) else {
                continue;
            };
            if entry.tag == LedgerTag::Removed {
                // The covering record's request removal was lost: the stub
                // goes on the record, and P has no request.
                if let Some(record) = index
                    .codex_parent_side
                    .get_mut(p_key)
                    .filter(|record| covers(record, &key, &entry))
                {
                    record.pace = Some(crate::snapshots::SidePace::merged(
                        record.pace,
                        crate::snapshots::SidePace {
                            not_before_unix_seconds: entry.stub_not_before,
                            attempts_floor: 6,
                        },
                    ));
                    index.codex_parent_side_requests.remove(p_key);
                    continue;
                }
            }
            let entry = match entry.tag {
                LedgerTag::Gone => {
                    index.codex_parent_side_requests.remove(p_key);
                    continue;
                }
                // The covering record's save was lost (no record covers this
                // object): one paced re-read once the gate opens.
                LedgerTag::Removed => {
                    let rearmed = LedgerEntry {
                        tag: LedgerTag::Live,
                        attempts: entry.attempts.min(6),
                        not_before: entry.stub_not_before,
                        ..entry
                    };
                    self.write_existing(&key, rearmed);
                    record(Event::RequestRearmed);
                    rearmed
                }
                _ => entry,
            };
            if let Some(request) = entry.request((key.dev, key.ino)) {
                index
                    .codex_parent_side_requests
                    .insert(p_key.clone(), request);
            }
        }
        gate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_layout_bound::{bound, layout_supported, tree_node_bytes, tree_nodes, Counter};
    use crate::snapshots::{SideRequest, SideRequestState};

    fn entry() -> LedgerEntry {
        LedgerEntry {
            tag: LedgerTag::Live,
            attempts: 1,
            written_pass: 0,
            covered: 0,
            needed_extent: 10,
            state_extent: 20,
            state_ctime: (1, 2),
            attempt_extent: 20,
            attempt_ctime: (1, 2),
            not_before: 60,
            needed_charge: 0,
            stub_not_before: 0,
        }
    }

    fn key(ns: u128, p: u128) -> LedgerKey {
        LedgerKey {
            ns,
            p,
            dev: 1,
            ino: u64::try_from(p).unwrap(),
        }
    }

    #[test]
    fn ledger_charge_is_the_full_node_formula_and_covers_a_full_map() {
        let node = tree_node_bytes::<LedgerKey, LedgerEntry>().unwrap();
        assert_eq!(SIDE_LEDGER_BYTES, (MAX_SIDE_LEDGER + 1) * node);
        assert_eq!(size_of::<LedgerEntry>(), 96);
        assert_eq!(size_of::<GateSlot>(), 48);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(SIDE_LEDGER_BYTES, 125_840);
        // A real map at the limit costs exactly the charge.
        let mut c = Counter::new(usize::MAX);
        tree_nodes::<LedgerKey, LedgerEntry>(MAX_SIDE_LEDGER, &mut c).unwrap();
        assert!(c.bytes <= SIDE_LEDGER_BYTES);
    }

    /// U-T64(f): the charge is constant, lock-free and inside the state bound.
    #[test]
    fn shared_cache_charges_the_constant_without_locking_the_ledger() {
        let empty = SharedCache::default();
        let full = SharedCache::default();
        {
            let mut ledger = full.side_ledger();
            ledger.begin_pass(7, 1000);
            for p in 0..MAX_SIDE_LEDGER as u128 {
                if layout_supported() {
                    assert_eq!(ledger.charge(key(7, p + 1), entry(), 1000), Ok(true));
                } else {
                    ledger.entries.insert(key(7, p + 1), entry());
                }
            }
            assert_eq!(ledger.len(), MAX_SIDE_LEDGER);
        }
        assert_eq!(bound(&full, usize::MAX), bound(&empty, usize::MAX));
        assert_eq!(bound(&empty, usize::MAX).is_some(), layout_supported());
        if layout_supported() {
            // The term is exactly the constant: one visit, no walk.
            let mut with = Counter::new(usize::MAX);
            crate::heap_layout_bound::HeapLayoutBound::heap_bound(&empty, &mut with).unwrap();
            let mut without = Counter::new(usize::MAX);
            crate::heap_layout_bound::HeapLayoutBound::heap_bound(&empty.inner, &mut without)
                .unwrap();
            crate::heap_layout_bound::HeapLayoutBound::heap_bound(&empty.cursor, &mut without)
                .unwrap();
            assert_eq!(with.bytes, without.bytes + SIDE_LEDGER_BYTES);
        }
        // Held lock: heap_bound still answers.
        let held = full.side_ledger();
        assert_eq!(bound(&full, usize::MAX), bound(&empty, usize::MAX));
        drop(held);
    }

    #[test]
    fn charge_refuses_past_the_limit_and_never_evicts_the_caller() {
        if !layout_supported() {
            let mut ledger = SideLedger::default();
            assert_eq!(
                ledger.charge(key(1, 1), entry(), 0),
                Err(ChargeRefusal::LayoutUnsupported)
            );
            assert_eq!(ledger.len(), 0);
            return;
        }
        let mut ledger = SideLedger::default();
        ledger.begin_pass(1, 1000);
        for p in 1..=MAX_SIDE_LEDGER as u128 {
            assert_eq!(ledger.charge(key(1, p), entry(), 1000), Ok(true));
        }
        // Rewriting an existing key needs no room.
        assert_eq!(ledger.charge(key(1, 1), entry(), 1000), Ok(false));
        assert_eq!(
            ledger.charge(key(1, 999), entry(), 99_999),
            Err(ChargeRefusal::Full)
        );
        assert_eq!(ledger.len(), MAX_SIDE_LEDGER);
    }

    /// U-T60(d)(xvi): eviction order across namespaces.
    #[test]
    fn eviction_is_lossless_first_then_idle_namespaces() {
        if !layout_supported() {
            return;
        }
        let (x, c) = (11, 22);
        let mut ledger = SideLedger::default();
        ledger.begin_pass(x, 1000);
        for p in 1..=(MAX_SIDE_LEDGER as u128 - 1) {
            ledger.charge(key(x, p), entry(), 1000).unwrap();
        }
        ledger.note_saved(x, 1001, true);
        // A later unsaved pass of X writes one more entry.
        ledger.begin_pass(x, 1100);
        ledger.charge(key(x, 100), entry(), 1100).unwrap();
        assert_eq!(ledger.len(), MAX_SIDE_LEDGER);

        // C's pass: X saved its first 63 entries, so they go losslessly.
        ledger.begin_pass(c, 1200);
        assert_eq!(ledger.charge(key(c, 1), entry(), 1200), Ok(true));
        assert!(ledger.get(&key(x, 100)).is_some(), "unsaved entry kept");
        for p in 2..=(MAX_SIDE_LEDGER as u128 - 1) {
            ledger.charge(key(c, p), entry(), 1200).unwrap();
        }
        // Only X's unsaved entry and C's own remain: not yet idle.
        assert_eq!(
            ledger.charge(key(c, 900), entry(), 1200),
            Err(ChargeRefusal::Full)
        );
        // X's last save is an hour old: its unsaved entry may go.
        assert_eq!(ledger.charge(key(c, 900), entry(), 1001 + 3600), Ok(true));
        assert!(ledger.get(&key(x, 100)).is_none());
        // C's own entries are never evicted.
        assert_eq!(
            ledger.charge(key(c, 901), entry(), u64::MAX),
            Err(ChargeRefusal::Full)
        );
        assert_eq!(ledger.namespace(c).count(), MAX_SIDE_LEDGER);
    }

    #[test]
    fn gate_opens_only_after_a_saved_pass_and_slots_are_bounded() {
        let mut ledger = SideLedger::default();
        // First sight: allowed, first in process.
        assert_eq!(
            ledger.begin_pass(5, 10),
            GateOpen {
                side_allowed: true,
                first_in_process: true,
            }
        );
        // The pass did not save: the next pass is gated.
        assert!(!ledger.begin_pass(5, 20).side_allowed);
        ledger.note_saved(5, 25, false);
        assert_eq!(
            ledger.begin_pass(5, 30),
            GateOpen {
                side_allowed: true,
                first_in_process: false,
            }
        );
        // More than 8 namespaces: slots are replaced, the gate table stays 8.
        for ns in 100..120 {
            ledger.begin_pass(ns, 40 + ns as u64);
        }
        assert_eq!(ledger.gate.iter().flatten().count(), GATE_SLOTS);
        assert!(ledger.slot(5).is_none());
        // A forgotten namespace counts as unseen-gate: allowed.
        assert!(ledger.begin_pass(5, 500).side_allowed);
    }

    /// U-T60(d)(xiv): a poisoned ledger lock clears the ledger.
    #[test]
    fn poisoned_ledger_is_cleared_and_usable() {
        let cache = std::sync::Arc::new(SharedCache::default());
        cache.side_ledger().begin_pass(3, 10);
        let poisoner = cache.clone();
        let _ = std::thread::spawn(move || {
            let _ledger = poisoner.side_ledger();
            panic!("poison the side ledger");
        })
        .join();
        assert!(cache.side.is_poisoned());
        let (pass, counts) =
            crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
                cache.side_ledger().pass_seq()
            });
        assert_eq!(pass, 0);
        assert_eq!(counts.side_requests_rearmed, 1);
        assert!(!cache.side.is_poisoned());
    }

    #[test]
    fn entry_projection_round_trips_every_request_state() {
        for state in [
            SideRequestState::Live,
            SideRequestState::Evicted,
            SideRequestState::Short { covered: 77 },
            SideRequestState::Lossy,
            SideRequestState::Unsealed,
        ] {
            let request = SideRequest {
                dev_ino: (3, 4),
                needed_extent: 10,
                state,
                state_extent: 20,
                state_ctime: (5, 6),
                attempt_extent: 30,
                attempt_ctime: (7, 8),
                attempts: 3,
                not_before_unix_seconds: 99,
                needed_charge: Some(4096),
            };
            let entry = LedgerEntry::of_request(&request);
            assert_eq!(entry.request((3, 4)), Some(request));
            assert!(entry.same_projection(&LedgerEntry {
                written_pass: 9,
                stub_not_before: 9,
                ..entry
            }));
            assert!(!entry.same_projection(&LedgerEntry {
                attempts: 4,
                ..entry
            }));
        }
        let removed = LedgerEntry {
            tag: LedgerTag::Removed,
            ..entry()
        };
        assert_eq!(removed.request((1, 1)), None);
        assert_eq!(
            LedgerEntry {
                tag: LedgerTag::Gone,
                ..entry()
            }
            .request((1, 1)),
            None
        );
    }

    #[test]
    fn only_the_charge_creates_and_every_write_stamps_the_pass() {
        let mut ledger = SideLedger::default();
        ledger.begin_pass(1, 10);
        assert!(!ledger.write_existing(&key(1, 1), entry()));
        assert_eq!(ledger.get(&key(1, 1)), None);
        ledger.entries.insert(key(1, 1), entry());
        ledger.begin_pass(1, 20);
        let cured = LedgerEntry {
            attempts: 6,
            ..entry()
        };
        assert!(ledger.write_existing(&key(1, 1), cured));
        assert_eq!(
            ledger.get(&key(1, 1)),
            Some(&LedgerEntry {
                written_pass: 2,
                ..cured
            })
        );
    }

    fn file_entry() -> crate::snapshots::ScanIndexEntry {
        crate::snapshots::ScanIndexEntry {
            size_bytes: 42,
            modified_unix_seconds: 1_700_000_000,
            modified_unix_nanos: None,
            source_file_fingerprint: "sha256:test".to_string(),
            last_snapshot_fingerprint: None,
            last_upload_body_witness: None,
            effective_upload_body_witness_revision: 0,
            scan_identity_version: None,
            codex_joined_member_set: None,
            codex_captured_joined_member_set: None,
            codex_protected_owner: None,
            codex_applied_tier_receipt: None,
            codex_applied_tier_receipt_required: false,
            codex_captured_tier_receipt: None,
            codex_captured_tier_receipt_required: false,
            codex_captured_uncommitted: false,
            codex_counting_v2: false,
        }
    }

    /// C14: prune what the loaded index already holds or what is dead, then
    /// hydrate the rest; other namespaces are untouched.
    #[test]
    fn begin_index_pass_prunes_saved_and_dead_entries_and_hydrates_the_rest() {
        let ns = 9;
        let at = |p_key: &str, ino: u64| LedgerKey {
            ns,
            p: parent_of(p_key),
            dev: 1,
            ino,
        };
        let live = LedgerEntry {
            attempts: 3,
            ..entry()
        };
        let mut index = crate::snapshots::ScanIndex::default();
        for key in ["/a", "/b", "/c", "/d", "/e", "/f"] {
            index.files.insert(key.into(), file_entry());
        }
        let mut ledger = SideLedger::default();
        // (a) saved.
        index
            .codex_parent_side_requests
            .insert("/a".into(), live.request((1, 1)).unwrap());
        ledger.entries.insert(at("/a", 1), live);
        // An unsaved charge: the index holds the older attempt count.
        let older = LedgerEntry {
            attempts: 1,
            ..entry()
        };
        index
            .codex_parent_side_requests
            .insert("/b".into(), older.request((1, 2)).unwrap());
        ledger.entries.insert(at("/b", 2), live);
        // (c) the saved request is for another object.
        index
            .codex_parent_side_requests
            .insert("/c".into(), live.request((1, 30)).unwrap());
        ledger.entries.insert(at("/c", 3), live);
        // (c) Gone and the index agrees; Gone with a saved request.
        let gone = LedgerEntry {
            tag: LedgerTag::Gone,
            ..entry()
        };
        ledger.entries.insert(at("/d", 4), gone);
        index
            .codex_parent_side_requests
            .insert("/e".into(), live.request((1, 5)).unwrap());
        ledger.entries.insert(at("/e", 5), gone);
        // A lost covering save: no record covers the object.
        ledger.entries.insert(
            at("/f", 6),
            LedgerEntry {
                tag: LedgerTag::Removed,
                attempts: 7,
                stub_not_before: 5000,
                ..entry()
            },
        );
        // (c) P left the index.
        ledger.entries.insert(at("/left", 7), live);
        // Another namespace.
        ledger.entries.insert(key(10, 1), live);

        let (gate, counts) =
            crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
                ledger.begin_index_pass(ns, 100, &mut index)
            });
        assert!(gate.side_allowed);
        assert_eq!(counts.side_requests_rearmed, 1);
        let kept = ledger
            .namespace(ns)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        let mut expected = vec![at("/b", 2), at("/e", 5), at("/f", 6)];
        expected.sort();
        assert_eq!(kept, expected);
        assert!(ledger.get(&key(10, 1)).is_some());

        let requests = &index.codex_parent_side_requests;
        assert_eq!(requests.get("/a"), live.request((1, 1)).as_ref());
        assert_eq!(requests.get("/b"), live.request((1, 2)).as_ref());
        assert_eq!(requests.get("/c"), live.request((1, 30)).as_ref());
        assert_eq!(requests.get("/d"), None);
        assert_eq!(requests.get("/e"), None);
        let rearmed = requests.get("/f").unwrap();
        assert_eq!(rearmed.state, crate::snapshots::SideRequestState::Live);
        assert_eq!(
            (rearmed.attempts, rearmed.not_before_unix_seconds),
            (6, 5000)
        );
        assert_eq!(rearmed.dev_ino, (1, 6));
        assert_eq!(ledger.get(&at("/f", 6)).unwrap().tag, LedgerTag::Live);

        // With no entry in the namespace, C14 is the gate only.
        let before = index.codex_parent_side_requests.clone();
        let mut quiet = SideLedger::default();
        quiet.begin_index_pass(ns, 100, &mut index);
        assert_eq!(index.codex_parent_side_requests, before);
    }

    /// A side record of object (1, ino) whose seal covers `[0, sealed)`.
    fn side_record(
        ino: u64,
        sealed: u64,
        pace: Option<crate::snapshots::SidePace>,
    ) -> crate::snapshots::CodexParentSide {
        let stamp = serde_json::json!({
            "length": sealed,
            "device": 1,
            "inode": ino,
            "modified": [1_792_540_800, 0],
            "changed": [1_792_540_800, 0],
        });
        serde_json::from_value(serde_json::json!({
            "verdict": { "kind": "settled" },
            "seal": {
                "stamp": stamp,
                "scope": "f".repeat(64),
                "sample_len": 0,
                "head_sha256": "f".repeat(64),
                "boundary_sha256": "f".repeat(64),
                "verified_unix_seconds": 1_792_540_800,
                "sealed_unix_seconds": 1_792_540_800,
            },
            "parsed": {
                "dev": 1,
                "ino": ino,
                "extent": sealed,
                "modified": [1_792_540_800, 0],
                "changed": [1_792_540_800, 0],
            },
            "pace": pace,
            "generation": 1,
            "referenced_epoch": 0,
        }))
        .unwrap()
    }

    /// D3: the record terms of C14. (dev, ino) equality is identity only:
    /// the stub moves onto a record, and (b) prunes, only when the record's
    /// seal also covers `needed_extent` (and, for (b), its pace covers the
    /// stub).
    #[test]
    fn begin_index_pass_record_terms_need_the_same_object_and_coverage() {
        use crate::snapshots::SidePace;
        let ns = 11;
        let at = |p_key: &str, ino: u64| LedgerKey {
            ns,
            p: parent_of(p_key),
            dev: 1,
            ino,
        };
        let removed = LedgerEntry {
            tag: LedgerTag::Removed,
            attempts: 7,
            needed_extent: 4096,
            stub_not_before: 5000,
            ..entry()
        };
        let mut index = crate::snapshots::ScanIndex::default();
        for key in ["/cover", "/short", "/short-paced", "/other"] {
            index.files.insert(key.into(), file_entry());
        }
        let short_pace = SidePace {
            not_before_unix_seconds: 9000,
            attempts_floor: 6,
        };
        let earlier_pace = SidePace {
            not_before_unix_seconds: 100,
            attempts_floor: 2,
        };
        let records = [
            // Same object, covering: the stub goes on the record.
            ("/cover", side_record(1, 8192, Some(earlier_pace))),
            // Same object, insufficient coverage: one paced re-read.
            ("/short", side_record(2, 1024, None)),
            // Same object, short, already paced past the stub: (b) still
            // needs coverage, so this re-reads too.
            ("/short-paced", side_record(3, 1024, Some(short_pace))),
            // Another object: (c) prunes the entry; the record is untouched.
            ("/other", side_record(40, 8192, None)),
        ];
        for (key, record) in &records {
            index
                .codex_parent_side
                .insert((*key).into(), record.clone());
        }
        let mut ledger = SideLedger::default();
        ledger.entries.insert(at("/cover", 1), removed);
        ledger.entries.insert(at("/short", 2), removed);
        ledger.entries.insert(at("/short-paced", 3), removed);
        ledger.entries.insert(at("/other", 4), removed);

        let (_, counts) = crate::local_resource_diagnostics::codex_side_lifecycle::observe(|| {
            ledger.begin_index_pass(ns, 100, &mut index)
        });
        // Only the two short records re-arm.
        assert_eq!(counts.side_requests_rearmed, 2);
        let kept = ledger
            .namespace(ns)
            .map(|(key, entry)| (*key, entry.tag))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            kept,
            BTreeMap::from([
                (at("/cover", 1), LedgerTag::Removed),
                (at("/short", 2), LedgerTag::Live),
                (at("/short-paced", 3), LedgerTag::Live),
            ])
        );
        assert_eq!(
            index.codex_parent_side["/cover"].pace,
            Some(SidePace {
                not_before_unix_seconds: 5000,
                attempts_floor: 6,
            })
        );
        assert!(!index.codex_parent_side_requests.contains_key("/cover"));
        for (key, ino) in [("/short", 2), ("/short-paced", 3)] {
            let request = index.codex_parent_side_requests[key];
            assert_eq!(request.state, crate::snapshots::SideRequestState::Live);
            assert_eq!(
                (
                    request.dev_ino,
                    request.attempts,
                    request.not_before_unix_seconds
                ),
                ((1, ino), 6, 5000)
            );
        }
        assert_eq!(index.codex_parent_side["/short"], records[1].1);
        assert_eq!(index.codex_parent_side["/short-paced"], records[2].1);
        assert_eq!(index.codex_parent_side["/other"], records[3].1);
        assert!(!index.codex_parent_side_requests.contains_key("/other"));

        // After the save that carried the stub, (b) prunes the covering entry.
        ledger.begin_index_pass(ns, 200, &mut index);
        assert!(ledger.get(&at("/cover", 1)).is_none());
        assert!(!index.codex_parent_side_requests.contains_key("/cover"));
    }

    #[test]
    fn namespace_view_and_prune_touch_only_that_namespace() {
        let mut ledger = SideLedger::default();
        for (ns, p) in [(1, 1), (1, 2), (2, 1), (u128::MAX, 1)] {
            ledger.entries.insert(key(ns, p), entry());
        }
        assert_eq!(ledger.namespace(1).count(), 2);
        assert!(ledger.has_namespace(u128::MAX));
        assert!(!ledger.has_namespace(3));
        ledger.prune(1, |key, _| key.p == 2);
        assert_eq!(ledger.namespace(1).count(), 1);
        assert_eq!(ledger.namespace(2).count(), 1);
        assert_ne!(
            namespace_of(Path::new("/a/index.json")),
            namespace_of(Path::new("/b/index.json"))
        );
        assert_ne!(parent_of("/p.jsonl"), parent_of("/q.jsonl"));
    }
}
