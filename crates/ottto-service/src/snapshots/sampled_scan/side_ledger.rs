//! U1a-2a: the process side-request ledger. It paces Codex parent side
//! requests across failed passes: a charge made in a pass that never saved is
//! still here, so a lost save never buys another read. Scalars only, at most
//! `MAX_SIDE_LEDGER` entries, charged as the fixed `SIDE_LEDGER_BYTES` in
//! `SharedCache::heap_bound` and in every insert reservation, never walked.
//!
//! Authority: for a key with an entry, the entry is the truth; the loaded
//! index request is overwritten with its projection. Only the side charge
//! (G7) creates entries; every other writer updates an existing one.

use super::SharedCache;
use crate::local_resource_diagnostics::codex_side_lifecycle::{record, Event};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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
/// D5′: the ledger's inline tables (gate slots, seen namespaces, the map
/// head, counters) are inside `size_of::<SharedCache>()`, which every
/// whole-cache bound charges beside `SIDE_LEDGER_BYTES`; this pins their size.
const _: () = assert!(size_of::<SideLedger>() <= 576);

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
    /// D5′: the ledger's stamp for the last write (`SideLedger::next_wseq`;
    /// 0 = never stamped, which no save covers).
    pub(in crate::snapshots) wseq: u32,
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
            wseq: 0,
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

    /// The request this entry stands for, with the index's
    /// `referenced_epoch` (the ledger keeps none). `Removed` and `Gone`
    /// stand for no request.
    pub(in crate::snapshots) fn request(
        &self,
        dev_ino: (u64, u64),
        referenced_epoch: u64,
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
            referenced_epoch,
        })
    }

    /// Equal persisted projection (every field but the ledger's own
    /// `wseq` and `stub_not_before`): the index already holds it.
    pub(in crate::snapshots) fn same_projection(&self, other: &Self) -> bool {
        Self {
            wseq: 0,
            stub_not_before: 0,
            ..*self
        } == Self {
            wseq: 0,
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
    /// D5′ custody: the stamp this slot was placed with. A save mark binds
    /// to it, so a callback for a replaced or re-placed slot moves nothing.
    incarnation: u32,
    /// D5′: the highest save mark of a successful selected save (full or a
    /// partial checkpoint) of this slot; entries stamped at or below it are
    /// on disk. 0 = no proven save.
    saved_wseq: u32,
    /// The same for full saves only (lossless eviction).
    full_saved_wseq: u32,
}

/// D5′: what a selected save may later prove, read immediately before the
/// call that assembles its content. Bound to the namespace and to its slot's
/// incarnation; `wseq` is the last stamp issued (`None` once exhausted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct SaveMark {
    ns: u128,
    /// 0: no slot when the mark was read.
    incarnation: u32,
    wseq: Option<u32>,
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
    /// D5′: the last stamp issued, for entry writes and slot placements.
    wseq: u32,
    /// Sticky: the stamp ran out; from then on no save covers anything.
    wseq_exhausted: bool,
}

impl Default for SideLedger {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            gate: [None; GATE_SLOTS],
            pass_seq: 0,
            seen_ns: [0; GATE_SLOTS],
            wseq: 0,
            wseq_exhausted: false,
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

    #[cfg(test)]
    pub(in crate::snapshots) fn pass_seq(&self) -> u32 {
        self.pass_seq
    }

    fn slot(&self, ns: u128) -> Option<&GateSlot> {
        self.gate.iter().flatten().find(|slot| slot.ns == ns)
    }

    fn slot_mut(&mut self, ns: u128) -> Option<&mut GateSlot> {
        self.gate.iter_mut().flatten().find(|slot| slot.ns == ns)
    }

    /// D5′: a fresh stamp. Checked: once it runs out the ledger is
    /// exhausted for the process and every later stamp is 0 (uncertain).
    fn next_wseq(&mut self) -> u32 {
        match self.wseq.checked_add(1) {
            Some(next) if !self.wseq_exhausted => {
                self.wseq = next;
                next
            }
            _ => {
                self.wseq_exhausted = true;
                0
            }
        }
    }

    /// D5′ C15 capture: read immediately before the call that assembles and
    /// writes the selected save, so every entry stamped at or below it was
    /// written into the index that save serializes.
    pub(in crate::snapshots) fn save_mark(&self, ns: u128) -> SaveMark {
        let incarnation = self.slot(ns).map_or(0, |slot| slot.incarnation);
        SaveMark {
            ns,
            incarnation,
            wseq: (!self.wseq_exhausted && incarnation != 0).then_some(self.wseq),
        }
    }

    /// D5′ (c): a successful selected save of this slot already holds the
    /// entry. Exhaustion, an unstamped entry, no slot or no proven save: no.
    fn saved_covers(&self, ns: u128, entry: &LedgerEntry) -> bool {
        !self.wseq_exhausted
            && entry.wseq != 0
            && self
                .slot(ns)
                .is_some_and(|slot| entry.wseq <= slot.saved_wseq)
    }

    /// C14 step 1, at the start of a namespace's pass. A replaced slot's
    /// entries stay; only the namespace's gate memory is lost. Production
    /// enters through `open_index_pass` with the page's kind.
    #[cfg(test)]
    pub(in crate::snapshots) fn begin_pass(&mut self, ns: u128, now: u64) -> GateOpen {
        self.begin_pass_of(ns, now, crate::snapshots::CodexPageKind::Ordinary)
    }

    /// C14 step 1 for a page of `kind`. Only an ordinary pass closes the
    /// gate until its save: a continuation page makes no G7 charge, so it
    /// leaves no unsaved charge for the gate to hold back, and it neither
    /// clears `saved` nor manufactures it (C-1). The next ordinary pass sees
    /// the last ordinary or EOF save's outcome. A namespace with no slot
    /// (new or evicted) is placed as for an ordinary pass.
    pub(in crate::snapshots) fn begin_pass_of(
        &mut self,
        ns: u128,
        now: u64,
        kind: crate::snapshots::CodexPageKind,
    ) -> GateOpen {
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
                let incarnation = self.next_wseq();
                // New, replaced or reused: no save of this slot is proven.
                self.gate[at] = Some(GateSlot {
                    ns,
                    saved: false,
                    last_pass_unix: now,
                    last_saved_unix: now,
                    incarnation,
                    saved_wseq: 0,
                    full_saved_wseq: 0,
                });
                true
            }
        };
        if kind == crate::snapshots::CodexPageKind::Ordinary {
            let slot = self.slot_mut(ns).expect("slot was just found or placed");
            slot.saved = false;
            slot.last_pass_unix = now;
        }
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

    /// C15, on the `Ok` arm only: the namespace's selected save, carrying
    /// every side field, succeeded. `mark` was read before that save was
    /// assembled; it moves the slot's watermarks (`full` only for the full
    /// save) and never past it. A mark for another namespace or another
    /// incarnation of the slot (replaced or re-placed since) moves nothing,
    /// not even the gate. Sync cycles are also serialized
    /// (`SNAPSHOT_SYNC_LOCK`), so no other pass of this namespace writes
    /// between the mark and this call.
    pub(in crate::snapshots) fn note_saved(
        &mut self,
        ns: u128,
        now: u64,
        full: bool,
        mark: SaveMark,
    ) {
        let Some(slot) = self
            .slot_mut(ns)
            .filter(|slot| mark.ns == ns && slot.incarnation == mark.incarnation)
        else {
            return;
        };
        slot.saved = true;
        slot.last_saved_unix = now;
        if let Some(wseq) = mark.wseq {
            slot.saved_wseq = slot.saved_wseq.max(wseq);
            if full {
                slot.full_saved_wseq = slot.full_saved_wseq.max(wseq);
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
        if !self.entries.contains_key(key) {
            return false;
        }
        let wseq = self.next_wseq();
        self.entries.insert(*key, LedgerEntry { wseq, ..entry });
        true
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
            wseq: self.next_wseq(),
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
        // D5′: lossless only when a full save of the slot proves the entry.
        let lossless = self
            .entries
            .iter()
            .find(|(key, entry)| {
                key.ns != caller
                    && !self.wseq_exhausted
                    && entry.wseq != 0
                    && self
                        .slot(key.ns)
                        .is_some_and(|slot| entry.wseq <= slot.full_saved_wseq)
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

    /// Tests: a full ledger for `ns` (F4b admission controls).
    #[cfg(test)]
    pub(in crate::snapshots) fn fill_for_test(&mut self, ns: u128) {
        self.begin_pass(ns, 1000);
        for p in 1..=MAX_SIDE_LEDGER as u128 {
            let key = LedgerKey {
                ns,
                p,
                dev: 1,
                ino: p as u64,
            };
            let entry = LedgerEntry {
                tag: LedgerTag::Live,
                attempts: 1,
                wseq: 0,
                covered: 0,
                needed_extent: 0,
                state_extent: 0,
                state_ctime: (0, 0),
                attempt_extent: 0,
                attempt_ctime: (0, 0),
                not_before: 0,
                needed_charge: 0,
                stub_not_before: 0,
            };
            if self.charge(key, entry, 1000).is_err() {
                self.entries.insert(key, entry);
            }
        }
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

    /// Rows 30 and 36: every entry of P (by key digest; `None` = every P:
    /// a replay) in `ns` ends its generation (`Gone`, freshly stamped), in
    /// the same step as the index's removal. Allocates nothing under the
    /// lock.
    pub(in crate::snapshots) fn end_generation(&mut self, ns: u128, p: Option<u128>) {
        loop {
            // Bound first: the iterator's borrow ends before the write.
            let next = self
                .namespace(ns)
                .find(|(key, entry)| p.map_or(true, |p| key.p == p) && entry.tag != LedgerTag::Gone)
                .map(|(key, entry)| (*key, *entry));
            let Some((key, entry)) = next else {
                break;
            };
            self.write_existing(
                &key,
                LedgerEntry {
                    tag: LedgerTag::Gone,
                    ..entry
                },
            );
        }
    }

    /// D6(b) (row 32): the epoch prune may drop the request `key` names only
    /// when no charge here is unproven: no entry, or one a successful
    /// selected save of its slot holds (D5′). An in-flight read's G7 charge
    /// is unsaved, so its request stays.
    pub(in crate::snapshots) fn prunable(&self, key: &LedgerKey) -> bool {
        self.entries
            .get(key)
            .map_or(true, |entry| self.saved_covers(key.ns, entry))
    }

    /// Row 32: `key`'s generation ends (`Gone`, freshly stamped) in the same
    /// step as the index's removal; nothing without an entry.
    pub(in crate::snapshots) fn end_key(&mut self, key: &LedgerKey) {
        if let Some(entry) = self.entries.get(key).copied() {
            self.write_existing(
                key,
                LedgerEntry {
                    tag: LedgerTag::Gone,
                    ..entry
                },
            );
        }
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

/// C14 (R2-L2): the index's file keys by parent digest, for `wanted` only.
/// One SHA-256 per file key, so it runs with the ledger lock released
/// (C14 is single-threaded under `SNAPSHOT_SYNC_LOCK`).
pub(in crate::snapshots) fn index_parent_keys(
    files: &BTreeMap<String, crate::snapshots::ScanIndexEntry>,
    wanted: &BTreeSet<u128>,
) -> BTreeMap<u128, String> {
    files
        .keys()
        .filter_map(|key| {
            let p = parent_of(key);
            wanted.contains(&p).then(|| (p, key.clone()))
        })
        .collect()
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
    /// the namespace it builds nothing. Production runs the three parts with
    /// the lock released around the hashing (`begin_codex_side_pass`, R2-L2).
    #[cfg(test)]
    pub(in crate::snapshots) fn begin_index_pass(
        &mut self,
        ns: u128,
        now: u64,
        index: &mut crate::snapshots::ScanIndex,
    ) -> GateOpen {
        let (gate, wanted) =
            self.open_index_pass(ns, now, crate::snapshots::CodexPageKind::Ordinary);
        if let Some(wanted) = wanted {
            let keys = index_parent_keys(&index.files, &wanted);
            self.hydrate_index_pass(ns, &wanted, &keys, index);
        }
        gate
    }

    /// C14's first part, under the lock: the gate slot (`begin_pass_of`
    /// for the page's kind), and the parent digests of this namespace's
    /// entries (None: it has none, and C14 builds nothing).
    pub(in crate::snapshots) fn open_index_pass(
        &mut self,
        ns: u128,
        now: u64,
        kind: crate::snapshots::CodexPageKind,
    ) -> (GateOpen, Option<BTreeSet<u128>>) {
        let gate = self.begin_pass_of(ns, now, kind);
        if !self.has_namespace(ns) {
            return (gate, None);
        }
        let wanted = self.namespace(ns).map(|(key, _)| key.p).collect();
        (gate, Some(wanted))
    }

    /// C14's last part, under the lock again: prune and eager hydrate of
    /// this namespace's entries against `keys` (`index_parent_keys` of the
    /// index as loaded, for `wanted`). An entry whose parent is not in
    /// `wanted` was written since the first part and is kept as it is.
    pub(in crate::snapshots) fn hydrate_index_pass(
        &mut self,
        ns: u128,
        wanted: &BTreeSet<u128>,
        keys: &BTreeMap<u128, String>,
        index: &mut crate::snapshots::ScanIndex,
    ) {
        let requests = &index.codex_parent_side_requests;
        let records = &index.codex_parent_side;
        // D5′: the different-object terms prune only an entry a successful
        // selected save of this slot proves; anything uncertain is kept and
        // hydrated (the kept entry is the pacing).
        let covered = self
            .namespace(ns)
            .filter(|(_, entry)| self.saved_covers(ns, entry))
            .map(|(key, _)| *key)
            .collect::<std::collections::BTreeSet<_>>();
        self.prune(ns, |key, entry| {
            // (c) P left the index, and a successful selected save holds
            // that (R2-L7, r79): an unsaved charge keeps its custody.
            let Some(p_key) = keys.get(&key.p) else {
                return wanted.contains(&key.p) && covered.contains(key);
            };
            let record = records.get(p_key);
            // (c) the saved record is for another object.
            if record.is_some_and(|record| record.parsed.dev_ino() != (key.dev, key.ino))
                && covered.contains(key)
            {
                return true;
            }
            match requests.get(p_key) {
                // (c) the saved request is for another object.
                Some(loaded) if loaded.dev_ino != (key.dev, key.ino) => covered.contains(key),
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
                // D5′: this key's generation ended, so only this object's
                // request goes; a replacement's request (another key of the
                // same P, hydrated in either key order) stays.
                LedgerTag::Gone => {
                    if index
                        .codex_parent_side_requests
                        .get(p_key)
                        .is_some_and(|request| request.dev_ino == (key.dev, key.ino))
                    {
                        index.codex_parent_side_requests.remove(p_key);
                    }
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
            // D6(b): the loaded same-object request's epoch survives the
            // hydrate; none (a lost save) is 0, unknown, never pruned.
            let epoch = index
                .codex_parent_side_requests
                .get(p_key)
                .filter(|loaded| loaded.dev_ino == (key.dev, key.ino))
                .map_or(0, |loaded| loaded.referenced_epoch);
            if let Some(request) = entry.request((key.dev, key.ino), epoch) {
                index
                    .codex_parent_side_requests
                    .insert(p_key.clone(), request);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap_layout_bound::layout_supported;
    use crate::snapshots::{SideRequest, SideRequestState};

    fn entry() -> LedgerEntry {
        LedgerEntry {
            tag: LedgerTag::Live,
            attempts: 1,
            wseq: 0,
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
        let mark = ledger.save_mark(x);
        ledger.note_saved(x, 1001, true, mark);
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
        let mark = ledger.save_mark(5);
        ledger.note_saved(5, 25, false, mark);
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
                referenced_epoch: 7,
            };
            let entry = LedgerEntry::of_request(&request);
            assert_eq!(entry.request((3, 4), 7), Some(request));
            // D6(b): the epoch is index-only; the projection ignores it.
            assert_eq!(
                LedgerEntry::of_request(&SideRequest {
                    referenced_epoch: 0,
                    ..request
                }),
                entry
            );
            assert!(entry.same_projection(&LedgerEntry {
                wseq: 9,
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
        assert_eq!(removed.request((1, 1), 0), None);
        assert_eq!(
            LedgerEntry {
                tag: LedgerTag::Gone,
                ..entry()
            }
            .request((1, 1), 0),
            None
        );
    }

    #[test]
    fn only_the_charge_creates_and_every_write_stamps_a_fresh_wseq() {
        let mut ledger = SideLedger::default();
        // Placing the slot takes stamp 1.
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
            Some(&LedgerEntry { wseq: 2, ..cured })
        );
        assert!(ledger.write_existing(&key(1, 1), cured));
        assert_eq!(ledger.get(&key(1, 1)).unwrap().wseq, 3);
    }

    fn file_entry() -> crate::snapshots::ScanIndexEntry {
        crate::snapshots::ScanIndexEntry {
            codex_fragment: None,
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
            codex_counting_owner: None,
            opened_changed_nanos: 0,
            opened_birth_nanos: 0,
            upload_context_receipt: None,
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
        // Every entry below is written in an earlier pass whose save is
        // proven (see the end of the setup), so (c) may prune.
        ledger.begin_pass(ns, 50);
        let live = stamped(&mut ledger, live);
        // (a) saved.
        index
            .codex_parent_side_requests
            .insert("/a".into(), live.request((1, 1), 0).unwrap());
        ledger.entries.insert(at("/a", 1), live);
        // An unsaved charge: the index holds the older attempt count.
        let older = LedgerEntry {
            attempts: 1,
            ..entry()
        };
        index
            .codex_parent_side_requests
            .insert("/b".into(), older.request((1, 2), 0).unwrap());
        ledger.entries.insert(at("/b", 2), live);
        // (c) the saved request is for another object.
        index
            .codex_parent_side_requests
            .insert("/c".into(), live.request((1, 30), 0).unwrap());
        ledger.entries.insert(at("/c", 3), live);
        // (c) Gone and the index agrees; Gone with a saved request.
        let gone = stamped(
            &mut ledger,
            LedgerEntry {
                tag: LedgerTag::Gone,
                ..entry()
            },
        );
        ledger.entries.insert(at("/d", 4), gone);
        index
            .codex_parent_side_requests
            .insert("/e".into(), live.request((1, 5), 0).unwrap());
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
        let mark = ledger.save_mark(ns);
        ledger.note_saved(ns, 60, false, mark);

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
        assert_eq!(requests.get("/a"), live.request((1, 1), 0).as_ref());
        assert_eq!(requests.get("/b"), live.request((1, 2), 0).as_ref());
        assert_eq!(requests.get("/c"), live.request((1, 30), 0).as_ref());
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

    /// R2-L7 (r79): P's leaving the index prunes its entry only once a
    /// successful selected save holds it; an unsaved charge keeps custody.
    #[test]
    fn p_left_the_index_prunes_only_saved_charges() {
        let ns = 13;
        let left = LedgerKey {
            ns,
            p: parent_of("/left"),
            dev: 1,
            ino: 7,
        };
        let mut index = crate::snapshots::ScanIndex::default();
        index.files.insert("/other".into(), file_entry());
        let mut ledger = SideLedger::default();
        ledger.begin_pass(ns, 50);
        let charged = stamped(
            &mut ledger,
            LedgerEntry {
                attempts: 3,
                ..entry()
            },
        );
        ledger.entries.insert(left, charged);
        ledger.begin_index_pass(ns, 100, &mut index);
        assert_eq!(ledger.get(&left), Some(&charged), "unsaved: kept");
        let mark = ledger.save_mark(ns);
        ledger.note_saved(ns, 110, false, mark);
        ledger.begin_index_pass(ns, 200, &mut index);
        assert_eq!(ledger.get(&left), None, "saved: pruned");
    }

    /// `entry` as the ledger's next write would stamp it.
    fn stamped(ledger: &mut SideLedger, entry: LedgerEntry) -> LedgerEntry {
        LedgerEntry {
            wseq: ledger.next_wseq(),
            ..entry
        }
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
        ledger.begin_pass(ns, 50);
        let removed = stamped(&mut ledger, removed);
        ledger.entries.insert(at("/cover", 1), removed);
        ledger.entries.insert(at("/short", 2), removed);
        ledger.entries.insert(at("/short-paced", 3), removed);
        ledger.entries.insert(at("/other", 4), removed);
        // A proven save of this slot holds them all (so (c) may prune /other).
        let mark = ledger.save_mark(ns);
        ledger.note_saved(ns, 60, false, mark);

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

    /// D5′ controls: one parent `P` replaced between objects.
    const P: &str = "/p.jsonl";

    fn pkey(ns: u128, ino: u64) -> LedgerKey {
        LedgerKey {
            ns,
            p: parent_of(P),
            dev: 1,
            ino,
        }
    }

    fn index_with_p() -> crate::snapshots::ScanIndex {
        let mut index = crate::snapshots::ScanIndex::default();
        index.files.insert(P.into(), file_entry());
        index
    }

    /// G7: the side charge writes the entry and P's request in one step.
    fn g7(
        ledger: &mut SideLedger,
        index: &mut crate::snapshots::ScanIndex,
        key: LedgerKey,
        attempts: u8,
    ) -> SideRequest {
        let charged = LedgerEntry {
            attempts,
            ..entry()
        };
        assert!(ledger.charge(key, charged, 100).is_ok());
        let request = charged.request((key.dev, key.ino), 0).unwrap();
        index.codex_parent_side_requests.insert(P.into(), request);
        request
    }

    /// A replace: the old key's generation ends (`Gone`) and its request goes.
    fn replace(ledger: &mut SideLedger, index: &mut crate::snapshots::ScanIndex, old: LedgerKey) {
        let held = *ledger.get(&old).unwrap();
        assert!(ledger.write_existing(
            &old,
            LedgerEntry {
                tag: LedgerTag::Gone,
                ..held
            }
        ));
        index.codex_parent_side_requests.remove(P);
    }

    /// A successful selected save: the mark read before it, `note_saved` on
    /// `Ok`. Returns the saved file.
    fn save(
        ledger: &mut SideLedger,
        index: &crate::snapshots::ScanIndex,
        ns: u128,
        full: bool,
    ) -> crate::snapshots::ScanIndex {
        let mark = ledger.save_mark(ns);
        let saved = index.clone();
        ledger.note_saved(ns, 110, full, mark);
        saved
    }

    fn tags(ledger: &SideLedger, ns: u128) -> BTreeMap<LedgerKey, (LedgerTag, u8)> {
        ledger
            .namespace(ns)
            .map(|(key, entry)| (*key, (entry.tag, entry.attempts)))
            .collect()
    }

    /// D5′ (i), U-T60(d)(xvii): a replace before a failed save. The new
    /// key's charge is kept and hydrated with its attempts (no reset), and
    /// the old key's `Gone` removes nothing of the replacement's, in both
    /// key orders.
    #[test]
    fn d5_replace_before_a_failed_save_keeps_the_new_charge_in_either_key_order() {
        if !layout_supported() {
            return;
        }
        for (old_ino, new_ino) in [(5, 9), (9, 5)] {
            let ns = 21;
            let (old, new) = (pkey(ns, old_ino), pkey(ns, new_ino));
            let mut ledger = SideLedger::default();
            let mut work = index_with_p();
            ledger.begin_index_pass(ns, 100, &mut work);
            g7(&mut ledger, &mut work, old, 1);
            let file = save(&mut ledger, &work, ns, true);
            // The next pass charges the old object again, then P is replaced
            // and the new object charged; the pass fails (no C15).
            let mut work = file.clone();
            ledger.begin_index_pass(ns, 200, &mut work);
            g7(&mut ledger, &mut work, old, 2);
            replace(&mut ledger, &mut work, old);
            let charged = g7(&mut ledger, &mut work, new, 3);
            let mut loaded = file.clone();
            ledger.begin_index_pass(ns, 300, &mut loaded);
            assert_eq!(
                tags(&ledger, ns),
                BTreeMap::from([(old, (LedgerTag::Gone, 2)), (new, (LedgerTag::Live, 3))]),
                "{old_ino} -> {new_ino}"
            );
            assert_eq!(loaded.codex_parent_side_requests.get(P), Some(&charged));
        }
    }

    /// D5′ (ii), the parent's counterexample: a partial save, then a replace
    /// and a charge in the same pass, then a failed full save. The partial
    /// save's mark does not cover the later charge.
    #[test]
    fn d5_partial_save_before_a_replace_then_failure_keeps_the_new_charge() {
        if !layout_supported() {
            return;
        }
        for (old_ino, new_ino) in [(5, 9), (9, 5)] {
            let ns = 22;
            let (old, new) = (pkey(ns, old_ino), pkey(ns, new_ino));
            let mut ledger = SideLedger::default();
            let mut work = index_with_p();
            ledger.begin_index_pass(ns, 100, &mut work);
            g7(&mut ledger, &mut work, old, 1);
            let partial = save(&mut ledger, &work, ns, false);
            replace(&mut ledger, &mut work, old);
            let charged = g7(&mut ledger, &mut work, new, 2);
            // The full save fails: no C15.
            let mut loaded = partial.clone();
            ledger.begin_index_pass(ns, 200, &mut loaded);
            assert_eq!(
                tags(&ledger, ns),
                BTreeMap::from([(old, (LedgerTag::Gone, 1)), (new, (LedgerTag::Live, 2))]),
                "{old_ino} -> {new_ino}"
            );
            assert_eq!(loaded.codex_parent_side_requests.get(P), Some(&charged));
        }
    }

    /// D5′ (iii) and (iii′): a saved replacement prunes both keys; a later
    /// replace written after that save's mark, then a failure, is kept.
    #[test]
    fn d5_saved_replacement_prunes_and_a_later_unsaved_replace_is_kept() {
        if !layout_supported() {
            return;
        }
        for (old_ino, new_ino, third_ino) in [(5, 9, 13), (13, 9, 5)] {
            let ns = 23;
            let (old, new, third) = (pkey(ns, old_ino), pkey(ns, new_ino), pkey(ns, third_ino));
            let mut ledger = SideLedger::default();
            let mut work = index_with_p();
            ledger.begin_index_pass(ns, 100, &mut work);
            g7(&mut ledger, &mut work, old, 1);
            replace(&mut ledger, &mut work, old);
            let saved_request = g7(&mut ledger, &mut work, new, 2);
            let file = save(&mut ledger, &work, ns, true);
            let mut loaded = file.clone();
            ledger.begin_index_pass(ns, 200, &mut loaded);
            assert_eq!(tags(&ledger, ns), BTreeMap::new());
            assert_eq!(
                loaded.codex_parent_side_requests.get(P),
                Some(&saved_request)
            );
            // (iii′) This pass replaces again after the save, then fails.
            g7(&mut ledger, &mut loaded, new, 3);
            replace(&mut ledger, &mut loaded, new);
            let charged = g7(&mut ledger, &mut loaded, third, 1);
            let mut reloaded = file.clone();
            ledger.begin_index_pass(ns, 300, &mut reloaded);
            assert_eq!(
                tags(&ledger, ns),
                BTreeMap::from([(new, (LedgerTag::Gone, 3)), (third, (LedgerTag::Live, 1))])
            );
            assert_eq!(reloaded.codex_parent_side_requests.get(P), Some(&charged));
        }
    }

    /// D5′ (iv): a namespace whose slot was replaced comes back with a fresh
    /// slot and no proven save, so its mismatched entry is kept; the
    /// namespace that reused its slot index is never pruned by its marks.
    #[test]
    fn d5_replaced_or_reused_slot_proves_nothing() {
        if !layout_supported() {
            return;
        }
        let x = 31;
        let mut ledger = SideLedger::default();
        let mut work = index_with_p();
        ledger.begin_index_pass(x, 100, &mut work);
        let stale = g7(&mut ledger, &mut work, pkey(x, 5), 1);
        save(&mut ledger, &work, x, true);
        // A file that now holds another object for P.
        let mut other = index_with_p();
        other.codex_parent_side_requests.insert(
            P.into(),
            SideRequest {
                dev_ino: (1, 77),
                ..stale
            },
        );
        let at = ledger
            .gate
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.ns == x))
            .unwrap();
        for ns in 100..100 + GATE_SLOTS as u128 {
            ledger.begin_pass(ns, 200 + ns as u64);
        }
        assert!(ledger.slot(x).is_none());
        let y = ledger.gate[at].unwrap().ns;
        // Y's entry is stamped before X's save (inside X's old watermark).
        ledger.entries.insert(
            pkey(y, 6),
            LedgerEntry {
                attempts: 4,
                wseq: 1,
                ..entry()
            },
        );
        let mut loaded = other.clone();
        ledger.begin_index_pass(y, 400, &mut loaded);
        assert_eq!(tags(&ledger, y).len(), 1, "Y's entry is kept");
        // X's fresh slot: the earlier save proves nothing.
        let mut loaded = other.clone();
        ledger.begin_index_pass(x, 500, &mut loaded);
        assert_eq!(
            tags(&ledger, x),
            BTreeMap::from([(pkey(x, 5), (LedgerTag::Live, 1))])
        );
        assert_eq!(loaded.codex_parent_side_requests.get(P), Some(&stale));
    }

    /// D5′ custody: a save callback with a mark read for a slot that was
    /// replaced and re-placed since, or for another namespace, moves no
    /// watermark and does not open the gate.
    #[test]
    fn d5_stale_or_foreign_marks_move_nothing() {
        let (x, y) = (41, 42);
        let mut ledger = SideLedger::default();
        ledger.begin_pass(x, 100);
        ledger.begin_pass(y, 100);
        let stale = ledger.save_mark(x);
        for ns in 100..100 + GATE_SLOTS as u128 {
            ledger.begin_pass(ns, 200 + ns as u64);
        }
        ledger.begin_pass(x, 300);
        let fresh = *ledger.slot(x).unwrap();
        assert_ne!(fresh.incarnation, stale.incarnation);
        ledger.note_saved(x, 310, true, stale);
        assert_eq!(*ledger.slot(x).unwrap(), fresh);
        assert!(!ledger.begin_pass(x, 320).side_allowed);
        // Another namespace's mark never lands on this slot.
        ledger.begin_pass(y, 330);
        let y_slot = *ledger.slot(y).unwrap();
        ledger.note_saved(y, 340, true, ledger.save_mark(x));
        assert_eq!(*ledger.slot(y).unwrap(), y_slot);
        // A current mark does.
        let mark = ledger.save_mark(y);
        ledger.note_saved(y, 350, true, mark);
        let saved = ledger.slot(y).unwrap();
        assert!(saved.saved);
        assert_eq!(
            (saved.saved_wseq, saved.full_saved_wseq),
            (ledger.wseq, ledger.wseq)
        );
    }

    /// D5′ (vii): a write between the mark and the successful save's
    /// callback is not covered by it.
    #[test]
    fn d5_a_write_after_the_mark_is_not_covered() {
        if !layout_supported() {
            return;
        }
        let ns = 61;
        let (old, new) = (pkey(ns, 5), pkey(ns, 9));
        let mut ledger = SideLedger::default();
        let mut work = index_with_p();
        ledger.begin_index_pass(ns, 100, &mut work);
        g7(&mut ledger, &mut work, old, 1);
        let mark = ledger.save_mark(ns);
        let file = work.clone();
        replace(&mut ledger, &mut work, old);
        let charged = g7(&mut ledger, &mut work, new, 2);
        ledger.note_saved(ns, 110, true, mark);
        let mut loaded = file.clone();
        ledger.begin_index_pass(ns, 200, &mut loaded);
        assert_eq!(
            tags(&ledger, ns),
            BTreeMap::from([(old, (LedgerTag::Gone, 1)), (new, (LedgerTag::Live, 2))])
        );
        assert_eq!(loaded.codex_parent_side_requests.get(P), Some(&charged));
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

    /// Stage 1 C-1 (a), (b): a continuation pass reads the gate and leaves
    /// `saved` and `last_pass_unix` as they were, so the next ordinary pass
    /// sees the last ordinary save's outcome; the ordinary pass is unchanged.
    /// A namespace with no slot (evicted) is placed as for an ordinary pass.
    #[test]
    fn a_continuation_pass_keeps_the_gate_and_places_a_missing_slot() {
        use crate::snapshots::CodexPageKind::Continuation;
        let mut ledger = SideLedger::default();
        // (a) The ordinary save succeeded.
        ledger.begin_pass(5, 10);
        let mark = ledger.save_mark(5);
        ledger.note_saved(5, 15, false, mark);
        let saved = *ledger.slot(5).unwrap();
        assert!(saved.saved);
        for now in [20, 21, 22] {
            assert!(ledger.begin_pass_of(5, now, Continuation).side_allowed);
            assert_eq!(*ledger.slot(5).unwrap(), saved, "neither cleared nor set");
        }
        assert!(ledger.begin_pass(5, 30).side_allowed, "next ordinary");
        // (b) That ordinary pass's save failed: a continuation does not
        // open the gate.
        let unsaved = *ledger.slot(5).unwrap();
        assert_eq!((unsaved.saved, unsaved.last_pass_unix), (false, 30));
        assert!(!ledger.begin_pass_of(5, 40, Continuation).side_allowed);
        assert_eq!(*ledger.slot(5).unwrap(), unsaved);
        assert!(!ledger.begin_pass(5, 50).side_allowed, "still gated");
        // Evicted by GATE_SLOTS newer namespaces: placed as today.
        for ns in 100..100 + GATE_SLOTS as u128 {
            ledger.begin_pass(ns, 60 + ns as u64);
        }
        assert!(ledger.slot(5).is_none());
        let incarnation = ledger.wseq + 1;
        assert!(ledger.begin_pass_of(5, 500, Continuation).side_allowed);
        assert_eq!(
            *ledger.slot(5).unwrap(),
            GateSlot {
                ns: 5,
                saved: false,
                last_pass_unix: 500,
                last_saved_unix: 500,
                incarnation,
                saved_wseq: 0,
                full_saved_wseq: 0,
            }
        );
        assert!(!ledger.begin_pass(5, 510).side_allowed);
    }

    /// Stage 1 C-1 (c): the EOF continuation page's full save (C15 on its
    /// `Ok` arm, mark read before it) moves the slot's watermarks and opens
    /// the gate; the continuation's C14 before it moved nothing.
    #[test]
    fn an_eof_continuation_save_moves_the_watermarks() {
        use crate::snapshots::CodexPageKind::Continuation;
        if !layout_supported() {
            return;
        }
        let ns = 61;
        let mut ledger = SideLedger::default();
        ledger.begin_pass(ns, 100);
        // An ordinary charge whose save failed.
        ledger.charge(key(ns, 1), entry(), 100).unwrap();
        let charged = *ledger.get(&key(ns, 1)).unwrap();
        assert!(!ledger.saved_covers(ns, &charged));
        let before = *ledger.slot(ns).unwrap();
        assert!(!ledger.begin_pass_of(ns, 200, Continuation).side_allowed);
        assert_eq!(*ledger.slot(ns).unwrap(), before, "C14 moves nothing");
        let mark = ledger.save_mark(ns);
        ledger.note_saved(ns, 300, true, mark);
        let slot = *ledger.slot(ns).unwrap();
        assert!(slot.saved);
        assert_eq!(
            (slot.saved_wseq, slot.full_saved_wseq),
            (ledger.wseq, ledger.wseq)
        );
        assert_eq!((slot.last_saved_unix, slot.last_pass_unix), (300, 100));
        assert!(ledger.saved_covers(ns, &charged), "the charge is on disk");
        assert!(ledger.begin_pass(ns, 400).side_allowed);
    }
}
