//! One durable request-census record per Claude transcript (index
//! key), bound to the exact revision and census window that produced it, plus
//! a shadow of the convergence predicate those records would allow.
//!
//! A record is local-only and content-free: the sorted 8-byte SHA-256 prefixes
//! of the provider request ids one parse saw. It is never proof, usage or
//! upload input. This module only produces, persists and measures records; no
//! fence, coverage, posture or upload decision reads them. A record lives
//! while its file is indexed (or is held-new custody) and leaves only with
//! the file, at a positive-absence exit. No age, budget or pressure retires
//! or refuses one. The narrowed
//! unhealthy-retry carry conservatively refuses its per-family exception
//! on saved negative evidence for loss or incomplete identity, and uses a
//! bound native record only to refuse additional causes in the narrow id-less
//! exception. A record never supplies a body ACK or new-window coverage.
//!
//! Census state follows the working index (`self`), never `previous`: a held
//! or partially committed key keeps the record of the revision this window
//! parsed, even when its entry reverts. A failed object/scope check invalidates
//! the record, keeping only the first-seen birth of the same physical object
//! (a birth stub every reader treats as absent).

use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref, rfc3339_unix_seconds,
    ClaudeRequestCensusShadowCounts, ScanIndex, ScanIndexEntry, SharedMap, SnapshotItem,
};

/// The duplicate-owner bound of the shadow disjointness measure.
const MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS: usize = 250_000;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

// N1 diagnostics only: process totals on the existing local census line.
// Reloading a held record does not enter it again; a lost/over-budget record
// is not a successful clearance. No persisted or uploaded bookkeeping.
// Slots: entered, cleared.
crate::local_resource_diagnostics::process_static!(fn with_identity_incomplete_holds:
    [std::sync::atomic::AtomicU64; 2] = [const { std::sync::atomic::AtomicU64::new(0) }; 2]);

fn add_identity_incomplete_hold_total(slot: usize, count: u64) {
    with_identity_incomplete_holds(|totals| {
        let _ = totals[slot].fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |total| Some(total.saturating_add(count)),
        );
    });
}

fn identity_incomplete_hold_total(slot: usize) -> u64 {
    with_identity_incomplete_holds(|totals| totals[slot].load(std::sync::atomic::Ordering::Relaxed))
}

fn note_identity_incomplete_hold(entered: bool, cleared: bool) {
    for (slot, changed) in [entered, cleared].into_iter().enumerate() {
        if changed {
            add_identity_incomplete_hold_total(slot, 1);
        }
    }
}

/// Independent relaxed process totals (entered, cleared), test-thread local
/// in unit tests as the existing history-upgrade local counts are.
pub(super) fn identity_incomplete_hold_totals() -> (u64, u64) {
    (
        identity_incomplete_hold_total(0),
        identity_incomplete_hold_total(1),
    )
}

/// Bumped only when request-id or occurrence extraction, or the shape rule,
/// changes. A bump makes every stored record inert until its file is parsed
/// again. `CLAUDE_REQUEST_CENSUS_CANARY` pins what the fixed fixture corpus
/// yields under it; a change to that literal without a bump needs review.
pub(crate) const CLAUDE_REQUEST_CENSUS_DERIVATION: u16 = 1;
/// `(derivation, sha256 of the canary corpus table)`. The derivation canary
/// test fails until both move together.
#[cfg(test)]
pub(crate) const CLAUDE_REQUEST_CENSUS_CANARY: (u16, &str) = (
    1,
    "13c57766a314142a46296ef186e752768a2e5dd18822bb8c0a9300bcfc74af76",
);
/// Alarm base only: the per-pass `claude_state_v2` line flags census
/// occupancy at 75% of this many request hashes. Nothing refuses, strips or
/// tombstones a record by it; a record lives while its file is indexed.
pub(crate) const CLAUDE_REQUEST_CENSUS_HASH_ALARM_BASE: usize = 2_097_152;
const MAX_SHADOW_ENTRIES: usize = 65_536;
const MAX_SHADOW_WORKSPACE_BYTES: usize = 128 * 1024 * 1024;
const MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES: usize = 4_096;
/// Longest scalar string the decoder copies (a fingerprint is 64 bytes).
const MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRequestCensusShape {
    /// Loss-free, identity complete, at least one id (zero-usage ids included).
    Exact,
    /// Loss-free, identity complete, no id.
    Empty,
    /// Loss-free, but an id-less response or one id on two responses.
    IdentityIncomplete,
    /// Parse loss: a dropped response, line loss, an incomplete or residue
    /// parse, or more than one item. Hashes are the ids seen.
    Lossy,
    /// Tombstone an older release stored when its hash budget was full: no
    /// hashes. Nothing produces one now; stored ones load as they are.
    OverBudget,
}

impl ClaudeRequestCensusShape {
    const ALL: [Self; 5] = [
        Self::Exact,
        Self::Empty,
        Self::IdentityIncomplete,
        Self::Lossy,
        Self::OverBudget,
    ];

    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Empty => "empty",
            Self::IdentityIncomplete => "identity_incomplete",
            Self::Lossy => "lossy",
            Self::OverBudget => "over_budget",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|shape| shape.wire() == value)
    }

    /// Exact needs an id; Empty and the tombstone carry none.
    fn admits(self, request_hashes: &[u64]) -> bool {
        match self {
            Self::Exact => !request_hashes.is_empty(),
            Self::Empty | Self::OverBudget => request_hashes.is_empty(),
            Self::IdentityIncomplete | Self::Lossy => true,
        }
    }

    /// The record leaves its own family census-unknown.
    fn unknown(self) -> bool {
        matches!(self, Self::IdentityIncomplete | Self::Lossy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensusRecord {
    /// The parse's candidate fingerprint (sidecar-inclusive), whether or not
    /// the entry was recorded with it.
    source_file_fingerprint: [u8; 32],
    /// `CLAUDE_REQUEST_CENSUS_DERIVATION` at production.
    derivation: u16,
    /// The census window end (unix seconds) of the traversal that parsed it.
    window: u64,
    shape: ClaudeRequestCensusShape,
    /// The parsed content (root, member) differs from the path-derived pair.
    twin: bool,
    /// Not source-verified (a tail parse that still owes
    /// its sampled audit, or a read that cannot certify its source). The census
    /// produces it as for a verified parse and only notes it here.
    unverified: bool,
    /// Sorted, strictly ascending `claude_request_hash` of every request id
    /// (None: none). Shared, never copied, by every clone of the index (the
    /// working, committed and selected-subset copies hold one buffer).
    request_hashes: Option<Arc<[u64]>>,
    /// First-seen birth of the physical object at this key, set once and
    /// bound to its (device, inode).
    birth: Option<ClaudeRequestBirth>,
    /// Retired: the hashes were dropped (old, settled file); this is how many
    /// there were. A retired record still counts as recorded.
    retired: Option<u64>,
    /// Old-path requests and conserved tokens last built from this file.
    old_path_usage: Option<(u64, u64)>,
    /// The file's modification time (unix seconds) at the parse that wrote
    /// the record.
    modified: Option<u64>,
}

/// First-seen creation time of one physical file, with the identity of the
/// object it was read from. A different device or inode is a different
/// object, so its birth is never carried onto the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaudeRequestBirth {
    pub(crate) unix_seconds: u64,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestBirth {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        Some(())
    }
}

/// One shared hash buffer: the slice and the `Arc` counts.
fn shared_hashes_bytes(hashes: &Option<Arc<[u64]>>) -> usize {
    hashes.as_ref().map_or(0, |hashes| {
        hashes.len() * std::mem::size_of::<u64>() + 2 * std::mem::size_of::<usize>()
    })
}

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestCensusRecord {
    // Owns one shared u64 buffer.
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Exhaustive destructuring: a new owned field is a compile error until
        // it is charged here. The inline fields own no heap. A shared buffer
        // is charged in full in every clone (never less than one copy each).
        let Self {
            source_file_fingerprint: _,
            derivation: _,
            window: _,
            shape: _,
            twin: _,
            unverified: _,
            request_hashes,
            birth: _,
            retired: _,
            old_path_usage: _,
            modified: _,
        } = self;
        c.add(shared_hashes_bytes(request_hashes))
    }
}

/// A sorted unique hash list as a shared buffer (None when empty).
pub(crate) fn shared_hashes(hashes: Vec<u64>) -> Option<Arc<[u64]>> {
    (!hashes.is_empty()).then(|| Arc::from(hashes))
}

impl ClaudeRequestCensusRecord {
    /// What the census hash total counts.
    fn hash_count(&self) -> usize {
        self.request_hashes().len()
    }

    pub(crate) fn request_hashes(&self) -> &[u64] {
        self.request_hashes.as_deref().unwrap_or(&[])
    }

    pub(crate) fn birth(&self) -> Option<ClaudeRequestBirth> {
        self.birth
    }

    pub(crate) fn retired(&self) -> Option<u64> {
        self.retired
    }

    /// The census window end of the traversal that parsed it.
    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    /// The file's modification time at the parse.
    pub(crate) fn modified(&self) -> Option<u64> {
        self.modified
    }

    /// Missing ids in a lossy scan cannot disprove an earlier removal.
    pub(crate) fn is_lossy(&self) -> bool {
        self.shape == ClaudeRequestCensusShape::Lossy
    }

    pub(crate) fn over_budget(&self) -> bool {
        self.shape == ClaudeRequestCensusShape::OverBudget
    }

    pub(crate) fn current_derivation(&self) -> bool {
        self.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION
    }

    /// Not source-verified (S2, prefix-certified reads included) or a path
    /// twin: never complete evidence for a negative claim.
    pub(crate) fn unverified_or_twin(&self) -> bool {
        self.unverified || self.twin
    }

    /// Neither a path twin nor retired.
    fn not_twin_or_retired(&self) -> bool {
        !self.twin && self.retired.is_none()
    }

    /// Source-verified, neither a path twin nor retired.
    fn verified_not_twin_or_retired(&self) -> bool {
        !self.unverified && self.not_twin_or_retired()
    }

    /// A current native body can supersede an unverified census record only if
    /// the record describes a complete, loss-free parse of that revision.
    /// Terminal oversized-line settlement is NOT complete proof evidence.
    /// Identity-incomplete records wait for a Full audit: saved-witness
    /// reconstruction does not itself refuse their bodies.
    pub(crate) fn can_bind_recomposed_body(&self) -> bool {
        self.current_derivation()
            && self.not_twin_or_retired()
            && matches!(
                self.shape,
                ClaudeRequestCensusShape::Exact | ClaudeRequestCensusShape::Empty
            )
    }

    /// An unverified identity-incomplete record holds its root until a
    /// Full audit verifies its source (delay, never cancel).
    pub(super) fn identity_incomplete_hold(&self) -> bool {
        self.current_derivation()
            && self.unverified
            && self.not_twin_or_retired()
            && self.shape == ClaudeRequestCensusShape::IdentityIncomplete
    }

    /// `e2` copy proof: this record is the census of the entry's CURRENT
    /// revision (same fingerprint, current derivation, its own content) and
    /// still lists every request id it read. Retired and over-budget records
    /// dropped their hashes, so they prove nothing.
    pub(crate) fn proves_current(&self, entry_fingerprint: &str) -> bool {
        self.proves_scan() && fingerprint_matches(self, entry_fingerprint)
    }

    /// `e2` copy proof from a scan whose upload is withheld (its index entry
    /// not advanced): the record of that scan still lists every request id
    /// it read (current derivation, its own content, not retired or over
    /// budget). The caller binds it to the file.
    pub(crate) fn proves_scan(&self) -> bool {
        self.current_derivation()
            && self.not_twin_or_retired()
            && self.shape != ClaudeRequestCensusShape::OverBudget
    }

    /// The record lists `hash` (`claude_request_hash`).
    pub(crate) fn holds_hash(&self, hash: u64) -> bool {
        self.request_hashes().binary_search(&hash).is_ok()
    }

    /// A #588/failed-finish invalidation kept only the first-seen birth:
    /// every reader treats the key as having no record.
    pub(crate) fn is_birth_stub(&self) -> bool {
        self.derivation == BIRTH_STUB_DERIVATION
    }

    fn birth_stub(birth: ClaudeRequestBirth) -> Self {
        Self {
            derivation: BIRTH_STUB_DERIVATION,
            birth: Some(birth),
            ..Self::bookkeeping([0; 32], 0)
        }
    }

    /// A record with no hashes and no optional field.
    fn bookkeeping(fingerprint: [u8; 32], window: u64) -> Self {
        Self {
            source_file_fingerprint: fingerprint,
            derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
            window,
            shape: ClaudeRequestCensusShape::Empty,
            twin: false,
            unverified: false,
            request_hashes: None,
            birth: None,
            retired: None,
            old_path_usage: None,
            modified: None,
        }
    }

    /// Strict freshness (Sol N6): this record is the current census of the
    /// entry whose fingerprint is `entry_fingerprint`. Lossy, identity
    /// incomplete, unverified, over-budget, retired or other-derivation
    /// records are unknown, never current.
    pub(crate) fn current_for(&self, entry_fingerprint: &str) -> bool {
        self.current_derivation()
            && matches!(
                self.shape,
                ClaudeRequestCensusShape::Exact | ClaudeRequestCensusShape::Empty
            )
            && self.verified_not_twin_or_retired()
            && fingerprint_matches(self, entry_fingerprint)
    }
}

/// Keys of the retired money ledger. An older build could leave one in the
/// index; every census decoder drops it. Ordinary keys are absolute file
/// paths (`local_index_key`), so they always start with `/`.
fn is_ledger_key(key: &str) -> bool {
    ["otel:", "sweep:", "fam:", "mh:"]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

/// Birth stubs carry this derivation, which no parse ever produces.
const BIRTH_STUB_DERIVATION: u16 = 0;

/// The record was produced at the entry's fingerprint.
pub(crate) fn fingerprint_matches(
    record: &ClaudeRequestCensusRecord,
    entry_fingerprint: &str,
) -> bool {
    decode_fingerprint(entry_fingerprint)
        .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
}

/// The 8-byte prefix of the SHA-256 that pending already keys request ids by
/// (`format!("{:x}", Sha256::digest(id))`): a pending hash maps to a record
/// hash by its first 16 hex digits.
pub(crate) fn claude_request_hash(request_id: &str) -> u64 {
    let digest = Sha256::digest(request_id.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// `ScanIndex::claude_request_census`: every record by index key, with the
/// hash total kept in step for the occupancy alarm. A record lives while its
/// file is indexed (or is held-new custody) and leaves only at a
/// positive-absence exit (`ScanIndex::drop_file_entry`) or a replacement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensus {
    records: SharedMap<String, ClaudeRequestCensusRecord>,
    hash_total: usize,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensus; records, hash_total);

/// One family's answer from [`ClaudeRequestCensus::family_transcript_holders`].
#[derive(Debug, Default)]
pub(crate) struct ClaudeFamilyHolders {
    /// Candidate request hashes some transcript record of the family holds.
    pub(crate) held: BTreeSet<u64>,
    /// Family members (`root` or `root_agent-*`) that have a record.
    pub(crate) members: BTreeSet<String>,
}

/// The sorted unique `candidates` a transcript record holds.
pub(super) fn held_candidates<'a>(
    record: &'a ClaudeRequestCensusRecord,
    candidates: &'a [u64],
) -> impl Iterator<Item = u64> + 'a {
    record
        .request_hashes()
        .iter()
        .copied()
        .filter(move |hash| candidates.binary_search(hash).is_ok())
}

// Test seam: transcript holder walks on this thread hit their deadline
// (bit 1: the copy-decision walk, bit 2: the side-call walk).
#[cfg(test)]
thread_local! {
    static WALK_DEADLINE_FOR_TEST: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
const MAIN_WALK: u8 = 1;
#[cfg(test)]
const FAMILY_WALK: u8 = 2;

#[cfg(test)]
fn walk_deadline_for_test<T>(walks: u8, run: impl FnOnce() -> T) -> T {
    let previous = WALK_DEADLINE_FOR_TEST.with(|slot| slot.replace(walks));
    let value = run();
    WALK_DEADLINE_FOR_TEST.with(|slot| slot.set(previous));
    value
}

/// Every transcript holder walk on this thread hits its deadline.
#[cfg(test)]
pub(crate) fn with_walk_deadline_for_test<T>(run: impl FnOnce() -> T) -> T {
    walk_deadline_for_test(MAIN_WALK | FAMILY_WALK, run)
}

/// Only the side-call (family) walk hits its deadline.
#[cfg(test)]
pub(crate) fn with_side_call_walk_deadline_for_test<T>(run: impl FnOnce() -> T) -> T {
    walk_deadline_for_test(FAMILY_WALK, run)
}

#[cfg(test)]
fn walk_deadline_forced(walk: u8) -> bool {
    WALK_DEADLINE_FOR_TEST.with(std::cell::Cell::get) & walk != 0
}

impl ClaudeRequestCensus {
    /// Storage sees invalidation stubs too; ordinary readers deliberately do not.
    pub(crate) fn storage_records(&self) -> &SharedMap<String, ClaudeRequestCensusRecord> {
        &self.records
    }

    /// Request hashes held, for the occupancy alarm.
    pub(crate) fn hash_total(&self) -> usize {
        self.hash_total
    }

    /// The one insert: replaces `key`'s record whole. No budget refuses,
    /// strips or tombstones a record.
    pub(crate) fn insert(&mut self, key: String, record: ClaudeRequestCensusRecord) {
        self.remove(&key);
        self.hash_total += record.hash_count();
        self.records.insert(key, record);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The key's record; a birth stub is no record.
    pub(crate) fn get(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records
            .get(key)
            .filter(|record| !record.is_birth_stub())
    }

    /// Every record; birth stubs are skipped.
    pub(crate) fn records(&self) -> impl Iterator<Item = (&String, &ClaudeRequestCensusRecord)> {
        self.records
            .iter()
            .filter(|(_, record)| !record.is_birth_stub())
    }

    /// `e2` side calls: which of each wanted family's sorted unique candidate
    /// hashes a transcript record of THAT family holds, and which members
    /// have a record. One walk of the keys (a borrowed path parse, no hash
    /// read outside a wanted family); only the wanted families' records are
    /// intersected. Families never cross. None when `deadline` passes
    /// (checked every 256 records): the caller counts and discloses it.
    pub(crate) fn family_transcript_holders(
        &self,
        wanted: &BTreeMap<&str, Vec<u64>>,
        deadline: std::time::Instant,
    ) -> Option<BTreeMap<String, ClaudeFamilyHolders>> {
        let mut found = BTreeMap::<String, ClaudeFamilyHolders>::new();
        if wanted.is_empty() {
            return Some(found);
        }
        #[cfg(test)]
        if walk_deadline_forced(FAMILY_WALK) {
            return None;
        }
        Self::walk_transcript_holders(self.records(), Some(deadline), |_, member, record| {
            let Some(candidates) = wanted.get(member.root) else {
                return;
            };
            if !found.contains_key(member.root) {
                found.insert(member.root.to_owned(), ClaudeFamilyHolders::default());
            }
            let Some(family) = found.get_mut(member.root) else {
                return;
            };
            family.held.extend(held_candidates(record, candidates));
            family.members.insert(member.into_owned().1);
        })?;
        Some(found)
    }

    /// `e2` copy decisions, once per folder per page: every MAIN transcript
    /// record (never a subagent) directly in `folder` (an index key; None:
    /// every folder) holding some of the sorted unique `wanted` hashes, with
    /// its key, session and the hashes it holds. The caller decides whether
    /// the record proves anything (current revision, other session, earlier
    /// birth). The same walk as `family_transcript_holders`, over the folder's
    /// key range only. None when `deadline` passes: the caller cannot decide.
    pub(crate) fn main_transcript_holders<'a>(
        &'a self,
        folder: Option<&str>,
        wanted: &[u64],
        deadline: Option<std::time::Instant>,
        mut visit: impl FnMut(&'a str, &'a str, &'a ClaudeRequestCensusRecord, &[u64]),
    ) -> Option<()> {
        if wanted.is_empty() {
            return Some(());
        }
        #[cfg(test)]
        if deadline.is_some() && walk_deadline_forced(MAIN_WALK) {
            return None;
        }
        let prefix = folder
            .map(|folder| format!("{folder}{}", std::path::MAIN_SEPARATOR))
            .unwrap_or_default();
        let children = self
            .records
            .range::<str, _>((
                std::ops::Bound::Included(prefix.as_str()),
                std::ops::Bound::Unbounded,
            ))
            .take_while(|(key, _)| key.starts_with(&prefix))
            .filter(|(key, record)| {
                (folder.is_none() || !key[prefix.len()..].contains(std::path::MAIN_SEPARATOR))
                    && !record.is_birth_stub()
            });
        let mut hits = Vec::new();
        Self::walk_transcript_holders(children, deadline, |key, member, record| {
            if member.subagent_stem.is_some() {
                return;
            }
            hits.clear();
            hits.extend(held_candidates(record, wanted));
            if !hits.is_empty() {
                visit(key, member.root, record, &hits);
            }
        })
    }

    /// One walk of `records` (a borrowed path parse per key).
    /// None when a `deadline` passes (checked every 256 records).
    pub(super) fn walk_transcript_holders<'a>(
        records: impl Iterator<Item = (&'a String, &'a ClaudeRequestCensusRecord)>,
        deadline: Option<std::time::Instant>,
        mut visit: impl FnMut(
            &'a str,
            super::ClaudeIndexPathMemberRef<'a>,
            &'a ClaudeRequestCensusRecord,
        ),
    ) -> Option<()> {
        for (position, (key, record)) in records.enumerate() {
            if position % 256 == 255 && deadline.is_some_and(|at| std::time::Instant::now() >= at) {
                return None;
            }
            if let Some(member) = super::claude_index_path_member_ref(Path::new(key)) {
                visit(key, member, record);
            }
        }
        Some(())
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if let Some(old) = self.records.remove(key) {
            self.hash_total -= old.hash_count();
        }
    }

    /// Remove `key`'s record and return it (its hashes move to the caller;
    /// nothing is copied).
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let old = self.records.remove(key)?;
        self.hash_total -= old.hash_count();
        Some(old.into_inner())
    }

    /// Invalidate `key`'s record but keep its first-seen birth in place, so a
    /// re-created record of the SAME physical object keeps it (#588 selected
    /// restore, failed finish, comparison target). The stub replaces the
    /// record in its own map slot: no key or node is allocated, so a prepaid
    /// restore stays within its reservation. Every reader skips stubs.
    pub(crate) fn invalidate_keeping_birth(&mut self, key: &str) {
        let Some(birth) = self.records.get(key).map(|record| record.birth) else {
            return;
        };
        let Some(birth) = birth else {
            self.remove(key);
            return;
        };
        let Some(slot) = self.records.get_mut(key) else {
            return;
        };
        // The old record is dropped (freed), the stub is inline only.
        let old = std::mem::replace(slot, ClaudeRequestCensusRecord::birth_stub(birth));
        self.hash_total -= old.hash_count();
    }

    /// The birth `key`'s next record carries: the old record's (or its
    /// stub's) when the parse read the same physical object, else this read's.
    fn carried_birth(
        &self,
        key: &str,
        opened: Option<ClaudeRequestBirth>,
    ) -> Option<ClaudeRequestBirth> {
        let previous = self.records.get(key).and_then(|record| record.birth);
        match (previous, opened) {
            (Some(previous), Some(opened))
                if previous.device == opened.device && previous.inode == opened.inode =>
            {
                Some(previous)
            }
            // A replacement: a new object, a new first-seen birth.
            (_, Some(opened)) => Some(opened),
            // A read without an opened identity (no creation time) keeps
            // nothing it cannot bind to the object.
            (_, None) => None,
        }
    }
}

/// `ScanIndex::claude_request_census_shadow`: the little the shadow needs to
/// remember between terminals. Count-only; nothing reads it into a decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensusShadowState {
    /// `would_open` at the previous complete terminal.
    would_open: Option<bool>,
    /// Terminals whose `would_open` differed from the previous one.
    would_open_flips: u64,
    /// S3(d) tripwire: a verified complete re-parse at an unchanged
    /// fingerprint and derivation changed the hash set or shape.
    derivation_drift: u64,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensusShadowState; would_open, would_open_flips, derivation_drift);

impl ClaudeRequestCensusShadowState {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Compact wire form, keys short on purpose:
/// `{"v":1,"fp":"<64 hex>","w":<unix>,"s":"exact","tw":true,"u":true,"b":"<base64>"}`.
/// `b` is the request hashes as base64 of big-endian u64s (10.67 B per hash);
/// the decoder still reads the older `h` (16 hex per hash). Optional fields,
/// each omitted when absent: `bi`/`bd`/`bn` (birth unix seconds, device,
/// inode), `r` (retired hash count), `ur`/`ut` (old-path requests, tokens),
/// the record's file mtime `m`. `tw`, `u` and `b` are omitted when false or
/// empty. The decoder skips any other field, so the retired money ledger's
/// field names decode and are ignored.
impl Serialize for ClaudeRequestCensusRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &self.derivation)?;
        map.serialize_entry("fp", &LowerHex(&self.source_file_fingerprint))?;
        map.serialize_entry("w", &self.window)?;
        map.serialize_entry("s", self.shape.wire())?;
        if self.twin {
            map.serialize_entry("tw", &true)?;
        }
        if self.unverified {
            map.serialize_entry("u", &true)?;
        }
        if !self.request_hashes().is_empty() {
            map.serialize_entry("b", &HashBase64(self.request_hashes()))?;
        }
        if let Some(birth) = &self.birth {
            map.serialize_entry("bi", &birth.unix_seconds)?;
            map.serialize_entry("bd", &birth.device)?;
            map.serialize_entry("bn", &birth.inode)?;
        }
        if let Some(retired) = self.retired {
            map.serialize_entry("r", &retired)?;
        }
        if let Some((requests, tokens)) = self.old_path_usage {
            map.serialize_entry("ur", &requests)?;
            map.serialize_entry("ut", &tokens)?;
        }
        if let Some(modified) = self.modified {
            map.serialize_entry("m", &modified)?;
        }
        map.end()
    }
}

impl Serialize for ClaudeRequestCensus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.records.serialize(serializer)
    }
}

impl Serialize for ClaudeRequestCensusShadowState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Some(would_open) = self.would_open {
            map.serialize_entry("o", &would_open)?;
        }
        if self.would_open_flips > 0 {
            map.serialize_entry("f", &self.would_open_flips)?;
        }
        if self.derivation_drift > 0 {
            map.serialize_entry("d", &self.derivation_drift)?;
        }
        map.end()
    }
}

/// Persisted readers isolate optional evidence before Serde interprets it.
/// Ordinary index bytes pass through unchanged. The census field is read
/// whole, whatever its size; only nesting past `MAX_EVIDENCE_DEPTH` reads as
/// null. The token scanner never converts a number.
pub(super) fn decode_index<R: std::io::Read>(reader: R) -> serde_json::Result<ScanIndex> {
    CensusRead::new(reader).decode()
}

pub(super) fn normalized_bounded_bytes(bytes: &[u8]) -> anyhow::Result<(Vec<u8>, bool, bool)> {
    use std::io::Read;
    let mut normalized = Vec::new();
    let mut reader = CensusRead::new(bytes);
    reader.read_to_end(&mut normalized)?;
    Ok((normalized, reader.duplicate_census, reader.duplicate_shadow))
}

pub(super) fn decode_bounded_index(bytes: &[u8]) -> anyhow::Result<ScanIndex> {
    super::lenient_decode::read_bounded(bytes)
}

/// Derive positional slots from Serde's own field metadata rather than pinning
/// offsets to ScanIndex's declaration order. JSON struct sequences are accepted
/// by the old reader too; they need the same evidence bounds as object fields.
fn sequence_fields() -> (usize, usize, usize) {
    struct Fields<'a>(&'a mut Option<&'static [&'static str]>);
    impl<'de> Deserializer<'de> for Fields<'_> {
        type Error = serde::de::value::Error;
        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
            Err(serde::de::Error::custom("field metadata only"))
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            *self.0 = Some(fields);
            Err(serde::de::Error::custom("field metadata only"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }
    static SLOTS: std::sync::OnceLock<(usize, usize, usize)> = std::sync::OnceLock::new();
    *SLOTS.get_or_init(|| {
        let mut fields = None;
        let _ = ScanIndex::deserialize(Fields(&mut fields));
        let fields = fields.expect("derived ScanIndex field metadata");
        assert_eq!(
            fields,
            super::lenient_decode::FIELDS,
            "ScanIndex field registry drift"
        );
        let slot = |name| {
            fields
                .iter()
                .position(|field| *field == name)
                .expect("census field")
        };
        (
            slot("claude_request_census"),
            slot("claude_request_census_shadow"),
            slot("reread_guard"),
        )
    })
}

// Explicit resource depth gate for optional evidence, shared with the original
// input lexical gate. Above it evidence is unknown/null, never corruption.
pub(super) const MAX_EVIDENCE_DEPTH: usize = 256;
pub(super) fn validate_gated_syntax<R: std::io::Read>(reader: R) -> serde_json::Result<()> {
    let mut reader = CensusRead::new(reader);
    reader.syntax_only = true;
    serde_json::from_reader::<_, serde::de::IgnoredAny>(std::io::BufReader::new(reader)).map(|_| ())
}

struct CensusRead<R> {
    reader: std::io::BufReader<R>,
    replay: Option<u8>,
    output: std::io::Cursor<Vec<u8>>,
    depth: usize,
    root_array: bool,
    array_index: usize,
    sequence_fields: (usize, usize, usize),
    retired_guard: bool,
    quoted: bool,
    escaped: bool,
    expect_key: bool,
    seen_census: bool,
    seen_shadow: bool,
    duplicate_census: bool,
    duplicate_shadow: bool,
    shadow_key: bool,
    shadow_state: bool,
    capture: bool,
    syntax_only: bool,
    #[cfg(test)]
    read_calls: usize,
    #[cfg(test)]
    next_calls: usize,
}

impl<R: std::io::Read> CensusRead<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: std::io::BufReader::new(reader),
            replay: None,
            output: std::io::Cursor::new(Vec::new()),
            depth: 0,
            root_array: false,
            array_index: 0,
            sequence_fields: sequence_fields(),
            retired_guard: false,
            quoted: false,
            escaped: false,
            expect_key: false,
            seen_census: false,
            seen_shadow: false,
            duplicate_census: false,
            duplicate_shadow: false,
            shadow_key: false,
            shadow_state: false,
            capture: false,
            syntax_only: false,
            #[cfg(test)]
            read_calls: 0,
            #[cfg(test)]
            next_calls: 0,
        }
    }

    fn decode(&mut self) -> serde_json::Result<ScanIndex> {
        // Serde's io::Bytes uses BufReader's buffered read_byte specialization.
        // Buffering only the underlying file would still call our Read per byte.
        let mut index = serde_json::from_reader(std::io::BufReader::new(&mut *self))?;
        self.invalidate_duplicates(&mut index);
        Ok(index)
    }

    fn invalidate_duplicates(&self, index: &mut ScanIndex) {
        if self.duplicate_census {
            index.claude_request_census = ClaudeRequestCensus::default();
        }
        if self.duplicate_shadow {
            index.claude_request_census_shadow = ClaudeRequestCensusShadowState::default();
        }
    }

    /// Buffer only enough of a root key to recognize every escaped spelling
    /// of our two names. Long ordinary keys continue streaming unchanged.
    fn root_key(&mut self) -> std::io::Result<Vec<u8>> {
        let mut key = vec![b'"'];
        self.quoted = true;
        self.escaped = false;
        while key.len() < 256 {
            let Some(byte) = self.byte()? else {
                break;
            };
            key.push(byte);
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quoted = false;
                break;
            }
        }
        self.shadow_key = false;
        self.retired_guard = false;
        if !self.quoted {
            if let Ok(name) = serde_json::from_slice::<String>(&key) {
                let duplicate = match name.as_str() {
                    "claude_request_census" => {
                        self.shadow_key = true;
                        self.shadow_state = false;
                        let duplicate = self.seen_census;
                        self.seen_census = true;
                        self.duplicate_census |= duplicate;
                        duplicate
                    }
                    "claude_request_census_shadow" => {
                        self.shadow_key = true;
                        self.shadow_state = true;
                        let duplicate = self.seen_shadow;
                        self.seen_shadow = true;
                        self.duplicate_shadow |= duplicate;
                        duplicate
                    }
                    "reread_guard" => {
                        self.shadow_key = true;
                        self.retired_guard = true;
                        return Ok(b"\"_ignored_retired_reread_guard\"".to_vec());
                    }
                    _ => false,
                };
                if duplicate {
                    // Keep duplicate auxiliary fields out of the derived
                    // struct's duplicate-field error path. Their evidence is
                    // invalidated after decoding; ordinary duplicates still fail.
                    return Ok(b"\"_ignored_census_duplicate\"".to_vec());
                }
            }
        }
        Ok(key)
    }

    fn byte(&mut self) -> std::io::Result<Option<u8>> {
        use std::io::Read;
        if let Some(byte) = self.replay.take() {
            return Ok(Some(byte));
        }
        let mut byte = [0];
        loop {
            match self.reader.read(&mut byte) {
                // Keep root-key/evidence capture state across interrupted I/O.
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => return Ok((result? != 0).then_some(byte[0])),
            }
        }
    }

    fn evidence(&mut self) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut depth = 0_usize;
        let mut quoted = false;
        let mut escaped = false;
        // Original admitted evidence was grammar-checked by the lexical
        // boundary. The syntax-only pass substitutes null without buffering
        // or interpreting census records, even before header controls run.
        let mut overflow = self.syntax_only || self.retired_guard;
        while let Some(byte) = self.byte()? {
            if !quoted && depth == 0 && matches!(byte, b',' | b'}' | b']') {
                self.replay = Some(byte);
                break;
            }
            if !overflow {
                bytes.push(byte);
            }
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => {
                        depth = depth.saturating_add(1);
                        if depth > MAX_EVIDENCE_DEPTH && !overflow {
                            bytes = Vec::new();
                            overflow = true;
                        }
                    }
                    b'}' | b']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        if overflow {
            return Ok(b"null".to_vec());
        }
        // Parsing is isolated from the enclosing index, including numeric
        // conversion and wrong-token errors. Only canonical, finite tokens
        // leave this reader. JSON syntax outside the optional field is intact.
        Ok(if self.shadow_state {
            let state = serde_json::from_slice::<ClaudeRequestCensusShadowState>(&bytes)
                .unwrap_or_default();
            drop(bytes);
            serde_json::to_vec(&state).expect("shadow serialization")
        } else {
            let census = serde_json::from_slice::<ClaudeRequestCensus>(&bytes).unwrap_or_default();
            drop(bytes);
            serde_json::to_vec(&census).expect("census serialization")
        })
    }

    fn next(&mut self) -> std::io::Result<Option<u8>> {
        #[cfg(test)]
        {
            self.next_calls += 1;
        }
        use std::io::Read;
        let mut byte = [0];
        if self.output.read(&mut byte)? != 0 {
            return Ok(Some(byte[0]));
        }
        // Release the previous raw buffer before allocating another one.
        self.output = std::io::Cursor::new(Vec::new());
        if self.capture {
            self.capture = false;
            self.output = std::io::Cursor::new(self.evidence()?);
            if self.output.read(&mut byte)? != 0 {
                return Ok(Some(byte[0]));
            }
        }
        let Some(byte) = self.byte()? else {
            return Ok(None);
        };
        if self.root_array
            && self.depth == 1
            && !self.quoted
            && !byte.is_ascii_whitespace()
            && !matches!(byte, b',' | b']')
            && (self.array_index == self.sequence_fields.0
                || self.array_index == self.sequence_fields.1
                || self.array_index == self.sequence_fields.2)
        {
            self.shadow_state = self.array_index == self.sequence_fields.1;
            self.retired_guard = self.array_index == self.sequence_fields.2;
            self.replay = Some(byte);
            self.output = std::io::Cursor::new(self.evidence()?);
            return self.next();
        }
        if self.quoted {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quoted = false;
            }
        } else {
            match byte {
                b'"' if self.depth == 1 && !self.root_array && self.expect_key => {
                    self.output = std::io::Cursor::new(self.root_key()?);
                    return self.next();
                }
                b'"' => {
                    self.quoted = true;
                }
                b'{' | b'[' => {
                    if self.depth == 0 {
                        self.root_array = byte == b'[';
                        self.expect_key = byte == b'{';
                    }
                    self.depth = self.depth.saturating_add(1);
                }
                b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                b':' if self.depth == 1 => {
                    self.expect_key = false;
                    self.capture = self.shadow_key;
                    self.shadow_key = false;
                }
                b',' if self.depth == 1 => {
                    self.shadow_key = false;
                    self.expect_key = !self.root_array;
                    self.array_index = self.array_index.saturating_add(1);
                }
                _ => {}
            }
        }
        Ok(Some(byte))
    }
}

impl<R: std::io::Read> std::io::Read for CensusRead<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        use std::io::BufRead;
        #[cfg(test)]
        {
            self.read_calls += 1;
        }
        let mut written = 0;
        while written < out.len() {
            // Canonical evidence and rewritten root keys need no further scan.
            let copied = std::io::Read::read(&mut self.output, &mut out[written..])?;
            if copied != 0 {
                written += copied;
                continue;
            }
            // Every top-level sequence value must visit next(), even a
            // scalar with no structural byte, to recognize census slots.
            if !(self.capture
                || self.replay.is_some()
                || self.escaped
                || self.root_array && self.depth == 1 && !self.quoted)
            {
                let bytes = match self.reader.fill_buf() {
                    Ok(bytes) => bytes,
                    // Retain the bytes already copied into out. Retrying at
                    // Serde's Bytes layer would discard that consumed prefix.
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                let limit = bytes.len().min(out.len() - written);
                let run = bytes[..limit]
                    .iter()
                    .position(|&byte| {
                        if self.quoted {
                            matches!(byte, b'"' | b'\\')
                        } else {
                            matches!(byte, b'"' | b'{' | b'}' | b'[' | b']' | b':' | b',')
                        }
                    })
                    .unwrap_or(limit);
                if run != 0 {
                    out[written..written + run].copy_from_slice(&bytes[..run]);
                    self.reader.consume(run);
                    written += run;
                    continue;
                }
            }
            let Some(byte) = self.next()? else {
                break;
            };
            out[written] = byte;
            written += 1;
        }
        Ok(written)
    }
}

/// Streaming and per entry: a malformed record is dropped, never the index,
/// and a non-map field is an empty census. Persisted readers first bound raw
/// buffering with CensusRead. Raw sub-parses isolate token errors from their
/// enclosing container; no record is materialized as a `serde_json::Value`.
impl<'de> Deserialize<'de> for ClaudeRequestCensus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        let mut isolated = serde_json::Deserializer::from_str(raw.get());
        Ok(isolated
            .deserialize_any(CensusVisitor)
            .map(|(census, _)| census)
            .unwrap_or_default())
    }
}

/// One stored record (the state_v2 `file.census` row): an undecodable record
/// is an error, never a default record.
impl<'de> Deserialize<'de> for ClaudeRequestCensusRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RecordSeed
            .deserialize(deserializer)?
            .ok_or_else(|| serde::de::Error::custom("state_v2_census_record"))
    }
}

/// The census entry rule both stored routes share (the v1 index map and the
/// state_v2 rows): a key of at most 4,096 bytes that is not a retired ledger
/// key. No entry, record, byte or hash budget.
pub(super) fn admits_entry_key(key: &str) -> bool {
    key.len() <= MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES && !is_ledger_key(key)
}

/// One v1 census entry: its record, or None (dropped).
fn decode_entry(key: &str, raw: &str) -> Option<ClaudeRequestCensusRecord> {
    admits_entry_key(key)
        .then(|| serde_json::from_str::<ClaudeRequestCensusRecord>(raw).ok())
        .flatten()
}

/// Tolerant like the census: anything unexpected reads as the default.
impl<'de> Deserialize<'de> for ClaudeRequestCensusShadowState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        if raw.get().len() > MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES {
            return Ok(Self::default());
        }
        let mut isolated = serde_json::Deserializer::from_str(raw.get());
        Ok(isolated
            .deserialize_any(ShadowStateVisitor)
            .unwrap_or_default())
    }
}

/// Every non-map JSON shape: drained and read as `Self::Value::default()`.
macro_rules! tolerate_non_map {
    ($de:lifetime) => {
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_seq<A: SeqAccess<$de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Self::Value::default())
        }
    };
}

/// The index's census, entry by entry (`decode_entry`).
struct CensusVisitor;
impl<'de> Visitor<'de> for CensusVisitor {
    /// The census and how many entries it did not keep (a duplicate key
    /// keeps its last record and counts as not kept).
    type Value = (ClaudeRequestCensus, u64);
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census map")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Self::Value::default())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut census = ClaudeRequestCensus::default();
        let mut dropped = 0_u64;
        while let Some(key) = map.next_key::<String>()? {
            let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
            let Some(record) = decode_entry(&key, raw.get()) else {
                dropped += 1;
                continue;
            };
            dropped += u64::from(census.records.contains_key(&key));
            census.insert(key, record);
        }
        Ok((census, dropped))
    }
}

struct ShadowStateVisitor;
impl<'de> Visitor<'de> for ShadowStateVisitor {
    type Value = ClaudeRequestCensusShadowState;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census shadow state")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Self::Value::default())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut state = ClaudeRequestCensusShadowState::default();
        while let Some(field) = map.next_key::<String>()? {
            let value = map.next_value::<Loose>()?;
            match (field.as_str(), value) {
                ("o", Loose::Bool(would_open)) => state.would_open = Some(would_open),
                ("f", Loose::U64(flips)) => state.would_open_flips = flips,
                ("d", Loose::U64(drift)) => state.derivation_drift = drift,
                _ => {}
            }
        }
        Ok(state)
    }
}

/// One record value, whatever its size.
struct RecordSeed;
impl<'de> DeserializeSeed<'de> for RecordSeed {
    type Value = Option<ClaudeRequestCensusRecord>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(RecordVisitor)
    }
}

/// `None` drops the entry.
struct RecordVisitor;
impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Option<ClaudeRequestCensusRecord>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census record")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        const FIELDS: [&str; 15] = [
            "v", "fp", "w", "s", "tw", "u", "h", "b", "bi", "bd", "bn", "r", "ur", "ut", "m",
        ];
        let mut seen = 0_u64;
        let mut malformed = false;
        let mut derivation = None;
        let mut source_file_fingerprint = None;
        let mut window = 0;
        let mut shape = None;
        let mut twin = false;
        let mut unverified = false;
        let mut request_hashes = Vec::new();
        // Every other field is an unsigned scalar.
        let mut scalars = BTreeMap::<&'static str, u64>::new();
        while let Some(field) = map.next_key::<String>()? {
            let Some(position) = FIELDS.iter().position(|known| *known == field) else {
                // Forward compatible: an unknown field (the retired money
                // ledger's included) is skipped.
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            let bit = 1_u64 << position;
            // `h` and `b` are two spellings of one field.
            let alias = match FIELDS[position] {
                "h" => 1_u64 << 7,
                "b" => 1_u64 << 6,
                _ => 0,
            };
            if seen & (bit | alias) != 0 {
                malformed = true;
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            seen |= bit;
            match FIELDS[position] {
                name @ ("h" | "b") => {
                    let encoding = if name == "h" {
                        HashEncoding::Hex
                    } else {
                        HashEncoding::Base64
                    };
                    match map.next_value_seed(HashesSeed { encoding })? {
                        Some(hashes) => request_hashes = hashes,
                        None => malformed = true,
                    }
                }
                "v" | "fp" | "w" | "s" | "tw" | "u" => {
                    match (field.as_str(), map.next_value::<Loose>()?) {
                        ("v", Loose::U64(value)) => derivation = u16::try_from(value).ok(),
                        ("fp", Loose::Str(value)) => {
                            source_file_fingerprint = decode_fingerprint(&value)
                        }
                        ("w", Loose::U64(value)) => window = value,
                        ("s", Loose::Str(value)) => {
                            shape = ClaudeRequestCensusShape::from_wire(&value)
                        }
                        ("tw", Loose::Bool(value)) => twin = value,
                        ("u", Loose::Bool(value)) => unverified = value,
                        _ => malformed = true,
                    }
                }
                name => match map.next_value::<Loose>()? {
                    Loose::U64(value) => {
                        scalars.insert(name, value);
                    }
                    _ => malformed = true,
                },
            }
        }
        if malformed {
            return Ok(None);
        }
        let (Some(derivation), Some(source_file_fingerprint), Some(shape)) =
            (derivation, source_file_fingerprint, shape)
        else {
            return Ok(None);
        };
        let scalar = |name: &str| scalars.get(name).copied();
        // Grouped fields are all-or-nothing: a partial group is malformed.
        let group = |names: &[&str]| -> Option<Option<Vec<u64>>> {
            let values = names.iter().map(|name| scalar(name)).collect::<Vec<_>>();
            if values.iter().all(Option::is_none) {
                Some(None)
            } else if values.iter().all(Option::is_some) {
                Some(Some(values.into_iter().flatten().collect()))
            } else {
                None
            }
        };
        let (Some(birth), Some(old_path_usage)) =
            (group(&["bi", "bd", "bn"]), group(&["ur", "ut"]))
        else {
            return Ok(None);
        };
        let retired = scalar("r");
        let modified = scalar("m");
        Ok(
            (shape.admits(&request_hashes) || retired.is_some()).then_some(
                ClaudeRequestCensusRecord {
                    source_file_fingerprint,
                    derivation,
                    window,
                    shape,
                    twin,
                    unverified,
                    request_hashes: shared_hashes(request_hashes),
                    birth: birth.map(|values| ClaudeRequestBirth {
                        unix_seconds: values[0],
                        device: values[1],
                        inode: values[2],
                    }),
                    retired,
                    old_path_usage: old_path_usage.map(|values| (values[0], values[1])),
                    modified,
                },
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashEncoding {
    Hex,
    Base64,
}

/// A hash list string (`h` hex, `b` base64), whatever its length.
struct HashesSeed {
    encoding: HashEncoding,
}
impl<'de> DeserializeSeed<'de> for HashesSeed {
    type Value = Option<Vec<u64>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(HashesVisitor {
            encoding: self.encoding,
        })
    }
}

struct HashesVisitor {
    encoding: HashEncoding,
}
impl<'de> Visitor<'de> for HashesVisitor {
    type Value = Option<Vec<u64>>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ascending request hashes")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(match self.encoding {
            HashEncoding::Hex => decode_hashes(value),
            HashEncoding::Base64 => decode_base64_hashes(value),
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

/// A scalar the decoder accepts; every other shape is `Other`.
enum Loose {
    U64(u64),
    Bool(bool),
    Str(String),
    Other,
}
impl<'de> Deserialize<'de> for Loose {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LooseVisitor)
    }
}
struct LooseVisitor;
impl<'de> Visitor<'de> for LooseVisitor {
    type Value = Loose;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a scalar")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Loose, E> {
        Ok(Loose::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Loose, E> {
        Ok(u64::try_from(value).map_or(Loose::Other, Loose::U64))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Loose, E> {
        Ok(Loose::U64(value))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Loose, E> {
        Ok(if value.len() <= MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES {
            Loose::Str(value.to_owned())
        } else {
            Loose::Other
        })
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Loose, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Loose, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
}

use crate::hex::LowerHex;

/// Base64 (standard, padded) of the big-endian bytes of each hash, streamed
/// three hashes (24 bytes, 32 characters) at a time without a whole buffer.
struct HashBase64<'a>(&'a [u64]);
impl fmt::Display for HashBase64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine;
        let mut bytes = [0_u8; 24];
        let mut text = [0_u8; 32];
        for chunk in self.0.chunks(3) {
            for (slot, hash) in bytes.chunks_exact_mut(8).zip(chunk) {
                slot.copy_from_slice(&hash.to_be_bytes());
            }
            let written = base64::engine::general_purpose::STANDARD
                .encode_slice(&bytes[..chunk.len() * 8], &mut text)
                .map_err(|_| fmt::Error)?;
            f.write_str(std::str::from_utf8(&text[..written]).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for HashBase64<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Strictly ascending, non-empty, whole hashes only; anything else is None.
fn decode_base64_hashes(value: &str) -> Option<Vec<u64>> {
    use base64::Engine;
    let text = value.as_bytes();
    if text.is_empty() || text.len() % 4 != 0 {
        return None;
    }
    let mut hashes = Vec::with_capacity(text.len() / 4 * 3 / 8);
    let mut bytes = [0_u8; 24];
    let count = text.len().div_ceil(32);
    for (index, chunk) in text.chunks(32).enumerate() {
        // Only the final chunk may carry padding or a partial group.
        if index + 1 != count && chunk.contains(&b'=') {
            return None;
        }
        let read = base64::engine::general_purpose::STANDARD
            .decode_slice(chunk, &mut bytes)
            .ok()?;
        if read == 0 || read % 8 != 0 {
            return None;
        }
        for slot in bytes[..read].chunks_exact(8) {
            let hash = u64::from_be_bytes(slot.try_into().ok()?);
            if hashes.last().is_some_and(|last| *last >= hash) {
                return None;
            }
            hashes.push(hash);
        }
    }
    Some(hashes)
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn decode_fingerprint(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 || !lower_hex(bytes) {
        return None;
    }
    let mut fingerprint = [0_u8; 32];
    for (slot, pair) in fingerprint.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(fingerprint)
}

fn decode_hashes(value: &str) -> Option<Vec<u64>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 16 != 0 || !lower_hex(bytes) {
        return None;
    }
    let mut hashes = Vec::with_capacity(bytes.len() / 16);
    for chunk in bytes.chunks_exact(16) {
        let hash = u64::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        if hashes.last().is_some_and(|last| *last >= hash) {
            return None;
        }
        hashes.push(hash);
    }
    Some(hashes)
}

/// The record one parse of a Claude family-member file yields, or None when
/// the fingerprint is not a 64-hex digest (never a scan candidate's).
/// `complete` is `ParsedJsonlFile::complete`; `lossy` is any dropped
/// response, recognized-usage drop or over-cap line. `itemless_request_hashes`
/// are `claude_buffered_request_hashes`, used only when the parse yields no
/// item.
#[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
pub(crate) fn claude_request_census_record(
    path_owner: &(String, String),
    items: &[SnapshotItem],
    itemless_request_hashes: Vec<u64>,
    source_file_fingerprint: &str,
    window: u64,
    complete: bool,
    lossy: bool,
    unverified: bool,
) -> Option<ClaudeRequestCensusRecord> {
    let source_file_fingerprint = decode_fingerprint(source_file_fingerprint)?;
    let mut request_hashes = if items.is_empty() {
        itemless_request_hashes
    } else {
        items
            .iter()
            .flat_map(|item| item.claude_usage_request_ids.iter())
            .map(|request_id| claude_request_hash(request_id))
            .collect::<Vec<_>>()
    };
    request_hashes.sort_unstable();
    request_hashes.dedup();
    request_hashes.shrink_to_fit();
    let shape = match items {
        _ if !complete || lossy => ClaudeRequestCensusShape::Lossy,
        // A Claude file yields at most one item; more is treated as loss.
        [_, _, ..] => ClaudeRequestCensusShape::Lossy,
        // No item, no response id (a confirmed-empty file).
        [] if request_hashes.is_empty() => ClaudeRequestCensusShape::Empty,
        // Responses without positive usage (API errors) make no item. Their
        // ids are kept, but no item certified the identity.
        [] => ClaudeRequestCensusShape::IdentityIncomplete,
        [item] if !item.claude_context_curve_identity_complete => {
            ClaudeRequestCensusShape::IdentityIncomplete
        }
        [_] if request_hashes.is_empty() => ClaudeRequestCensusShape::Empty,
        [_] => ClaudeRequestCensusShape::Exact,
    };
    let twin = items.iter().any(|item| {
        claude_snapshot_family_root_ref(item) != path_owner.0
            || item.source_session_id != path_owner.1
    });
    // Old-path requests and conserved tokens this parse built, for the shadow
    // family rows of members a later page does not rebuild.
    let old_path_usage = items
        .iter()
        .fold((0_u64, 0_u64), |(requests, tokens), item| {
            (
                requests.saturating_add(item.request_count),
                tokens.saturating_add(claude_conserved_tokens(item)),
            )
        });
    Some(ClaudeRequestCensusRecord {
        source_file_fingerprint,
        derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
        window,
        shape,
        twin,
        unverified,
        request_hashes: shared_hashes(request_hashes),
        birth: None,
        retired: None,
        old_path_usage: Some(old_path_usage),
        modified: None,
    })
}

/// Input, output, cache read, both cache writes and unattributed tokens.
/// Reasoning is part of output and is not added again.
pub(crate) fn claude_conserved_tokens(item: &SnapshotItem) -> u64 {
    [
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.unattributed_total_tokens,
    ]
    .into_iter()
    .fold(0_u64, u64::saturating_add)
}

/// What the owned scan loop knows about one finished Claude parse besides
/// its items.
pub(crate) struct ClaudeRequestCensusParse<'a> {
    pub(crate) path: &'a Path,
    pub(crate) index_key: &'a str,
    pub(crate) source_file_fingerprint: &'a str,
    pub(crate) census_window_end: &'a str,
    pub(crate) complete: bool,
    pub(crate) lossy: bool,
    pub(crate) source_verified: bool,
    /// Successful, loss-free, debt-free Unchanged acquisition. Its checkpoint
    /// binds the same physical object and interpretation scope; this is not
    /// Full credit and cannot promote an unverified census record.
    pub(crate) unchanged_source: bool,
    pub(crate) itemless_request_hashes: Vec<u64>,
    /// Creation time and identity of the object this parse opened, when the
    /// parse opened one and the file system reports a creation time.
    pub(crate) opened_birth: Option<ClaudeRequestBirth>,
    /// The candidate's modification time (unix seconds; 0 unknown), kept on
    /// the record.
    pub(crate) modified_unix_seconds: u64,
}

/// The request-id hashes of the Claude responses a parser buffered, taken
/// before `finish` consumes it. Only a parse with no positive usage needs
/// them: it yields no item, so its ids (zero-usage API errors included) would
/// otherwise reach no record. Sorted and unique.
pub(super) fn claude_buffered_request_hashes(parser: &super::OwnedJsonlParser) -> Vec<u64> {
    let mut hashes = parser
        .accumulator
        .claude_responses
        .values()
        .flat_map(|response| {
            let first = response.records.first();
            response
                .records
                .iter()
                .filter_map(move |record| record.request_id(first))
        })
        .map(claude_request_hash)
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

/// Every Claude family-member parse that reaches `finish` replaces the key's
/// record with one bound to the candidate fingerprint and this window: a
/// complete parse by its shape, an incomplete or residue parse as `Lossy`
/// with the ids it saw. Only an identical, debt-free Unchanged completion
/// carries forward an existing record's verification.
pub(crate) fn record_claude_request_census(
    index: &mut ScanIndex,
    parse: ClaudeRequestCensusParse<'_>,
    items: &[SnapshotItem],
) {
    if !index.persistence_available() {
        return;
    }

    let Some(path_owner) = claude_index_path_family_member(parse.path) else {
        return;
    };
    #[cfg(test)]
    if records_disabled_for_test(parse.path) {
        return;
    }
    let was_held = index
        .claude_request_census
        .get(parse.index_key)
        .is_some_and(ClaudeRequestCensusRecord::identity_incomplete_hold);
    let window = rfc3339_unix_seconds(parse.census_window_end).unwrap_or_default();
    let Some(record) = claude_request_census_record(
        &path_owner,
        items,
        parse.itemless_request_hashes,
        parse.source_file_fingerprint,
        window,
        parse.complete,
        parse.lossy,
        !parse.source_verified,
    ) else {
        index
            .claude_request_census
            .invalidate_keeping_birth(parse.index_key);
        return;
    };
    let mut record = record;
    record.birth = index
        .claude_request_census
        .carried_birth(parse.index_key, parse.opened_birth);
    record.modified = (parse.modified_unix_seconds > 0).then_some(parse.modified_unix_seconds);
    if let Some(old) = index.claude_request_census.get(parse.index_key) {
        let comparable = |record: &ClaudeRequestCensusRecord| {
            !record.unverified
                && record.retired.is_none()
                && !matches!(
                    record.shape,
                    ClaudeRequestCensusShape::Lossy | ClaudeRequestCensusShape::OverBudget
                )
        };
        if parse.unchanged_source
            && parse.complete
            && !parse.lossy
            && comparable(old)
            && old.derivation == record.derivation
            && old.source_file_fingerprint == record.source_file_fingerprint
            && old.shape == record.shape
            && old.request_hashes == record.request_hashes
            && old.twin == record.twin
        {
            record.unverified = false;
        }
        // S3(d): the same verified revision under the same derivation must
        // yield the same census. Residue, lossy and budget tombstones (whose
        // shape and hashes the budget replaced) and retired records (whose
        // hashes retirement dropped) are excluded.
        if parse.complete
            && comparable(old)
            && comparable(&record)
            && old.derivation == record.derivation
            && old.source_file_fingerprint == record.source_file_fingerprint
            && (old.shape != record.shape || old.request_hashes != record.request_hashes)
        {
            let state = &mut index.claude_request_census_shadow;
            state.derivation_drift = state.derivation_drift.saturating_add(1);
        }
    }
    index
        .claude_request_census
        .insert(parse.index_key.to_owned(), record);
    if let Some(stored) = index.claude_request_census.get(parse.index_key) {
        note_identity_incomplete_hold(
            !was_held && stored.identity_incomplete_hold(),
            was_held
                && stored.current_derivation()
                && !stored.twin
                && stored.retired.is_none()
                && matches!(
                    stored.shape,
                    ClaudeRequestCensusShape::Exact
                        | ClaudeRequestCensusShape::Empty
                        | ClaudeRequestCensusShape::IdentityIncomplete
                )
                && (!stored.unverified || stored.can_bind_recomposed_body()),
        );
    }
}

/// A forced family member reads natively only for evidence stored state cannot
/// supply: no census record, or an unverified or twin record that cannot bind
/// a recomposed body (an identity-incomplete hold waits for its Full audit).
pub(super) fn forced_member_needs_native(index: &ScanIndex, key: &str) -> bool {
    index.claude_request_census.get(key).map_or(true, |record| {
        record.unverified_or_twin() && !record.can_bind_recomposed_body()
    })
}

/// A parse that reaches no record after a failed finish leaves the key without
/// one, never with an older revision's.
pub(crate) fn invalidate_claude_request_census(index: &mut ScanIndex, path: &Path) {
    if !index.persistence_available() {
        return;
    }

    let key = super::local_index_key(path);
    // Growth debt prevents retirement, not invalidation after a failed
    // object/scope check. Keep scheduling debt, but make old proof inert;
    // unverified alone is insufficient because proves_scan accepts it.
    if claude_index_path_family_member(path).is_some() {
        index.claude_request_census.invalidate_keeping_birth(&key);
    }
}

/// Complete Claude terminal, before any join and before the snapshot_sync
/// folds: measure the shadow census. Nothing reads the result into a
/// decision, and nothing is pruned or retired here: a record leaves only
/// with its file (`ScanIndex::drop_file_entry`).
pub(crate) fn settle_claude_request_census_terminal(
    index: &mut ScanIndex,
    residue_index_keys: &BTreeSet<String>,
    census_window_end: &str,
) -> ClaudeRequestCensusShadowCounts {
    if !index.persistence_available() {
        return ClaudeRequestCensusShadowCounts::default();
    }

    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    let join = ClaudeRequestCensusJoin::new(index, window, residue_index_keys);
    let mut counts = join.counts(true);
    let state = &mut index.claude_request_census_shadow;
    if state
        .would_open
        .is_some_and(|before| before != counts.would_open)
    {
        state.would_open_flips = state.would_open_flips.saturating_add(1);
    }
    state.would_open = Some(counts.would_open);
    counts.would_open_flips = state.would_open_flips;
    counts.derivation_drift = state.derivation_drift;
    counts.json_bytes = serialized_bytes(&index.claude_request_census);
    counts.heap_bytes =
        crate::heap_layout_bound::completed_bound(&index.claude_request_census, usize::MAX)
            .unwrap_or_default();
    counts
}

fn serialized_bytes(census: &ClaudeRequestCensus) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, census).map_or(0, |()| count.0)
}

/// Per-key answer for a posture seam. It is computed only in
/// tests; nothing in production reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeCensusMemberStatus {
    /// The predicate holds, the own record is Exact or Empty from a verified
    /// parse, the own family is not census-unknown, and no hash of the record
    /// appears under any other key.
    Disjoint,
    /// Some hash also appears under another key (a twin included).
    SharesHash,
    /// The own family is census-unknown.
    FamilyUnknown,
    /// Covered, but by a record that may not back a positive verdict (S2(a)).
    Unverified,
    /// The predicate is false, or the own record is missing or inert.
    Unobserved,
}

/// Why a key has no record that would cover it, first match wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeRequestCensusCoverage {
    /// Record fingerprint equals the key's non-empty entry fingerprint.
    Fingerprint,
    /// Record parsed in this census window, whatever the entry now says.
    Window,
    OverBudget,
    AccountHold,
    Residue,
    Placeholder,
    EmptyFingerprint,
    FingerprintMismatch,
    /// No record, or one from another derivation.
    Migrate,
}

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestCensusCoverage {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        Some(())
    }
}

/// One pass over the index: per-key coverage, shape counts, the hash join
/// across every present record (covering or not: either can only add
/// duplicates) and the census-unknown families. Coverage, path-owner, shared
/// and unknown-key trees plus merge buffers are bounded before allocation;
/// their peak requested layout is reported separately. No hash is copied.
pub(crate) struct ClaudeRequestCensusJoin {
    counts: ClaudeRequestCensusShadowCounts,
    coverage: BTreeMap<String, ClaudeRequestCensusCoverage>,
    shared_keys: BTreeSet<String>,
    unknown_roots: BTreeSet<String>,
}

impl ClaudeRequestCensusJoin {
    pub(crate) fn new(
        index: &ScanIndex,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> Self {
        let census = &index.claude_request_census;
        let mut join = Self {
            counts: ClaudeRequestCensusShadowCounts {
                transient_limited: !index.persistence_available(),
                // Birth stubs are no record.
                records: census.records().count(),
                hashes: census.hash_total,
                hash_budget_usage_percent: census.hash_total.saturating_mul(100)
                    / CLAUDE_REQUEST_CENSUS_HASH_ALARM_BASE,
                ..ClaudeRequestCensusShadowCounts::default()
            },
            coverage: BTreeMap::new(),
            shared_keys: BTreeSet::new(),
            unknown_roots: BTreeSet::new(),
        };
        // Shadow-only workspace bound. Oversized inventories remain closed;
        // ordinary scan decisions and existing resource caps are unchanged.
        if index.files.len() > MAX_SHADOW_ENTRIES
            || census.records.len() > MAX_SHADOW_ENTRIES
            || Self::workspace_bound(index).map_or(true, |bytes| bytes > MAX_SHADOW_WORKSPACE_BYTES)
            || index
                .files
                .keys()
                .chain(census.records.keys())
                .any(|key| key.len() > MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES)
        {
            join.counts.transient_limited = true;
            return join;
        }
        let mut path_owners = BTreeMap::<(String, String), usize>::new();
        for (key, entry) in &index.files {
            let Some(path_owner) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            if index.confirmed_empty_files.contains(key) {
                continue;
            }
            join.counts.family_keys += 1;
            let record = census
                .get(key)
                .filter(|record| record.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION);
            let coverage = Self::coverage(index, key, entry, record, window, residue_index_keys);
            let counts = &mut join.counts;
            match coverage {
                ClaudeRequestCensusCoverage::Fingerprint => counts.covered_by_fingerprint += 1,
                ClaudeRequestCensusCoverage::Window => counts.covered_by_window += 1,
                ClaudeRequestCensusCoverage::OverBudget => counts.missing_over_budget += 1,
                ClaudeRequestCensusCoverage::AccountHold => counts.missing_account_hold += 1,
                ClaudeRequestCensusCoverage::Residue => counts.missing_residue += 1,
                ClaudeRequestCensusCoverage::Placeholder => counts.missing_placeholder += 1,
                ClaudeRequestCensusCoverage::EmptyFingerprint => {
                    counts.missing_empty_fingerprint += 1
                }
                ClaudeRequestCensusCoverage::FingerprintMismatch => {
                    counts.missing_fingerprint_mismatch += 1
                }
                ClaudeRequestCensusCoverage::Migrate => counts.missing_migrate += 1,
            }
            let covered = matches!(
                coverage,
                ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window
            );
            if !covered
                && index
                    .claude_usage_authority_quarantine
                    .contains_key(&path_owner.0)
            {
                counts.quarantine_without_record += 1;
            }
            if let Some(record) = record.filter(|_| covered) {
                match record.shape {
                    ClaudeRequestCensusShape::Exact => counts.shape_exact += 1,
                    ClaudeRequestCensusShape::Empty => counts.shape_empty += 1,
                    ClaudeRequestCensusShape::IdentityIncomplete => {
                        counts.shape_identity_incomplete += 1
                    }
                    ClaudeRequestCensusShape::Lossy => counts.shape_lossy += 1,
                    ClaudeRequestCensusShape::OverBudget => {}
                }
                counts.unverified += usize::from(record.unverified);
                counts.twin += usize::from(record.twin);
                if record.shape.unknown() || record.twin {
                    join.unknown_roots.insert(path_owner.0.clone());
                }
            }
            join.coverage.insert(key.clone(), coverage);
            *path_owners.entry(path_owner).or_default() += 1;
        }
        join.observe_workspace(
            crate::heap_layout_bound::completed_bound(&path_owners, usize::MAX)
                .unwrap_or(usize::MAX),
        );
        // A path twin: one (root, member) on two or more keys.
        join.unknown_roots.extend(
            path_owners
                .into_iter()
                .filter(|(_, keys)| *keys > 1)
                .map(|((root, _), _)| root),
        );
        // A member that is not a counted key (residue never indexed, or a
        // confirmed-empty file) still leaves its family census-unknown.
        for (key, record) in &census.records {
            if join.coverage.contains_key(key)
                || record.derivation != CLAUDE_REQUEST_CENSUS_DERIVATION
                || !(record.shape.unknown() || record.twin)
            {
                continue;
            }
            if let Some((root, _)) = claude_index_path_family_member(Path::new(key)) {
                join.unknown_roots.insert(root);
            }
        }
        join.counts.family_unknown_roots = join.unknown_roots.len();
        join.merge_hashes(census);
        join.observe_workspace(0);
        join
    }

    /// Bound the peak requested layout before constructing a key copy.
    /// One full B-tree node per entry (the repository's layout bound), full
    /// path bytes for every root/member substring (two for the owner pair),
    /// and double vector capacities
    /// cover coverage/path owners/shared/unknown plus all merge buffers.
    fn workspace_bound(index: &ScanIndex) -> Option<usize> {
        use crate::heap_layout_bound::tree_node_bytes;
        let files = index.files.len();
        let records = index.claude_request_census.records.len();
        let file_keys = index
            .files
            .keys()
            .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))?;
        let record_keys = index
            .claude_request_census
            .records
            .keys()
            .try_fold(0_usize, |bytes, key| bytes.checked_add(key.len()))?;
        let mut bytes = files
            .checked_add(1)?
            .checked_mul(tree_node_bytes::<String, ClaudeRequestCensusCoverage>()?)?;
        bytes = bytes.checked_add(
            files
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<(String, String), usize>()?)?,
        )?;
        bytes = bytes.checked_add(
            records
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, ()>()?)?,
        )?;
        bytes = bytes.checked_add(
            files
                .checked_add(records)?
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, ()>()?)?,
        )?;
        bytes = bytes.checked_add(file_keys.checked_mul(4)?)?;
        bytes = bytes.checked_add(record_keys.checked_mul(2)?)?;
        let merge_slot = std::mem::size_of::<(&String, &[u64])>()
            + std::mem::size_of::<Reverse<(u64, usize, usize)>>()
            + std::mem::size_of::<usize>();
        bytes.checked_add(records.checked_mul(2 * merge_slot)?)
    }

    fn observe_workspace(&mut self, extra: usize) {
        let owned = crate::heap_layout_bound::completed_bound(&self.coverage, usize::MAX)
            .and_then(|coverage| {
                crate::heap_layout_bound::completed_bound(&self.shared_keys, usize::MAX)
                    .and_then(|shared| coverage.checked_add(shared))
            })
            .and_then(|bytes| {
                crate::heap_layout_bound::completed_bound(&self.unknown_roots, usize::MAX)
                    .and_then(|roots| bytes.checked_add(roots))
            })
            .unwrap_or(usize::MAX);
        self.counts.transient_peak_bytes = self
            .counts
            .transient_peak_bytes
            .max(owned.saturating_add(extra));
    }

    fn coverage(
        index: &ScanIndex,
        key: &str,
        entry: &ScanIndexEntry,
        record: Option<&ClaudeRequestCensusRecord>,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> ClaudeRequestCensusCoverage {
        if let Some(record) =
            record.filter(|record| record.shape != ClaudeRequestCensusShape::OverBudget)
        {
            if decode_fingerprint(&entry.source_file_fingerprint)
                .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
            {
                return ClaudeRequestCensusCoverage::Fingerprint;
            }
            if window != 0 && record.window == window {
                return ClaudeRequestCensusCoverage::Window;
            }
        }
        if record.is_some_and(|record| record.shape == ClaudeRequestCensusShape::OverBudget) {
            ClaudeRequestCensusCoverage::OverBudget
        } else if index.claude_account_deferred_holds.contains_key(key) {
            ClaudeRequestCensusCoverage::AccountHold
        } else if residue_index_keys.contains(key) {
            ClaudeRequestCensusCoverage::Residue
        } else if entry.last_snapshot_fingerprint.is_none()
            && !index.file_snapshot_fingerprints.contains_key(key)
        {
            ClaudeRequestCensusCoverage::Placeholder
        } else if entry.source_file_fingerprint.is_empty() {
            ClaudeRequestCensusCoverage::EmptyFingerprint
        } else if record.is_some() {
            ClaudeRequestCensusCoverage::FingerprintMismatch
        } else {
            ClaudeRequestCensusCoverage::Migrate
        }
    }

    /// k-way merge of the sorted per-record hash lists. Hashes are unique per
    /// record, so a run of equal hashes is one hash under that many keys.
    fn merge_hashes(&mut self, census: &ClaudeRequestCensus) {
        let lists = census
            .records
            .iter()
            .filter(|(_, record)| !record.request_hashes().is_empty())
            .map(|(key, record)| (key, record.request_hashes()))
            .collect::<Vec<_>>();
        let mut heap = lists
            .iter()
            .enumerate()
            .map(|(list, (_, hashes))| Reverse((hashes[0], list, 0_usize)))
            .collect::<BinaryHeap<_>>();
        let mut run: Option<u64> = None;
        let mut run_lists = Vec::new();
        while let Some(Reverse((hash, list, position))) = heap.pop() {
            if run != Some(hash) {
                self.close_run(&lists, &run_lists);
                run = Some(hash);
                run_lists.clear();
            }
            run_lists.push(list);
            if let Some(next) = lists[list].1.get(position + 1) {
                heap.push(Reverse((*next, list, position + 1)));
            }
        }
        self.close_run(&lists, &run_lists);
        self.observe_workspace(
            lists
                .capacity()
                .saturating_mul(std::mem::size_of::<(&String, &[u64])>())
                .saturating_add(
                    heap.capacity()
                        .saturating_mul(std::mem::size_of::<Reverse<(u64, usize, usize)>>()),
                )
                .saturating_add(
                    run_lists
                        .capacity()
                        .saturating_mul(std::mem::size_of::<usize>()),
                ),
        );
    }

    fn close_run(&mut self, lists: &[(&String, &[u64])], run_lists: &[usize]) {
        if run_lists.len() < 2 {
            return;
        }
        self.counts.duplicate_hashes += 1;
        self.counts.duplicate_owner_entries = self
            .counts
            .duplicate_owner_entries
            .saturating_add(run_lists.len());
        self.shared_keys
            .extend(run_lists.iter().map(|list| lists[*list].0.clone()));
    }

    /// `claude_census_disjointness_complete`: on a terminal page with
    /// `census_complete`, (1) every indexed Claude family-member key that is
    /// not confirmed empty has a covering record (by fingerprint or this
    /// window; never excused by a quarantine), and (2) the duplicate owners
    /// fit the owner bound. It states only
    /// that every visible request id was compared with every other key's ids,
    /// never that any member is unique or owned.
    pub(crate) fn disjointness_complete(&self, census_complete: bool) -> bool {
        let counts = &self.counts;
        census_complete
            && !counts.transient_limited
            && counts.covered_by_fingerprint + counts.covered_by_window == counts.family_keys
            && counts.duplicate_owner_entries <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    }

    #[cfg_attr(not(test), allow(dead_code, reason = "only tests call it so far"))]
    pub(crate) fn member_status(
        &self,
        index: &ScanIndex,
        key: &str,
        census_complete: bool,
    ) -> ClaudeCensusMemberStatus {
        if !self.disjointness_complete(census_complete) {
            return ClaudeCensusMemberStatus::Unobserved;
        }
        let covered = matches!(
            self.coverage.get(key),
            Some(ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window)
        );
        let (Some(record), Some((root, _))) = (
            index.claude_request_census.get(key).filter(|_| covered),
            claude_index_path_family_member(Path::new(key)),
        ) else {
            return ClaudeCensusMemberStatus::Unobserved;
        };
        if self.shared_keys.contains(key) {
            ClaudeCensusMemberStatus::SharesHash
        } else if self.unknown_roots.contains(&root) || record.shape.unknown() {
            ClaudeCensusMemberStatus::FamilyUnknown
        } else if record.unverified {
            ClaudeCensusMemberStatus::Unverified
        } else {
            ClaudeCensusMemberStatus::Disjoint
        }
    }

    fn counts(&self, census_complete: bool) -> ClaudeRequestCensusShadowCounts {
        ClaudeRequestCensusShadowCounts {
            would_open: self.disjointness_complete(census_complete),
            shared_keys: self.shared_keys.len(),
            ..self.counts
        }
    }
}

/// Design signature of the shadow predicate (see `disjointness_complete`).
#[cfg(test)]
pub(crate) fn claude_census_disjointness_complete(
    index: &ScanIndex,
    census_window_end: &str,
    census_complete: bool,
) -> bool {
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    ClaudeRequestCensusJoin::new(index, window, &BTreeSet::new())
        .disjointness_complete(census_complete)
}

#[cfg(test)]
pub(crate) fn claude_census_member_status(
    index: &ScanIndex,
    key: &str,
    census_window_end: &str,
    census_complete: bool,
) -> ClaudeCensusMemberStatus {
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    ClaudeRequestCensusJoin::new(index, window, &BTreeSet::new()).member_status(
        index,
        key,
        census_complete,
    )
}

/// Test-only control: scans of files under a registered root write no record,
/// so a pipeline can run the same corpus with records off. Keyed by root, not
/// a global switch, because tests run in parallel.
#[cfg(test)]
static RECORDS_DISABLED_ROOTS: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn disable_records_under_for_test(root: &Path) {
    let mut roots = RECORDS_DISABLED_ROOTS.lock().expect("records control");
    roots.push(root.to_path_buf());
    if let Ok(canonical) = std::fs::canonicalize(root) {
        roots.push(canonical);
    }
}

#[cfg(test)]
fn records_disabled_for_test(path: &Path) -> bool {
    RECORDS_DISABLED_ROOTS
        .lock()
        .expect("records control")
        .iter()
        .any(|root| path.starts_with(root))
}

#[cfg(test)]
impl ClaudeRequestCensusRecord {
    /// `request_hashes` must already be strictly ascending.
    pub(crate) fn synthetic_for_test(
        source_file_fingerprint: &str,
        window: u64,
        shape: ClaudeRequestCensusShape,
        request_hashes: Vec<u64>,
    ) -> Self {
        assert!(request_hashes.windows(2).all(|pair| pair[0] < pair[1]));
        Self {
            source_file_fingerprint: decode_fingerprint(source_file_fingerprint)
                .expect("64 lowercase hex"),
            derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
            window,
            shape,
            twin: false,
            unverified: false,
            request_hashes: shared_hashes(request_hashes),
            birth: None,
            retired: None,
            old_path_usage: None,
            modified: None,
        }
    }
    /// Drop the hashes and keep their count, as an older release's 35-day
    /// retirement stored it.
    pub(crate) fn retire(&mut self) {
        let count = self.hash_count() as u64 + self.retired.unwrap_or(0);
        self.request_hashes = None;
        self.retired = Some(count);
    }
    pub(crate) fn with_modified_for_test(mut self, modified: Option<u64>) -> Self {
        self.modified = modified;
        self
    }
    pub(crate) fn is_birth_stub_for_test(&self) -> bool {
        self.is_birth_stub()
    }
    pub(crate) fn with_birth_for_test(mut self, birth: Option<ClaudeRequestBirth>) -> Self {
        self.birth = birth;
        self
    }
    pub(crate) fn retired_for_test(&self) -> Option<u64> {
        self.retired
    }
    pub(crate) fn with_derivation_for_test(mut self, derivation: u16) -> Self {
        self.derivation = derivation;
        self
    }
    pub(crate) fn with_unverified_for_test(mut self, unverified: bool) -> Self {
        self.unverified = unverified;
        self
    }
    pub(crate) fn shape_for_test(&self) -> ClaudeRequestCensusShape {
        self.shape
    }
    pub(crate) fn request_hashes_for_test(&self) -> &[u64] {
        self.request_hashes()
    }
    pub(crate) fn window_for_test(&self) -> u64 {
        self.window
    }
    pub(crate) fn twin_for_test(&self) -> bool {
        self.twin
    }
    pub(crate) fn unverified_for_test(&self) -> bool {
        self.unverified
    }
    pub(crate) fn fingerprint_hex_for_test(&self) -> String {
        LowerHex(&self.source_file_fingerprint).to_string()
    }
}

#[cfg(test)]
impl ClaudeRequestCensus {
    /// Records, birth stubs excluded (a stub is no record).
    pub(crate) fn len_for_test(&self) -> usize {
        self.records().count()
    }
    pub(crate) fn hash_total_for_test(&self) -> usize {
        self.hash_total
    }
    pub(crate) fn keys_for_test(&self) -> Vec<String> {
        self.records().map(|(key, _)| key.clone()).collect()
    }
    pub(crate) fn insert_for_test(&mut self, key: &str, record: ClaudeRequestCensusRecord) {
        self.insert(key.to_owned(), record);
    }
    pub(crate) fn record_for_test(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records.get(key)
    }
    pub(crate) fn invalidate_keeping_birth_for_test(&mut self, key: &str) {
        self.invalidate_keeping_birth(key);
    }
    pub(crate) fn carried_birth_for_test(
        &mut self,
        key: &str,
        opened: Option<ClaudeRequestBirth>,
    ) -> Option<ClaudeRequestBirth> {
        self.carried_birth(key, opened)
    }
}

#[cfg(test)]
impl ClaudeRequestCensusShadowState {
    pub(crate) fn derivation_drift_for_test(&self) -> u64 {
        self.derivation_drift
    }
    pub(crate) fn would_open_for_test(&self) -> Option<bool> {
        self.would_open
    }
}

#[cfg(test)]
impl ScanIndex {
    pub(crate) fn claude_request_census_for_test(&self) -> &ClaudeRequestCensus {
        &self.claude_request_census
    }

    pub(crate) fn claude_request_census_mut_for_test(&mut self) -> &mut ClaudeRequestCensus {
        &mut self.claude_request_census
    }

    pub(crate) fn claude_request_census_shadow_for_test(&self) -> &ClaudeRequestCensusShadowState {
        &self.claude_request_census_shadow
    }

    pub(crate) fn seed_census_correction_for_test(&mut self, root: &str) {
        let record = self
            .claude_usage_authority_quarantine
            .get_mut(root)
            .expect("terminal authority");
        record.contract = super::CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_owned();
        record.proof_correction = Some(super::ClaudeAuthorityProofCorrection {
            proof_witness_fingerprint: record.proven_witness_fingerprint.clone(),
            owed_member_ids: record
                .member_source_file_fingerprints
                .keys()
                .cloned()
                .collect(),
        });
    }

    /// Every decision the census, fence, rearm, quarantine and settlement
    /// paths persist, with paths made relative to `base` and source
    /// fingerprints reduced to present/cleared, so two fixtures at different
    /// temporary paths compare. The record map and shadow state are excluded:
    /// they are the only state the census adds.
    pub(crate) fn claude_census_decision_view_for_test(&self, base: &Path) -> serde_json::Value {
        let canonical_base = std::fs::canonicalize(base).unwrap_or_default();
        let relative = |key: &str| {
            Path::new(key)
                .strip_prefix(base)
                .or_else(|_| Path::new(key).strip_prefix(&canonical_base))
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| key.to_owned())
        };
        let files = self
            .files
            .iter()
            .map(|(key, entry)| {
                (
                    relative(key),
                    serde_json::json!({
                        "rearmed": entry.source_file_fingerprint.is_empty(),
                        "snapshot": entry.last_snapshot_fingerprint,
                        "body_witness": entry.last_upload_body_witness,
                        "confirmed_empty": self.confirmed_empty_files.contains(key),
                        "entities": self.file_snapshot_fingerprints.get(key),
                        "unverified_source": entry.has_unverified_source(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let quarantine = self
            .claude_usage_authority_quarantine
            .iter()
            .map(|(root, record)| {
                (
                    root.clone(),
                    serde_json::json!({
                        "disposition": format!("{:?}", record.disposition),
                        "failed": record.failed_reconstruction_count,
                        "proof_correction": record.proof_correction,
                        "members": record.member_source_file_fingerprints.keys().collect::<Vec<_>>(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        serde_json::json!({
            "files": files,
            "witnesses": self.claude_usage_family_witnesses,
            "quarantine": quarantine,
            "deferred_holds": self
                .claude_account_deferred_holds
                .keys()
                .map(|key| relative(key))
                .collect::<Vec<_>>(),
            "accepted": self.accepted_snapshot_fingerprints,
            "activity": self.snapshot_activity_at,
            "quarantined": self.quarantined_snapshot_fingerprints.keys().collect::<Vec<_>>(),
            "bounded_sweep_unsettled": self.bounded_sweep_had_unsettled_upload,
            "traversal_active": self.traversal.is_some(),
        })
    }
}

#[cfg(test)]
mod reader_regression_tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn census_index_decode_uses_buffered_reads_and_structural_steps() {
        let mut index = ScanIndex::default();
        // Real persisted index data: 4 MiB of long strings, plus escaped quotes,
        // backslashes and punctuation that must stay inside the string state.
        let padding = "x".repeat(8192);
        for row in 0..512 {
            index
                .confirmed_empty_files
                .insert(format!("synthetic/{row}/{padding}/\"escaped\\path,:[{{}}]"));
        }
        for bytes in [
            serde_json::to_vec(&index).expect("compact index"),
            serde_json::to_vec_pretty(&index).expect("pretty index"),
        ] {
            assert!(bytes.len() > 4 * 1024 * 1024);
            let tokens = bytes
                .iter()
                .filter(|&&byte| {
                    matches!(byte, b'"' | b'\\' | b'{' | b'}' | b'[' | b']' | b':' | b',')
                })
                .count();
            let mut reader = CensusRead::new(bytes.as_slice());
            // This is the production decoder, including its Serde buffering.
            let decoded = reader.decode().expect("decode synthetic index");
            assert_eq!(decoded.confirmed_empty_files, index.confirmed_empty_files);
            assert!(reader.read_calls <= bytes.len() / 8192 + 4);
            // Counters catch a per-byte scanner even if Read itself is buffered.
            assert!(reader.next_calls <= 4 * tokens + 128);
            assert!(reader.next_calls < bytes.len() / 64);
        }
    }

    #[test]
    fn census_bulk_reads_preserve_quotes_and_buffer_boundaries() {
        let long_key = "k".repeat(300);
        let padding = "x".repeat(8191);
        let bytes = serde_json::to_vec(&serde_json::json!({
            (long_key): [format!("{padding}\\\"{{}}[],:"), 12.345, true, null],
            "claude_request_census_shadow": {"o": true, "f": 7},
            "ordinary": "trailing",
        }))
        .expect("synthetic bytes");
        // Keep the original byte scanner as a reference for normalization.
        let expected = {
            let mut reader = CensusRead::new(bytes.as_slice());
            let mut output = Vec::new();
            while let Some(byte) = reader.next().expect("reference byte") {
                output.push(byte);
            }
            output
        };
        for size in [1, 2, 7, 8191, 8192, 8193] {
            let mut reader = CensusRead::new(bytes.as_slice());
            let mut output = Vec::new();
            let mut buffer = vec![0; size];
            loop {
                let read = reader.read(&mut buffer).expect("chunk");
                if read == 0 {
                    break;
                }
                output.extend_from_slice(&buffer[..read]);
            }
            assert_eq!(output, expected, "read buffer size {size}");
        }
    }

    #[test]
    fn census_bulk_decode_retries_interruptions_without_losing_consumed_bytes() {
        struct InterruptedChunks<'a> {
            remaining: &'a [u8],
            chunk_size: usize,
            interrupt_next: bool,
            interruptions: usize,
        }
        impl Read for InterruptedChunks<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.interrupt_next {
                    self.interrupt_next = false;
                    self.interruptions += 1;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let limit = out.len().min(self.chunk_size);
                let read = self.remaining.read(&mut out[..limit])?;
                self.interrupt_next = read != 0;
                Ok(read)
            }
        }

        let mut index = ScanIndex {
            claude_request_census: serde_json::from_value(serde_json::json!({
                "synthetic/member": {"v": 1, "fp": "00".repeat(32), "w": 7, "s": "empty"},
            }))
            .expect("valid evidence"),
            claude_request_census_shadow: ClaudeRequestCensusShadowState {
                would_open: Some(true),
                would_open_flips: 7,
                derivation_drift: 0,
            },
            ..ScanIndex::default()
        };
        index
            .confirmed_empty_files
            .insert(format!("synthetic/{}", "x".repeat(16 * 1024)));
        assert!(!index.claude_request_census.is_empty());
        let expected = serde_json::to_value(&index).expect("expected index");
        let bytes = serde_json::to_vec(&index).expect("index bytes");
        // Every chunk is followed by an interruption. This includes ordinary
        // copied runs, root-key capture and optional evidence capture. The
        // schema-prefix case specifically interrupts after a consumed prefix.
        for chunk_size in [1, 7, b"{\"schema_version\":".len(), 8191] {
            let mut source = InterruptedChunks {
                remaining: &bytes,
                chunk_size,
                interrupt_next: false,
                interruptions: 0,
            };
            let decoded = decode_index(&mut source).expect("interrupted load/CAS read");
            assert!(source.interruptions > 0);
            assert_eq!(serde_json::to_value(decoded).expect("decoded"), expected);
        }
    }
}

#[cfg(test)]
mod memo_accounting_tests {
    use super::*;

    #[test]
    fn batched_hex_keeps_canonical_bytes_for_all_values_and_chunk_edges() {
        let bytes = (0..=255).collect::<Vec<u8>>();
        for len in [0, 1, 31, 32, 33, 63, 64, 255, 256] {
            let expected = bytes[..len]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(LowerHex(&bytes[..len]).to_string(), expected);
            assert_eq!(
                serde_json::to_vec(&LowerHex(&bytes[..len])).unwrap(),
                serde_json::to_vec(&expected).unwrap()
            );
        }
    }
}

/// Same index census visitor and admission, but no tolerant record loss.
pub(super) fn decode_persistence_census<R: std::io::Read>(
    mut reader: R,
) -> anyhow::Result<ClaudeRequestCensus> {
    use std::io::Read;
    let mut first = [0];
    reader.read_exact(&mut first)?;
    anyhow::ensure!(first == [b'{'], "census map required");
    let mut decoder =
        serde_json::Deserializer::from_reader(std::io::Cursor::new(first).chain(reader));
    let (census, dropped) = decoder.deserialize_map(CensusVisitor)?;
    decoder.end()?;
    anyhow::ensure!(dropped == 0, "census records unavailable");
    Ok(census)
}
