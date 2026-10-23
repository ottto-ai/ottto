//! Slice D1: one durable request-census record per Claude transcript (index
//! key), bound to the exact revision and census window that produced it, plus
//! a shadow of the convergence predicate those records would allow.
//!
//! A record is local-only and content-free: the sorted 8-byte SHA-256 prefixes
//! of the provider request ids one parse saw. It is never proof, usage or
//! upload input. D1 only produces, persists, prunes and measures records; no
//! fence, coverage, rearm, posture or upload decision reads them.
//!
//! Census state follows the working index (`self`), never `previous`: a held
//! or partially committed key keeps the record of the revision this window
//! parsed, even when its entry reverts. A #588 selected restore invalidates
//! the key's record instead (fail-closed), keeping only the first-seen birth
//! of the same physical object (a birth stub every reader treats as absent).

use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref, rfc3339_unix_seconds,
    ClaudeRequestCensusShadowCounts, ScanIndex, ScanIndexEntry, SnapshotItem,
    MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
};
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::{Error as _, SerializeMap};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// Bumped only when request-id or occurrence extraction, or the shape rule,
/// changes. A bump makes every stored record inert until its file is parsed
/// again. `CLAUDE_REQUEST_CENSUS_CANARY` pins what the fixed fixture corpus
/// yields under it; SOURCE reviews any change to that literal without a bump.
pub(crate) const CLAUDE_REQUEST_CENSUS_DERIVATION: u16 = 1;
/// `(derivation, sha256 of the canary corpus table)`. The derivation canary
/// test fails until both move together.
#[cfg(test)]
pub(crate) const CLAUDE_REQUEST_CENSUS_CANARY: (u16, &str) = (
    1,
    "e8e0dbc0cce7d3afefdb65752cda8f8236c6f5704a00aa1080e46620473e0ff5",
);
/// 16 MiB of hashes per census. The scan index's census (transcript records)
/// and the P1 ledger's own census (telemetry, message-only, family and sweep
/// records) each have this bound and the serialized one below: two separate
/// budgets, not one shared. A record that would push the total past it is
/// kept as an `OverBudget` tombstone without hashes, which never counts as
/// observed.
pub(crate) const MAX_CLAUDE_REQUEST_CENSUS_HASHES: usize = 2_097_152;
/// Serialized budget of the whole census field (keys, fixed fields and base64
/// hashes), charged exactly at insert. The hash bound alone serializes to
/// about 22.4 MB; the rest is keys and fixed fields with headroom for long
/// paths. Measured at M4 size: about 9.5 MB for the index's transcript
/// records and about 23 MB for the ledger.
pub(crate) const MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES: usize = 48 * 1024 * 1024;
/// Part of the serialized budget only tombstones may use, so a record that
/// does not fit always leaves an `OverBudget` tombstone behind (never a silent
/// gap). A key whose tombstone does not fit either gets no record at all,
/// which every reader treats as missing (unknown, never "no holder").
const TOMBSTONE_RESERVE_BYTES: usize = 1024 * 1024;
/// Decoder bounds: at most this many records, and keys of at most this many
/// bytes. Anything beyond is skipped entry by entry, never the index.
const MAX_CLAUDE_REQUEST_CENSUS_RECORDS: usize = MAX_DECODE_ENTRIES;
/// Interpretation and raw buffering budgets are independent of retained
/// records: at most this many entries are visited, whatever they hold.
const MAX_DECODE_ENTRIES: usize = 65_536;
pub(crate) const MAX_RAW_BYTES: usize = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES + 1024 * 1024;
/// One record's largest legitimate encoding: every hash of the budget in
/// base64, plus fixed fields. Legacy hex records were bounded by the old
/// 1,048,576-hash budget (16 MiB), which fits too.
pub(crate) const MAX_RECORD_BYTES: usize = base64_len(MAX_CLAUDE_REQUEST_CENSUS_HASHES) + 4096;
const MAX_SHADOW_WORKSPACE_BYTES: usize = 64 * 1024 * 1024;
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
    /// Tombstone: the hash budget was full, so no hashes are stored.
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
    /// Pending ruling S2: not source-verified (a tail parse that still owes
    /// its sampled audit, or a read that cannot certify its source). D1
    /// produces it as for a verified parse and only notes it here.
    unverified: bool,
    /// Sorted, strictly ascending `claude_request_hash` of every request id
    /// (None: none). Shared, never copied, by every clone of the index (the
    /// working, committed and selected-subset copies hold one buffer).
    request_hashes: Option<Arc<[u64]>>,
    /// Transcript-only safety extension; MONEY never reads these fields.
    safety: Option<Box<TranscriptSafety>>,
    safety_hashes: Option<Arc<[u64]>>,
    /// First-seen birth of the physical object at this key, set once and
    /// bound to its (device, inode).
    birth: Option<ClaudeRequestBirth>,
    /// Retired: the hashes were dropped (old, settled file); this is how many
    /// there were. A retired record still counts as recorded.
    retired: Option<u64>,
    /// Old-path requests and conserved tokens last built from this file.
    old_path_usage: Option<(u64, u64)>,
    /// Transcript records: the file's modification time (unix seconds) at the
    /// parse that wrote the record. Retirement reads it, never the index.
    modified: Option<u64>,
    /// P1 money ledger records only (they live in the ledger's own store,
    /// never in the scan index): boxed so transcript records stay small.
    ledger: Option<Box<ClaudeLedgerFields>>,
}

fn is_false(value: &bool) -> bool {
    !value
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Optional record-local capability. `ac` describes acquired bytes, not
/// parser/ownership completeness. Missing capabilities remain migration debt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct TranscriptSafety {
    sc: u8,
    #[serde(skip_serializing_if = "is_false")]
    sr: bool,
    #[serde(skip_serializing_if = "is_false")]
    ac: bool,
    #[serde(skip_serializing_if = "is_false")]
    ld: bool,
    #[serde(skip_serializing_if = "is_false")]
    mi: bool,
    oc: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    co: Vec<(String, String)>,
    #[serde(skip_serializing_if = "is_false")]
    owner_overflow: bool,
    #[serde(skip_serializing_if = "is_false")]
    all_read_residue: bool,
    #[serde(skip_serializing_if = "is_zero")]
    unread_since: u64,
    #[serde(skip_serializing_if = "is_zero")]
    last_progress_at: u64,
    #[serde(skip_serializing_if = "is_zero")]
    unread_complete_terminals: u64,
    #[serde(skip_serializing_if = "is_zero")]
    acquired: u64,
    #[serde(skip_serializing_if = "is_zero")]
    extent: u64,
}
crate::heap_layout_bound::fields!(TranscriptSafety; sc, sr, ac, ld, mi, oc, co, owner_overflow, all_read_residue, unread_since, last_progress_at, unread_complete_terminals, acquired, extent);

/// The fields only P1 ledger records carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeLedgerFields {
    /// Telemetry records (`otel:` keys): the sidecar tail position.
    tail: Option<ClaudeTelemetryTailState>,
    /// Telemetry records: one compact fact per request hash, same order
    /// (`claude_request_money::facts`).
    facts: Option<Box<[u8]>>,
    /// `sweep:` records: a persisted resumable sweep position.
    sweep: Option<ClaudeLedgerSweep>,
    /// `fam:` records: the family's last complete published shadow body.
    family: Option<ClaudeFamilyMemo>,
}

/// A resumable sweep of the ledger (the telemetry tail, the missing-sidecar
/// check, the row reconstruction). The cursor is the record's fingerprint
/// bytes (all zero: the sweep's start); the window is the current sweep's
/// start time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeLedgerSweep {
    /// Start time of the last sweep that finished without debt: everything
    /// it covers was read through at least that time. 0: never.
    pub(crate) complete_through: u64,
    /// The current sweep has debt (it cannot complete a clean pass).
    pub(crate) debt: u64,
}

/// One family's last complete shadow body (`fam:` records): what the next
/// removal delta is bound to. The record's fingerprint is the union
/// revision (member set) it was built over.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeFamilyMemo {
    pub(crate) removed_requests: u64,
    pub(crate) removed_tokens: u64,
    /// The snapshot id of the family row this memo describes: a later
    /// removal delta names it as its basis.
    pub(crate) snapshot: u64,
}

/// A bounded audit of `[0, target_offset)` in progress across pages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeTelemetryAudit {
    pub(crate) target_offset: u64,
    /// `line_sum` of the record when the audit started (over the target).
    pub(crate) target_sum: u64,
    pub(crate) position: u64,
    pub(crate) partial_sum: u64,
    /// Bytes of an oversized line skipped so far at `position`.
    pub(crate) skip_bytes: u64,
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

/// Where the telemetry tail reader stopped in one API sidecar. Offsets only
/// ever sit just past a `\n`. `line_sum` is a resumable checksum of every
/// consumed line in `[0, offset)` (wrapping sum of per-line keyed digests), so
/// an append extends it without rereading, and an audit can recompute it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClaudeTelemetryTailState {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) offset: u64,
    /// First 8 bytes of SHA-256 over the (up to) 64 bytes before `offset`.
    pub(crate) anchor: u64,
    pub(crate) line_sum: u64,
    pub(crate) last_append_unix: u64,
    /// The audit last verified `line_sum` over `[0, audited_offset)`.
    pub(crate) audited_offset: u64,
    pub(crate) audited_unix: u64,
    /// Complete directory sweeps in a row that did not find the sidecar.
    pub(crate) missing_sweeps: u64,
    /// Earliest event time (unix seconds) of any row read; 0 unknown.
    pub(crate) first_event_unix: u64,
    /// Bytes of an oversized line skipped so far at `offset` (the offset
    /// then sits inside that line); 0 when `offset` follows a newline.
    pub(crate) skip_bytes: u64,
    /// A resumable audit in progress.
    pub(crate) audit: Option<ClaudeTelemetryAudit>,
}

/// Resident bytes of one record beyond its payload (key, hashes, facts):
/// its map node share, its ledger fields' box and its hash buffer's `Arc`
/// counts (the terms `resident_bytes` charges).
pub(crate) const RECORD_RESIDENT_OVERHEAD_BYTES: usize =
    (std::mem::size_of::<String>() + std::mem::size_of::<ClaudeRequestCensusRecord>()) * 3 / 2
        + std::mem::size_of::<ClaudeLedgerFields>()
        + 2 * std::mem::size_of::<usize>();

/// The smallest serialized entry, `"":{"v":0,"fp":"<64 hex>","w":0,"s":"exact"}`
/// and its separator, rounded down: a census of N serialized bytes holds at
/// most N / this many records.
pub(crate) const MIN_ENTRY_SERIALIZED_BYTES: usize = 96;

/// One shared hash buffer: the slice and the `Arc` counts.
fn shared_hashes_bytes(hashes: &Option<Arc<[u64]>>) -> usize {
    hashes.as_ref().map_or(0, |hashes| {
        hashes.len() * std::mem::size_of::<u64>() + 2 * std::mem::size_of::<usize>()
    })
}

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestCensusRecord {
    // Owns one shared u64 buffer and, for ledger records, one boxed group.
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
            safety,
            safety_hashes,
            birth: _,
            retired: _,
            old_path_usage: _,
            modified: _,
            ledger,
        } = self;
        c.add(shared_hashes_bytes(request_hashes))?;
        c.add(shared_hashes_bytes(safety_hashes))?;
        if let Some(safety) = safety {
            crate::heap_layout_bound::HeapLayoutBound::heap_bound(safety, c)?;
        }
        match ledger {
            Some(fields) => c.add(
                std::mem::size_of::<ClaudeLedgerFields>()
                    + fields.facts.as_ref().map_or(0, |facts| facts.len()),
            ),
            None => Some(()),
        }
    }
}

/// A sorted unique hash list as a shared buffer (None when empty).
pub(crate) fn shared_hashes(hashes: Vec<u64>) -> Option<Arc<[u64]>> {
    (!hashes.is_empty()).then(|| Arc::from(hashes))
}

impl ClaudeRequestCensusRecord {
    /// What the hash budget charges.
    fn hash_count(&self) -> usize {
        self.request_hashes()
            .len()
            .saturating_add(self.safety_hashes.as_ref().map_or(0, |hashes| hashes.len()))
    }

    pub(crate) fn request_hashes(&self) -> &[u64] {
        self.request_hashes.as_deref().unwrap_or(&[])
    }

    pub(crate) fn duplicate_safety_hashes(&self) -> &[u64] {
        if self.retired.is_some() {
            self.safety_hashes.as_deref().unwrap_or(&[])
        } else {
            self.request_hashes()
        }
    }

    fn safety_complete(&self) -> bool {
        !self.over_budget()
            && self.safety.as_ref().map_or(true, |safety| !safety.sr)
            && (self.retired.is_none() || self.safety.as_ref().is_some_and(|safety| safety.sc == 1))
    }

    /// Move the existing Arc; no duplicate hash allocation at retirement.
    pub(crate) fn retire_transcript_preserving_safety(&mut self) {
        if self.retired.is_none() {
            self.retired = Some(self.request_hashes().len() as u64);
            self.safety_hashes = self.request_hashes.take();
            let safety = self.safety.get_or_insert_with(Default::default);
            safety.sc = 1;
            safety.oc = if self.twin { 0 } else { 1 };
        }
    }

    fn mark_safety_refused(&mut self) {
        let twin = self.twin;
        self.safety
            .get_or_insert_with(|| {
                Box::new(TranscriptSafety {
                    sc: 1,
                    oc: u8::from(!twin),
                    ..TranscriptSafety::default()
                })
            })
            .sr = true;
    }

    /// Another handle on the record's hash buffer (nothing is copied).
    pub(crate) fn shared_request_hashes(&self) -> Option<Arc<[u64]>> {
        self.request_hashes.clone()
    }

    pub(crate) fn birth(&self) -> Option<ClaudeRequestBirth> {
        self.birth
    }

    pub(crate) fn retired(&self) -> Option<u64> {
        self.retired
    }

    pub(crate) fn old_path_usage(&self) -> Option<(u64, u64)> {
        self.old_path_usage
    }

    pub(crate) fn tail(&self) -> Option<&ClaudeTelemetryTailState> {
        self.ledger.as_ref()?.tail.as_ref()
    }

    /// A telemetry record's facts (one per request hash, same order).
    pub(crate) fn facts(&self) -> Option<&[u8]> {
        self.ledger.as_ref()?.facts.as_deref()
    }

    /// A ledger record's start or observation time (unix seconds).
    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    #[cfg(test)]
    pub(crate) fn modified(&self) -> Option<u64> {
        self.modified
    }

    pub(crate) fn sweep(&self) -> Option<(&[u8; 32], u64, ClaudeLedgerSweep)> {
        let sweep = self.ledger.as_ref()?.sweep?;
        Some((&self.source_file_fingerprint, self.window, sweep))
    }

    pub(crate) fn family_memo(&self) -> Option<(&[u8; 32], ClaudeFamilyMemo)> {
        let memo = self.ledger.as_ref()?.family?;
        Some((&self.source_file_fingerprint, memo))
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

    /// Both records were produced at the same file fingerprint (a ledger
    /// `mh:` record and the transcript record it describes).
    pub(crate) fn same_fingerprint(&self, other: &Self) -> bool {
        self.source_file_fingerprint == other.source_file_fingerprint
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
            safety: None,
            safety_hashes: None,
            birth: None,
            retired: None,
            old_path_usage: None,
            modified: None,
            ledger: None,
        }
    }

    /// A `sweep:` record: cursor bytes, the sweep's start and its state.
    pub(crate) fn sweep_record(
        cursor: [u8; 32],
        start_unix: u64,
        sweep: ClaudeLedgerSweep,
    ) -> Self {
        Self {
            ledger: Some(Box::new(ClaudeLedgerFields {
                sweep: Some(sweep),
                ..ClaudeLedgerFields::default()
            })),
            ..Self::bookkeeping(cursor, start_unix)
        }
    }

    /// A `fam:` record: the union revision and the family's last body.
    pub(crate) fn family_record(
        revision: [u8; 32],
        observed_unix: u64,
        memo: ClaudeFamilyMemo,
    ) -> Self {
        Self {
            ledger: Some(Box::new(ClaudeLedgerFields {
                family: Some(memo),
                ..ClaudeLedgerFields::default()
            })),
            ..Self::bookkeeping(revision, observed_unix)
        }
    }

    /// A `mh:` record: the message-only (`M`) hashes one transcript parse
    /// saw, bound to that parse's fingerprint (empty: known none).
    pub(crate) fn message_record(of: &Self, message_hashes: Vec<u64>) -> Self {
        Self {
            shape: if message_hashes.is_empty() {
                ClaudeRequestCensusShape::Empty
            } else {
                ClaudeRequestCensusShape::Exact
            },
            request_hashes: shared_hashes(message_hashes),
            ..Self::bookkeeping(of.source_file_fingerprint, of.window)
        }
    }

    /// The same telemetry record with its tail state replaced (no hash or
    /// fact is copied: they move, or stay shared).
    pub(crate) fn with_tail(mut self, tail: ClaudeTelemetryTailState) -> Self {
        self.ledger.get_or_insert_with(Box::default).tail = Some(tail);
        self
    }

    /// Strict freshness (Sol N6): this record is the current census of the
    /// entry whose fingerprint is `entry_fingerprint`. Lossy, identity
    /// incomplete, unverified, over-budget, retired or other-derivation
    /// records are unknown, never current.
    pub(crate) fn current_for(&self, entry_fingerprint: &str) -> bool {
        self.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION
            && matches!(
                self.shape,
                ClaudeRequestCensusShape::Exact | ClaudeRequestCensusShape::Empty
            )
            && !self.unverified
            && !self.twin
            && self.retired.is_none()
            && decode_fingerprint(entry_fingerprint)
                .is_some_and(|fingerprint| fingerprint == self.source_file_fingerprint)
    }

    /// Freshness of a ledger holder: `current_for`, or a loss-free
    /// identity-incomplete record (it has message-only, id-less or displaced
    /// responses) whose message-only ids are known (`message_known`, the
    /// ledger's `mh:` record of this revision). Its request and message
    /// hashes are complete for the ids it has.
    pub(crate) fn current_holder_for(&self, entry_fingerprint: &str, message_known: bool) -> bool {
        self.current_for(entry_fingerprint)
            || (self.shape == ClaudeRequestCensusShape::IdentityIncomplete
                && message_known
                && self.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION
                && !self.unverified
                && !self.twin
                && self.retired.is_none()
                && decode_fingerprint(entry_fingerprint)
                    .is_some_and(|fingerprint| fingerprint == self.source_file_fingerprint))
    }

    /// A telemetry record (`otel:` key): exact hashes with one fact each, a
    /// tail position and its first-seen time in `birth`.
    pub(crate) fn telemetry(
        request_hashes: Vec<u64>,
        facts: Box<[u8]>,
        tail: ClaudeTelemetryTailState,
        first_seen_unix: u64,
    ) -> Self {
        let mut fingerprint = [0_u8; 32];
        fingerprint.copy_from_slice(&Sha256::digest(b"claude_telemetry_tail:v1"));
        Self {
            shape: if request_hashes.is_empty() {
                ClaudeRequestCensusShape::Empty
            } else {
                ClaudeRequestCensusShape::Exact
            },
            request_hashes: shared_hashes(request_hashes),
            safety: None,
            safety_hashes: None,
            birth: Some(ClaudeRequestBirth {
                unix_seconds: first_seen_unix,
                device: tail.device,
                inode: tail.inode,
            }),
            ledger: Some(Box::new(ClaudeLedgerFields {
                tail: Some(tail),
                facts: Some(facts),
                ..ClaudeLedgerFields::default()
            })),
            ..Self::bookkeeping(fingerprint, tail.last_append_unix)
        }
    }

    /// A rebuilt telemetry record keeps the retired count of the one it
    /// replaces, so retirement is never forgotten by a later append.
    pub(crate) fn carry_retired(&mut self, previous: Option<u64>) {
        self.retired = previous;
    }

    /// Drop the hashes (and a telemetry record's facts) and keep their count
    /// (retirement). A retired telemetry record's money is unavailable.
    pub(crate) fn retire(&mut self) {
        let count = self.request_hashes().len() as u64 + self.retired.unwrap_or(0);
        self.request_hashes = None;
        self.safety = None;
        self.safety_hashes = None;
        if let Some(fields) = self.ledger.as_mut() {
            fields.facts = None;
        }
        self.retired = Some(count);
    }
}

/// Census keys of the P1 money ledger. They live in the ledger's own store
/// (`claude_request_money::store`), never in the scan index; ordinary keys
/// are absolute file paths (`local_index_key`), so they always start with
/// `/` and ledger keys never do. An index that still holds one (a pre-release
/// build) drops it on load.
pub(crate) const TELEMETRY_KEY_PREFIX: &str = "otel:";
/// Persisted sweep positions (`sweep:tail`, `sweep:missing`, `sweep:message`).
pub(crate) const SWEEP_KEY_PREFIX: &str = "sweep:";
/// One family's last complete shadow body (`fam:<sha256 of the root>`).
pub(crate) const FAMILY_KEY_PREFIX: &str = "fam:";
/// The message-only hashes of one transcript parse (`mh:<index key>`).
pub(crate) const MESSAGE_KEY_PREFIX: &str = "mh:";
/// Birth stubs carry this derivation, which no parse ever produces.
const BIRTH_STUB_DERIVATION: u16 = 0;

pub(crate) fn is_ledger_key(key: &str) -> bool {
    key.starts_with(TELEMETRY_KEY_PREFIX)
        || key.starts_with(SWEEP_KEY_PREFIX)
        || key.starts_with(FAMILY_KEY_PREFIX)
        || key.starts_with(MESSAGE_KEY_PREFIX)
}

/// The `mh:` key of a transcript's index key.
pub(crate) fn message_key(index_key: &str) -> String {
    format!("{MESSAGE_KEY_PREFIX}{index_key}")
}

/// The `fam:` key of a root session.
pub(crate) fn family_key(root_session_id: &str) -> String {
    format!(
        "{FAMILY_KEY_PREFIX}{:x}",
        Sha256::digest(root_session_id.as_bytes())
    )
}

/// The telemetry record key of a root session: the API sidecar's own file
/// stem (SHA-256 of the session id). One key per physical sidecar path, so a
/// root spelled two ways can never share or split a record.
pub(crate) fn telemetry_key(root_session_id: &str) -> String {
    format!(
        "{TELEMETRY_KEY_PREFIX}{:x}",
        Sha256::digest(root_session_id.as_bytes())
    )
}

/// The record was produced at the entry's fingerprint.
pub(crate) fn fingerprint_matches(
    record: &ClaudeRequestCensusRecord,
    entry_fingerprint: &str,
) -> bool {
    decode_fingerprint(entry_fingerprint)
        .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
}

const fn base64_len(hashes: usize) -> usize {
    (hashes * 8).div_ceil(3) * 4
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
/// hash total kept in step so the budget check never walks the map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensus {
    records: BTreeMap<String, ClaudeRequestCensusRecord>,
    hash_total: usize,
    /// Exact serialized bytes of every `"key":record` pair.
    serialized_total: usize,
    /// Maintained on each charge/uncharge. Inserts never scan the corpus.
    retired_order: BTreeSet<(u64, String)>,
    extension_order: BTreeSet<(u64, String)>,
    admission_serialized_total: usize,
    active_hash_total: usize,
    safety_incomplete: SafetyIncomplete,
    ambiguous: BTreeSet<String>,
    producer_refused: u64,
    decode_lost: bool,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensus; records, hash_total, serialized_total, retired_order, extension_order, admission_serialized_total, active_hash_total, safety_incomplete, ambiguous, producer_refused, decode_lost);

const MAX_RECLAIMED_KEYS: usize = 4096;

/// A bounded set of exact local keys. No key is logged. Missing/malformed
/// persisted state is sticky closed, never interpreted as an empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SafetyIncomplete {
    derivation: u16,
    keys: BTreeSet<String>,
    since: u64,
    overflow: bool,
    reclaimed: u64,
}
impl Default for SafetyIncomplete {
    fn default() -> Self {
        Self {
            derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
            keys: BTreeSet::new(),
            since: 0,
            overflow: false,
            reclaimed: 0,
        }
    }
}
crate::heap_layout_bound::fields!(SafetyIncomplete; derivation, keys, since, overflow, reclaimed);
fn safety_key_id(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}
impl SafetyIncomplete {
    fn closed() -> Self {
        Self {
            overflow: true,
            ..Self::default()
        }
    }
    fn incomplete(&self) -> bool {
        self.overflow || !self.keys.is_empty()
    }
    fn note(&mut self, key: &str, hashes: usize, now: u64) {
        let key = safety_key_id(key);
        let key = key.as_str();
        self.reclaimed = self.reclaimed.saturating_add(hashes as u64);
        if !self.incomplete() {
            self.since = now;
        }
        if self.keys.len() < MAX_RECLAIMED_KEYS {
            self.keys.insert(key.to_owned());
        } else if !self.keys.contains(key) {
            self.overflow = true;
        }
    }
    fn restored(&mut self, key: &str) {
        self.keys.remove(&safety_key_id(key));
        if !self.incomplete() {
            self.since = 0;
        }
    }
}

/// Why an insert did not store the record as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRequestCensusInsert {
    Stored,
    Tombstone,
    /// Not even the tombstone fits: the key has no record (read as missing).
    Refused,
}

fn entry_serialized_bytes(key: &str, record: &ClaudeRequestCensusRecord) -> usize {
    // `"key":` plus the record plus one separator.
    serialized_len(&key)
        .saturating_add(serialized_len(record))
        .saturating_add(2)
}

/// Main's admission form. Safety-only fields cannot displace a money record.
fn admission_bytes(key: &str, record: &ClaudeRequestCensusRecord) -> usize {
    let mut legacy = record.clone();
    legacy.safety = None;
    legacy.safety_hashes = None;
    entry_serialized_bytes(key, &legacy)
}

fn serialized_len<T: Serialize + ?Sized>(value: &T) -> usize {
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
    serde_json::to_writer(&mut count, value).map_or(usize::MAX, |()| count.0)
}

impl ClaudeRequestCensus {
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

    pub(crate) fn hash_total(&self) -> usize {
        self.hash_total
    }

    /// Records held (birth stubs included).
    pub(crate) fn record_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn serialized_total(&self) -> usize {
        self.serialized_total
    }

    /// Serialized bytes a full record may still take before the tombstone
    /// reserve (what the ledger admits its growth against).
    pub(crate) fn serialized_headroom(&self) -> usize {
        (MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - TOMBSTONE_RESERVE_BYTES)
            .saturating_sub(self.serialized_total)
    }

    /// Hashes a record may still add.
    pub(crate) fn hash_headroom(&self) -> usize {
        MAX_CLAUDE_REQUEST_CENSUS_HASHES.saturating_sub(self.hash_total)
    }

    /// The records whose keys start with `prefix`, in key order.
    pub(crate) fn records_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a ClaudeRequestCensusRecord)> + 'a {
        self.records
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .take_while(move |(key, _)| key.starts_with(prefix))
            .filter(|(_, record)| !record.is_birth_stub())
    }

    /// Heap this census holds, measured: its shared buffers, boxed ledger
    /// groups, keys and its map slots (a B-tree slot share at two-thirds
    /// node occupancy). One copy: the ledger is never cloned. None when
    /// `deadline` passes during the walk (checked before every record).
    pub(crate) fn resident_bytes(&self, deadline: std::time::Instant) -> Option<usize> {
        let node =
            (std::mem::size_of::<String>() + std::mem::size_of::<ClaudeRequestCensusRecord>()) * 3
                / 2;
        self.records
            .iter()
            .try_fold(0_usize, |bytes, (key, record)| {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                let ledger = record.ledger.as_ref().map_or(0, |fields| {
                    std::mem::size_of::<ClaudeLedgerFields>()
                        + fields.facts.as_ref().map_or(0, |facts| facts.len())
                });
                Some(
                    bytes
                        .saturating_add(node)
                        .saturating_add(key.capacity())
                        .saturating_add(shared_hashes_bytes(&record.request_hashes))
                        .saturating_add(shared_hashes_bytes(&record.safety_hashes))
                        .saturating_add(
                            record
                                .safety
                                .as_ref()
                                .and_then(|safety| {
                                    crate::heap_layout_bound::completed_bound(safety, usize::MAX)
                                })
                                .unwrap_or(0),
                        )
                        .saturating_add(ledger),
                )
            })
    }

    /// Move every record of `other` in (a ledger shard), each against the
    /// budgets like a decoded record and against `max_records` in total (a
    /// new key past it is dropped). True when every record was kept.
    pub(crate) fn absorb(&mut self, other: Self, max_records: usize) -> bool {
        let mut kept = true;
        self.ambiguous.extend(other.ambiguous.iter().cloned());
        for key in &other.ambiguous {
            self.remove(key);
        }
        for (key, record) in other.records {
            if self.ambiguous.contains(&key) {
                kept = false;
                continue;
            }
            if self.records.len() >= max_records && !self.records.contains_key(&key) {
                kept = false;
                continue;
            }
            kept &= self.insert_decoded(key, record);
        }
        kept
    }

    fn charge(&mut self, key: &str, record: &ClaudeRequestCensusRecord, sign: bool) {
        let hashes = record.hash_count();
        let bytes = entry_serialized_bytes(key, record);
        let admission = admission_bytes(key, record);
        let active = record.request_hashes().len();
        if sign {
            self.admission_serialized_total += admission;
            self.active_hash_total += active;
        } else {
            self.admission_serialized_total -= admission;
            self.active_hash_total -= active;
        }
        if record.safety.is_some() {
            let order = (record.window, key.to_owned());
            if sign {
                self.extension_order.insert(order);
            } else {
                self.extension_order.remove(&order);
            }
        }
        let retired = record.retired.is_some() && record.safety_hashes.is_some();
        let order = (record.modified.unwrap_or(record.window), key.to_owned());
        if retired {
            if sign {
                self.retired_order.insert(order);
            } else {
                self.retired_order.remove(&order);
            }
        }
        if sign {
            self.hash_total += hashes;
            self.serialized_total = self.serialized_total.saturating_add(bytes);
        } else {
            self.hash_total -= hashes;
            self.serialized_total = self.serialized_total.saturating_sub(bytes);
        }
    }

    /// Replaces `key`'s record. A record whose hashes or serialized size would
    /// push the totals past the budgets is stored as an `OverBudget`
    /// tombstone instead; tombstones may use the reserve, full records not.
    pub(crate) fn insert(
        &mut self,
        key: String,
        mut record: ClaudeRequestCensusRecord,
    ) -> ClaudeRequestCensusInsert {
        if let Some(old) = self.records.remove(&key) {
            self.charge(&key, &old, false);
        }
        let limit = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - TOMBSTONE_RESERVE_BYTES;
        let main_fits = self
            .active_hash_total
            .saturating_add(record.request_hashes().len())
            <= MAX_CLAUDE_REQUEST_CENSUS_HASHES
            && self
                .admission_serialized_total
                .saturating_add(admission_bytes(&key, &record))
                <= limit;
        let mut outcome = ClaudeRequestCensusInsert::Stored;
        if !main_fits {
            record.shape = ClaudeRequestCensusShape::OverBudget;
            record.request_hashes = None;
            record.safety_hashes = None;
            record.safety = None;
            record.retired = None;
            if let Some(fields) = record.ledger.as_mut() {
                fields.facts = None;
            }
            self.producer_refused = self.producer_refused.saturating_add(1);
            outcome = ClaudeRequestCensusInsert::Tombstone;
            if self
                .admission_serialized_total
                .saturating_add(admission_bytes(&key, &record))
                > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
            {
                return ClaudeRequestCensusInsert::Refused;
            }
        }
        if !is_ledger_key(&key) {
            let mut marker = self.safety_incomplete.clone();
            let mut bytes = self
                .serialized_total
                .saturating_add(entry_serialized_bytes(&key, &record));
            let mut hashes = self.hash_total.saturating_add(record.hash_count());
            // Optional safety metadata is best effort; never drop active hashes.
            // Retain the key as incomplete until an authorized parse restores it.
            // No scan: the maintained extension queue contains precisely these keys.
            let mut plan = BTreeMap::new();
            let marker_bytes = |_: &SafetyIncomplete| 0_usize;
            if bytes.saturating_add(marker_bytes(&marker))
                > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                && record.retired.is_none()
                && record.safety.is_some()
            {
                let before = entry_serialized_bytes(&key, &record);
                record.safety = None;
                bytes = bytes
                    .saturating_sub(before)
                    .saturating_add(entry_serialized_bytes(&key, &record));
                marker.note(&key, 0, record.window);
            }
            for (_, extension_key) in &self.extension_order {
                if bytes.saturating_add(marker_bytes(&marker))
                    <= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                {
                    break;
                }
                let old = &self.records[extension_key];
                let mut replacement = old.clone();
                replacement.safety = None;
                bytes = bytes
                    .saturating_sub(entry_serialized_bytes(extension_key, old))
                    .saturating_add(entry_serialized_bytes(extension_key, &replacement));
                marker.note(extension_key, 0, record.window);
                plan.insert(extension_key.clone(), replacement);
            }
            if record.retired.is_some()
                && (hashes > MAX_CLAUDE_REQUEST_CENSUS_HASHES
                    || bytes > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES)
            {
                let before = entry_serialized_bytes(&key, &record);
                let original = record.safety_hashes.take();
                let original_len = original.as_ref().map_or(0, |hashes| hashes.len());
                let safety = record.safety.get_or_insert_with(Default::default);
                safety.sc = 1;
                safety.sr = true;
                let base = entry_serialized_bytes(&key, &record);
                let free_bytes = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES.saturating_sub(
                    bytes
                        .saturating_sub(before)
                        .saturating_add(base)
                        .saturating_add(8),
                );
                let keep = original_len
                    .min(MAX_CLAUDE_REQUEST_CENSUS_HASHES.saturating_sub(self.hash_total))
                    .min(free_bytes.saturating_mul(3) / 32);
                record.safety_hashes = original
                    .as_ref()
                    .and_then(|hashes| shared_hashes(hashes[..keep].to_vec()));
                if bytes
                    .saturating_sub(before)
                    .saturating_add(entry_serialized_bytes(&key, &record))
                    > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                {
                    record.safety_hashes = None;
                    record.safety = None;
                }
                let retained = record
                    .safety_hashes
                    .as_ref()
                    .map_or(0, |hashes| hashes.len());
                marker.note(&key, original_len.saturating_sub(retained), record.window);
                hashes = self.hash_total.saturating_add(record.hash_count());
                bytes = bytes
                    .saturating_sub(before)
                    .saturating_add(entry_serialized_bytes(&key, &record));
            }
            // A retired reparse has already declined its own new safety if
            // necessary. Peer reclaim here can fund only its MONEY core metadata,
            // never additional reconstruction safety or active hashes.
            for (_, retired_key) in &self.retired_order {
                if hashes <= MAX_CLAUDE_REQUEST_CENSUS_HASHES
                    && bytes.saturating_add(marker_bytes(&marker))
                        <= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                {
                    break;
                }
                let old = plan.get(retired_key).unwrap_or(&self.records[retired_key]);
                let old_hashes = old
                    .safety_hashes
                    .as_deref()
                    .expect("indexed retirement buffer");
                let hash_need = hashes.saturating_sub(MAX_CLAUDE_REQUEST_CENSUS_HASHES);
                let mut without_buffer = old.clone();
                without_buffer.safety_hashes = None;
                without_buffer.mark_safety_refused();
                let base_total = bytes
                    .saturating_sub(entry_serialized_bytes(retired_key, old))
                    .saturating_add(entry_serialized_bytes(retired_key, &without_buffer));
                let encoded_room = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                    .saturating_sub(base_total)
                    .saturating_sub(8);
                let retain_by_bytes = (encoded_room / 4).saturating_mul(3) / 8;
                let byte_need = old_hashes.len().saturating_sub(retain_by_bytes);
                let reclaimed = old_hashes.len().min(hash_need.max(byte_need).max(1));
                let mut replacement = old.clone();
                replacement.safety_hashes =
                    shared_hashes(old_hashes[..old_hashes.len() - reclaimed].to_vec());
                replacement.mark_safety_refused();
                marker.note(retired_key, reclaimed, record.window);
                hashes = hashes.saturating_sub(reclaimed);
                bytes = bytes
                    .saturating_sub(entry_serialized_bytes(retired_key, old))
                    .saturating_add(entry_serialized_bytes(retired_key, &replacement));
                if replacement.safety_hashes.is_none()
                    && bytes > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
                {
                    let before = entry_serialized_bytes(retired_key, &replacement);
                    replacement.safety = None;
                    bytes = bytes
                        .saturating_sub(before)
                        .saturating_add(entry_serialized_bytes(retired_key, &replacement));
                }
                plan.insert(retired_key.clone(), replacement);
            }
            if hashes > MAX_CLAUDE_REQUEST_CENSUS_HASHES
                || bytes.saturating_add(marker_bytes(&marker))
                    > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
            {
                // Do not commit a partial reclaim or invent an OverBudget money
                // record. The exact serialized pressure blocker is explicit.
                return ClaudeRequestCensusInsert::Refused;
            }
            for (replaced_key, replacement) in plan {
                self.remove(&replaced_key);
                self.charge(&replaced_key, &replacement, true);
                self.records.insert(replaced_key, replacement);
            }
            self.safety_incomplete = marker;
        }
        if record.safety_complete()
            && record
                .safety
                .as_ref()
                .is_some_and(|safety| safety.ac && !safety.owner_overflow)
        {
            self.safety_incomplete.restored(&key);
        }
        self.ambiguous.remove(&key);
        self.charge(&key, &record, true);
        self.records.insert(key, record);
        outcome
    }

    /// A decoded record that would pass either budget is dropped, never
    /// stored. True when stored without replacing a duplicate key.
    fn insert_decoded(&mut self, key: String, record: ClaudeRequestCensusRecord) -> bool {
        let duplicate = self.records.remove(&key);
        if let Some(old) = &duplicate {
            self.charge(&key, old, false);
        }
        let fits = self
            .hash_total
            .checked_add(record.hash_count())
            .is_some_and(|total| total <= MAX_CLAUDE_REQUEST_CENSUS_HASHES)
            && self
                .serialized_total
                .checked_add(entry_serialized_bytes(&key, &record))
                .is_some_and(|total| total <= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES);
        if fits {
            self.charge(&key, &record, true);
            self.records.insert(key, record);
        }
        fits && duplicate.is_none()
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if let Some(old) = self.records.remove(key) {
            self.charge(key, &old, false);
        }
    }

    /// Remove `key`'s record and return it, uncharged (its hashes move to
    /// the caller; nothing is copied).
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let old = self.records.remove(key)?;
        self.charge(key, &old, false);
        Some(old)
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
        self.charge(key, &old, false);
        drop(old);
        self.charge(key, &ClaudeRequestCensusRecord::birth_stub(birth), true);
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

    /// Terminal prune: keep a file record (or stub) only while its key is
    /// indexed or was walked in this generation. Ledger records never belong
    /// in the index (they live in the ledger's own store).
    /// Returns how many transcript records (stubs aside) it dropped.
    fn retain_keys(&mut self, keep: impl Fn(&str) -> bool, kept_ids: &BTreeSet<String>) -> u64 {
        let mut dropped = 0_u64;
        self.safety_incomplete
            .keys
            .retain(|key| kept_ids.contains(key));
        if !self.safety_incomplete.incomplete() {
            self.safety_incomplete.since = 0;
        }
        self.ambiguous.retain(|key| keep(key));
        self.records.retain(|key, record| {
            let kept = !is_ledger_key(key) && keep(key.as_str());
            dropped += u64::from(!kept && !record.is_birth_stub());
            kept
        });
        self.recount();
        dropped
    }

    fn recount(&mut self) {
        let records = std::mem::take(&mut self.records);
        self.hash_total = 0;
        self.serialized_total = 0;
        self.retired_order.clear();
        self.extension_order.clear();
        self.active_hash_total = 0;
        self.admission_serialized_total = 0;
        for (key, record) in &records {
            self.charge(key, record, true);
        }
        self.records = records;
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
    safety_incomplete: Option<SafetyIncomplete>,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensusShadowState; would_open, would_open_flips, derivation_drift, safety_incomplete);

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
/// the record's file mtime `m`. P1 ledger records (in the ledger's own store
/// only) add the telemetry tail `to`, `td`, `tn`, `ta`, `tc`, `tl`, `tv`,
/// `tw2`, `tm`, `te`, `tk` with its resumable audit `xa`/`xs`/`xp`/`xq`/`xk`
/// and its facts `f` (base64), a sweep `sk`/`sd` and a family memo
/// `fr`/`ft`/`fd`/`fs`. `tw`, `u` and `b` are omitted when false or empty.
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
        if let Some(safety) = &self.safety {
            map.serialize_entry("x", safety)?;
        }
        if let Some(hashes) = &self.safety_hashes {
            map.serialize_entry("sb", &HashBase64(hashes))?;
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
        let Some(ledger) = self.ledger.as_deref() else {
            return map.end();
        };
        if let Some(sweep) = &ledger.sweep {
            map.serialize_entry("sk", &sweep.complete_through)?;
            map.serialize_entry("sd", &sweep.debt)?;
        }
        if let Some(memo) = &ledger.family {
            map.serialize_entry("fr", &memo.removed_requests)?;
            map.serialize_entry("ft", &memo.removed_tokens)?;
            map.serialize_entry("fs", &memo.snapshot)?;
        }
        if let Some(facts) = &ledger.facts {
            map.serialize_entry("f", &BytesBase64(facts))?;
        }
        if let Some(tail) = &ledger.tail {
            map.serialize_entry("to", &tail.offset)?;
            map.serialize_entry("td", &tail.device)?;
            map.serialize_entry("tn", &tail.inode)?;
            map.serialize_entry("ta", &tail.anchor)?;
            map.serialize_entry("tc", &tail.line_sum)?;
            map.serialize_entry("tl", &tail.last_append_unix)?;
            map.serialize_entry("tv", &tail.audited_offset)?;
            map.serialize_entry("tw2", &tail.audited_unix)?;
            map.serialize_entry("tm", &tail.missing_sweeps)?;
            map.serialize_entry("te", &tail.first_event_unix)?;
            map.serialize_entry("tk", &tail.skip_bytes)?;
            if let Some(audit) = &tail.audit {
                map.serialize_entry("xa", &audit.target_offset)?;
                map.serialize_entry("xs", &audit.target_sum)?;
                map.serialize_entry("xp", &audit.position)?;
                map.serialize_entry("xq", &audit.partial_sum)?;
                map.serialize_entry("xk", &audit.skip_bytes)?;
            }
        }
        map.end()
    }
}

impl Serialize for ClaudeRequestCensus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Compact each record inside the pretty outer index. At the supported
        // 65,536-key boundary the row indentation fits the existing 1 MiB raw
        // allowance; nested optional metadata cannot inflate a valid 48 MiB
        // record inventory past that decoder boundary. One bounded record's
        // encoding scratch is live at a time, included in overlap receipts.
        let mut map = serializer.serialize_map(Some(self.records.len()))?;
        for (key, record) in &self.records {
            let raw = serde_json::value::to_raw_value(record).map_err(S::Error::custom)?;
            map.serialize_entry(key, &raw)?;
        }
        map.end()
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
        if let Some(state) = &self.safety_incomplete {
            map.serialize_entry("s", state)?;
        }
        map.end()
    }
}

/// Persisted readers bound raw optional evidence before Serde can buffer a
/// scalar. Ordinary index bytes pass through unchanged. Oversized evidence is
/// drained with constant space and replaced by null; interpretation stops at
/// MAX_RAW_BYTES. Draining necessarily remains linear in the input bytes.
/// The token scanner never converts a number or copies an unbounded string.
pub(super) fn decode_index<R: std::io::Read>(reader: R) -> serde_json::Result<ScanIndex> {
    CensusRead::new(reader).decode()
}

pub(super) fn decode_bounded_index(bytes: &[u8]) -> anyhow::Result<ScanIndex> {
    use std::io::Read;
    let mut normalized = Vec::new();
    let mut reader = CensusRead::new(bytes);
    reader.read_to_end(&mut normalized)?;
    let mut index = crate::snapshot_retry::decode_state(&normalized)?;
    reader.invalidate_duplicates(&mut index);
    Ok(index)
}

/// Derive positional slots from Serde's own field metadata rather than pinning
/// offsets to ScanIndex's declaration order. JSON struct sequences are accepted
/// by the old reader too; they need the same evidence bounds as object fields.
fn sequence_fields() -> (usize, usize) {
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
    static SLOTS: std::sync::OnceLock<(usize, usize)> = std::sync::OnceLock::new();
    *SLOTS.get_or_init(|| {
        let mut fields = None;
        let _ = ScanIndex::deserialize(Fields(&mut fields));
        let fields = fields.expect("derived ScanIndex field metadata");
        let slot = |name| {
            fields
                .iter()
                .position(|field| *field == name)
                .expect("census field")
        };
        (
            slot("claude_request_census"),
            slot("claude_request_census_shadow"),
        )
    })
}

struct CensusRead<R> {
    reader: std::io::BufReader<R>,
    replay: Option<u8>,
    output: std::io::Cursor<Vec<u8>>,
    depth: usize,
    root_array: bool,
    array_index: usize,
    sequence_fields: (usize, usize),
    quoted: bool,
    escaped: bool,
    expect_key: bool,
    seen_census: bool,
    seen_shadow: bool,
    ambiguous_census: bool,
    duplicate_census: bool,
    duplicate_shadow: bool,
    shadow_key: bool,
    shadow_state: bool,
    capture: bool,
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
            quoted: false,
            escaped: false,
            expect_key: false,
            seen_census: false,
            seen_shadow: false,
            ambiguous_census: false,
            duplicate_census: false,
            duplicate_shadow: false,
            shadow_key: false,
            shadow_state: false,
            capture: false,
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
        index.claude_request_census.safety_incomplete = index
            .claude_request_census_shadow
            .safety_incomplete
            .clone()
            .unwrap_or_else(SafetyIncomplete::closed);
        if self.ambiguous_census || self.duplicate_census || self.duplicate_shadow {
            index.claude_request_census.safety_incomplete.overflow = true;
        }
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
        let mut overflow = false;
        while let Some(byte) = self.byte()? {
            if !quoted && depth == 0 && matches!(byte, b',' | b'}' | b']') {
                self.replay = Some(byte);
                break;
            }
            if !overflow {
                if bytes.len() == MAX_RAW_BYTES {
                    bytes = Vec::new();
                    overflow = true;
                } else {
                    bytes.push(byte);
                }
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
                    b'{' | b'[' => depth = depth.saturating_add(1),
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
            self.ambiguous_census |= census.decode_lost || !census.ambiguous.is_empty();
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
                || self.array_index == self.sequence_fields.1)
        {
            self.shadow_state = self.array_index == self.sequence_fields.1;
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
/// and a non-map field is an empty census. Persisted readers first cap raw
/// buffering with CensusRead; callers deserializing directly must supply bounded
/// input. Raw sub-parses isolate token errors from their enclosing container;
/// no record is materialized as a `serde_json::Value`.
impl<'de> Deserialize<'de> for ClaudeRequestCensus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        let refused = || Self {
            decode_lost: true,
            ..Self::default()
        };
        if raw.get().len() > MAX_RAW_BYTES || !raw.get().trim_start().starts_with('{') {
            return Ok(refused());
        }
        let mut isolated = serde_json::Deserializer::from_str(raw.get());
        Ok(isolated
            .deserialize_any(CensusVisitor { ledger: false })
            .map(|(mut census, dropped)| {
                census.decode_lost = dropped > 0;
                census
            })
            .unwrap_or_else(|_| refused()))
    }
}

/// Decode one shard file of the P1 ledger's own store
/// (`claude_request_money::store`) with the same record codec, keeping only
/// ledger keys, each record bounded by the whole census budget rather than
/// one file's hashes. None unless it is one JSON map whose every entry was
/// kept: a ledger shard that lost a record is corrupt, never partly trusted.
pub(crate) fn decode_ledger_shard(bytes: &[u8]) -> Option<ClaudeRequestCensus> {
    if bytes.len() > MAX_RAW_BYTES
        || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return None;
    }
    let mut isolated = serde_json::Deserializer::from_slice(bytes);
    let (census, dropped) = isolated
        .deserialize_any(CensusVisitor { ledger: true })
        .ok()?;
    isolated.end().ok()?;
    (dropped == 0).then_some(census)
}

/// Tolerant like the census: anything unexpected reads as the default.
impl<'de> Deserialize<'de> for ClaudeRequestCensusShadowState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        if raw.get().len() > 512 * 1024 + MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES {
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

/// `ledger`: a ledger shard (only ledger keys kept); otherwise the index's
/// census (ledger keys dropped: they never belong in the index).
struct CensusVisitor {
    ledger: bool,
}
impl<'de> Visitor<'de> for CensusVisitor {
    /// The census and how many entries it did not keep.
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
        let mut attempted = 0;
        let mut dropped = 0_u64;
        let mut remaining_work = MAX_RAW_BYTES;
        let mut seen = BTreeSet::new();
        census.safety_incomplete = SafetyIncomplete::closed();
        loop {
            if attempted == MAX_DECODE_ENTRIES || remaining_work == 0 {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    dropped += 1;
                }
                break;
            }
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            attempted += 1;
            if is_ledger_key(&key) != self.ledger {
                dropped += u64::from(self.ledger);
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if !seen.insert(key.clone()) {
                census.remove(&key);
                census.ambiguous.insert(key);
                census.safety_incomplete.overflow = true;
                dropped += 1;
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if key.len() > MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES
                || census.records.len() >= MAX_CLAUDE_REQUEST_CENSUS_RECORDS
            {
                dropped += 1;
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let remaining = MAX_CLAUDE_REQUEST_CENSUS_HASHES - census.hash_total;
            let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
            let bytes = raw.get().len();
            let record_limit = if self.ledger {
                MAX_RAW_BYTES
            } else {
                MAX_RECORD_BYTES
            };
            if bytes > record_limit || bytes > remaining_work {
                dropped += 1;
                remaining_work = 0;
                continue;
            }
            remaining_work -= bytes;
            let mut isolated = serde_json::Deserializer::from_str(raw.get());
            let kept = match (RecordSeed { remaining }).deserialize(&mut isolated) {
                Ok(Some(record)) => census.insert_decoded(key, record),
                _ => false,
            };
            dropped += u64::from(!kept);
        }
        if !census.ambiguous.is_empty() {
            census.safety_incomplete.overflow = true;
        }
        if (census.records.is_empty() && dropped == 0) || self.ledger {
            census.safety_incomplete = SafetyIncomplete::default();
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
        let mut marker_seen = false;
        while let Some(field) = map.next_key::<String>()? {
            if field == "s" {
                let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                state.safety_incomplete = Some(if marker_seen || raw.get().len() > 512 * 1024 {
                    SafetyIncomplete::closed()
                } else {
                    serde_json::from_str::<SafetyIncomplete>(raw.get())
                        .ok()
                        .filter(|state| {
                            state.keys.len() <= MAX_RECLAIMED_KEYS
                                && state
                                    .keys
                                    .iter()
                                    .all(|key| key.len() == 64 && lower_hex(key.as_bytes()))
                        })
                        .map(|state| {
                            if state.derivation < CLAUDE_REQUEST_CENSUS_DERIVATION {
                                SafetyIncomplete::default()
                            } else if state.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION {
                                state
                            } else {
                                SafetyIncomplete::closed()
                            }
                        })
                        .unwrap_or_else(SafetyIncomplete::closed)
                });
                marker_seen = true;
                continue;
            }
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

/// One record value, decoded against the remaining hash budget.
struct RecordSeed {
    remaining: usize,
}
impl<'de> DeserializeSeed<'de> for RecordSeed {
    type Value = Option<ClaudeRequestCensusRecord>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(RecordVisitor {
            remaining: self.remaining,
        })
    }
}

/// `None` drops the entry.
struct RecordVisitor {
    remaining: usize,
}
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
        const FIELDS: [&str; 39] = [
            "v", "fp", "w", "s", "tw", "u", "h", "b", "f", "bi", "bd", "bn", "r", "ur", "ut", "to",
            "td", "tn", "ta", "tc", "tl", "tv", "tw2", "tm", "te", "tk", "xa", "xs", "xp", "xq",
            "xk", "m", "sk", "sd", "fr", "ft", "fs", "x", "sb",
        ];
        let mut seen = 0_u64;
        let mut malformed = false;
        let mut extension_bad = false;
        let mut derivation = None;
        let mut source_file_fingerprint = None;
        let mut window = 0;
        let mut shape = None;
        let mut twin = false;
        let mut unverified = false;
        let mut request_hashes = Vec::new();
        let mut safety_hashes = Vec::new();
        let mut safety = None;
        let mut facts = None;
        // Every other P1 field is an unsigned scalar.
        let mut scalars = BTreeMap::<&'static str, u64>::new();
        while let Some(field) = map.next_key::<String>()? {
            let Some(position) = FIELDS.iter().position(|known| *known == field) else {
                // Forward compatible: an unknown field is skipped.
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
                if matches!(FIELDS[position], "x" | "sb") {
                    extension_bad = true;
                    map.next_value::<Box<serde_json::value::RawValue>>()?;
                } else {
                    malformed = true;
                    map.next_value::<IgnoredAny>()?;
                }
                continue;
            }
            seen |= bit;
            match FIELDS[position] {
                "x" => {
                    let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                    safety = (raw.get().len() <= 4096)
                        .then(|| serde_json::from_str::<TranscriptSafety>(raw.get()).ok())
                        .flatten()
                        .map(Box::new);
                    extension_bad |= safety.is_none();
                }
                "sb" => {
                    let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                    let mut isolated = serde_json::Deserializer::from_str(raw.get());
                    match (HashesSeed {
                        remaining: self.remaining,
                        encoding: HashEncoding::Base64,
                    })
                    .deserialize(&mut isolated)
                    {
                        Ok(Some(hashes)) if isolated.end().is_ok() => safety_hashes = hashes,
                        _ => extension_bad = true,
                    }
                }
                name @ ("h" | "b") => {
                    let encoding = if name == "h" {
                        HashEncoding::Hex
                    } else {
                        HashEncoding::Base64
                    };
                    match map.next_value_seed(HashesSeed {
                        remaining: self.remaining,
                        encoding,
                    })? {
                        Some(hashes) => request_hashes = hashes,
                        None => malformed = true,
                    }
                }
                // Bounded by the record's raw size; checked against the
                // record's own hash count below.
                "f" => match map.next_value_seed(FactsSeed)? {
                    Some(bytes) => facts = Some(bytes),
                    None => malformed = true,
                },
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
        extension_bad |= request_hashes.len().saturating_add(safety_hashes.len()) > self.remaining;
        if let Some(extension) = &safety {
            extension_bad |= extension.sc != 1
                || extension.oc > 1
                || extension.co.len() > 8
                || extension
                    .co
                    .iter()
                    .any(|(root, member)| root.len() > 128 || member.len() > 128)
                || !extension.co.windows(2).all(|pair| pair[0] < pair[1])
                || (extension.ac
                    && (extension.acquired != extension.extent || extension.unread_since != 0))
                || extension.acquired > extension.extent
                || extension.last_progress_at < extension.unread_since;
        }
        extension_bad |=
            !safety_hashes.is_empty() && (!request_hashes.is_empty() || !scalars.contains_key("r"));
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
        let (Some(birth), Some(old_path_usage), Some(tail), Some(audit), Some(sweep), Some(family)) = (
            group(&["bi", "bd", "bn"]),
            group(&["ur", "ut"]),
            group(&[
                "to", "td", "tn", "ta", "tc", "tl", "tv", "tw2", "tm", "te", "tk",
            ]),
            group(&["xa", "xs", "xp", "xq", "xk"]),
            group(&["sk", "sd"]),
            group(&["fr", "ft", "fs"]),
        ) else {
            return Ok(None);
        };
        let retired = scalar("r");
        if let Some(extension) = &safety {
            if retired.is_some() && !extension.sr && retired != Some(safety_hashes.len() as u64) {
                extension_bad = true;
            }
            if shape == ClaudeRequestCensusShape::Lossy
                && extension.ac
                && !(extension.ld || extension.mi || extension.all_read_residue)
            {
                extension_bad = true;
            }
        }
        if extension_bad {
            safety_hashes.clear();
            safety = Some(Box::new(TranscriptSafety {
                sc: 1,
                oc: 1,
                sr: true,
                ..TranscriptSafety::default()
            }));
        }
        let modified = scalar("m");
        let audit = audit.map(|values| ClaudeTelemetryAudit {
            target_offset: values[0],
            target_sum: values[1],
            position: values[2],
            partial_sum: values[3],
            skip_bytes: values[4],
        });
        if audit.is_some() && tail.is_none()
            || audit.is_some_and(|audit| audit.position > audit.target_offset)
        {
            return Ok(None);
        }
        let tail = tail.map(|values| ClaudeTelemetryTailState {
            offset: values[0],
            device: values[1],
            inode: values[2],
            anchor: values[3],
            line_sum: values[4],
            last_append_unix: values[5],
            audited_offset: values[6],
            audited_unix: values[7],
            missing_sweeps: values[8],
            first_event_unix: values[9],
            skip_bytes: values[10],
            audit,
        });
        if tail.is_some_and(|tail| {
            tail.audited_offset > tail.offset
                || tail
                    .audit
                    .is_some_and(|audit| audit.target_offset > tail.offset)
        }) {
            return Ok(None);
        }
        let sweep = sweep.map(|values| ClaudeLedgerSweep {
            complete_through: values[0],
            debt: values[1],
        });
        let family = family.map(|values| ClaudeFamilyMemo {
            removed_requests: values[0],
            removed_tokens: values[1],
            snapshot: values[2],
        });
        // Facts belong to a telemetry record and hold exactly one fact per
        // hash; anything else is malformed.
        if facts.as_ref().is_some_and(|facts| {
            tail.is_none()
                || !super::claude_request_money::facts::valid(facts, request_hashes.len())
        }) {
            return Ok(None);
        }
        let ledger = (tail.is_some() || facts.is_some() || sweep.is_some() || family.is_some())
            .then(|| {
                Box::new(ClaudeLedgerFields {
                    tail,
                    facts,
                    sweep,
                    family,
                })
            });
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
                    safety,
                    safety_hashes: shared_hashes(safety_hashes),
                    birth: birth.map(|values| ClaudeRequestBirth {
                        unix_seconds: values[0],
                        device: values[1],
                        inode: values[2],
                    }),
                    retired,
                    old_path_usage: old_path_usage.map(|values| (values[0], values[1])),
                    modified,
                    ledger,
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

/// A hash list string (`h` hex, `b` base64). It is refused before any
/// decoding when it would hold more hashes than the remaining budget.
struct HashesSeed {
    remaining: usize,
    encoding: HashEncoding,
}
impl<'de> DeserializeSeed<'de> for HashesSeed {
    type Value = Option<Vec<u64>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(HashesVisitor {
            remaining: self.remaining,
            encoding: self.encoding,
        })
    }
}

struct HashesVisitor {
    remaining: usize,
    encoding: HashEncoding,
}
impl<'de> Visitor<'de> for HashesVisitor {
    type Value = Option<Vec<u64>>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ascending request hashes")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        let hashes = match self.encoding {
            HashEncoding::Hex => value.len() / 16,
            HashEncoding::Base64 => value.len() / 4 * 3 / 8,
        };
        if hashes > self.remaining {
            return Ok(None);
        }
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

/// A record's facts (`f`, base64): the bytes, or None when malformed.
struct FactsSeed;
impl<'de> DeserializeSeed<'de> for FactsSeed {
    type Value = Option<Box<[u8]>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(FactsVisitor)
    }
}
struct FactsVisitor;
impl<'de> Visitor<'de> for FactsVisitor {
    type Value = Option<Box<[u8]>>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("base64 telemetry facts")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()
            .map(Vec::into_boxed_slice))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

/// Base64 (standard, padded) of a byte buffer, streamed in 3 KiB pieces.
struct BytesBase64<'a>(&'a [u8]);
impl fmt::Display for BytesBase64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use base64::Engine;
        let mut text = [0_u8; 4096];
        for chunk in self.0.chunks(3072) {
            let written = base64::engine::general_purpose::STANDARD
                .encode_slice(chunk, &mut text)
                .map_err(|_| fmt::Error)?;
            f.write_str(std::str::from_utf8(&text[..written]).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}
impl Serialize for BytesBase64<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
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

struct LowerHex<'a>(&'a [u8]);
impl fmt::Display for LowerHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}
impl Serialize for LowerHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

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
#[allow(clippy::too_many_arguments)]
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
            .take(MAX_CLAUDE_REQUEST_CENSUS_HASHES + 1)
            .collect::<Vec<_>>()
    };
    if request_hashes.len() > MAX_CLAUDE_REQUEST_CENSUS_HASHES {
        return Some(ClaudeRequestCensusRecord {
            source_file_fingerprint,
            derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
            window,
            shape: ClaudeRequestCensusShape::OverBudget,
            unverified,
            ..ClaudeRequestCensusRecord::bookkeeping(source_file_fingerprint, window)
        });
    }
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
    let mut owners = BTreeSet::new();
    for item in items {
        owners.insert((
            claude_snapshot_family_root_ref(item).to_owned(),
            item.source_session_id.clone(),
        ));
        if owners.len() > 8 {
            break;
        }
    }
    let owner_overflow = owners.len() > 8
        || owners
            .iter()
            .any(|(root, member)| root.len() > 128 || member.len() > 128);
    let safety = Box::new(TranscriptSafety {
        sc: 1,
        oc: 1,
        ac: complete,
        ld: lossy,
        mi: items.len() > 1,
        co: if owner_overflow {
            Vec::new()
        } else {
            owners.into_iter().collect()
        },
        owner_overflow,
        ..TranscriptSafety::default()
    });
    Some(ClaudeRequestCensusRecord {
        source_file_fingerprint,
        derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
        window,
        shape,
        twin,
        unverified,
        request_hashes: shared_hashes(request_hashes),
        safety: Some(safety),
        safety_hashes: None,
        birth: None,
        retired: None,
        old_path_usage: Some(old_path_usage),
        modified: None,
        ledger: None,
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
    pub(crate) acquired_eof: bool,
    pub(crate) acquired: u64,
    pub(crate) extent: u64,
    pub(crate) lossy: bool,
    pub(crate) source_verified: bool,
    pub(crate) itemless_request_hashes: Vec<u64>,
    /// Creation time and identity of the object this parse opened, when the
    /// parse opened one and the file system reports a creation time.
    pub(crate) opened_birth: Option<ClaudeRequestBirth>,
    /// The candidate's modification time (unix seconds; 0 unknown), kept on
    /// the record for retirement.
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
        .take(MAX_CLAUDE_REQUEST_CENSUS_HASHES + 1)
        .collect::<Vec<_>>();
    if hashes.len() > MAX_CLAUDE_REQUEST_CENSUS_HASHES {
        return hashes;
    }
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

/// Every Claude family-member parse that reaches `finish` replaces the key's
/// record with one bound to the candidate fingerprint and this window: a
/// complete parse by its shape, an incomplete or residue parse as `Lossy`
/// with the ids it saw. An older record never survives a newer parse.
pub(crate) fn record_claude_request_census(
    index: &mut ScanIndex,
    parse: ClaudeRequestCensusParse<'_>,
    items: &[SnapshotItem],
) {
    let Some(path_owner) = claude_index_path_family_member(parse.path) else {
        return;
    };
    #[cfg(test)]
    if records_disabled_for_test(parse.path) {
        return;
    }
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
    let record_fingerprint = record.source_file_fingerprint;
    if let Some(safety) = record.safety.as_mut() {
        safety.ac = parse.acquired_eof && parse.acquired == parse.extent;
        safety.acquired = parse.acquired;
        safety.extent = parse.extent;
        safety.all_read_residue = safety.ac && !parse.complete;
        safety.ld |= safety.all_read_residue;
        if !safety.ac {
            safety.unread_since = window;
            safety.last_progress_at = window;
            if let Some(old) = index.claude_request_census.get(parse.index_key) {
                if let Some(previous) = &old.safety {
                    if !previous.ac {
                        safety.unread_since = previous.unread_since;
                        safety.unread_complete_terminals = previous.unread_complete_terminals;
                        if (old.source_file_fingerprint == record_fingerprint
                            && safety.acquired <= previous.acquired)
                            || safety.acquired == 0
                        {
                            safety.last_progress_at = previous.last_progress_at;
                        }
                    }
                }
            }
        }
    }
    record.birth = index
        .claude_request_census
        .carried_birth(parse.index_key, parse.opened_birth);
    record.modified = (parse.modified_unix_seconds > 0).then_some(parse.modified_unix_seconds);
    if let Some(old) = index.claude_request_census.get(parse.index_key) {
        // S3(d): the same verified revision under the same derivation must
        // yield the same census. Residue, lossy and budget tombstones (whose
        // shape and hashes the budget replaced) and retired records (whose
        // hashes retirement dropped) are excluded.
        let comparable = |record: &ClaudeRequestCensusRecord| {
            !record.unverified
                && record.safety.as_ref().map_or(true, |safety| safety.ac)
                && record.safety_complete()
                && !matches!(
                    record.shape,
                    ClaudeRequestCensusShape::Lossy | ClaudeRequestCensusShape::OverBudget
                )
        };
        if parse.complete
            && comparable(old)
            && comparable(&record)
            && old.derivation == record.derivation
            && old.source_file_fingerprint == record.source_file_fingerprint
            && (old.shape != record.shape
                || old.duplicate_safety_hashes() != record.duplicate_safety_hashes())
        {
            let state = &mut index.claude_request_census_shadow;
            state.derivation_drift = state.derivation_drift.saturating_add(1);
        }
        // An unchanged re-parse of a retired record (a backfill, a resume
        // miss) stays retired while its file is still past the cutoff: its
        // hashes, and the index bytes, do not bounce back.
        let cutoff = window.saturating_sub(CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS);
        if old.retired.is_some()
            && window > 0
            && old.derivation == record.derivation
            && old.source_file_fingerprint == record.source_file_fingerprint
            && record.modified.is_some_and(|modified| modified < cutoff)
        {
            record.retire_transcript_preserving_safety();
        }
    }
    let _ = index
        .claude_request_census
        .insert(parse.index_key.to_owned(), record);
}

/// A parse that reaches no record (a failed finish, or a native comparison
/// target whose record allocation is not prepaid) leaves the key without
/// one, never with an older revision's.
pub(crate) fn invalidate_claude_request_census(index: &mut ScanIndex, path: &Path) {
    if claude_index_path_family_member(path).is_some() {
        index
            .claude_request_census
            .invalidate_keeping_birth(&super::local_index_key(path));
    }
}

/// Complete Claude terminal, before any join and before the snapshot_sync
/// folds: prune records of keys neither indexed nor walked this generation,
/// then measure the shadow census. Nothing reads the result into a decision.
#[cfg(test)]
pub(crate) fn settle_claude_request_census_terminal(
    index: &mut ScanIndex,
    observed_index_keys: &BTreeSet<String>,
    residue_index_keys: &BTreeSet<String>,
    census_window_end: &str,
) -> ClaudeRequestCensusShadowCounts {
    prepare_claude_request_census_terminal(
        index,
        observed_index_keys,
        residue_index_keys,
        census_window_end,
        &mut None,
    )
}

pub(crate) fn prepare_claude_request_census_terminal(
    index: &mut ScanIndex,
    observed_index_keys: &BTreeSet<String>,
    residue_index_keys: &BTreeSet<String>,
    census_window_end: &str,
    view: &mut Option<Arc<CensusShadowView>>,
) -> ClaudeRequestCensusShadowCounts {
    let started = std::time::Instant::now();
    let files = &index.files;
    let kept_ids = files
        .keys()
        .chain(observed_index_keys.iter())
        .map(|key| safety_key_id(key))
        .collect::<BTreeSet<_>>();
    let vanished = index.claude_request_census.retain_keys(
        |key| files.contains_key(key) || observed_index_keys.contains(key),
        &kept_ids,
    );
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    let aged = retire_claude_transcript_records(index, window);
    note_transcript_retirements(aged, vanished);
    for record in index.claude_request_census.records.values_mut() {
        if let Some(safety) = record.safety.as_mut().filter(|safety| !safety.ac) {
            safety.unread_complete_terminals = safety.unread_complete_terminals.saturating_add(1);
        }
    }
    index.claude_request_census.recount();
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
    counts.census_evidence_bytes = counts.json_bytes.saturating_add(serialized_len(
        &index.claude_request_census.safety_incomplete,
    )) as u64;
    counts.shadow_elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
    counts.heap_bytes =
        crate::heap_layout_bound::completed_bound(&index.claude_request_census, usize::MAX)
            .unwrap_or_default();
    counts.shadow_peak_heap_bytes = counts.transient_peak_bytes;
    *view = CensusShadowView::prepare(index, join, counts, census_window_end).map(Arc::new);
    counts
}

/// Synchronize the optional root metadata immediately before the atomic save.
/// Partial selected saves retain the same working census/admission transaction.
pub(crate) fn prepare_safety_checkpoint(index: &mut ScanIndex) {
    if !index.claude_request_census.records.is_empty()
        || index.claude_request_census.safety_incomplete.incomplete()
        || index.claude_request_census_shadow.would_open.is_some()
    {
        index.claude_request_census_shadow.safety_incomplete =
            Some(index.claude_request_census.safety_incomplete.clone());
    }
}

/// A transcript is retired 35 days after its last modification.
pub(crate) const CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS: u64 = 35 * 24 * 60 * 60;

/// Process counters of transcript retirements (aged, vanished) for the P1
/// shadow line; D1's counts are unchanged.
static TRANSCRIPT_RETIRED: [std::sync::atomic::AtomicU64; 2] = [
    std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];

fn note_transcript_retirements(aged: u64, vanished: u64) {
    use std::sync::atomic::Ordering;
    TRANSCRIPT_RETIRED[0].fetch_add(aged, Ordering::Relaxed);
    TRANSCRIPT_RETIRED[1].fetch_add(vanished, Ordering::Relaxed);
}

/// Transcript records retired since the process started: (aged, vanished).
pub(crate) fn transcript_retirements() -> (u64, u64) {
    use std::sync::atomic::Ordering;
    (
        TRANSCRIPT_RETIRED[0].load(Ordering::Relaxed),
        TRANSCRIPT_RETIRED[1].load(Ordering::Relaxed),
    )
}

/// P1 ledger transcript retirement, by the record's own mtime (never the
/// index entry's): a record whose file was last modified more than 35 days
/// before this window keeps its hash count and drops its hashes. A later
/// request in another file that reuses one of those ids then counts as
/// `owned_after_retirement` (an overcount risk the ledger discloses: the
/// copy is counted although the original already was).
///
/// A vanished file (StateMissing's red producer removes its index entry at
/// page end) is not retired here: the terminal prune drops its record and
/// counts it, so a copy elsewhere owns those ids under the approved rule
/// (telemetry owner first, else the copy). Retirement edits records in
/// place: nothing is cloned.
fn retire_claude_transcript_records(index: &mut ScanIndex, window: u64) -> u64 {
    if window == 0 {
        return 0;
    }
    let cutoff = window.saturating_sub(CLAUDE_TRANSCRIPT_RETIREMENT_SECONDS);
    let files = &index.files;
    let census = &mut index.claude_request_census;
    let mut aged = 0_u64;
    let mut candidates = Vec::new();
    for (key, record) in &census.records {
        if record.is_birth_stub() || record.retired.is_some() || record.hash_count() == 0 {
            continue;
        }
        // Not dirty: the indexed revision is still the one the record (and
        // its mtime) describes.
        let Some(entry) = files.get(key.as_str()).filter(|entry| {
            decode_fingerprint(&entry.source_file_fingerprint)
                .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
        }) else {
            continue;
        };
        // A record written before `m` (#664) takes the entry's mtime: the
        // equal fingerprint hashes that same mtime.
        let modified = record
            .modified
            .or((entry.modified_unix_seconds > 0).then_some(entry.modified_unix_seconds));
        if !modified.is_some_and(|modified| modified < cutoff) {
            continue;
        }
        candidates.push(key.clone());
    }
    for key in candidates {
        let Some(mut record) = census.take(&key) else {
            continue;
        };
        record.retire_transcript_preserving_safety();
        if census
            .serialized_total
            .saturating_add(entry_serialized_bytes(&key, &record))
            > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
        {
            let lost = record.safety_hashes.take().map_or(0, |hashes| hashes.len());
            record.safety.as_mut().expect("retirement capability").sr = true;
            census.safety_incomplete.note(&key, lost, window);
            if census
                .serialized_total
                .saturating_add(entry_serialized_bytes(&key, &record))
                > MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
            {
                record.safety = None;
            }
        }
        census.charge(&key, &record, true);
        census.records.insert(key, record);
        aged += 1;
    }
    aged
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

/// Per-key answer for Context 2c and D2's posture seam. D1 computes it only in
/// tests; nothing in production reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ClaudeCensusMemberStatus {
    /// The predicate holds, the own record is Exact or Empty from a verified
    /// parse, the own family is not census-unknown, and no hash of the record
    /// appears under any other key.
    Disjoint,
    /// Some hash also appears under another key (a twin included).
    SharesHash,
    SharesHashWithRetiredOwner,
    SafetyIncomplete,
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
#[derive(Debug)]
pub(crate) struct ClaudeRequestCensusJoin {
    counts: ClaudeRequestCensusShadowCounts,
    coverage: BTreeMap<String, ClaudeRequestCensusCoverage>,
    shared_keys: BTreeSet<String>,
    unknown_roots: BTreeSet<String>,
    retired_shared_keys: BTreeSet<String>,
    retired_keys: BTreeSet<String>,
    key_reasons: BTreeMap<String, u8>,
    shared_reasons: BTreeMap<String, u8>,
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
                // Birth stubs are no record.
                derivation_drift: index.claude_request_census_shadow.derivation_drift,
                shadow_spec_version: 3,
                shadow_join_builds: 1,
                shadow_healthy_terminals_attempted: 1,
                shadow_refusal_rate_known: true,
                safety_incomplete: census.safety_incomplete.incomplete(),
                safety_incomplete_since: census.safety_incomplete.since,
                safety_incomplete_overflow: census.safety_incomplete.overflow,
                safety_reclaimed: census.safety_incomplete.reclaimed,
                safety_reclaimed_keys: census.safety_incomplete.keys.len(),
                safety_incomplete_alarm: census.safety_incomplete.incomplete()
                    && (census.safety_incomplete.since == 0
                        || window.saturating_sub(census.safety_incomplete.since) > 7 * 86400),
                d2_hash_budget_alarm: census.safety_incomplete.incomplete()
                    || census.hash_total.saturating_mul(100)
                        >= MAX_CLAUDE_REQUEST_CENSUS_HASHES * 80,
                retired_records: census
                    .records()
                    .filter(|(_, record)| record.retired.is_some())
                    .count(),
                active_hash_total: census
                    .records()
                    .map(|(_, record)| record.request_hashes().len())
                    .sum(),
                retired_hash_total: census
                    .records()
                    .map(|(_, record)| {
                        record
                            .safety_hashes
                            .as_ref()
                            .map_or(0, |hashes| hashes.len())
                    })
                    .sum(),
                retired_safety_missing: census
                    .records()
                    .filter(|(_, record)| record.retired.is_some() && record.safety.is_none())
                    .count(),
                decode_ambiguous_keys: census.ambiguous.len(),
                producer_refused_keys: census.producer_refused as usize,
                records: census.records().count(),
                hashes: census.hash_total,
                hash_budget_usage_percent: census.hash_total.saturating_mul(100)
                    / MAX_CLAUDE_REQUEST_CENSUS_HASHES,
                hash_budget_warning: census.hash_total.saturating_mul(100)
                    >= MAX_CLAUDE_REQUEST_CENSUS_HASHES * 80,
                ..ClaudeRequestCensusShadowCounts::default()
            },
            key_reasons: BTreeMap::new(),
            shared_reasons: BTreeMap::new(),
            retired_shared_keys: BTreeSet::new(),
            retired_keys: BTreeSet::new(),
            coverage: BTreeMap::new(),
            shared_keys: BTreeSet::new(),
            unknown_roots: BTreeSet::new(),
        };
        // Shadow-only workspace bound. Oversized inventories remain closed;
        // ordinary scan decisions and existing resource caps are unchanged.
        if index.files.len() > MAX_DECODE_ENTRIES
            || census.records.len() > MAX_DECODE_ENTRIES
            || Self::workspace_bound(index).map_or(true, |bytes| bytes > MAX_SHADOW_WORKSPACE_BYTES)
            || index
                .files
                .keys()
                .chain(census.records.keys())
                .any(|key| key.len() > MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES)
        {
            join.counts.transient_limited = true;
            join.counts.shadow_healthy_terminals_memory_refused = 1;
            join.counts.shadow_healthy_terminal_refusal_rate_ppm = 1_000_000;
            return join;
        }
        join.retired_keys = census
            .records()
            .filter(|(_, record)| record.retired.is_some())
            .map(|(key, _)| key.clone())
            .collect();
        for (key, record) in census.records() {
            if record.over_budget() || record.safety.as_ref().is_some_and(|safety| safety.sr) {
                join.counts.safety_resource_refused_keys += 1;
            } else if !record.safety_complete() || !record.current_derivation() {
                join.counts.missing_migrate += 1;
            }
            let Some(safety) = &record.safety else {
                if record.shape == ClaudeRequestCensusShape::Lossy {
                    join.counts.shape_lossy_unread += 1;
                    join.counts.shape_lossy_classification_unknown += 1;
                    join.counts.unread_liveness_unknown_keys += 1;
                }
                if record.twin {
                    join.counts.alias_migrate_keys += 1;
                }
                continue;
            };
            join.counts.alias_migrate_keys += usize::from(record.twin && safety.oc != 1);
            join.counts.content_owner_pairs += safety.co.len();
            join.counts.content_owner_overflow_keys += usize::from(safety.owner_overflow);
            join.counts.shape_all_read_residue += usize::from(safety.all_read_residue);
            if !safety.ac {
                join.counts.shape_lossy_unread += 1;
                join.counts.unread_liveness_unknown_keys +=
                    usize::from(safety.unread_since == 0 || safety.last_progress_at == 0);
                let age = window.saturating_sub(safety.unread_since);
                join.counts.unread_oldest_age_seconds =
                    join.counts.unread_oldest_age_seconds.max(age);
                join.counts.unread_last_progress_age_seconds = join
                    .counts
                    .unread_last_progress_age_seconds
                    .max(window.saturating_sub(safety.last_progress_at));
                join.counts.unread_max_complete_terminals = join
                    .counts
                    .unread_max_complete_terminals
                    .max(safety.unread_complete_terminals);
                join.counts.unread_age_alarm_keys += usize::from(age > 7 * 86400);
                join.counts.unread_terminal_alarm_keys +=
                    usize::from(safety.unread_complete_terminals > 20);
            } else if safety.ld {
                join.counts.shape_lossy_dropped += 1;
            } else if safety.mi {
                join.counts.shape_multi_item += 1;
            }
            if record.twin || record.shape.unknown() {
                if let Some((root, _)) = claude_index_path_family_member(Path::new(key)) {
                    join.unknown_roots.insert(root);
                }
                join.unknown_roots
                    .extend(safety.co.iter().map(|(root, _)| root.clone()));
            }
        }
        let mut path_owners = BTreeMap::<(String, String), usize>::new();
        for (key, entry) in &index.files {
            let Some(path_owner) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            if index.confirmed_empty_files.contains(key) {
                join.counts.confirmed_empty_keys += 1;
                let record = census.get(key).filter(|record| record.current_derivation());
                let coverage =
                    Self::coverage(index, key, entry, record, window, residue_index_keys);
                let covered = matches!(
                    coverage,
                    ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window
                );
                join.counts.missing_confirmed_empty_records += usize::from(!covered);
                if record
                    .filter(|_| covered)
                    .is_some_and(|record| record.shape.unknown() || record.twin)
                {
                    join.unknown_roots.insert(path_owner.0.clone());
                }
                join.coverage.insert(key.clone(), coverage);
                *path_owners.entry(path_owner).or_default() += 1;
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
                    ClaudeRequestCensusShape::Lossy => {}
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
        for (key, record) in census.records() {
            let alias = record.twin
                || claude_index_path_family_member(Path::new(key))
                    .is_some_and(|owner| path_owners.get(&owner).is_some_and(|keys| *keys > 1));
            let inert = !record.safety_complete()
                || record.safety.as_ref().is_some_and(|safety| !safety.ac)
                || !matches!(
                    join.coverage.get(key),
                    Some(
                        ClaudeRequestCensusCoverage::Fingerprint
                            | ClaudeRequestCensusCoverage::Window
                    )
                )
                || record.shape.unknown()
                || record.unverified;
            let reason = u8::from(record.window != window)
                | (u8::from(inert) << 1)
                | (u8::from(record.retired.is_some()) << 2)
                | (u8::from(alias) << 3);
            if reason != 0 {
                join.key_reasons.insert(key.clone(), reason);
            }
        }
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
        let mut migration = BTreeSet::new();
        for (key, record) in census.records() {
            if !record.current_derivation()
                || (record.retired.is_some() && record.safety.is_none())
                || (record.twin && record.safety.as_ref().map_or(true, |safety| safety.oc != 1))
                || (record.shape == ClaudeRequestCensusShape::Lossy && record.safety.is_none())
            {
                migration.insert(key);
            }
        }
        for (key, coverage) in &join.coverage {
            if matches!(coverage, ClaudeRequestCensusCoverage::Migrate)
                || (index.confirmed_empty_files.contains(key) && census.get(key).is_none())
            {
                migration.insert(key);
            }
        }
        join.counts.migration_keys_estimated = migration.len();
        join.counts.migration_estimate_known = true;
        for key in migration {
            if let Some(entry) = index.files.get(key) {
                join.counts.migration_input_bytes_estimated = join
                    .counts
                    .migration_input_bytes_estimated
                    .saturating_add(usize::try_from(entry.size_bytes).unwrap_or(usize::MAX));
            } else {
                join.counts.migration_estimate_known = false;
            }
        }
        join.counts.shape_lossy = join
            .counts
            .shape_lossy_unread
            .saturating_add(join.counts.shape_lossy_dropped)
            .saturating_add(join.counts.shape_multi_item);
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
        // Two retired-owner sets, the post-save digest basis and settled roots.
        bytes = bytes.checked_add(
            records
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, ()>()?.checked_mul(2)?)?,
        )?;
        bytes = bytes.checked_add(
            records
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, [u8; 32]>()?)?,
        )?;
        bytes = bytes.checked_add(
            files
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, bool>()?)?,
        )?;
        bytes = bytes.checked_add(record_keys.checked_mul(3)?)?;
        for record in index.claude_request_census.records.values() {
            if let Some(safety) = &record.safety {
                for (root, _) in &safety.co {
                    bytes = bytes
                        .checked_add(tree_node_bytes::<String, ()>()?)?
                        .checked_add(root.len())?;
                }
            }
        }
        bytes = bytes.checked_add(
            records
                .checked_add(1)?
                .checked_mul(tree_node_bytes::<String, u8>()?.checked_mul(2)?)?,
        )?;
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
                crate::heap_layout_bound::completed_bound(&self.retired_shared_keys, usize::MAX)
                    .and_then(|extra| bytes.checked_add(extra))
            })
            .and_then(|bytes| {
                crate::heap_layout_bound::completed_bound(&self.retired_keys, usize::MAX)
                    .and_then(|extra| bytes.checked_add(extra))
            })
            .and_then(|bytes| {
                crate::heap_layout_bound::completed_bound(&self.unknown_roots, usize::MAX)
                    .and_then(|roots| bytes.checked_add(roots))
            })
            .unwrap_or(usize::MAX);
        let owned = owned
            .saturating_add(
                crate::heap_layout_bound::completed_bound(&self.key_reasons, usize::MAX)
                    .unwrap_or(usize::MAX),
            )
            .saturating_add(
                crate::heap_layout_bound::completed_bound(&self.shared_reasons, usize::MAX)
                    .unwrap_or(usize::MAX),
            );
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
            if !residue_index_keys.contains(key)
                && decode_fingerprint(&entry.source_file_fingerprint)
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
            .filter(|(_, record)| !record.duplicate_safety_hashes().is_empty())
            .map(|(key, record)| (key, record.duplicate_safety_hashes()))
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
        let reason = run_lists.iter().fold(0_u8, |mask, list| {
            mask | self
                .key_reasons
                .get(lists[*list].0)
                .copied()
                .unwrap_or_default()
        });
        if reason != 0 {
            for list in run_lists {
                *self
                    .shared_reasons
                    .entry(lists[*list].0.clone())
                    .or_default() |= reason;
            }
        }
        if run_lists
            .iter()
            .any(|list| self.retired_keys.contains(lists[*list].0))
        {
            self.retired_shared_keys
                .extend(run_lists.iter().map(|list| lists[*list].0.clone()));
        }
    }

    /// `claude_census_disjointness_complete`: on a terminal page with
    /// `census_complete`, (1) every indexed Claude family-member key that is
    /// not confirmed empty has a covering record (by fingerprint or this
    /// window; never excused by a quarantine), (2) the hash total fits the
    /// budget and (3) the duplicate owners fit the owner bound. It states only
    /// that every visible request id was compared with every other key's ids,
    /// never that any member is unique or owned.
    pub(crate) fn disjointness_complete(&self, census_complete: bool) -> bool {
        let counts = &self.counts;
        census_complete
            && !counts.safety_incomplete
            && counts.missing_confirmed_empty_records == 0
            && counts.safety_resource_refused_keys == 0
            && counts.shape_lossy_unread == 0
            && counts.retired_safety_missing == 0
            && counts.content_owner_overflow_keys == 0
            && counts.alias_migrate_keys == 0
            && counts.missing_migrate == 0
            && counts.decode_ambiguous_keys == 0
            && counts.derivation_drift == 0
            && !counts.transient_limited
            && counts.covered_by_fingerprint + counts.covered_by_window == counts.family_keys
            && counts.hashes <= MAX_CLAUDE_REQUEST_CENSUS_HASHES
            && counts.duplicate_owner_entries <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn member_status(
        &self,
        index: &ScanIndex,
        key: &str,
        census_complete: bool,
    ) -> ClaudeCensusMemberStatus {
        if self.counts.safety_incomplete {
            return ClaudeCensusMemberStatus::SafetyIncomplete;
        }
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
        if self.retired_shared_keys.contains(key) {
            ClaudeCensusMemberStatus::SharesHashWithRetiredOwner
        } else if self.shared_keys.contains(key) {
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
            strong_comparison_complete: self.disjointness_complete(census_complete),
            shares_hash_with_retired_owner_keys: self.retired_shared_keys.len(),
            shadow_keys_visited: self.coverage.len(),
            shadow_hashes_visited: self.counts.hashes,
            shadow_work_units: self.coverage.len().saturating_add(self.counts.hashes) as u64,
            shadow_workspace_peak_bytes: self.counts.transient_peak_bytes,
            would_open: self.disjointness_complete(census_complete),
            shared_keys: self.shared_keys.len(),
            ..self.counts
        }
    }
}

/// One prepared terminal join, shared by fold diagnostics and save qualification.
/// Digests retain an equality basis without cloning hash buffers or pending rows.
#[derive(Debug)]
pub(crate) struct CensusShadowView {
    generation: u64,
    window: String,
    join: ClaudeRequestCensusJoin,
    records: BTreeMap<String, [u8; 32]>,
    marker: [u8; 32],
    settled_roots: BTreeMap<String, bool>,
    comparison: std::sync::Mutex<Option<ShadowComparison>>,
}
#[derive(Debug)]
struct ShadowComparison {
    pending: BTreeMap<String, [u8; 32]>,
    counts: ClaudeRequestCensusShadowCounts,
}
fn evidence_digest(value: &impl Serialize) -> [u8; 32] {
    struct HashWriter(Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value).expect("evidence serialization");
    writer.0.finalize().into()
}
impl CensusShadowView {
    fn prepare(
        index: &ScanIndex,
        join: ClaudeRequestCensusJoin,
        counts: ClaudeRequestCensusShadowCounts,
        window: &str,
    ) -> Option<Self> {
        if counts.transient_limited {
            return None;
        }
        let records = index
            .claude_request_census
            .records
            .iter()
            .map(|(key, record)| (key.clone(), evidence_digest(record)))
            .collect();
        let mut settled_roots = BTreeMap::new();
        for key in index.files.keys() {
            if let Some((root, _)) = claude_index_path_family_member(Path::new(key)) {
                let settled = matches!(
                    join.member_status(index, key, true),
                    ClaudeCensusMemberStatus::Disjoint
                );
                *settled_roots.entry(root).or_insert(true) &= settled;
            }
        }
        Some(Self {
            settled_roots,
            generation: index.generation,
            window: window.to_owned(),
            join,
            records,
            marker: evidence_digest(&index.claude_request_census.safety_incomplete),
            comparison: std::sync::Mutex::new(Some(ShadowComparison {
                pending: BTreeMap::new(),
                counts,
            })),
        })
    }

    pub(crate) fn settled_for(&self, index: &ScanIndex, root: &str) -> bool {
        !index.claude_request_census.safety_incomplete.incomplete()
            && self.settled_roots.get(root).copied().unwrap_or(false)
    }

    /// Called after pending accumulation, before authority/fence mutation. The
    /// legacy full-hash comparison is independent of the legacy global bit.
    pub(crate) fn compare_legacy(
        &self,
        index: &ScanIndex,
        window: &str,
    ) -> ClaudeRequestCensusShadowCounts {
        let mut slot = self
            .comparison
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let comparison = slot.as_mut().expect("prepared comparison");
        let mut counts = comparison.counts;
        if self.generation != index.generation || self.window != window {
            counts.legacy_compare_generation_mismatch = true;
            return counts;
        }
        let started = std::time::Instant::now();
        let mut owner_keys = BTreeMap::<(String, String), Vec<&String>>::new();
        for key in self.records.keys() {
            if let Some(owner) = claude_index_path_family_member(Path::new(key)) {
                owner_keys.entry(owner).or_default().push(key);
            }
        }
        let mut legacy_owners = BTreeMap::<&str, BTreeSet<&String>>::new();
        let mut comparable = BTreeSet::new();
        let mut uncomparable = BTreeSet::new();
        let mut pending = BTreeMap::new();
        // Refuse before allocating the potentially large legacy occurrence map.
        let expanded_owners = index
            .claude_usage_family_pending
            .iter()
            .try_fold(0_usize, |total, (root, pending)| {
                pending.member_request_id_hashes.iter().try_fold(
                    total,
                    |total, (member, hashes)| {
                        hashes
                            .len()
                            .checked_mul(
                                owner_keys
                                    .get(&(root.clone(), member.clone()))
                                    .map_or(0, Vec::len),
                            )
                            .and_then(|entries| total.checked_add(entries))
                    },
                )
            })
            .unwrap_or(usize::MAX);
        let occurrences = expanded_owners;
        let basis_bytes = self
            .records
            .len()
            .saturating_mul(1024)
            .saturating_add(index.claude_usage_family_pending.len().saturating_mul(1024));
        let estimate = expanded_owners
            .saturating_mul(1024)
            .saturating_add(counts.transient_peak_bytes)
            .saturating_add(basis_bytes);
        if estimate > MAX_SHADOW_WORKSPACE_BYTES {
            counts.legacy_compare_budget_refused = true;
            counts.shadow_work_limited = 1;
            counts.shadow_healthy_terminals_memory_refused = 1;
            counts.shadow_healthy_terminal_refusal_rate_ppm = 1_000_000;
            comparison.counts = counts;
            return counts;
        }
        for (root, evidence) in &index.claude_usage_family_pending {
            pending.insert(root.clone(), evidence_digest(evidence));
            if evidence.census_window_end != window || evidence.invalid {
                uncomparable.insert(root.clone());
                if self.settled_for(index, root) {
                    counts.d2_settled_pending_invalid_families += 1;
                    let cause = evidence.diagnostic_invalid_causes;
                    counts.d2_settled_pending_identity_families += usize::from(cause & 1 != 0);
                    counts.d2_settled_pending_occurrence_mismatch_families +=
                        usize::from(cause & 2 != 0);
                    counts.d2_settled_pending_cap_families += usize::from(cause & 4 != 0);
                    counts.d2_settled_pending_member_changed_families +=
                        usize::from(cause & 8 != 0);
                    counts.d2_settled_pending_other_families += usize::from(cause == 0);
                }
                continue;
            }
            comparable.insert(root.clone());
            for (member, hashes) in &evidence.member_request_id_hashes {
                let Some(keys) = owner_keys.get(&(root.clone(), member.clone())) else {
                    uncomparable.insert(root.clone());
                    continue;
                };
                for hash in hashes {
                    let Some(_prefix) = hash
                        .get(..16)
                        .filter(|_| hash.len() == 64)
                        .and_then(|value| u64::from_str_radix(value, 16).ok())
                    else {
                        uncomparable.insert(root.clone());
                        continue;
                    };
                    legacy_owners
                        .entry(hash.as_str())
                        .or_default()
                        .extend(keys.iter().copied());
                }
            }
        }
        for (root, _) in owner_keys.keys() {
            if !comparable.contains(root) {
                uncomparable.insert(root.clone());
            }
        }
        let legacy_shared = legacy_owners
            .values()
            .filter(|keys| keys.len() > 1)
            .flat_map(|keys| keys.iter().map(|key| (*key).clone()))
            .collect::<BTreeSet<_>>();
        let mut missing_roots = BTreeSet::new();
        let mut reverse_roots = BTreeSet::new();
        for key in self.records.keys() {
            let Some((root, _)) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            if !comparable.contains(&root) || uncomparable.contains(&root) {
                continue;
            }
            counts.legacy_compare_keys += 1;
            if legacy_shared.contains(key) && !self.join.shared_keys.contains(key) {
                counts.legacy_dup_not_d2_shared += 1;
                missing_roots.insert(root.clone());
            }
            if self.join.shared_keys.contains(key) && !legacy_shared.contains(key) {
                counts.d2_shared_not_legacy += 1;
                reverse_roots.insert(root.clone());
            }
        }
        counts.legacy_dup_not_d2_shared_families = missing_roots.len();
        counts.d2_shared_not_legacy_families = reverse_roots.len();
        for root in reverse_roots {
            let keys = owner_keys
                .iter()
                .filter(|((owner, _), _)| *owner == root)
                .flat_map(|(_, keys)| keys.iter().copied())
                .collect::<Vec<_>>();
            let reason = keys.iter().fold(0_u8, |mask, key| {
                mask | self
                    .join
                    .shared_reasons
                    .get(*key)
                    .copied()
                    .unwrap_or_default()
            });
            let old = reason & 1 != 0;
            let inert = reason & 2 != 0;
            let retired = reason & 4 != 0;
            let alias = reason & 8 != 0;
            counts.shadow_diff_retired_families += usize::from(retired);
            counts.shadow_diff_inert_families += usize::from(inert);
            counts.shadow_diff_alias_families += usize::from(alias);
            counts.shadow_diff_old_families += usize::from(old);
            counts.shadow_diff_unclassified_families +=
                usize::from(!(retired || inert || alias || old));
        }
        counts.legacy_compare_families = comparable.difference(&uncomparable).count();
        counts.legacy_uncomparable_families = uncomparable.len();
        counts.shadow_work_units = counts
            .shadow_work_units
            .saturating_add(expanded_owners as u64);
        counts.legacy_compare_ready = true;
        counts.shadow_projected_dependent_known = false;
        counts.shadow_compare_heap_bytes = occurrences.saturating_mul(1024);
        counts.shadow_workspace_peak_bytes = counts.shadow_workspace_peak_bytes.max(
            counts
                .transient_peak_bytes
                .saturating_add(counts.shadow_compare_heap_bytes),
        );
        counts.shadow_elapsed_us = counts
            .shadow_elapsed_us
            .saturating_add(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        comparison.pending = pending;
        comparison.counts = counts;
        counts
    }

    pub(crate) fn qualify_saved(&self, saved: &ScanIndex) -> ClaudeRequestCensusShadowCounts {
        let started = std::time::Instant::now();
        let slot = self
            .comparison
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let comparison = slot.as_ref().expect("prepared comparison");
        let mut counts = comparison.counts;
        counts.shadow_post_save_equality_checked = true;
        counts.legacy_compare_generation_mismatch |=
            saved.generation != self.generation.saturating_add(1);
        let record_mismatches = self
            .records
            .iter()
            .filter(|(key, digest)| {
                saved
                    .claude_request_census
                    .records
                    .get(*key)
                    .map_or(true, |record| evidence_digest(record) != **digest)
            })
            .count();
        let pending_mismatches = comparison
            .pending
            .iter()
            .filter(|(root, digest)| {
                saved
                    .claude_usage_family_pending
                    .get(*root)
                    .map_or(true, |pending| evidence_digest(pending) != **digest)
            })
            .count();
        counts.shadow_post_save_mismatch_keys = record_mismatches
            .saturating_add(pending_mismatches)
            .saturating_add(
                self.records
                    .len()
                    .abs_diff(saved.claude_request_census.records.len()),
            )
            .saturating_add(
                comparison
                    .pending
                    .len()
                    .abs_diff(saved.claude_usage_family_pending.len()),
            )
            .saturating_add(usize::from(
                self.marker != evidence_digest(&saved.claude_request_census.safety_incomplete),
            ));
        counts.shadow_elapsed_us = counts
            .shadow_elapsed_us
            .saturating_add(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
        counts.shadow_post_save_qualified = counts.legacy_compare_ready
            && !counts.legacy_compare_generation_mismatch
            && counts.shadow_post_save_mismatch_keys == 0;
        counts
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
            safety: None,
            safety_hashes: None,
            birth: None,
            retired: None,
            old_path_usage: None,
            modified: None,
            ledger: None,
        }
    }
    pub(crate) fn without_safety_for_test(mut self) -> Self {
        self.safety = None;
        self.safety_hashes = None;
        self
    }
    pub(crate) fn with_acquired_eof_for_test(mut self, acquired: bool) -> Self {
        self.safety = Some(Box::new(TranscriptSafety {
            sc: 1,
            oc: 1,
            ac: acquired,
            ld: acquired && self.shape == ClaudeRequestCensusShape::Lossy,
            ..TranscriptSafety::default()
        }));
        self
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
    pub(crate) fn insert_for_test(
        &mut self,
        key: &str,
        record: ClaudeRequestCensusRecord,
    ) -> ClaudeRequestCensusInsert {
        self.insert(key.to_owned(), record)
    }
    pub(crate) fn serialized_total_for_test(&self) -> usize {
        self.serialized_total
    }
    pub(crate) fn exact_serialized_len_for_test(&self) -> usize {
        serialized_bytes(self)
    }
    pub(crate) fn record_for_test(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records.get(key)
    }
    pub(crate) fn invalidate_keeping_birth_for_test(&mut self, key: &str) {
        self.invalidate_keeping_birth(key);
    }
    pub(crate) fn totals_for_test(&self) -> (usize, usize) {
        (self.hash_total, self.serialized_total)
    }
    pub(crate) fn recounted_for_test(&self) -> (usize, usize) {
        let mut copy = self.clone();
        copy.recount();
        copy.totals_for_test()
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
    /// they are the only state D1 adds.
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
        let pending = self
            .claude_usage_family_pending
            .iter()
            .map(|(root, pending)| {
                (
                    root.clone(),
                    serde_json::json!({
                        "invalid": pending.invalid,
                        "window": pending.census_window_end,
                        "members": pending.member_request_id_hashes,
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
            "fence_closed": self.claude_duplicate_request_witness_overflowed,
            "duplicate_owners": self.claude_duplicate_request_owners,
            "rearm_attempt": self.claude_duplicate_fence_rearm_attempt,
            "next_full_rearm": self.claude_duplicate_fence_next_full_rearm_unix_seconds,
            "pending": pending,
            "witnesses": self.claude_usage_family_witnesses,
            "quarantine": quarantine,
            "owned_start": self
                .claude_owned_start_census
                .iter()
                .map(|(member, witness)| (
                    member.clone(),
                    (
                        witness.verified_source_file_fingerprint.is_some(),
                        witness.emitted_source_file_fingerprint.is_some(),
                    ),
                ))
                .collect::<BTreeMap<_, _>>(),
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
                safety_incomplete: None,
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
mod phase_b_tests {
    use super::*;

    const WINDOW: &str = "2026-08-02T09:00:00Z";
    const A: &str = "/phase-b/projects/a.jsonl";
    const B: &str = "/phase-b/projects/b.jsonl";

    fn record(seed: char, hashes: Vec<u64>) -> ClaudeRequestCensusRecord {
        let mut record = ClaudeRequestCensusRecord::synthetic_for_test(
            &seed.to_string().repeat(64),
            7,
            ClaudeRequestCensusShape::Exact,
            hashes,
        );
        record.safety = Some(Box::new(TranscriptSafety {
            sc: 1,
            oc: 1,
            ac: true,
            ..TranscriptSafety::default()
        }));
        record
    }
    fn index_with(records: Vec<(&str, ClaudeRequestCensusRecord)>) -> ScanIndex {
        let mut index = ScanIndex::default();
        for (key, record) in records {
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = LowerHex(&record.source_file_fingerprint).to_string();
            index.files.insert(key.to_owned(), entry);
            assert_eq!(
                index.claude_request_census.insert_for_test(key, record),
                ClaudeRequestCensusInsert::Stored
            );
        }
        index
    }

    #[test]
    fn retired_peer_safety_veto_survives_money_retirement_and_restart() {
        let mut a = record('a', vec![9]);
        a.retire_transcript_preserving_safety();
        a.retire_transcript_preserving_safety();
        assert_eq!(a.retired, Some(1));
        assert!(a.request_hashes().is_empty());
        assert!(a.shared_request_hashes().is_none());
        assert_eq!(a.duplicate_safety_hashes(), &[9]);
        let index = index_with(vec![(A, a), (B, record('b', vec![9]))]);
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-retired-restart");
        let path = scratch.join("index.json");
        let mut index = index;
        index.save(&path).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        let join = ClaudeRequestCensusJoin::new(&loaded, 7, &BTreeSet::new());
        assert!(join.disjointness_complete(true));
        assert_eq!(
            join.member_status(&loaded, B, true),
            ClaudeCensusMemberStatus::SharesHashWithRetiredOwner
        );
        assert_eq!(loaded.claude_request_census.hash_total, 2);
    }

    #[test]
    fn reclaimed_hash_closes_copy_until_healthy_original_prune() {
        let mut a = record('a', vec![9]);
        a.retire_transcript_preserving_safety();
        a.safety_hashes = None;
        a.safety.as_mut().unwrap().sr = true;
        let mut index = index_with(vec![(A, a), (B, record('b', vec![9]))]);
        index.claude_request_census.safety_incomplete.note(A, 1, 1);
        let join = ClaudeRequestCensusJoin::new(&index, 10 * 86400, &BTreeSet::new());
        assert!(!join.disjointness_complete(true));
        assert_eq!(
            join.member_status(&index, B, true),
            ClaudeCensusMemberStatus::SafetyIncomplete
        );
        assert!(join.counts.safety_incomplete_alarm);
        let view = CensusShadowView::prepare(
            &index,
            join,
            ClaudeRequestCensusShadowCounts::default(),
            WINDOW,
        )
        .unwrap();
        assert!(!view.settled_for(&index, "b"));
        index.files.remove(A);
        let counts = settle_claude_request_census_terminal(
            &mut index,
            &BTreeSet::from([B.to_owned()]),
            &BTreeSet::new(),
            WINDOW,
        );
        assert!(!counts.safety_incomplete);
        assert_eq!(counts.safety_reclaimed_keys, 0);
        assert!(counts.strong_comparison_complete);
        assert_eq!(
            claude_census_member_status(&index, B, WINDOW, true),
            ClaudeCensusMemberStatus::Disjoint
        );
    }

    #[test]
    fn safety_marker_overflow_is_sticky_after_prune_restore_and_restart() {
        let mut index = index_with(vec![(B, record('b', vec![1]))]);
        for key in 0..=MAX_RECLAIMED_KEYS {
            index
                .claude_request_census
                .safety_incomplete
                .note(&format!("/keys/{key}"), 1, 7);
        }
        assert_eq!(
            index.claude_request_census.safety_incomplete.keys.len(),
            MAX_RECLAIMED_KEYS
        );
        assert!(index.claude_request_census.safety_incomplete.overflow);
        let counts = settle_claude_request_census_terminal(
            &mut index,
            &BTreeSet::new(),
            &BTreeSet::new(),
            WINDOW,
        );
        assert!(counts.safety_incomplete);
        assert_eq!(counts.safety_reclaimed_keys, 0);
        index
            .claude_request_census
            .insert_for_test(B, record('b', vec![1]));
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-marker-overflow");
        let path = scratch.join("index.json");
        index.save(&path).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.claude_request_census.safety_incomplete.overflow);
        assert!(!claude_census_disjointness_complete(&loaded, WINDOW, true));
    }

    #[test]
    fn old_retired_capability_is_migration_debt_not_money_over_budget() {
        let mut old = record('a', vec![9]);
        old.safety = None;
        old.retire();
        let index = index_with(vec![(A, old), (B, record('b', vec![8]))]);
        assert!(!index.claude_request_census.get(A).unwrap().over_budget());
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        assert_eq!(join.counts.retired_safety_missing, 1);
        assert!(!join.disjointness_complete(true));
    }

    #[test]
    fn all_read_loss_is_local_but_unread_acquisition_closes_other_families() {
        for (acquired, expected) in [(true, true), (false, false)] {
            let mut a = record('a', vec![9]);
            a.shape = ClaudeRequestCensusShape::Lossy;
            let safety = a.safety.as_mut().unwrap();
            safety.ac = acquired;
            safety.ld = acquired;
            safety.all_read_residue = acquired;
            safety.unread_since = if acquired { 0 } else { 1 };
            safety.last_progress_at = safety.unread_since;
            safety.unread_complete_terminals = if acquired { 0 } else { 21 };
            let index = index_with(vec![(A, a), (B, record('b', vec![8]))]);
            let join = ClaudeRequestCensusJoin::new(&index, 9 * 86400, &BTreeSet::new());
            assert_eq!(join.disjointness_complete(true), expected);
            if acquired {
                assert_eq!(
                    join.member_status(&index, B, true),
                    ClaudeCensusMemberStatus::Disjoint
                );
                assert_eq!(join.counts.shape_all_read_residue, 1);
            } else {
                assert_eq!(
                    join.member_status(&index, B, true),
                    ClaudeCensusMemberStatus::Unobserved
                );
                assert_eq!(join.counts.unread_age_alarm_keys, 1);
                assert_eq!(join.counts.unread_terminal_alarm_keys, 1);
            }
        }
    }

    #[test]
    fn absent_malformed_and_duplicate_markers_preserve_siblings_and_close() {
        let mut index = index_with(vec![(B, record('b', vec![8]))]);
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-marker-decode");
        let path = scratch.join("index.json");
        index.save(&path).unwrap();
        let good = serde_json::to_value(&index).unwrap();
        for marker in [
            None,
            Some(serde_json::json!(false)),
            Some(serde_json::json!({"keys": [], "overflow": false})),
        ] {
            let mut value = good.clone();
            let shadow = value["claude_request_census_shadow"]
                .as_object_mut()
                .unwrap();
            shadow.remove("s");
            if let Some(marker) = marker {
                shadow.insert("s".to_owned(), marker);
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert!(loaded.files.contains_key(B));
            assert!(loaded.claude_request_census.get(B).is_some());
            assert!(loaded.claude_request_census.safety_incomplete.overflow);
        }
        let mut bytes = serde_json::to_string(&good).unwrap();
        let needle = "\"s\":{\"derivation\":";
        bytes = bytes.replacen(needle, "\"s\":false,\"s\":{\"derivation\":", 1);
        std::fs::write(&path, bytes).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.claude_request_census.safety_incomplete.overflow);
    }

    #[test]
    fn duplicate_record_keys_never_resurrect_even_after_a_malformed_first() {
        let b = serde_json::to_string(&record('b', vec![8])).unwrap();
        for first in ["false".to_owned(), b.clone()] {
            let raw = format!(r#"{{"{A}":{first},"{A}":{b},"{A}":{b},"{B}":{b}}}"#);
            let census: ClaudeRequestCensus = serde_json::from_str(&raw).unwrap();
            assert!(census.get(A).is_none());
            assert!(census.get(B).is_some());
            let again: ClaudeRequestCensus =
                serde_json::from_slice(&serde_json::to_vec(&census).unwrap()).unwrap();
            assert!(again.get(A).is_none());
            assert!(again.safety_incomplete.incomplete());
        }
    }

    #[test]
    fn post_save_equality_qualifies_only_the_exact_record_and_pending_basis() {
        let index = index_with(vec![(B, record('b', vec![8]))]);
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        let counts = join.counts(true);
        let view = CensusShadowView::prepare(&index, join, counts, WINDOW).unwrap();
        assert!(view.compare_legacy(&index, WINDOW).legacy_compare_ready);
        let mut saved = index.clone();
        saved.generation += 1;
        assert!(view.qualify_saved(&saved).shadow_post_save_qualified);
        // Successful save/generation alone cannot qualify a selected restoration.
        saved
            .claude_request_census
            .insert_for_test(B, record('b', vec![99]));
        let mismatch = view.qualify_saved(&saved);
        assert!(!mismatch.shadow_post_save_qualified);
        assert!(mismatch.shadow_post_save_mismatch_keys > 0);
    }
    #[test]
    fn failed_cas_cannot_persist_admission_or_reclaim() {
        let mut a = record('a', (0..MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64).collect());
        a.retire_transcript_preserving_safety();
        let mut committed = index_with(vec![(A, a)]);
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-cas-reclaim");
        let path = scratch.join("index.json");
        committed.save(&path).unwrap();
        let mut candidate = committed.clone();
        assert_eq!(
            candidate.claude_request_census.insert_for_test(
                B,
                record('b', vec![MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64])
            ),
            ClaudeRequestCensusInsert::Stored
        );
        assert!(candidate
            .claude_request_census
            .safety_incomplete
            .incomplete());
        committed.save(&path).unwrap();
        assert!(candidate.save(&path).is_err());
        let saved = ScanIndex::load(&path).unwrap();
        assert!(!saved.claude_request_census.safety_incomplete.incomplete());
        assert!(saved.claude_request_census.get(B).is_none());
        assert_eq!(
            saved
                .claude_request_census
                .get(A)
                .unwrap()
                .duplicate_safety_hashes()
                .len(),
            MAX_CLAUDE_REQUEST_CENSUS_HASHES
        );
    }

    #[test]
    fn legacy_comparison_refuses_physical_owner_fanout_before_expansion() {
        let mut index = ScanIndex::default();
        for copy in 0..1000 {
            let key = format!("/phase-b/projects/project-{copy}/member.jsonl");
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = "b".repeat(64);
            index.files.insert(key.clone(), entry);
            let mut tombstone = record('b', vec![]);
            tombstone.shape = ClaudeRequestCensusShape::OverBudget;
            index.claude_request_census.insert_for_test(&key, tombstone);
        }
        index.claude_usage_family_pending.insert(
            "member".to_owned(),
            crate::snapshots::ClaudeUsageFamilyPending {
                diagnostic_invalid_causes: 0,
                census_window_end: WINDOW.to_owned(),
                invalid: false,
                member_request_id_hashes: BTreeMap::from([(
                    "member".to_owned(),
                    (0..10000).map(|id| format!("{id:064x}")).collect(),
                )]),
                member_occurrences: BTreeMap::new(),
            },
        );
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        let counts = join.counts(true);
        let view = CensusShadowView::prepare(&index, join, counts, WINDOW).unwrap();
        let compared = view.compare_legacy(&index, WINDOW);
        assert!(compared.legacy_compare_budget_refused);
        assert!(!compared.legacy_compare_ready);
        assert_eq!(compared.shadow_healthy_terminals_memory_refused, 1);
    }

    #[test]
    fn synthetic_scale_receipt_includes_old_new_and_checkpoint_decode_overlap() {
        const FILES: usize = 12400;
        let mut index = ScanIndex::default();
        let mut next = 0_u64;
        for file in 0..FILES {
            let count = MAX_CLAUDE_REQUEST_CENSUS_HASHES / FILES
                + usize::from(file < MAX_CLAUDE_REQUEST_CENSUS_HASHES % FILES);
            let key = format!("/phase-b/projects/scale-{file}.jsonl");
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = "a".repeat(64);
            index.files.insert(key.clone(), entry);
            let hashes = (next..next + count as u64).collect();
            next += count as u64;
            assert_eq!(
                index
                    .claude_request_census
                    .insert_for_test(&key, record('a', hashes)),
                ClaudeRequestCensusInsert::Stored
            );
        }
        prepare_safety_checkpoint(&mut index);
        let checkpoint = serde_json::to_vec_pretty(&index).unwrap();
        let ((counts, workspace), allocation) =
            crate::retry_allocation_probe::measure_caller_thread(|| {
                let old = index.clone();
                let working = index.clone();
                let (join, workspace) = crate::retry_allocation_probe::measure(|| {
                    ClaudeRequestCensusJoin::new(&working, 7, &BTreeSet::new())
                });
                let counts = join.counts(true);
                let saved = decode_index(checkpoint.as_slice()).unwrap();
                assert_eq!(
                    saved.claude_request_census.hash_total,
                    MAX_CLAUDE_REQUEST_CENSUS_HASHES
                );
                assert_eq!(old.claude_request_census.records().count(), FILES);
                (counts, workspace.requested_peak_with_overlap)
            });
        eprintln!("FIX3_PHASE_B_SCALE files={FILES} hashes={} requested_peak_with_overlap={} workspace_peak={} attempted={} refused={} refusal_rate_ppm={} includes_old_new_checkpoint_decode=true per_caller_thread=true runtime_corpus=false",
            next, allocation.requested_peak_with_overlap, workspace, counts.shadow_healthy_terminals_attempted, counts.shadow_healthy_terminals_memory_refused, counts.shadow_healthy_terminal_refusal_rate_ppm);
        assert!(
            workspace <= 64 * 1024 * 1024,
            "workspace receipt: {workspace}"
        );
        assert!(
            allocation.requested_peak_with_overlap <= 128 * 1024 * 1024,
            "additional peak receipt: {}",
            allocation.requested_peak_with_overlap
        );
        assert_eq!(counts.shadow_healthy_terminals_attempted, 1);
        assert_eq!(
            counts.shadow_healthy_terminals_memory_refused,
            u64::from(counts.transient_limited)
        );
    }
    #[test]
    fn malformed_optional_safety_retains_money_bytes_but_closes_the_whole_shadow() {
        let mut index = index_with(vec![(A, record('a', vec![9])), (B, record('b', vec![8]))]);
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-inert-safety");
        let path = scratch.join("index.json");
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["files"].as_object_mut().unwrap().remove(A);
        value["claude_request_census"][A]["x"]["sc"] = serde_json::json!(99);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            loaded
                .claude_request_census
                .get(A)
                .unwrap()
                .request_hashes(),
            &[9]
        );
        assert!(loaded.claude_request_census.get(B).is_some());
        let join = ClaudeRequestCensusJoin::new(&loaded, 7, &BTreeSet::new());
        assert!(!join.disjointness_complete(true));
        assert_eq!(join.counts.safety_resource_refused_keys, 1);
    }

    #[test]
    fn malformed_unindexed_base_record_cannot_silently_restore_strong_comparison() {
        let mut index = index_with(vec![(A, record('a', vec![9])), (B, record('b', vec![8]))]);
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-base-loss");
        let path = scratch.join("index.json");
        index.save(&path).unwrap();
        let mut value = serde_json::to_value(&index).unwrap();
        value["files"].as_object_mut().unwrap().remove(A);
        value["claude_request_census"][A]["b"] = serde_json::json!("not base64");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut loaded = ScanIndex::load(&path).unwrap();
        assert!(loaded.claude_request_census.get(A).is_none());
        assert!(loaded.claude_request_census.get(B).is_some());
        assert!(loaded.claude_request_census.safety_incomplete.incomplete());
        assert!(!claude_census_disjointness_complete(&loaded, WINDOW, true));
        loaded.save(&path).unwrap();
        assert!(!claude_census_disjointness_complete(
            &ScanIndex::load(&path).unwrap(),
            WINDOW,
            true
        ));
    }
    #[test]
    fn old_lossy_capability_gap_closes_an_unrelated_exact_family() {
        let mut old = record('a', vec![9]).without_safety_for_test();
        old.shape = ClaudeRequestCensusShape::Lossy;
        let index = index_with(vec![(A, old), (B, record('b', vec![8]))]);
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        assert!(!join.disjointness_complete(true));
        assert_eq!(join.counts.shape_lossy_classification_unknown, 1);
        assert_eq!(
            join.member_status(&index, B, true),
            ClaudeCensusMemberStatus::Unobserved
        );
    }

    #[test]
    fn a_full_supported_reparse_restores_a_reclaimed_key_without_money_resurrection() {
        let mut a = record('a', vec![9]);
        a.retire_transcript_preserving_safety();
        a.safety_hashes = None;
        a.safety.as_mut().unwrap().sr = true;
        let mut index = index_with(vec![(A, a), (B, record('b', vec![8]))]);
        index.claude_request_census.safety_incomplete.note(A, 1, 7);
        let mut restored = record('a', vec![9]);
        restored.retire_transcript_preserving_safety();
        assert_eq!(
            index.claude_request_census.insert_for_test(A, restored),
            ClaudeRequestCensusInsert::Stored
        );
        assert!(!index.claude_request_census.safety_incomplete.incomplete());
        let restored = index.claude_request_census.get(A).unwrap();
        assert_eq!(restored.retired(), Some(1));
        assert!(restored.request_hashes().is_empty());
        assert_eq!(restored.duplicate_safety_hashes(), &[9]);
    }
    #[test]
    fn optional_safety_numeric_overflow_never_drops_valid_money_fields() {
        let mut index = index_with(vec![(A, record('a', vec![9]).without_safety_for_test())]);
        prepare_safety_checkpoint(&mut index);
        let base = serde_json::to_string(&index).unwrap();
        let scratch = crate::test_scratch::ScratchDir::new("phase-b-safety-number");
        let path = scratch.join("index.json");
        for extra in [
            r#""sb":1e400,"#,
            r#""x":1e400,"#,
            r#""sb":false,"sb":1e400,"#,
            r#""x":false,"x":1e400,"#,
        ] {
            let bytes = base.replacen(r#""v":1"#, &format!(r#"{extra}"v":1"#), 1);
            std::fs::write(&path, bytes).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            let record = loaded
                .claude_request_census
                .get(A)
                .expect("valid MONEY record survives optional numeric overflow");
            assert_eq!(record.request_hashes(), &[9]);
            assert!(record.current_for(&"a".repeat(64)));
            assert!(!record.over_budget());
            let join = ClaudeRequestCensusJoin::new(&loaded, 7, &BTreeSet::new());
            assert!(!join.disjointness_complete(true));
        }
    }

    #[test]
    fn shared_difference_reasons_follow_the_inert_peer_to_the_current_key() {
        let mut index = index_with(vec![(A, record('a', vec![9])), (B, record('b', vec![9]))]);
        index.files.remove(A);
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        assert_eq!(
            join.shared_reasons.get(B).copied().unwrap_or_default() & 2,
            2
        );
        assert!(join.shared_keys.contains(B));
    }
    #[test]
    fn serialized_pressure_preserves_active_and_retired_money_admission() {
        const NEW: &str = "/phase-b/projects/new.jsonl";
        const KEY_BYTES: usize = 768;
        let mut candidate = ClaudeRequestCensus::default();
        let mut a = record('a', (0..200000).collect());
        a.retire_transcript_preserving_safety();
        candidate.insert_for_test(A, a);
        let mut b = record('b', vec![1]).without_safety_for_test();
        b.retire();
        candidate.insert_for_test(B, b);
        let filler = ClaudeRequestCensusRecord::synthetic_for_test(
            &"f".repeat(64),
            7,
            ClaudeRequestCensusShape::OverBudget,
            vec![],
        );
        let entry_base = entry_serialized_bytes("", &filler);
        let min_bytes = entry_base + 32;
        let full_bytes = entry_base + KEY_BYTES;
        let key = |row: usize, bytes: usize| {
            let prefix = format!("/f/{row:05}/");
            let tail = "f.jsonl";
            let room = bytes - prefix.len() - tail.len();
            format!(
                "{prefix}{}{}{tail}",
                "d/".repeat(room / 2),
                if room % 2 == 1 { "x" } else { "" }
            )
        };
        let mut row = 0;
        while MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - candidate.serialized_total
            > full_bytes + min_bytes
        {
            assert_eq!(
                candidate.insert_for_test(&key(row, KEY_BYTES), filler.clone()),
                ClaudeRequestCensusInsert::Stored
            );
            row += 1;
        }
        let mut room = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - candidate.serialized_total;
        if room > full_bytes {
            candidate.insert_for_test(&key(row, 32), filler.clone());
            row += 1;
            room = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES - candidate.serialized_total;
        }
        assert!(room >= min_bytes);
        candidate.insert_for_test(&key(row, room - entry_base), filler);
        assert_eq!(
            candidate.serialized_total,
            MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
        );
        let mut main = candidate.clone();
        let mut a = main.take(A).unwrap();
        a.retire();
        main.charge(A, &a, true);
        main.records.insert(A.to_owned(), a);
        let scope = |census: ClaudeRequestCensus, path: &str, fingerprint: char, root: &str| {
            let mut index = ScanIndex::default();
            let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = fingerprint.to_string().repeat(64);
            index.files.insert(path.to_owned(), entry);
            index.claude_request_census = census;
            let ledger = ClaudeRequestCensus::default();
            let scope = crate::snapshots::claude_request_ledger::ClaudeLedgerScope::build(
                &index,
                &ledger,
                &BTreeSet::new(),
                &BTreeSet::from([root]),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .unwrap();
            (
                scope.family_complete(root),
                serde_json::to_vec(&scope.debt).unwrap(),
            )
        };
        for retired in [false, true] {
            let (path, fingerprint, root, updated) = if retired {
                let mut updated = record('b', vec![1]);
                updated.birth = Some(ClaudeRequestBirth {
                    unix_seconds: 1700000000,
                    device: 1,
                    inode: 2,
                });
                updated.modified = Some(1700000000);
                updated.old_path_usage = Some((1, 10));
                updated.retire_transcript_preserving_safety();
                (B, 'b', "b", updated)
            } else {
                (NEW, 'c', "new", record('c', vec![200000]))
            };
            let mut control = main.clone();
            let mut actual = candidate.clone();
            let mut legacy = updated.clone();
            legacy.safety = None;
            legacy.safety_hashes = None;
            assert_eq!(
                control.insert_for_test(path, legacy),
                ClaudeRequestCensusInsert::Stored
            );
            assert_eq!(
                actual.insert_for_test(path, updated.clone()),
                ClaudeRequestCensusInsert::Stored,
                "retired={retired}"
            );
            assert!(actual.serialized_total <= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES);
            assert_eq!(actual.serialized_total, actual.recounted_for_test().1);
            assert_eq!(
                scope(actual, path, fingerprint, root),
                scope(control, path, fingerprint, root)
            );
        }
    }
    #[test]
    fn confirmed_empty_file_is_never_a_recordless_safety_excusal() {
        let mut index = index_with(vec![(A, record('a', vec![9])), (B, record('b', vec![9]))]);
        index.confirmed_empty_files.insert(A.to_owned());
        index.claude_request_census.remove(A);
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        assert!(!join.disjointness_complete(true));
        assert_eq!(join.counts.missing_confirmed_empty_records, 1);
        assert_eq!(
            join.member_status(&index, B, true),
            ClaudeCensusMemberStatus::Unobserved
        );
        // A real all-read zero-usage response still carries its visible IDs.
        let mut restored = record('a', vec![9]);
        restored.shape = ClaudeRequestCensusShape::IdentityIncomplete;
        index.claude_request_census.insert_for_test(A, restored);
        let join = ClaudeRequestCensusJoin::new(&index, 7, &BTreeSet::new());
        assert!(join.disjointness_complete(true));
        assert_eq!(
            join.member_status(&index, B, true),
            ClaudeCensusMemberStatus::SharesHash
        );
        assert_eq!(join.counts.missing_confirmed_empty_records, 0);
    }
}
