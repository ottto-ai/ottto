//! Durable warm-cache store (M1, store layer). A separate, local, owner-only
//! directory beside a source's scan index that keeps one record per retained
//! transcript entry, so a restart can continue from where the RAM cache
//! stopped. This module owns only the envelope, the crash-safe file writes,
//! the binding to the committed index generation, garbage collection and the
//! budget receipts. It holds no accumulator field: a record's body is opaque
//! here and is produced by a per-source allowlisted codec.
//!
//! Rules this layer enforces:
//! - Records are written only after a successful index save, stamped with
//!   that save's committed generation, and only when their content changed
//!   since the last durable write (dirty), at most `MAX_BATCH` per save.
//! - Each write is a flushed temp file (0600, create-new), then rename, with
//!   one directory and parent fsync per bounded batch/pass. A torn or flipped record fails its
//!   SHA-256 trailer and is refused as `Corrupt`.
//! - A record restores only under its own source, key, context and scope, and
//!   only when its generation is at or below the loaded index's committed
//!   generation and the index entry it was written for is still the
//!   committed one. Anything else is Full; nothing is partially applied.
//! - Unknown representations hold acquisition and survive every mutation. A
//!   known corrupt record (T14) permits one rebuild Full and its post-save
//!   rename-over replacement. If no replacement lands, RAM alone serves
//!   the key, or it is held without affecting the source census. More than
//!   `max(T14_BREAKER, 2%)` T14 records in one pass disable the store.
//! - Owner or mode faults are store-level: our own entries get 0700/0600
//!   back; a foreign owner disables the store for this process (memory-only).
//! - No local path, transcript text, raw sample or raw identifier enters a
//!   record envelope: the index key and the entry selection are digests, and
//!   the certificate is content-free (`DurableCertificate`). Nothing here is
//!   uploaded.
//! - Writes and GC require the state-directory single-writer lock
//!   (`SingleWriter`); this layer adds no lock of its own.
#![cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.

#[cfg(test)]
use crate::snapshots::sampled_scan::transition_fixture::{reach, CrashPoint};
use crate::transcript_acquisition::DurableCertificate;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

pub(crate) mod active;
mod stream;
pub(crate) use active::{ActiveLease, ActiveOverBudget, LeaseWait, ACTIVE_BYTES};
pub(crate) use stream::{
    FailureDisposition, PrepareStoreFailure, PreparedHeader, PreparedRecord, ReceiptProof,
    RecordIdentity,
};

/// Envelope format. Bump on any envelope or certificate layout change.
pub(crate) const FORMAT_V1: u16 = 1;
pub(crate) const FORMAT_V3: u16 = 3;
// Historical fixture/writer pin; never reinterpret v1 as the current writer.
pub(crate) const FORMAT_VERSION: u16 = FORMAT_V1;
const MAGIC: [u8; 8] = *b"ottto-dt";
/// One record never exceeds the RAM cache's per-entry bound
/// (`transcript_cache::ENTRY_BYTES`): the store keeps only what RAM can.
pub(crate) const RECORD_BYTES: usize = crate::transcript_cache::ENTRY_BYTES;
/// Verification memo precision, independent of disk admission.
pub(crate) const MAX_RECORDS: usize = crate::transcript_cache::CACHE_ENTRIES;
/// Dirty records written per index save; the rest stay dirty for the next.
pub(crate) const MAX_BATCH: usize = 32;
/// Encoded native/batch write allowance for one source pass.
pub(crate) const WRITE_PASS_BYTES: usize = 8 * 1024 * 1024;
const RECORD_SUFFIX: &str = ".rec";
const TEMP_SUFFIX: &str = ".tmp";

/// The fixed envelope size before the body (see `encode`).
pub(crate) const HEADER_BYTES: usize = 8 // magic
    + 2 // format_version
    + 32 // allowlist_digest
    + 1 // source
    + 32 * 4 // key, context, scope, entry digests
    + 8 // index generation
    + CERTIFICATE_BYTES
    + 4; // body length
pub(crate) const HEADER_V3_BYTES: usize = HEADER_BYTES + 9;
const DISPATCH_BYTES: usize = 43;
const CERTIFICATE_BYTES: usize = 8 * 3 // device, inode, length
    + 8 * 2 // mtime seconds, nanos
    + 8 // birth
    + 8 // sealed offset
    + 4 // sample length
    + 32 * 2 // sample digests
    + 8 // verified
    + 1 // debt flag
    + 8; // debt
const TRAILER_BYTES: usize = 32;
// Classifier reallocation (old header + envelope), then input + copied body.
// Conservative cumulative reservation; no credit is refunded between phases.
const INPUT_ENVELOPE: usize = RECORD_BYTES + HEADER_V3_BYTES + TRAILER_BYTES + 1;
pub(crate) const RESTORE_INPUT_BYTES: u64 =
    (3 * INPUT_ENVELOPE + std::mem::size_of::<DurableRecord>()) as u64;
pub(crate) const BODY_BYTES: usize = RECORD_BYTES - HEADER_BYTES - TRAILER_BYTES;

/// Every 32-byte digest in the envelope (outside the codec body), as
/// `Type.field`. Each is a domain-separated SHA-256; the H audit
/// (`h_fields_are_audited`) pins what fills each one alongside the body's
/// `H` fields (M1, SOURCE P2-5). The SHA-256 trailer is an integrity
/// checksum over the record's own bytes, not a value, so it is not listed.
#[cfg(test)]
pub(crate) const ENVELOPE_H: [&str; 7] = [
    "Envelope.allowlist",
    "Binding.key",
    "Binding.context",
    "Binding.scope",
    "Binding.entry",
    "DurableCertificate.head_sha256",
    "DurableCertificate.boundary_sha256",
];

/// The single-writer seam. The state-directory lock (#801's `StateDirLock`,
/// held as `crate::locked_state_dir::LockedStateDir`) implements it; nothing
/// else may outside tests. A second daemon cannot take the lock,
/// so it can never hold a writer for this store.
pub(crate) trait SingleWriter {
    /// The locked state directory. The store must live inside it.
    fn state_dir(&self) -> &Path;
}

/// Sources admitted by the durable property table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DurableSource {
    ClaudeCode,
    Codex,
}
impl DurableSource {
    fn tag(self) -> u8 {
        self.properties().tag
    }
    fn from_tag(tag: u8) -> Option<Self> {
        crate::snapshots::durable_sources::SOURCES
            .iter()
            .find(|row| row.tag == tag)
            .map(|row| row.source)
    }
}

pub(crate) type Digest32 = [u8; 32];

fn digest(domain: &str, parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The SHA-256 of a codec's compiled field list, in order.
#[cfg(test)]
pub(crate) fn allowlist_digest(fields: &[&str]) -> Digest32 {
    let parts = fields
        .iter()
        .map(|field| field.as_bytes())
        .collect::<Vec<_>>();
    digest("ottto-dt-allowlist:v1", &parts)
}

/// The record key: a digest of the index key, never the path key itself.
pub(crate) fn key_digest(source: DurableSource, index_key: &str) -> Digest32 {
    digest(
        "ottto-dt-key:v1",
        &[[source.tag()].as_slice(), index_key.as_bytes()],
    )
}

/// The interpretation scope a record is valid under: the file scope (which
/// already holds parser/scan versions, upload context and replay generation)
/// plus this store's format version, the codec's allowlist digest, the
/// identity contract in force and the Codex counting view. A change to any of
/// them refuses the record even when the file scope does not move.
#[cfg(test)]
pub(crate) fn scope_digest(
    file_scope: &str,
    allowlist: &Digest32,
    identity_contract: &str,
    counting_view: &str,
) -> Digest32 {
    scope_digest_for(
        FORMAT_VERSION,
        file_scope,
        allowlist,
        identity_contract,
        counting_view,
    )
}

pub(crate) fn scope_digest_for(
    format: u16,
    file_scope: &str,
    allowlist: &Digest32,
    identity_contract: &str,
    counting_view: &str,
) -> Digest32 {
    digest(
        "ottto-dt-scope:v1",
        &[
            file_scope.as_bytes(),
            format.to_le_bytes().as_slice(),
            allowlist.as_slice(),
            identity_contract.as_bytes(),
            counting_view.as_bytes(),
        ],
    )
}

/// Canonical immutable counting binds the existing body without extending it.
pub(crate) fn scope_digest_v3(
    file_scope: &str,
    allowlist: &Digest32,
    identity_contract: &str,
    counting: &[u8; 13],
) -> Digest32 {
    digest(
        "ottto-dt-scope:v3",
        &[
            file_scope.as_bytes(),
            &FORMAT_V3.to_le_bytes(),
            allowlist,
            identity_contract.as_bytes(),
            counting,
        ],
    )
}

fn retired_pin(source: DurableSource, format: u16, pin: &Digest32) -> bool {
    let retired = match source {
        DurableSource::ClaudeCode => {
            "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
        }
        DurableSource::Codex => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
    };
    format == FORMAT_V1 && parse_hex_digest(retired).as_ref() == Some(pin)
}

fn header_len(format: u16, source: DurableSource, allowlist: &Digest32) -> Result<usize, Refusal> {
    if format > FORMAT_V3 {
        return Err(Refusal::NewerFormat);
    }
    if retired_pin(source, format, allowlist) {
        return Ok(HEADER_BYTES);
    }
    source
        .properties()
        .representation(format, allowlist)
        .map(|r| r.header_bytes)
        .ok_or(Refusal::Unknown)
}

/// Replay semantics layered over the format/codec scope. These are binding
/// inputs, not codec fields: the existing tagged envelope can gain a later
/// old-tag decoder without changing the reduction allowlist.
pub(crate) fn replay_scope_digest(
    scope: &Digest32,
    effective_revision: u64,
    active_revision: u64,
    money_rule_version: u16,
    money_e2: bool,
) -> Digest32 {
    digest(
        "ottto-dt-replay-scope:v1",
        &[
            scope.as_slice(),
            &effective_revision.to_le_bytes(),
            &active_revision.to_le_bytes(),
            &money_rule_version.to_le_bytes(),
            &[u8::from(money_e2)],
        ],
    )
}

/// Per-file applied revision and money replay marks committed with the entry.
/// An old reduction cannot inherit a new applied-rule/obligation marker.
pub(crate) fn replay_entry_digest(
    entry: &Digest32,
    applied_revision: u64,
    money_marks: u8,
) -> Digest32 {
    digest(
        "ottto-dt-replay-entry:v1",
        &[
            entry.as_slice(),
            &applied_revision.to_le_bytes(),
            &[money_marks],
        ],
    )
}

/// The garbage-collection unit: the destination namespace and the account
/// (upload context) in force. A record from another context is unreachable.
pub(crate) fn context_digest(namespace: &str, upload_context: Option<&str>) -> Digest32 {
    digest(
        "ottto-dt-context:v1",
        &[
            namespace.as_bytes(),
            upload_context.unwrap_or("none").as_bytes(),
        ],
    )
}

/// The committed index selection a record was written for: the entry's
/// source fingerprint and upload body witness, as the index save committed
/// them.
pub(crate) fn entry_digest(source_file_fingerprint: &str, body_witness: Option<&str>) -> Digest32 {
    digest(
        "ottto-dt-entry:v1",
        &[
            source_file_fingerprint.as_bytes(),
            body_witness.unwrap_or("").as_bytes(),
        ],
    )
}

/// Where a scan index's store lives: a sibling directory of the index file.
pub(crate) fn store_dir_for_index(index_path: &Path) -> PathBuf {
    index_path.with_extension("durable-tail")
}

/// A record's binding to the index and scope. All identifiers are digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) source: DurableSource,
    pub(crate) key: Digest32,
    pub(crate) context: Digest32,
    pub(crate) scope: Digest32,
    pub(crate) entry: Digest32,
}

/// Local provenance in the envelope extension; never a body/ACK field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AcquisitionFields {
    pub(crate) acquired_revision: u64,
    pub(crate) protocol: crate::snapshots::AcquisitionProtocol,
}

/// Original verified wire facts survive decoding of retired body/header fields.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireIdentity {
    encoded_len: u64,
    trailer: Digest32,
}

/// A record before the store stamps it with a committed generation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingRecord {
    pub(crate) binding: Binding,
    pub(crate) certificate: DurableCertificate,
    /// The codec's allowlisted encoding; opaque to the store.
    pub(crate) body: Vec<u8>,
    /// The codec's allowlist digest, carried in the envelope.
    pub(crate) allowlist: Digest32,
    /// None only for the original v1 representation.
    pub(crate) acquisition: Option<AcquisitionFields>,
}
impl PendingRecord {
    fn format(&self) -> u16 {
        if self.acquisition.is_some() {
            FORMAT_V3
        } else {
            FORMAT_V1
        }
    }
}

/// A record as stored: the pending record plus the generation of the index
/// save it followed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DurableRecord {
    pub(crate) record: PendingRecord,
    pub(crate) index_generation: u64,
    pub(crate) format: u16,
    /// Validated v1 compatibility debt; never checkpoint authority.
    pub(crate) envelope_audit_debt: Option<u64>,
    pub(crate) wire: Option<WireIdentity>,
}

// Encoded bodies may contain private labels. Wrapping Debug implementations
// inherit this length-only representation; no content-derived identifiers escape.
impl std::fmt::Debug for PendingRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRecord")
            .field("format", &self.format())
            .field("body_len", &self.body.len())
            .finish()
    }
}
impl std::fmt::Debug for DurableRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableRecord")
            .field("format", &self.format)
            .field("body_len", &self.record.body.len())
            .finish()
    }
}

impl std::fmt::Debug for WireIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireIdentity")
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}
impl std::fmt::Debug for WireRecordIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireRecordIdentity")
            .field("format", &self.format)
            .field("encoded_len", &self.encoded_len)
            .finish()
    }
}
impl std::fmt::Debug for WireReceiptProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("WireReceiptProof")
            .field(&self.identity)
            .finish()
    }
}

/// Writer-owned retirement distinguishes absence/verified replacement from
/// unknown survivors and I/O. No outcome is an ACK or a receipt.
pub(crate) enum RetireOutcome {
    Retired,
    Superseded,
    Retry,
}

/// Exact verified predecessor; no caller can manufacture or clone its authority.
pub(crate) struct MutationWitness {
    key: Digest32,
    original: Digest32,
    content: Digest32,
    stamp: Stamp,
    // The current binding is folded into original for migration witnesses.
    // Keep the immutable floor inline without growing the prepaid custody node.
    migration_floor: Option<std::num::NonZeroU64>,
}
fn original_digest(record: &DurableRecord, content: &Digest32) -> Digest32 {
    digest(
        "ottto-dt-original:v1",
        &[
            content,
            &record.format.to_le_bytes(),
            &record.index_generation.to_le_bytes(),
            &record.wire.map_or(0, |w| w.encoded_len).to_le_bytes(),
            &record.wire.map_or([0; 32], |w| w.trailer),
        ],
    )
}
fn migration_binding(original: &Digest32, current: &Expected) -> Digest32 {
    digest(
        "ottto-dt-migration:v1",
        &[original, &current.binding.context, &current.binding.scope],
    )
}

/// Exact encoded candidate, including the original trailer (not a re-encoding
/// of decoded fields, which may discard retired positional values).
#[derive(Clone, Copy, PartialEq, Eq)]
struct WireRecordIdentity {
    key: Digest32,
    allowlist: Digest32,
    format: u16,
    generation: u64,
    encoded_len: u64,
    trailer: Digest32,
}
impl WireRecordIdentity {
    /// Only called with our encoded bytes or a fully verified decoded record.
    fn verified(record: &DurableRecord, bytes: &[u8]) -> Self {
        Self {
            key: record.record.binding.key,
            allowlist: record.record.allowlist,
            format: record.format,
            generation: record.index_generation,
            encoded_len: bytes.len() as u64,
            trailer: bytes[bytes.len() - TRAILER_BYTES..]
                .try_into()
                .expect("verified trailer"),
        }
    }
}

struct VerifiedRecord {
    record: Box<DurableRecord>,
    identity: WireRecordIdentity,
}
#[derive(Clone, Copy)]
struct PendingWrite {
    prior: Option<Stamp>,
    candidate: WireRecordIdentity,
    content: Digest32,
    completed: Option<Stamp>,
    failures: u8,
}
// Existing per-source pending reservation allows 4096 bytes per tree node.
const _: () = assert!(std::mem::size_of::<(Digest32, PendingWrite)>() <= 320);

/// Acquisition durability only; never accepted-money or replacement ACK credit.
#[derive(PartialEq, Eq)]
pub(crate) struct WireReceiptProof {
    identity: WireRecordIdentity,
    stamp: Stamp,
    content: Digest32,
}
const _: () = assert!(std::mem::size_of::<WireReceiptProof>() <= 256);
/// Verified absence (including ordinary retirement), after directory sync.
pub(crate) struct RetirementProof {
    candidate: WireRecordIdentity,
}
pub(crate) enum ReconcileOutcome {
    NoPending,
    Receipted(WireReceiptProof),
    Retired(RetirementProof),
}

/// Preservation classes: unknown representations (U) precede known corruption (T14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    NewerFormat,
    Unknown,
    Undecodable,
    Unbindable,
    Corrupt,
    // Slot 5 belongs to the retired UpgradeMissing alarm coordinate.
    ReceiptPending = 6,
    BehindAccepted = 7,
    /// Exact retired v1 pin: native rebuild only, never current-body decode.
    Repin = 8,
}

/// The outcome of reading one key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    Missing,
    Refused(Refusal),
    Found(Box<DurableRecord>),
}

/// What a restore must match, all from the loaded, committed index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Expected {
    pub(crate) binding: Binding,
    pub(crate) committed_generation: u64,
}

/// Why a well-formed record does not bind to the committed index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ineligible {
    Source,
    Key,
    /// Another destination namespace or account.
    Context,
    /// Another interpretation scope, format, allowlist, identity contract or
    /// counting view.
    Scope,
    /// Written after a save the loaded index does not contain (index old,
    /// checkpoint new).
    GenerationAhead,
    /// The committed entry is not the one this record was written for: a
    /// later save recorded another selection (an append, truncate, replace
    /// or edit) and no record followed it.
    EntryChanged,
}

impl DurableRecord {
    /// Store-level eligibility. The certificate's FD check
    /// (`DurableCertificate::admits`) and the RAM charge come after this.
    pub(crate) fn eligible(&self, expected: &Expected) -> Result<(), Ineligible> {
        let have = &self.record.binding;
        let want = &expected.binding;
        if have.source != want.source {
            Err(Ineligible::Source)
        } else if have.key != want.key {
            Err(Ineligible::Key)
        } else if have.context != want.context {
            Err(Ineligible::Context)
        } else if have.scope != want.scope {
            Err(Ineligible::Scope)
        } else if self.format == FORMAT_V1
            && have.source == DurableSource::Codex
            && self.index_generation > expected.committed_generation
        {
            Err(Ineligible::GenerationAhead)
        } else if self.format == FORMAT_V1
            && have.source == DurableSource::Codex
            && have.entry != want.entry
        {
            Err(Ineligible::EntryChanged)
        } else {
            Ok(())
        }
    }
}

/// Content-free counts for the budget receipts. One pass is one restore
/// read phase or one post-save write phase; `take_pass` resets them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct StoreCounters {
    /// Record files on disk after the last write or GC, and their bytes.
    pub(crate) disk_records: u64,
    pub(crate) disk_bytes: u64,
    /// The largest single record written or read.
    pub(crate) max_record_bytes: u64,
    /// Write amplification: bytes and records written, clean records not
    /// rewritten, dirty records deferred past `MAX_BATCH`, saves batched.
    pub(crate) bytes_written: u64,
    pub(crate) records_written: u64,
    pub(crate) records_clean: u64,
    pub(crate) records_deferred: u64,
    pub(crate) batches: u64,
    /// Encoded record refusals, independent of cache and memo capacity. A
    /// verified predecessor stays until replacement; without one, the entry
    /// is Full after restart.
    pub(crate) budget_refused: u64,
    pub(crate) durable_floor_skipped: u64,
    pub(crate) receipt_reconciled: u64,
    pub(crate) receipt_pending_held: u64,
    pub(crate) receipt_pending_records: u64,
    pub(crate) durable_write_failed_published: u64,
    /// A write failed and neither the explicit nor fallback temp cleanup
    /// established absence. Separate from integrity and receipt mismatch.
    pub(crate) store_write_cleanup_failed: u64,
    pub(crate) store_faults: u64,
    pub(crate) store_fault_reason: Option<&'static str>,
    pub(crate) stale_record_refused: u64,
    pub(crate) resource_paused_seconds: u64,
    pub(crate) resource_pause_checks: u64,
    pub(crate) resource_pause_skipped: u64,
    pub(crate) native_flushes: u64,
    /// Owned temps verified absent after directory sync, counted once.
    pub(crate) temp_discard_verified: u64,
    /// Failed explicit/fallback temp cleanup attempts, per pass.
    pub(crate) temp_discard_failed: u64,
    /// Temp cleanup reached through unwinding or a missed explicit exit.
    pub(crate) temp_drop_fallback: u64,
    /// Failed physical attempt boundaries: setup, inventory, statvfs.
    pub(crate) store_write_failed: [u64; 3],
    /// Per-pass read I/O.
    pub(crate) bytes_read: u64,
    pub(crate) records_read: u64,
    pub(crate) mutation_unproved: u64,
    /// Bounded verification memo turnover; never removes pending/spent authority.
    pub(crate) memo_evicted: u64,
    pub(crate) missing: u64,
    pub(crate) format_hold: [u64; 9],
    /// Writes skipped: predecessor unknown, or a new key while record files
    /// exceed `INVENTORY_BOUND` (offered again after the next save).
    pub(crate) store_write_skipped: [u64; 2],
    /// T14 rebuild authorizations (RAM may already hold the file), and mode repairs.
    pub(crate) t14_rebuild: u64,
    /// First admitted rebuild Full starts in this process, not persisted repetition history.
    pub(crate) t14_rebuild_full_started: u64,
    pub(crate) mode_repaired: u64,
    pub(crate) guard_header_bytes: u64,
    pub(crate) guard_verify_bytes: u64,
    pub(crate) delete_verify_bytes: u64,
    pub(crate) overwrite_verify_bytes: u64,
    pub(crate) uninventoried_records: u64,
    /// GC deletions: records and stale temp files.
    pub(crate) gc_records_deleted: u64,
    pub(crate) native_class_retired: u64,
    pub(crate) native_class_parked: u64,
    pub(crate) restore_unavailable_layout_gc: u64,
    pub(crate) gc_temps_deleted: u64,
    /// Actual dispatch/representation header bytes read by GC; body verification has separate counters.
    pub(crate) gc_records_read: u64,
    pub(crate) gc_bytes_read: u64,
    /// Records deleted because their selection was held or reverted.
    pub(crate) records_invalidated: u64,
    /// Peak transient encode/decode buffer, in bytes.
    pub(crate) peak_codec_bytes: u64,
}

/// GC's bounded, RAM-only view of decisions made by the native class owner.
/// An unknown class preserves A; exclusion never grants mutation authority.
#[derive(Clone, Copy)]
pub(crate) enum GcKeep {
    Unknown,
    Scope(Digest32),
    Excluded {
        audit_debt: Option<u64>,
    },
    LayoutUnavailable {
        audit_debt: Option<u64>,
        verified: bool,
    },
}

/// Fixed-size key/content/target identities for the strict Claude caller.
type BatchAcks = [Option<(Digest32, Digest32, Stamp)>; MAX_BATCH];
const BATCH_ACK_BYTES: usize = std::mem::size_of::<BatchAcks>();

/// What one post-save batch did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BatchReceipt {
    pub(crate) written: usize,
    pub(crate) clean: usize,
    pub(crate) deferred: usize,
    /// The deferred records' keys, so the caller offers them again after
    /// its next save.
    pub(crate) deferred_keys: Vec<Digest32>,
    pub(crate) budget_refused: usize,
    pub(crate) bytes_written: u64,
    /// Fixed allocation; no acknowledgement escapes a failed directory sync.
    committed: Option<Box<BatchAcks>>,
    /// Actual exact completions only; ordinary clean retries carry none.
    pub(crate) completed: Vec<WireReceiptProof>,
}

/// One store directory. The in-RAM map of last durable content digests
/// decides dirtiness, so a clean record is never rewritten.
pub(crate) struct DurableTailStore {
    dir: PathBuf,
    source: DurableSource,
    durable: BTreeMap<Digest32, (Option<Digest32>, Stamp, bool)>,
    counters: StoreCounters,
    cleanup: Arc<TempCleanupCounts>,
    /// The store-level fault that made this store memory-only for the process.
    disabled: Option<&'static str>,
    /// This pass: directory checked and [records loaded, T14 rebuilds].
    checked: bool,
    pass: [u64; 2],
    /// Process-lifetime attempts, removed only after a successful replacement.
    rebuilt: BTreeMap<Digest32, Rebuild>,
    startup_synced: bool,
    gc_after: Option<Digest32>,
    private_purge_after: Option<Digest32>,
    private_purge_dirty: bool,
    pending: BTreeMap<Digest32, PendingWrite>,
    resource_pause: Option<stream::ResourcePause>,
    stream_dirty: Arc<AtomicU64>,
    stream_flush_taken: bool,
    stream_records: usize,
    stream_bytes: usize,
    resource_checked: bool,
    resource_granted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rebuild {
    Authorized,  // Scheduling deferral has not spent the Full allowance.
    Started,     // The rebuild may offer its own replacement after save.
    Offered,     // Started and included in this post-save batch's pending records.
    NotReplaced, // Memory-only with RAM; otherwise a census-safe hold.
}

/// The most record files one GC or inventory pass looks at. Twice the
/// memo precision bound; existing-key updates remain possible beyond it; any
/// file past it is left untouched and counted.
const GC_RECORDS_PER_PASS: usize = 512;
#[cfg(any(test, feature = "replay-harness"))]
pub(crate) const INVENTORY_BOUND: usize = GC_RECORDS_PER_PASS;
/// T14 rebuilds one pass allows before the store is disabled: more than
/// `max(T14_BREAKER, 2% of the records loaded)`.
pub(crate) const T14_BREAKER: u64 = 20;
const REBUILT_BOUND: usize = 64;
// Three actual failures for one receipt bound this hold; lease waits do not count.
const RECEIPT_RECONCILE_FAILURES: u8 = 3;
// A memo entry stays within the 128 bytes per record `STORES_RESIDENT_BOUND` charges.
const _: () = assert!(std::mem::size_of::<(Digest32, (Option<Digest32>, Stamp, bool))>() <= 128);

/// Counts erasures and unadjudicated records in one privacy pass. No receipt
/// or per-key state escapes the store; partial progress is always reported.
pub(crate) struct PrivateLabelPurge {
    pub(crate) scanned: u64,
    pub(crate) erased: u64,
    pub(crate) refused: u64,
}

impl DurableTailStore {
    pub(crate) fn new(dir: PathBuf, source: DurableSource) -> Self {
        Self {
            dir,
            durable: BTreeMap::new(),
            source,
            counters: StoreCounters::default(),
            cleanup: Arc::new(TempCleanupCounts::default()),
            disabled: None,
            checked: false,
            pass: [0; 2],
            rebuilt: BTreeMap::new(),
            startup_synced: false,
            gc_after: None,
            private_purge_after: None,
            private_purge_dirty: false,
            pending: BTreeMap::new(),
            resource_pause: None,
            stream_dirty: Arc::default(),
            stream_flush_taken: false,
            stream_records: 0,
            stream_bytes: 0,
            resource_checked: false,
            resource_granted: false,
        }
    }

    /// A new pass: the directory is checked again and the T14 breaker resets.
    pub(crate) fn begin_pass(&mut self) {
        self.stream_flush_taken = false;
        self.stream_records = 0;
        self.stream_bytes = 0;
        self.resource_checked = false;
        self.resource_granted = false;
        self.checked = false;
        for (_, _, allowed) in self.durable.values_mut() {
            *allowed = false;
        }
        self.pass = [0; 2];
        self.usable(None);
    }

    pub(crate) fn disabled(&self) -> Option<&'static str> {
        self.disabled
    }

    pub(crate) fn disable(&mut self, cause: &'static str) {
        if self.disabled.is_none() {
            self.disabled = Some(cause);
        }
        self.durable.clear();
    }

    /// The store-level check, once per pass: a directory we own gets 0700
    /// back; anything else disables the store (absent is fine).
    fn usable(&mut self, writer: Option<&dyn SingleWriter>) -> bool {
        let writer = writer.or_else(|| {
            crate::locked_state_dir::held_for(&self.dir).map(|w| w as &dyn SingleWriter)
        });
        let writable = writer.is_some_and(|w| self.check_writer(w).is_ok());
        if !self.checked && self.disabled.is_none() {
            self.checked = true;
            match inspect_path(&self.dir) {
                Ok(metadata) if !metadata.is_dir() => self.disable("not_directory"),
                Ok(metadata) => {
                    if !self.repair(&self.dir.clone(), &metadata, 0o700, writable) {
                        return false;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => self.disable("directory_access"),
            }
        }
        if writable && !self.startup_synced && self.disabled.is_none() && self.dir.exists() {
            if self.sync_store().is_err() {
                self.disable("startup_sync");
            } else {
                self.startup_synced = true;
            }
        }
        self.disabled.is_none()
    }

    /// Our own entry gets `mode` back (counted); a foreign owner or a failed
    /// repair disables the store.
    fn repair(&mut self, path: &Path, metadata: &fs::Metadata, mode: u32, writable: bool) -> bool {
        if metadata.uid() != our_uid() {
            self.disable("foreign_owner");
        } else if metadata.permissions().mode() & 0o777 != mode {
            if !writable {
                self.disable("mode_without_writer");
                return false;
            }
            match fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
                Ok(()) => self.counters.mode_repaired += 1,
                Err(_) => self.disable("mode_unrepairable"),
            }
        }
        self.disabled.is_none()
    }

    #[cfg(test)]
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn representation(&mut self, key: &Digest32) -> Option<(u16, Digest32)> {
        self.classify(key, "delete", None)
            .ok()
            .flatten()
            .map(|h| (h.format, h.record.allowlist))
    }

    /// Missing reduction, including an exact retired representation.
    pub(crate) fn absent(&mut self, key: &Digest32) -> bool {
        self.missing_cause(key).is_some()
    }

    /// Cause only: retired envelopes are missing reductions, not restore authority.
    pub(crate) fn missing_cause(&mut self, key: &Digest32) -> Option<&'static str> {
        if self.disabled.is_some() || self.receipt_pending(key) {
            return None;
        }
        if inspect_path(&self.record_path(key)).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        {
            return Some("upgrade_state_missing");
        }
        matches!(self.classify(key, "presence", None), Err(Refusal::Repin)).then_some("repin")
    }

    pub(crate) fn counters(&self) -> StoreCounters {
        StoreCounters {
            receipt_pending_records: self.pending.len() as u64,
            resource_paused_seconds: self.counters.resource_paused_seconds.saturating_add(
                self.resource_pause
                    .as_ref()
                    .and_then(|p| std::time::SystemTime::now().duration_since(p.since).ok())
                    .map_or(0, |age| age.as_secs()),
            ),
            temp_discard_verified: self.cleanup.verified.load(Ordering::Relaxed),
            temp_discard_failed: self.cleanup.failed.load(Ordering::Relaxed),
            temp_drop_fallback: self.cleanup.fallback.load(Ordering::Relaxed),
            ..self.counters
        }
    }

    /// The counters since the last call, which resets them. The disk totals
    /// are a level, not a flow, and are kept.
    #[cfg(test)]
    pub(crate) fn take_pass(&mut self) -> StoreCounters {
        let mut pass = self.counters();
        pass.temp_discard_verified = self.cleanup.verified.swap(0, Ordering::Relaxed);
        pass.temp_discard_failed = self.cleanup.failed.swap(0, Ordering::Relaxed);
        pass.temp_drop_fallback = self.cleanup.fallback.swap(0, Ordering::Relaxed);
        self.counters = StoreCounters {
            disk_records: pass.disk_records,
            disk_bytes: pass.disk_bytes,
            ..StoreCounters::default()
        };
        pass
    }

    fn record_path(&self, key: &Digest32) -> PathBuf {
        self.dir.join(format!("{}{RECORD_SUFFIX}", hex(key)))
    }

    /// Owner/mode (store-level) precede header dispatch, which precedes the
    /// size check. Only a verified known record licenses mutation. `Ok(None)`
    /// also when the store is disabled.
    fn classify(
        &mut self,
        key: &Digest32,
        work: &str,
        writer: Option<&dyn SingleWriter>,
    ) -> Result<Option<Header>, Refusal> {
        let restoring = matches!(work, "restore" | "privacy_restore");
        let writable = writer
            .or_else(|| {
                crate::locked_state_dir::held_for(&self.dir).map(|w| w as &dyn SingleWriter)
            })
            .is_some_and(|w| self.check_writer(w).is_ok());
        if !self.usable(writer) {
            return Ok(None);
        }
        let path = self.record_path(key);
        let mut corrupt_retired = None;
        let result = (|| {
            let open = || {
                #[cfg(test)]
                test_hooks::before_access(&path, "open")?;
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&path)
            };
            let mut file = match open() {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    let repaired = match inspect_path(&path) {
                        Ok(m) => m.is_file() && self.repair(&path, &m, 0o600, writable),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                        Err(_) => false,
                    };
                    if self.disabled.is_some() {
                        return Ok(None);
                    }
                    match repaired.then(open) {
                        Some(Ok(file)) => file,
                        Some(Err(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                        _ => {
                            self.disable("record_access");
                            return Ok(None);
                        }
                    }
                }
                Err(e) => return Err(self.read_failure(e, Refusal::Undecodable)),
            };
            let Some(metadata) = self.inspect_file(&file) else {
                return Ok(None);
            };
            if !metadata.is_file() {
                return Err(Refusal::Undecodable);
            }
            if !self.repair(&path, &metadata, 0o600, writable) {
                return Ok(None);
            }
            #[cfg(test)]
            test_hooks::before_access(&path, "header")
                .map_err(|e| self.read_failure(e, Refusal::Undecodable))?;
            let mut header = Vec::with_capacity(HEADER_V3_BYTES);
            let first = Read::by_ref(&mut file)
                .take(DISPATCH_BYTES as u64)
                .read_to_end(&mut header);
            let mut n = header.len();
            if work == "delete" {
                self.counters.gc_records_read += 1;
                self.counters.gc_bytes_read += n as u64;
            } else {
                self.counters.guard_header_bytes += n as u64;
            }
            first.map_err(|e| self.read_failure(e, Refusal::Undecodable))?;
            let (_, _, _, size) = dispatch(&header)?;
            let rest = Read::by_ref(&mut file)
                .take((size - n) as u64)
                .read_to_end(&mut header);
            if work == "delete" {
                self.counters.gc_bytes_read += (header.len() - n) as u64;
            } else {
                self.counters.guard_header_bytes += (header.len() - n) as u64;
            }
            rest.map_err(|e| self.read_failure(e, Refusal::Corrupt))?;
            n = header.len();
            let mut binding = decode_header(&header, key, self.source)?;
            let retired = retired_pin(self.source, binding.format, &binding.record.allowlist);
            if retired && work != "overwrite" && work != "guard" {
                return Err(Refusal::Repin); // Missing to readers, opaque to current decoders.
            }
            if work == "presence" {
                return Ok(None); // Presence is never verification or mutation authority.
            }
            // After any repair: its ctime moved.
            let Some(metadata) = self.inspect_file(&file) else {
                return Ok(None);
            };
            let stamp = Stamp::of(&metadata);
            binding.stamp = Some(stamp);
            if !metadata.is_file() || metadata.len() > (RECORD_BYTES + size + TRAILER_BYTES) as u64
            {
                return Err(Refusal::Corrupt);
            }
            if let Some((content, old, _)) = self.durable.get(key) {
                if !restoring && *old == stamp && content.is_some() {
                    if retired && work == "guard" {
                        return Err(Refusal::Repin);
                    }
                    binding.content = *content;
                    return Ok(Some(binding));
                }
            }
            #[cfg(test)]
            test_hooks::before_access(&path, "body")
                .map_err(|e| self.read_failure(e, Refusal::Corrupt))?;
            let mut bytes = header;
            bytes.reserve_exact(INPUT_ENVELOPE - bytes.len());
            file.take((INPUT_ENVELOPE - n) as u64)
                .read_to_end(&mut bytes)
                .map_err(|e| self.read_failure(e, Refusal::Corrupt))?;
            let read = bytes.len().saturating_sub(n) as u64;
            match work {
                "delete" => self.counters.delete_verify_bytes += read,
                "overwrite" => self.counters.overwrite_verify_bytes += read,
                _ => self.counters.guard_verify_bytes += read,
            }
            self.note_codec(bytes.capacity());
            if let Err(reason) = verify(&bytes, self.source) {
                if retired
                    && work == "guard"
                    && self.rebuilt.get(key) != Some(&Rebuild::Started)
                    && reason == Refusal::Corrupt
                    && stamp_at(&path).ok() == Some(Some(stamp))
                {
                    corrupt_retired = Some(stamp);
                }
                return Err(reason);
            }
            if retired && work == "guard" {
                return Err(Refusal::Repin);
            }
            if work == "overwrite" || restoring {
                binding.content = Some(stored_digest(&bytes));
            }
            let content = stored_digest(&bytes);
            let allowed = self.durable.get(key).is_some_and(|(old, saved, allowed)| {
                *allowed && *saved == stamp && *old == Some(content)
            });
            self.memoize(*key, (Some(content), stamp, allowed || retired));
            if restoring {
                binding.verified = Some(bytes);
            }
            Ok(Some(binding))
        })();
        if self.disabled.is_some() {
            return Ok(None);
        }
        if let Err(reason) = result {
            let exact_corrupt = self.durable.get(key).is_some_and(|(content, stamp, _)| {
                content.is_none() && stamp_at(&self.record_path(key)).ok() == Some(Some(*stamp))
            });
            if !(exact_corrupt
                && (reason == Refusal::Repin
                    || (work == "overwrite"
                        && reason == Refusal::Corrupt
                        && self.rebuilt.get(key) == Some(&Rebuild::Started))))
            {
                self.durable.remove(key);
            }
            if let Some(stamp) = corrupt_retired {
                // Not verified content: only the exact corrupt predecessor that
                // the ordinary one-rebuild owner may replace after a Full.
                self.memoize(*key, (None, stamp, false));
            }
            if reason != Refusal::Repin {
                self.counters.format_hold[reason as usize] += 1;
            }
        }
        result
    }

    fn read_failure(&mut self, error: io::Error, reason: Refusal) -> Refusal {
        if error.kind() != io::ErrorKind::InvalidData {
            self.disable("record_access");
        }
        reason
    }

    fn inspect_file(&mut self, file: &File) -> Option<fs::Metadata> {
        #[cfg(test)]
        if test_hooks::before_access(&self.dir, "fstat").is_err() {
            self.disable("record_metadata");
            return None;
        }
        file.metadata()
            .inspect_err(|_| self.disable("record_metadata"))
            .ok()
    }

    /// U holds. T14 permits one rebuild; the adapter checks RAM before holding.
    #[cfg(test)]
    pub(crate) fn hold(&mut self, key: &Digest32) -> Option<Refusal> {
        // has_index=true short-circuits debt import, so this live-context sentinel is unused.
        self.guard_with_carrier(key, true, &[0; 32]).err()
    }

    /// Ok(Some(due)) is missing audit custody: acquire Full, never restore clean.
    /// Invalid records remain holds; the caller counts the carrier miss.
    pub(crate) fn guard_with_carrier(
        &mut self,
        key: &Digest32,
        has_index: bool,
        live_context: &Digest32,
    ) -> Result<Option<u64>, Refusal> {
        if self.disabled.is_some() {
            return Ok(None); // D-DISABLED: keep debt, publish valid RAM under native fences.
        }
        if self.receipt_pending(key) {
            return Err(Refusal::ReceiptPending);
        }
        let result = self.classify(key, "guard", None);
        self.pass[0] += u64::from(!matches!(result, Ok(None) | Err(Refusal::Repin)));
        match result {
            Err(Refusal::Repin) => Ok(None),
            Err(Refusal::Corrupt) if !self.rebuilt.contains_key(key) => {
                if self.pass[1] >= T14_BREAKER.max(self.pass[0] / 50) {
                    self.disable("t14_breaker");
                } else if self.rebuilt.len() >= REBUILT_BOUND {
                    self.disable("t14_rebuilt_overflow");
                } else {
                    self.pass[1] += 1;
                    self.counters.t14_rebuild += 1;
                    self.rebuilt.insert(*key, Rebuild::Authorized);
                }
                Ok(None)
            }
            Err(Refusal::Corrupt) if self.rebuilt[key] == Rebuild::Authorized => Ok(None),
            Ok(header) => Ok(header
                .filter(|header| !has_index && header.record.binding.context == *live_context)
                .and_then(|header| header.audit_debt)),
            Err(reason) => Err(reason),
        }
    }

    pub(crate) fn full_hold(&mut self, key: &Digest32, start: bool) -> Option<Refusal> {
        self.full_guard(key, start, true, &[0; 32]).err()
    }

    /// Settlement re-probe (R1): an entry-less key's validated same-context
    /// debt, read only. No T14 breaker accounting, rebuild authorization or
    /// hold; refusals and foreign contexts contribute nothing.
    pub(crate) fn carrier_debt(&mut self, key: &Digest32, live_context: &Digest32) -> Option<u64> {
        self.classify(key, "guard", None)
            .ok()
            .flatten()
            .filter(|header| header.record.binding.context == *live_context)
            .and_then(|header| header.audit_debt)
    }

    /// `full_hold` exposing missing audit custody as `guard_with_carrier`.
    pub(crate) fn full_guard(
        &mut self,
        key: &Digest32,
        start: bool,
        has_index: bool,
        live_context: &Digest32,
    ) -> Result<Option<u64>, Refusal> {
        let held = self.guard_with_carrier(key, has_index, live_context);
        if start
            && held.is_ok()
            && self.disabled.is_none()
            && self.rebuilt.get(key) == Some(&Rebuild::Authorized)
        {
            self.rebuilt.insert(*key, Rebuild::Started);
            self.counters.t14_rebuild_full_started += 1;
        }
        held
    }

    /// Cold caller owns the process-wide lease before taking Stores.
    pub(crate) fn read_bounded(
        &mut self,
        key: &Digest32,
        lease: &mut ActiveLease,
    ) -> Result<ReadOutcome, ActiveOverBudget> {
        lease.charge(RESTORE_INPUT_BYTES)?;
        Ok(self.read(key))
    }

    pub(crate) fn read(&mut self, key: &Digest32) -> ReadOutcome {
        if self.disabled.is_some() {
            return ReadOutcome::Missing; // Never reuse ambiguous disabled-store bytes.
        }
        if self.receipt_pending(key) {
            return ReadOutcome::Refused(Refusal::ReceiptPending);
        }
        match self.read_known(key, None, false) {
            Ok(Some(verified)) => ReadOutcome::Found(verified.record),
            Ok(None) => ReadOutcome::Missing,
            Err(Refusal::Repin) => {
                self.counters.missing += 1;
                ReadOutcome::Missing
            }
            Err(reason) => ReadOutcome::Refused(reason),
        }
    }
    fn read_known(
        &mut self,
        key: &Digest32,
        writer: Option<&dyn SingleWriter>,
        privacy_erasure: bool,
    ) -> Result<Option<VerifiedRecord>, Refusal> {
        let work = if privacy_erasure {
            "privacy_restore"
        } else {
            "restore"
        };
        let mut header = match self.classify(key, work, writer)? {
            Some(header) => header,
            None => {
                self.counters.missing += 1;
                return Ok(None);
            }
        };
        let bytes = header.verified.take().ok_or(Refusal::Corrupt)?;
        self.counters.records_read += 1;
        self.counters.bytes_read += bytes.len() as u64;
        self.counters.max_record_bytes = self.counters.max_record_bytes.max(bytes.len() as u64);
        let size = dispatch(&bytes).map_or(HEADER_V3_BYTES, |(_, _, _, size)| size);
        self.note_codec(bytes.capacity() + bytes.len().saturating_sub(size));
        match decode(&bytes) {
            Ok(record) => {
                if let Some((content, _, _)) = self.durable.get_mut(key) {
                    *content = Some(stored_digest(&bytes));
                }
                let identity = WireRecordIdentity::verified(&record, &bytes);
                Ok(Some(VerifiedRecord {
                    record: Box::new(record),
                    identity,
                }))
            }
            Err(reason) => Err(reason),
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
    pub(crate) fn receipt_pending(&self, key: &Digest32) -> bool {
        self.pending.get(key).is_some_and(|pending| {
            pending.completed.map_or(true, |stamp| {
                stamp_at(&self.record_path(key)).ok() != Some(Some(stamp))
            })
        })
    }

    /// Retain a real reconciliation completion in the existing bounded owner.
    /// It remains available until a successful batch delivers the exact proof.
    pub(crate) fn retain_receipt(&mut self, proof: WireReceiptProof) -> io::Result<()> {
        if stamp_at(&self.record_path(&proof.identity.key))? != Some(proof.stamp) {
            return Err(io::Error::other("completion changed"));
        }
        let pending = self
            .pending
            .get_mut(&proof.identity.key)
            .filter(|pending| {
                pending.candidate == proof.identity && pending.content == proof.content
            })
            .ok_or_else(|| io::Error::other("completion candidate changed"))?;
        pending.completed = Some(proof.stamp);
        Ok(())
    }

    /// Validate the entire delivery before releasing any completion custody.
    fn finish_batch(&mut self, mut receipt: BatchReceipt) -> io::Result<BatchReceipt> {
        for proof in &receipt.completed {
            if stamp_at(&self.record_path(&proof.identity.key))? != Some(proof.stamp)
                || !self
                    .pending
                    .get(&proof.identity.key)
                    .is_some_and(|pending| {
                        pending.candidate == proof.identity
                            && pending.content == proof.content
                            && pending.completed == Some(proof.stamp)
                    })
            {
                return Err(io::Error::other("batch completion changed"));
            }
        }
        if self.source == DurableSource::ClaudeCode && !receipt.completed.is_empty() {
            let acks = receipt
                .committed
                .get_or_insert_with(|| Box::new([None; MAX_BATCH]));
            for (i, proof) in receipt.completed.iter().enumerate() {
                acks[i] = Some((proof.identity.key, proof.content, proof.stamp));
            }
        }
        for proof in &receipt.completed {
            let key = proof.identity.key;
            self.rebuilt.remove(&key);
            self.memoize(key, (Some(proof.content), proof.stamp, true));
            self.pending.remove(&key);
            self.counters.max_record_bytes = self
                .counters
                .max_record_bytes
                .max(proof.identity.encoded_len);
        }
        self.counters.records_written += receipt.written as u64;
        self.counters.bytes_written += receipt.bytes_written;
        Ok(receipt)
    }

    pub(crate) fn reconcile_pending(
        &mut self,
        writer: &dyn SingleWriter,
        key: &Digest32,
    ) -> io::Result<ReconcileOutcome> {
        self.check_writer(writer)?;
        if self.disabled.is_some() {
            return Err(io::Error::other("store disabled"));
        }
        let result = self.reconcile_pending_inner(writer, key);
        if result.is_err() {
            if let Some(pending) = self.pending.get_mut(key) {
                pending.failures = pending.failures.saturating_add(1);
                if pending.failures >= RECEIPT_RECONCILE_FAILURES {
                    self.disable("receipt_unreconciled");
                }
            }
        }
        result
    }

    fn reconcile_pending_inner(
        &mut self,
        writer: &dyn SingleWriter,
        key: &Digest32,
    ) -> io::Result<ReconcileOutcome> {
        if !self.usable(Some(writer)) {
            return Err(io::Error::other("store disabled"));
        }
        let Some(PendingWrite {
            prior,
            candidate,
            content,
            completed,
            ..
        }) = self.pending.get(key).copied()
        else {
            return Ok(ReconcileOutcome::NoPending);
        };
        let path = self.record_path(key);
        let before = stamp_at(&path)?;
        if let Some(stamp) = completed {
            return if before == Some(stamp) {
                Ok(ReconcileOutcome::Receipted(WireReceiptProof {
                    identity: candidate,
                    stamp,
                    content,
                }))
            } else {
                Err(io::Error::other("retained completion changed"))
            };
        }
        self.durable.remove(key); // Reconcile fully verifies, even a memo hit.
        let receipted = match self.read_known(key, Some(writer), false) {
            Ok(Some(verified)) if before == stamp_at(&path)? => {
                if verified.identity == candidate {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(&path)?;
                    if Some(Stamp::of(&file.metadata()?)) != before {
                        return Err(io::Error::other("survivor changed"));
                    }
                    file.sync_all()?;
                    true
                } else if prior.is_some()
                    && before == prior
                    && verified.record.format == FORMAT_VERSION
                {
                    if stamp_at(&path)? != before {
                        return Err(io::Error::other("predecessor changed"));
                    }
                    remove_if_present(&path)?;
                    false
                } else {
                    return Err(io::Error::other("unadjudicated survivor"));
                }
            }
            Ok(None) if before.is_none() && self.disabled.is_none() => false,
            _ => return Err(io::Error::other("unverified survivor")),
        };
        self.sync_store()?;
        let after = stamp_at(&path)?;
        if (receipted && after != before) || (!receipted && after.is_some()) {
            return Err(io::Error::other("survivor changed"));
        }
        if receipted {
            // This is the exact positive receipt boundary, including a later
            // reconciliation outside the original write batch. Negative or
            // unresolved outcomes must never regrant a failed T14 rebuild.
            self.rebuilt.remove(key);
            self.counters.receipt_reconciled += 1;
            Ok(ReconcileOutcome::Receipted(WireReceiptProof {
                identity: candidate,
                stamp: after.expect("verified survivor"),
                content,
            }))
        } else {
            self.pending.remove(key);
            self.durable.remove(key);
            self.counters.durable_write_failed_published += 1;
            Ok(ReconcileOutcome::Retired(RetirementProof { candidate }))
        }
    }

    pub(crate) fn revoke(&mut self, key: &Digest32) {
        if let Some((_, _, allowed)) = self.durable.get_mut(key) {
            *allowed = false;
        }
    }
    pub(crate) fn revoke_all(&mut self) {
        for (_, _, allowed) in self.durable.values_mut() {
            *allowed = false;
        }
    }

    /// Only a fully verified original binding may authorize a v3 or Claude mutation.
    pub(crate) fn authorize(&mut self, record: &DurableRecord, expected: &Expected) {
        self.revoke(&record.record.binding.key);
        if let Some(proof) = self.mutation_witness(record, expected) {
            self.authorize_witness(record, expected, &proof);
        }
    }
    pub(crate) fn mutation_witness(
        &self,
        record: &DurableRecord,
        expected: &Expected,
    ) -> Option<MutationWitness> {
        if record.eligible(expected).is_err()
            || record.format == FORMAT_V1
                && (record.record.binding.entry != expected.binding.entry
                    || record.index_generation > expected.committed_generation)
        {
            return None;
        }
        let key = record.record.binding.key;
        let digest = record_digest(record);
        let (Some(content), stamp, _) = self.durable.get(&key)? else {
            return None;
        };
        let proof = MutationWitness {
            key,
            original: original_digest(record, &digest),
            content: digest,
            stamp: *stamp,
            migration_floor: None,
        };
        (*content == digest && self.witness_current(&proof)).then_some(proof)
    }
    pub(crate) fn witness_current(&self, proof: &MutationWitness) -> bool {
        fs::symlink_metadata(self.record_path(&proof.key))
            .is_ok_and(|m| Stamp::of(&m) == proof.stamp)
    }
    /// Key-specific durable write, still the exact target observed by that write.
    /// A clean retry, stale receipt or another key cannot retire custody.
    pub(crate) fn replacement_committed(
        &self,
        proof: &MutationWitness,
        receipt: &BatchReceipt,
    ) -> bool {
        receipt.committed.as_ref().is_some_and(|acks| {
            acks.iter().flatten().any(|(key, content, stamp)| {
                *key == proof.key
                    && *content != proof.content
                    && *stamp != proof.stamp
                    && self.durable.get(key).is_some_and(|(have, current, _)| {
                        *have == Some(*content) && current == stamp
                    })
                    && fs::symlink_metadata(self.record_path(key))
                        .is_ok_and(|m| Stamp::of(&m) == *stamp)
            })
        })
    }
    pub(crate) fn authorize_witness(
        &mut self,
        record: &DurableRecord,
        expected: &Expected,
        proof: &MutationWitness,
    ) {
        if proof.is_migration() {
            self.revoke(&record.record.binding.key);
            return;
        }
        self.authorize_bound_witness(
            record,
            expected,
            proof,
            original_digest(record, &record_digest(record)),
        );
    }
    fn authorize_bound_witness(
        &mut self,
        record: &DurableRecord,
        expected: &Expected,
        proof: &MutationWitness,
        identity: Digest32,
    ) {
        self.revoke(&record.record.binding.key);
        let content = record_digest(record);
        if record.eligible(expected).is_err()
            || record.format == FORMAT_V1
                && (record.record.binding.entry != expected.binding.entry
                    || record.index_generation > expected.committed_generation)
            || proof.key != record.record.binding.key
            || proof.original != identity
            || proof.content != content
            || !self.witness_current(proof)
        {
            return;
        }
        self.memoize(proof.key, (Some(content), proof.stamp, true));
    }
    /// The memo is a bounded optimization, never custody or receipt authority.
    /// Revoke a non-pending entry when full: its next mutation must re-verify
    /// the real predecessor. No spent grant or original witness is refunded.
    fn memoize(&mut self, key: Digest32, value: (Option<Digest32>, Stamp, bool)) {
        if self.durable.len() >= MAX_RECORDS && !self.durable.contains_key(&key) {
            let victim = self
                .durable
                .iter()
                .filter(|(digest, _)| !self.pending.contains_key(*digest))
                .min_by_key(|(_, (_, _, allowed))| *allowed)
                .map(|(digest, _)| *digest);
            let Some(victim) = victim else {
                // pending is bounded at 32, smaller than the 256-entry memo.
                self.counters.mutation_unproved += 1;
                return;
            };
            self.durable.remove(&victim);
            self.counters.memo_evicted += 1;
        }
        self.durable.insert(key, value);
    }

    /// Only the supported no-match acquisition classifier calls this, BEFORE O3 reserve.
    pub(crate) fn migration_witness(
        &self,
        record: &DurableRecord,
        current: &Expected,
        floor: u64,
    ) -> Option<MutationWitness> {
        if self.source != DurableSource::ClaudeCode
            || record.format != 1
            || record.record.binding.source != self.source
            || record.record.binding.key != current.binding.key
            || record.record.binding.context != current.binding.context
        {
            return None;
        }
        let mut original = current.clone();
        original.binding.scope = record.record.binding.scope;
        original.binding.entry = record.record.binding.entry;
        let mut proof = self.mutation_witness(record, &original)?;
        proof.original = migration_binding(&proof.original, current);
        proof.migration_floor = Some(std::num::NonZeroU64::new(floor)?);
        Some(proof)
    }
    pub(crate) fn migration_matches(
        &self,
        proof: &MutationWitness,
        record: &DurableRecord,
        current: &Expected,
    ) -> bool {
        proof.key == current.binding.key
            && record.record.binding.key == proof.key
            && record.record.binding.context == current.binding.context
            && proof.migration_floor.is_some()
            && proof.original
                == migration_binding(&original_digest(record, &record_digest(record)), current)
            && proof.content == record_digest(record)
            && self.witness_current(proof)
    }
    /// The caller supplies a completed native checkpoint and strict saved selection.
    pub(crate) fn authorize_migration(
        &mut self,
        record: &DurableRecord,
        current: &Expected,
        replacement: &DurableCertificate,
        proof: &MutationWitness,
    ) {
        self.revoke(&record.record.binding.key);
        let old = &record.record.certificate;
        if !self.migration_matches(proof, record, current)
            || (old.device, old.inode) != (replacement.device, replacement.inode)
            || (old.birth_nanos != 0
                && replacement.birth_nanos != 0
                && old.birth_nanos != replacement.birth_nanos)
            || !proof
                .migration_floor
                .is_some_and(|floor| replacement.sealed_offset >= floor.get())
        {
            return;
        }
        let mut original = current.clone();
        original.binding.scope = record.record.binding.scope;
        original.binding.entry = record.record.binding.entry;
        let identity = migration_binding(&original_digest(record, &record_digest(record)), current);
        self.authorize_bound_witness(record, &original, proof, identity);
    }
    fn authorized(&mut self, key: &Digest32, format: u16) -> bool {
        let allowed = format == FORMAT_V1 && self.source != DurableSource::ClaudeCode
            || self.durable.get(key).is_some_and(|(_, stamp, yes)| {
                *yes && fs::symlink_metadata(self.record_path(key))
                    .is_ok_and(|m| Stamp::of(&m) == *stamp)
            });
        self.counters.mutation_unproved += u64::from(!allowed);
        allowed
    }

    /// The post-save write. Call only after `ScanIndex::save` succeeded, with
    /// that save's committed generation and only entries that save kept.
    /// Clean records (same content as the last durable write) are skipped;
    /// at most `MAX_BATCH` dirty records are written, the rest are deferred.
    /// The bounded batch syncs the store and parent once; ambiguous outcomes stay pending.
    pub(crate) fn write_after_save<W: SingleWriter>(
        &mut self,
        writer: &W,
        committed_generation: u64,
        index_length: u64,
        pending: Vec<PendingRecord>,
    ) -> io::Result<BatchReceipt> {
        // A paused rebuild absent from pending must survive this save.
        for record in &pending {
            if self.rebuilt.get(&record.binding.key) == Some(&Rebuild::Started) {
                self.rebuilt.insert(record.binding.key, Rebuild::Offered);
            }
        }
        let result = self.write_batch(writer, committed_generation, index_length, pending);
        for (key, state) in &mut self.rebuilt {
            if *state == Rebuild::Offered {
                *state = if result.as_ref().is_ok_and(|r| r.deferred_keys.contains(key)) {
                    Rebuild::Started
                } else {
                    Rebuild::NotReplaced
                };
            }
        }
        result
    }

    fn write_batch<W: SingleWriter>(
        &mut self,
        writer: &W,
        committed_generation: u64,
        index_length: u64,
        pending: Vec<PendingRecord>,
    ) -> io::Result<BatchReceipt> {
        self.check_writer(writer)?;
        let mut receipt = BatchReceipt::default();
        let mut dirty = Vec::new();
        if !self.usable(Some(writer)) {
            return Ok(receipt);
        }
        if !self.check_resources(writer, index_length)? {
            receipt
                .deferred_keys
                .extend(pending.iter().map(|record| record.binding.key));
            receipt.deferred = receipt.deferred_keys.len();
            return Ok(receipt);
        }
        // The caller's bodies stay live for the whole batch.
        let pending_bytes = pending
            .iter()
            .map(|record| record.body.len())
            .sum::<usize>();
        // Deduplicate in the already-funded input allocation. First offer wins;
        // no extra key map survives beside the pending/candidate owner.
        let mut pending = pending;
        pending.reverse();
        while let Some(record) = pending.pop() {
            let key = record.binding.key;
            pending.retain(|other| other.binding.key != key);
            if record.binding.source != self.source
                || self
                    .source
                    .properties()
                    .representation(record.format(), &record.allowlist)
                    .is_none()
                || record.acquisition.is_some() && record.binding.entry != [0; 32]
            {
                self.counters.store_write_skipped[0] += 1;
                continue;
            }
            if matches!(
                self.rebuilt.get(&record.binding.key),
                Some(Rebuild::Authorized | Rebuild::NotReplaced)
            ) {
                continue;
            }
            if receipt
                .completed
                .iter()
                .any(|proof| proof.identity.key == key)
            {
                continue;
            }
            let content = content_digest(&record);
            let reconciliation = if self.pending.contains_key(&key) {
                match self.reconcile_pending(writer, &key) {
                    Ok(ReconcileOutcome::Receipted(proof)) => self.retain_receipt(proof),
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                }
            } else {
                Ok(())
            };
            if reconciliation.is_err() {
                let stamp = stamp_at(&self.record_path(&key))?;
                let same = self.pending.get(&key).is_some_and(|pending| {
                    pending.completed.is_none() && pending.prior.is_some() && pending.prior == stamp
                });
                if !(same
                    && matches!(
                        self.classify(&key, "overwrite", Some(writer)),
                        Err(Refusal::Corrupt)
                    ))
                {
                    receipt.deferred_keys.push(key);
                    continue;
                }
            }
            if let Some(PendingWrite {
                candidate,
                content: completed_content,
                completed: Some(stamp),
                ..
            }) = self.pending.get(&key).copied()
            {
                if receipt.completed.len() >= MAX_BATCH {
                    receipt.deferred_keys.push(key);
                    continue;
                }
                // Deliver the exact B receipt even when the native graph has
                // advanced to C. Requeue C; do not require B's body to survive.
                if completed_content != content {
                    receipt.deferred += 1;
                    receipt.deferred_keys.push(key);
                }
                receipt.written += 1;
                receipt.bytes_written += candidate.encoded_len;
                receipt.completed.push(WireReceiptProof {
                    identity: candidate,
                    stamp,
                    content: completed_content,
                });
                continue; // Exact completed B, before stale-A authorization or clean handling.
            }
            // A T14 predecessor is the rebuild's to replace.
            let (prior, previous_content) =
                match self.classify(&record.binding.key, "overwrite", Some(writer)) {
                    Err(Refusal::Corrupt) => (
                        fs::symlink_metadata(self.record_path(&record.binding.key))
                            .ok()
                            .map(|m| Stamp::of(&m)),
                        None,
                    ),
                    Err(_) => {
                        self.counters.store_write_skipped[0] += 1;
                        continue;
                    }
                    // Carry the exact verified predecessor into conditional retirement.
                    Ok(Some(old)) if !self.authorized(&record.binding.key, old.format) => continue,
                    Ok(Some(old)) => (old.stamp, old.content),
                    Ok(None) => (None, None),
                };
            if previous_content == Some(content) {
                receipt.clean += 1;
            } else {
                dirty.push((record, content, prior, previous_content.is_some()));
            }
        }
        if !self.usable(Some(writer)) {
            return Ok(BatchReceipt::default());
        }
        if dirty.is_empty() {
            self.counters.records_clean += receipt.clean as u64;
            return self.finish_batch(receipt);
        }
        ensure_private_dir(&self.dir).inspect_err(|_| self.counters.store_write_failed[0] += 1)?;
        self.checked = false;
        if !self.usable(Some(writer)) {
            return Ok(BatchReceipt::default()); // Keep completion custody; no unchecked delivery.
        }
        let (mut on_disk, mut unlisted) = self
            .scan_disk()
            .inspect_err(|_| self.counters.store_write_failed[1] += 1)?;
        // Native staging and this post-save batch share the pass allowance.
        // A declined native record must not bypass it through its RAM offer.
        let mut attempted = self.stream_records + receipt.completed.len();
        let mut encoded_pass_bytes = self.stream_bytes;
        for (record, content, prior, verified_prior) in dirty {
            if attempted >= MAX_BATCH {
                receipt.deferred += 1;
                receipt.deferred_keys.push(record.binding.key);
                continue;
            }
            let key = record.binding.key;
            let path = self.record_path(&key);
            // Past the inventory bound an existing key still replaces its own
            // record; a new key waits.
            if unlisted[0] > 0 && !on_disk.contains_key(&key) {
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        unlisted = [unlisted[0] - 1, unlisted[1].saturating_sub(metadata.len())];
                        on_disk.insert(key, metadata.len());
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            let stored = DurableRecord {
                envelope_audit_debt: record.certificate.audit_debt_unix_seconds,
                format: record.format(),
                record,
                index_generation: committed_generation,
                wire: None,
            };
            if stored.record.body.len() > BODY_BYTES {
                // Preserve the verified predecessor until an ordinary
                // replacement succeeds, including on budget refusal.
                self.durable.remove(&key);
                receipt.budget_refused += 1;
                continue;
            }
            let bytes = encode(&stored);
            if self.stream_records != 0
                && encoded_pass_bytes
                    .checked_add(bytes.len())
                    .map_or(true, |bytes| bytes > WRITE_PASS_BYTES)
            {
                receipt.deferred += 1;
                receipt.deferred_keys.push(key);
                continue;
            }
            let ack_bytes = if self.source == DurableSource::ClaudeCode {
                BATCH_ACK_BYTES
            } else {
                0
            };
            self.note_codec(pending_bytes + bytes.capacity() + ack_bytes);
            let previous = on_disk.get(&key).copied().unwrap_or(0);
            if previous == 0
                && !above_floor(&self.dir, bytes.len() as u64, index_length)
                    .inspect_err(|_| self.counters.store_write_failed[2] += 1)?
            {
                self.counters.durable_floor_skipped += 1;
                continue;
            }
            if self.pending.len() >= MAX_BATCH {
                // Completed candidates retain custody until atomic delivery.
                // A full owner defers before I/O; it does not disable the store.
                receipt.deferred += 1;
                receipt.deferred_keys.push(key);
                continue;
            }
            if ack_bytes != 0 {
                receipt
                    .committed
                    .get_or_insert_with(|| Box::new([None; MAX_BATCH]));
            }
            attempted += 1;
            encoded_pass_bytes = encoded_pass_bytes.saturating_add(bytes.len());
            let candidate = WireRecordIdentity::verified(&stored, &bytes);
            self.pending.insert(
                key,
                PendingWrite {
                    prior,
                    candidate,
                    content,
                    completed: None,
                    failures: 0,
                },
            );
            let attempt = write_atomic(
                writer,
                &self.dir,
                &path,
                &bytes,
                prior,
                Arc::clone(&self.cleanup),
            )
            .and_then(|stamp| {
                if stamp_at(&path)? != Some(stamp) {
                    return Err(io::Error::other("committed survivor changed"));
                }
                Ok(ReconcileOutcome::Receipted(WireReceiptProof {
                    identity: candidate,
                    stamp,
                    content,
                }))
            });
            if attempt.as_ref().is_err_and(write_cleanup_failed) {
                self.counters.store_write_cleanup_failed += 1;
            }
            if attempt.as_ref().is_err_and(stream::no_space) {
                // A capacity failure never authorizes predecessor retirement.
                // Drop only failed RAM authority and let the native owner retain
                // its key hold; the next successful write may replace A.
                self.pause_resources();
                self.pending.remove(&key);
                receipt.deferred += 1;
                receipt.deferred_keys.push(key);
                continue;
            }
            if attempt
                .as_ref()
                .is_err_and(|error| !write_cleanup_failed(error))
                && (verified_prior || self.rebuilt.get(&key) == Some(&Rebuild::Offered))
                && prior.is_some()
                && stamp_at(&path)? == prior
            {
                // The post-save index already refuses A. A failed rename left
                // that exact verified or T14 predecessor untouched: do not retire it
                // or lose the retry offer. The caller requeues this saved key,
                // and retained RAM stays usable. A failed T14 replacement must
                // not acquire receipt debt for a candidate that never survived.
                self.pending.remove(&key);
                return Err(attempt.err().expect("checked failed write"));
            }
            let outcome = attempt.or_else(|_| self.reconcile_pending(writer, &key));
            let proof = match outcome {
                Ok(ReconcileOutcome::Receipted(proof)) if proof.identity == candidate => proof,
                Ok(ReconcileOutcome::Retired(proof)) if proof.candidate == candidate => {
                    on_disk.remove(&key);
                    receipt.deferred += 1;
                    receipt.deferred_keys.push(key);
                    continue;
                }
                _ => {
                    self.counters.receipt_pending_held += 1;
                    receipt.deferred_keys.push(key);
                    continue;
                }
            };
            let encoded_len = proof.identity.encoded_len;
            // A rename alone is not a legacy batch receipt. Keep pending
            // incomplete until the one batch flush and final stamp check.
            receipt.completed.push(proof);
            on_disk.insert(key, encoded_len);
            receipt.written += 1;
            receipt.bytes_written += encoded_len;
        }
        self.counters.batches += 1;
        self.counters.records_clean += receipt.clean as u64;
        self.counters.records_deferred += receipt.deferred as u64;
        self.counters.budget_refused += receipt.budget_refused as u64;
        self.set_disk_level(&on_disk, unlisted);
        if !receipt.completed.is_empty() {
            // One flush for the whole bounded batch. A fault or a path swap
            // leaves every candidate pending and requeues its retained RAM;
            // it cannot deliver a receipt or turn a retry into a clean ACK.
            let delivery = self.sync_store().and_then(|()| {
                for proof in &receipt.completed {
                    if stamp_at(&self.record_path(&proof.identity.key))? != Some(proof.stamp) {
                        return Err(io::Error::other("batch survivor changed"));
                    }
                }
                Ok(())
            });
            if delivery.is_err() {
                self.counters.store_write_failed[2] += 1;
                for proof in receipt.completed.drain(..) {
                    if let Some(pending) = self.pending.get_mut(&proof.identity.key) {
                        pending.completed = None;
                    }
                    receipt.deferred_keys.push(proof.identity.key);
                    receipt.deferred += 1;
                }
                receipt.written = 0;
                receipt.bytes_written = 0;
                receipt.committed = None;
            } else {
                for proof in &receipt.completed {
                    let pending = self
                        .pending
                        .get_mut(&proof.identity.key)
                        .filter(|pending| {
                            pending.candidate == proof.identity && pending.content == proof.content
                        })
                        .ok_or_else(|| io::Error::other("batch candidate changed"))?;
                    pending.completed = Some(proof.stamp);
                }
            }
        }
        self.finish_batch(receipt)
    }

    /// Garbage collection after a successful save: delete stale temp files,
    /// verified known records from
    /// another context (account or namespace change) and records whose key
    /// is not kept or whose scope is not the kept one. A key kept with an
    /// unknown scope (`None`: its file was not decided this pass) keeps its
    /// record; restore still refuses it on a scope mismatch. Newer-format
    /// records are left for the binary that wrote them.
    pub(crate) fn gc<W: SingleWriter>(
        &mut self,
        writer: &W,
        live_context: &Digest32,
        keep: &BTreeMap<Digest32, Option<Digest32>>,
    ) -> io::Result<()> {
        let keep = keep
            .iter()
            .map(|(key, scope)| {
                (
                    *key,
                    match scope {
                        Some(scope) => GcKeep::Scope(*scope),
                        None => GcKeep::Unknown,
                    },
                )
            })
            .collect();
        self.gc_classified(writer, live_context, &keep)
    }

    pub(crate) fn gc_classified<W: SingleWriter>(
        &mut self,
        writer: &W,
        live_context: &Digest32,
        keep: &BTreeMap<Digest32, GcKeep>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        if !self.usable(Some(writer)) {
            return Ok(());
        }
        let page = self.inventory()?;
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.durable.clear();
                self.set_disk_level(&BTreeMap::new(), [0; 2]);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        #[cfg(test)]
        let entries = test_hooks::gc_entries(entries);
        let mut deleted = false;
        let mut on_disk = BTreeMap::new();
        self.counters.uninventoried_records = 0;
        let mut unlisted_bytes = 0;
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let path = entry.path();
            if dead_temp(name) && entry.file_type()?.is_file() {
                remove_if_present(&path)?;
                self.counters.gc_temps_deleted += 1;
                deleted = true;
                continue;
            }
            let Some(key) = name.strip_suffix(RECORD_SUFFIX).and_then(parse_hex_digest) else {
                continue;
            };
            let len = entry.metadata().map_or(0, |m| m.len());
            if !page.contains(&key) {
                self.counters.uninventoried_records += 1;
                unlisted_bytes += len;
                continue;
            }
            if self.pending.contains_key(&key) {
                on_disk.insert(key, len);
                continue;
            }
            let mut layout_retirement = None;
            let mut class_retirement = None;
            let verdict = match self.classify(&key, "delete", Some(writer)) {
                Ok(Some(header))
                    if header.format == FORMAT_V3
                        && !crate::heap_layout_bound::layout_supported() =>
                {
                    match keep.get(&key) {
                        Some(GcKeep::LayoutUnavailable {
                            audit_debt,
                            verified,
                        }) if *verified
                            || header.audit_debt.map_or(true, |due| {
                                audit_debt.is_some_and(|carrier| carrier > 0 && carrier <= due)
                            }) =>
                        {
                            layout_retirement = header.stamp;
                            None
                        }
                        _ => Some(len), // No actual settled read: preserve A.
                    }
                }
                Ok(Some(header))
                    if (matches!(keep.get(&key), Some(GcKeep::Excluded { .. }))
                        || !keep.contains_key(&key))
                        && header.format == FORMAT_V3
                        && header.record.acquisition.is_some_and(|fields| {
                            fields.protocol == crate::snapshots::AcquisitionProtocol::WriteAhead
                        })
                        && header.record.binding.context == *live_context =>
                {
                    let audit_debt = match keep.get(&key) {
                        Some(GcKeep::Excluded { audit_debt }) => *audit_debt,
                        _ => None,
                    };
                    // Class exclusion is an explicit owner decision, not restore
                    // or overwrite authority. Retire only a verified native v3
                    // record, after its #865 debt is carried by the index.
                    if header.audit_debt.is_some_and(|due| {
                        !audit_debt.is_some_and(|carrier| carrier > 0 && carrier <= due)
                    }) {
                        self.counters.native_class_parked += 1;
                        Some(len)
                    } else if let Some(stamp) = header.stamp {
                        class_retirement = Some(stamp);
                        None
                    } else {
                        Some(len)
                    }
                }
                Ok(Some(header)) if !self.authorized(&key, header.format) => Some(len),
                Ok(Some(header)) => {
                    // Missing membership cannot erase its debt evidence. A
                    // fresh-index cleanup has no trusted context (zero).
                    if header.audit_debt.is_some()
                        && !keep.contains_key(&key)
                        && (header.record.binding.context == *live_context
                            || *live_context == [0; 32])
                    {
                        self.counters.format_hold[Refusal::Unbindable as usize] += 1;
                        on_disk.insert(key, len);
                        continue;
                    }
                    let binding = header.record.binding;
                    let live = binding.context == *live_context
                        && match keep.get(&key) {
                            Some(GcKeep::Scope(scope)) => *scope == binding.scope,
                            Some(
                                GcKeep::Unknown
                                | GcKeep::Excluded { .. }
                                | GcKeep::LayoutUnavailable { .. },
                            ) => true,
                            None => false,
                        };
                    live.then_some(len)
                }
                Ok(None) if self.disabled.is_some() => return Ok(()),
                Ok(None) => continue,
                Err(_) => Some(len),
            };
            match verdict {
                Some(len) => {
                    on_disk.insert(key, len);
                }
                None => {
                    if let Some(stamp) = layout_retirement.or(class_retirement) {
                        if stamp_at(&path)? != Some(stamp) {
                            on_disk.insert(key, len);
                            continue; // Replaced since verification: never unlink the new record.
                        }
                    }
                    remove_if_present(&path)?;
                    self.counters.restore_unavailable_layout_gc +=
                        u64::from(layout_retirement.is_some());
                    self.counters.native_class_retired += u64::from(class_retirement.is_some());
                    self.durable.remove(&key);
                    self.counters.gc_records_deleted += 1;
                    deleted = true;
                }
            }
        }
        self.gc_after = page.last().copied();
        self.durable
            .retain(|key, _| !page.contains(key) || on_disk.contains_key(key));
        if deleted {
            self.sync_store()?;
        }
        self.set_disk_level(
            &on_disk,
            [self.counters.uninventoried_records, unlisted_bytes],
        );
        Ok(())
    }

    /// Same bounded name page used by the caller and GC. A cold restart begins
    /// at the first key; each completed pass moves past its last inspected key.
    /// Enumeration uses bounded memory even when disk has many more records.
    pub(crate) fn inventory(&self) -> io::Result<BTreeSet<Digest32>> {
        if self.disabled.is_some() {
            return Ok(BTreeSet::new());
        }
        let page = self.inventory_after(self.gc_after)?;
        if page.is_empty() && self.gc_after.is_some() {
            self.inventory_after(None)
        } else {
            Ok(page)
        }
    }
    fn inventory_after(&self, after: Option<Digest32>) -> io::Result<BTreeSet<Digest32>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(error) => return Err(error),
        };
        let mut keys = BTreeSet::new();
        for entry in entries {
            let name = entry?.file_name();
            if let Some(key) = name
                .to_str()
                .and_then(|name| name.strip_suffix(RECORD_SUFFIX))
                .and_then(parse_hex_digest)
                .filter(|key| after.map_or(true, |after| *key > after))
            {
                keys.insert(key);
                if keys.len() > GC_RECORDS_PER_PASS {
                    keys.pop_last();
                }
            }
        }
        Ok(keys)
    }

    /// Known-empty inventory is the only negative privacy fact. An absent
    /// store needs no sweep; an existing store with a missing/damaged inventory
    /// fails closed. The inventory carries key digests only, never labels.
    pub(crate) fn private_label_keys(&self) -> io::Result<Option<BTreeSet<Digest32>>> {
        if matches!(fs::symlink_metadata(&self.dir), Err(e) if e.kind() == io::ErrorKind::NotFound)
        {
            return Ok(Some(BTreeSet::new()));
        }
        let path = self.dir.with_extension("private-labels");
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(_) => return Ok(None),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != our_uid() || metadata.mode() & 0o777 != 0o600 {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((4 + 32 * MAX_RECORDS + 1) as u64)
            .read_to_end(&mut bytes)?;
        if !bytes.starts_with(b"PL01")
            || (bytes.len() - 4) % 32 != 0
            || bytes.len() > 4 + 32 * MAX_RECORDS
        {
            return Ok(None);
        }
        let mut keys = BTreeSet::new();
        for key in bytes[4..].chunks_exact(32) {
            if !keys.insert(key.try_into().expect("digest width")) {
                return Ok(None);
            }
        }
        Ok(Some(keys))
    }

    /// The same page for retention planning and erase; its cursor is separate
    /// from ordinary GC so neither owner can skip another owner's keys.
    pub(crate) fn private_label_candidates(&self) -> io::Result<BTreeSet<Digest32>> {
        match self.private_label_keys().unwrap_or(None) {
            Some(keys) => Ok(keys),
            None => self.inventory_after(self.private_purge_after),
        }
    }

    pub(crate) fn private_label_purge_needed(&self, keep: Option<&BTreeSet<Digest32>>) -> bool {
        !matches!(self.private_label_keys(), Ok(Some(keys)) if keys.iter().all(|key| keep.is_some_and(|keep| keep.contains(key))))
    }

    fn write_private_label_keys<W: SingleWriter>(
        &mut self,
        writer: &W,
        keys: Option<&BTreeSet<Digest32>>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        ensure_private_dir(&self.dir)?;
        let mut bytes = b"PL??".to_vec();
        if let Some(keys) = keys.filter(|keys| keys.len() <= MAX_RECORDS) {
            bytes = b"PL01".to_vec();
            for key in keys {
                bytes.extend_from_slice(key);
            }
        }
        let path = self.dir.with_extension("private-labels");
        write_atomic(
            writer,
            &self.dir,
            &path,
            &bytes,
            stamp_at(&path)?,
            self.cleanup.clone(),
        )?;
        self.sync_store()
    }

    /// Persist the inventory BEFORE any literal can reach a record or temp.
    pub(crate) fn mark_private_labels<W: SingleWriter>(
        &mut self,
        writer: &W,
        key: Digest32,
    ) -> io::Result<()> {
        // A newly staged literal invalidates a prior partial no-label sweep,
        // including a new canonical key ordered before its old cursor.
        self.private_purge_after = None;
        self.private_purge_dirty = false;
        let mut keys = self.private_label_keys().unwrap_or(None);
        if let Some(keys) = keys.as_mut() {
            keys.insert(key);
        }
        self.write_private_label_keys(writer, keys.as_ref())
    }

    /// Consent/source erasure uses the existing bounded inventory and verifier.
    /// `keep` is empty for revoked consent; otherwise it protects live PL keys.
    pub(crate) fn purge_private_labels_kept<W: SingleWriter>(
        &mut self,
        writer: &W,
        keep: &BTreeSet<Digest32>,
        mut contains: impl FnMut(&[u8]) -> bool,
    ) -> io::Result<PrivateLabelPurge> {
        self.check_writer(writer)?;
        let known = self.private_label_keys().unwrap_or(None);
        let keys = self.private_label_candidates()?;
        let mut remaining = BTreeSet::new();
        let mut report = PrivateLabelPurge {
            scanned: 0,
            erased: 0,
            refused: 0,
        };
        let mut erased = 0;
        for key in &keys {
            if keep.contains(key) {
                remaining.insert(*key);
                continue;
            }
            report.scanned += 1;
            let path = self.record_path(key);
            let before = match stamp_at(&path) {
                Ok(None) => continue,
                Ok(Some(stamp)) => stamp,
                Err(_) => {
                    report.refused += 1;
                    remaining.insert(*key);
                    continue;
                }
            };
            let verified = match self.read_known(key, Some(writer), true) {
                Ok(Some(verified)) => verified,
                Ok(None) if !path.exists() && self.disabled.is_none() => continue,
                Err(Refusal::Repin) => continue, // The pre-PL pin cannot contain label literals.
                _ => {
                    report.refused += 1;
                    remaining.insert(*key);
                    continue;
                }
            };
            if !contains(&verified.record.record.body) {
                continue;
            }
            if stamp_at(&path).ok() != Some(Some(before)) || remove_if_present(&path).is_err() {
                report.refused += 1;
                remaining.insert(*key);
                continue;
            }
            if let Some(pending) = self.pending.get_mut(key) {
                pending.completed = None;
            }
            self.durable.remove(key);
            erased += 1;
        }
        // No erase count until unlink AND its directory barrier have succeeded.
        if self.sync_store().is_err() {
            report.refused += erased.max(1);
            return Ok(report); // Previous inventory still says PL may exist.
        }
        report.erased = erased;
        if known.is_none() {
            self.private_purge_dirty |= report.refused > 0 || !remaining.is_empty();
            if keys.len() >= GC_RECORDS_PER_PASS {
                // Advance over retained/non-label records too; the marker stays
                // unknown until an entire bounded traversal proves erasure.
                self.private_purge_after = keys.last().copied();
                return Ok(report);
            }
            self.private_purge_after = None;
            if std::mem::take(&mut self.private_purge_dirty) {
                // Earlier pages may owe retry, but a failure on this page is
                // already counted. Never count the same refusal twice.
                report.refused = report.refused.max(1);
                return Ok(report);
            }
        }
        if self
            .write_private_label_keys(writer, Some(&remaining))
            .is_err()
        {
            report.refused += 1;
        }
        Ok(report)
    }

    pub(crate) fn purge_private_labels<W: SingleWriter>(
        &mut self,
        writer: &W,
        contains: impl FnMut(&[u8]) -> bool,
    ) -> io::Result<PrivateLabelPurge> {
        self.purge_private_labels_kept(writer, &BTreeSet::new(), contains)
    }

    /// Retire exactly the verified predecessor. `sync_due` belongs to writer
    /// custody: once unlink succeeds, absence never cancels the sync barrier.
    pub(crate) fn retire_exact<W: SingleWriter>(
        &mut self,
        writer: &W,
        proof: &MutationWitness,
        sync_due: &mut bool,
    ) -> RetireOutcome {
        let result = (|| -> io::Result<RetireOutcome> {
            self.check_writer(writer)?;
            if !self.usable(Some(writer))
                || self.pending.contains_key(&proof.key)
                || self.receipt_pending(&proof.key)
            {
                return Ok(RetireOutcome::Retry);
            }
            let path = self.record_path(&proof.key);
            let before = stamp_at(&path)?;
            match before {
                None => {
                    // Also covers a prior unlink whose sync returned an error.
                    #[cfg(test)]
                    test_hooks::transition_edge(CrashPoint::BeforeRetireSync, &self.dir)?;
                    self.sync_store()?;
                    #[cfg(test)]
                    test_hooks::transition_edge(CrashPoint::RetiredSynced, &self.dir)?;
                    if stamp_at(&path)?.is_some() {
                        return Ok(RetireOutcome::Retry);
                    }
                    self.durable.remove(&proof.key);
                    *sync_due = false;
                    self.counters.records_invalidated += 1;
                    return Ok(RetireOutcome::Retired);
                }
                Some(stamp) if stamp != proof.stamp => {
                    if *sync_due {
                        self.sync_store()?;
                    }
                    // A boolean witness miss is NOT supersession. Force a full
                    // survivor verification, preserving newer/unknown formats.
                    self.durable.remove(&proof.key);
                    let verified = self.read_known(&proof.key, Some(writer), false);
                    return Ok(
                        if matches!(verified, Ok(Some(_))) && stamp_at(&path)? == before {
                            *sync_due = false;
                            RetireOutcome::Superseded
                        } else {
                            RetireOutcome::Retry
                        },
                    );
                }
                Some(_) => {}
            }
            let _header = self
                .classify(&proof.key, "delete", Some(writer))
                .map_err(|_| io::Error::other("retirement classification"))?
                .ok_or_else(|| io::Error::other("retirement unknown survivor"))?;
            // The retained witness is the eligible original-binding authority;
            // begin_pass and memo turnover cannot revoke that exact predecessor.
            if stamp_at(&path)? != Some(proof.stamp) {
                return Ok(RetireOutcome::Retry);
            }
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::BeforeRetireUnlink, &path)?;
            remove_if_present(&path)?;
            *sync_due = true;
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::RetiredUnlink, &path)?;
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::BeforeRetireSync, &self.dir)?;
            self.sync_store()?;
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::RetiredSynced, &self.dir)?;
            if stamp_at(&path)?.is_some() {
                return Ok(RetireOutcome::Retry);
            }
            self.durable.remove(&proof.key);
            *sync_due = false;
            self.counters.records_invalidated += 1;
            Ok(RetireOutcome::Retired)
        })();
        result.unwrap_or(RetireOutcome::Retry)
    }

    /// Deletes the records of `keys` (held or reverted selections): a stale
    /// record for them must never restore.
    pub(crate) fn remove_keys<W: SingleWriter>(
        &mut self,
        writer: &W,
        keys: &BTreeSet<Digest32>,
    ) -> io::Result<usize> {
        self.check_writer(writer)?;
        let mut removed = 0;
        if !self.usable(Some(writer)) {
            return Ok(0);
        }
        for key in keys {
            let path = self.record_path(key);
            let allowed = !self.pending.contains_key(key)
                && self
                    .classify(key, "delete", Some(writer))
                    .ok()
                    .flatten()
                    .is_some_and(|header| self.authorized(key, header.format));
            if allowed {
                #[cfg(test)]
                test_hooks::transition_edge(CrashPoint::BeforeRetireUnlink, &path)?;
                remove_if_present(&path)?;
                #[cfg(test)]
                test_hooks::transition_edge(CrashPoint::RetiredUnlink, &path)?;
                removed += 1;
            }
            self.durable.remove(key);
        }
        if removed > 0 {
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::BeforeRetireSync, &self.dir)?;
            self.sync_store()?;
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::RetiredSynced, &self.dir)?;
            self.counters.records_invalidated += removed as u64;
            let (on_disk, unlisted) = self.scan_disk()?;
            self.set_disk_level(&on_disk, unlisted);
        }
        Ok(removed)
    }

    fn check_writer<W: SingleWriter + ?Sized>(&self, writer: &W) -> io::Result<()> {
        if self.dir.starts_with(writer.state_dir()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "store outside writer root",
            ))
        }
    }

    fn sync_store(&self) -> io::Result<()> {
        sync_dir(&self.dir)?;
        sync_dir(
            self.dir
                .parent()
                .ok_or_else(|| io::Error::other("store parent"))?,
        )
    }

    /// Record files and their sizes, as on disk now: the first
    /// `INVENTORY_BOUND` by key, the rest only counted and summed.
    fn scan_disk(&self) -> io::Result<(BTreeMap<Digest32, u64>, [u64; 2])> {
        #[cfg(test)]
        test_hooks::write_failure("inventory")?;
        let mut on_disk = BTreeMap::new();
        let mut unlisted = [0; 2];
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(key) = name
                .to_str()
                .and_then(|name| name.strip_suffix(RECORD_SUFFIX))
                .and_then(parse_hex_digest)
            else {
                continue;
            };
            let len = fs::symlink_metadata(entry.path())?.len();
            if on_disk.len() < GC_RECORDS_PER_PASS {
                on_disk.insert(key, len);
            } else {
                unlisted = [unlisted[0] + 1, unlisted[1] + len];
            }
        }
        Ok((on_disk, unlisted))
    }

    fn set_disk_level(&mut self, on_disk: &BTreeMap<Digest32, u64>, unlisted: [u64; 2]) {
        self.counters.disk_records = on_disk.len() as u64 + unlisted[0];
        self.counters.disk_bytes = on_disk.values().sum::<u64>() + unlisted[1];
    }

    fn note_codec(&mut self, bytes: usize) {
        self.counters.peak_codec_bytes = self.counters.peak_codec_bytes.max(bytes as u64);
    }
}

impl MutationWitness {
    pub(crate) fn same_predecessor(&self, other: &Self) -> bool {
        self.key == other.key && self.content == other.content && self.stamp == other.stamp
    }

    pub(crate) fn migration_floor(&self) -> Option<u64> {
        self.migration_floor.map(|floor| floor.get())
    }
    pub(crate) fn is_migration(&self) -> bool {
        self.migration_floor.is_some()
    }
}

/// What makes a record dirty: everything but the generation stamp, so a
/// later save of an unchanged entry rewrites nothing.
/// Hashes the header and the body in place: no copy of the body (its only
/// scratch is the admitted representation header).
fn content_digest(record: &PendingRecord) -> Digest32 {
    let mut header = Vec::with_capacity(HEADER_V3_BYTES);
    encode_header(&mut header, record, record.format(), 0);
    content_digest_parts(&header, &record.body)
}

fn content_digest_parts(header: &[u8], body: &[u8]) -> Digest32 {
    digest("ottto-dt-content:v2", &[header, body])
}

/// Memo the verified STORED representation, not the decoded certificate
/// whose compatibility debt was dropped.
fn stored_digest(bytes: &[u8]) -> Digest32 {
    let size = dispatch(bytes).expect("verified representation").3;
    let mut header = bytes[..size].to_vec();
    header[171..179].fill(0); // committed generation is not content
    content_digest_parts(&header, &bytes[size..bytes.len() - TRAILER_BYTES])
}

/// `stored_digest` of a decoded record: its envelope debt goes back into the
/// header (debt tag, due, then the body length end it).
fn record_digest(stored: &DurableRecord) -> Digest32 {
    let mut header = Vec::with_capacity(HEADER_V3_BYTES);
    encode_header(&mut header, &stored.record, stored.format, 0);
    let debt = header.len() - 12;
    header[debt - 1] = u8::from(stored.envelope_audit_debt.is_some());
    header[debt..debt + 8].copy_from_slice(&stored.envelope_audit_debt.unwrap_or(0).to_le_bytes());
    content_digest_parts(&header, &stored.record.body)
}

fn inspect_path(path: &Path) -> io::Result<fs::Metadata> {
    #[cfg(test)]
    test_hooks::before_access(path, "metadata")?;
    fs::symlink_metadata(path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn parse_hex_digest(text: &str) -> Option<Digest32> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = text.get(index * 2..index * 2 + 2)?;
        if !pair
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_hooks::write_failure("setup")?;
    #[cfg(test)]
    test_hooks::transition_edge(CrashPoint::BeforeDirectoryCreate, dir)?;
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {
            #[cfg(test)]
            test_hooks::transition_edge(CrashPoint::DirectoryCreated, dir)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    Ok(()) // The caller rechecks owner/type and repairs the new directory's mode.
}

// An absent record leaves index length plus max(2 GiB, 1% volume).
fn above_floor(dir: &Path, encoded: u64, index_len: u64) -> io::Result<bool> {
    #[cfg(test)]
    test_hooks::write_failure("statvfs")?;
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("store path"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable statvfs storage.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded and initialized the structure.
    let stat = unsafe { stat.assume_init() };
    // libc typedef widths vary by target; keep the checked product in u64.
    #[allow(clippy::unnecessary_cast)]
    let (fragment_bytes, available_blocks, volume_blocks) = (
        stat.f_frsize as u64,
        stat.f_bavail as u64,
        stat.f_blocks as u64,
    );
    let available = available_blocks.checked_mul(fragment_bytes);
    let volume = volume_blocks.checked_mul(fragment_bytes);
    Ok(floor_allows(available, volume, encoded, index_len))
}
fn floor_allows(available: Option<u64>, volume: Option<u64>, encoded: u64, index_len: u64) -> bool {
    available.zip(volume).is_some_and(|(available, volume)| {
        available
            .checked_sub(encoded)
            .and_then(|n| n.checked_sub(index_len))
            .is_some_and(|left| left >= (2 * 1024 * 1024 * 1024).max(volume / 100))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp([u64; 3], [i64; 4]);
impl Stamp {
    /// Exact process-local (dev, ino, size, mtime, ctime) verification stamp.
    fn of(m: &fs::Metadata) -> Self {
        Self(
            [m.dev(), m.ino(), m.len()],
            [m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()],
        )
    }
}

fn stamp_at(path: &Path) -> io::Result<Option<Stamp>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(Stamp::of(&metadata))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn our_uid() -> u32 {
    #[cfg(test)]
    if let Some(uid) = test_hooks::uid() {
        return uid;
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn dead_temp(name: &str) -> bool {
    let name = name
        .strip_prefix('.')
        .and_then(|n| n.strip_suffix(TEMP_SUFFIX));
    let Some((prefix, last)) = name.and_then(|n| n.rsplit_once('.')) else {
        return false;
    };
    let (record, pid, staged) = if let Some((record, pid)) = prefix.rsplit_once('.') {
        if record.ends_with(RECORD_SUFFIX) && last.parse::<u64>().is_ok() {
            (record, pid, true)
        } else if record.ends_with(RECORD_SUFFIX)
            && last
                .strip_prefix('a')
                .is_some_and(|n| n.parse::<u64>().is_ok())
        {
            (record, pid, false)
        } else {
            (prefix, last, false)
        }
    } else {
        (prefix, last, false)
    };
    let pid = pid.parse::<i32>().ok().filter(|pid| *pid > 0);
    let named = record
        .strip_suffix(RECORD_SUFFIX)
        .and_then(parse_hex_digest);
    // Owned stages can outlive Stores; a live process's stage is never a GC orphan.
    let ours = !staged && pid.is_some_and(|pid| pid.unsigned_abs() == std::process::id());
    // SAFETY: signal zero probes only, without sending a signal.
    named.is_some()
        && (ours
            || pid.is_some_and(|pid| unsafe { libc::kill(pid, 0) } == -1)
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
}

struct Header {
    record: PendingRecord,
    generation: u64,
    format: u16,
    body_len: usize,
    audit_debt: Option<u64>,
    stamp: Option<Stamp>,
    content: Option<Digest32>,
    verified: Option<Vec<u8>>,
}
fn dispatch(bytes: &[u8]) -> Result<(u16, Digest32, DurableSource, usize), Refusal> {
    let mut c = Cursor(bytes);
    if c.array::<8>() != Some(MAGIC) {
        return Err(Refusal::Undecodable);
    }
    let format = c.u16().ok_or(Refusal::Undecodable)?;
    if format > FORMAT_V3 {
        return Err(Refusal::NewerFormat);
    }
    let allowlist = c.array::<32>().ok_or(Refusal::Undecodable)?;
    let source =
        DurableSource::from_tag(c.u8().ok_or(Refusal::Undecodable)?).ok_or(Refusal::Unknown)?;
    Ok((
        format,
        allowlist,
        source,
        header_len(format, source, &allowlist)?,
    ))
}

fn decode_header(bytes: &[u8], key: &Digest32, source: DurableSource) -> Result<Header, Refusal> {
    let (format, allowlist, admitted, size) = dispatch(bytes)?;
    if bytes.len() < size {
        return Err(Refusal::Corrupt);
    }
    let mut c = Cursor(&bytes[DISPATCH_BYTES..size]);
    let binding = (|| {
        Some(Binding {
            source: admitted,
            key: c.array()?,
            context: c.array()?,
            scope: c.array()?,
            entry: c.array()?,
        })
    })()
    .ok_or(Refusal::Undecodable)?;
    if binding.key != *key || binding.source != source {
        return Err(Refusal::Unbindable);
    }
    let mut debt_valid = true;
    let parsed = (|| {
        let generation = c.u64()?;
        let acquisition = if format == FORMAT_V3 {
            if binding.entry != [0; 32] {
                return None;
            }
            Some(AcquisitionFields {
                acquired_revision: c.u64()?,
                protocol: match c.u8()? {
                    0 => crate::snapshots::AcquisitionProtocol::Legacy,
                    1 => crate::snapshots::AcquisitionProtocol::WriteAhead,
                    _ => return None,
                },
            })
        } else {
            None
        };
        let certificate = DurableCertificate {
            device: c.u64()?,
            inode: c.u64()?,
            length: c.u64()?,
            modified: (c.i64()?, c.i64()?),
            birth_nanos: c.u64()?,
            sealed_offset: c.u64()?,
            sample_len: c.u32()?,
            head_sha256: c.array()?,
            boundary_sha256: c.array()?,
            verified_unix_seconds: c.u64()?,
            // The old debt bytes are consumed, structurally checked and dropped.
            audit_debt_unix_seconds: {
                let tag = c.u8()?;
                let due = c.u64()?;
                debt_valid = matches!((tag, due), (0, 0) | (1, 1..));
                (tag == 1).then_some(due)
            },
        };
        Some(Header {
            record: PendingRecord {
                binding,
                certificate,
                body: Vec::new(),
                allowlist,
                acquisition,
            },
            generation,
            format,
            body_len: c.u32()? as usize,
            audit_debt: None,
            stamp: None,
            content: None,
            verified: None,
        })
    })();
    let mut header = parsed.ok_or(Refusal::Corrupt)?;
    if !debt_valid {
        return Err(Refusal::Unbindable);
    }
    header.audit_debt = header.record.certificate.audit_debt_unix_seconds.take();
    Ok(header)
}

fn verify(bytes: &[u8], source: DurableSource) -> Result<(), Refusal> {
    let bad = Refusal::Corrupt;
    let end = bytes.len().checked_sub(TRAILER_BYTES).ok_or(bad)?;
    if bytes[end..] != Sha256::digest(&bytes[..end])[..] {
        return Err(bad);
    }
    let key = bytes
        .get(43..75)
        .and_then(|b| b.try_into().ok())
        .ok_or(bad)?;
    let h = decode_header(bytes, &key, source)?;
    let start = header_len(h.format, source, &h.record.allowlist)?;
    if end.checked_sub(start) != Some(h.body_len) {
        return Err(bad);
    }
    if retired_pin(source, h.format, &h.record.allowlist) {
        // The retired body is opaque. Its checksum proves exact replacement
        // custody only; no current decoder or restore receives these bytes.
        return Ok(());
    }
    crate::snapshots::verify_durable_body(&bytes[start..end], source)
        .then_some(())
        .ok_or(bad)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_hooks::before_unlink(path)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Private ownership of a create-new temp. A temp is never record authority.
/// Keep its descriptor until commit/discard so pathname reuse cannot authorize
/// removing or promoting another inode.
#[derive(Default)]
struct TempCleanupCounts {
    verified: AtomicU64,
    failed: AtomicU64,
    fallback: AtomicU64,
}
// Includes Arc's two reference counts and alignment within the existing slot reserve.
const _: () =
    assert!(std::mem::size_of::<TempCleanupCounts>() + 2 * std::mem::size_of::<usize>() <= 64);

struct OwnedTemp {
    path: PathBuf,
    file: Option<File>,
    cleanup: Arc<TempCleanupCounts>,
}

impl OwnedTemp {
    fn prepare(dir: &Path, path: &Path, cleanup: Arc<TempCleanupCounts>) -> io::Result<Self> {
        Self::create(dir, path, cleanup, false)
    }
    fn prepare_atomic(
        dir: &Path,
        path: &Path,
        cleanup: Arc<TempCleanupCounts>,
    ) -> io::Result<Self> {
        // Short-lived owners stay under Stores. GC may reap their failed cleanup
        // on this process, but must preserve live outliving native stages.
        Self::create(dir, path, cleanup, true)
    }
    fn create(
        dir: &Path,
        path: &Path,
        cleanup: Arc<TempCleanupCounts>,
        atomic: bool,
    ) -> io::Result<Self> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT_TEMP
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("temp serial exhausted"))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "record name"))?;
        let kind = if atomic { "a" } else { "" };
        let temp = dir.join(format!(
            ".{name}.{}.{kind}{serial}{TEMP_SUFFIX}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&temp)?;
        Ok(Self {
            path: temp,
            file: Some(file),
            cleanup,
        })
    }

    fn sync(&self) -> io::Result<()> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("disarmed temp"))?
            .sync_all()
    }

    fn verify(&self) -> io::Result<()> {
        let held = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::other("disarmed temp"))?
            .metadata()?;
        let actual = fs::symlink_metadata(&self.path)?;
        if Stamp::of(&held) != Stamp::of(&actual) {
            return Err(io::Error::other("temp changed"));
        }
        Ok(())
    }

    fn commit(&mut self, path: &Path, prior: Option<Stamp>) -> io::Result<Stamp> {
        #[cfg(test)]
        test_hooks::before_rename(&self.path, path)?;
        self.verify()?;
        let actual = match fs::symlink_metadata(path) {
            Ok(metadata) => Some(Stamp::of(&metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if actual != prior {
            return Err(io::Error::other("predecessor changed"));
        }
        fs::rename(&self.path, path)?;
        // Disarm immediately after rename, including failure of the following fstat.
        // The canonical candidate now belongs to pending custody, never temp cleanup.
        let file = self.file.take().expect("owned temp");
        Ok(Stamp::of(&file.metadata()?))
    }

    fn discard(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            return Ok(());
        }
        let result = (|| {
            match self.verify() {
                Ok(()) => remove_if_present(&self.path)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            sync_dir(self.path.parent().expect("temp directory"))?;
            if !fs::symlink_metadata(&self.path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            {
                return Err(io::Error::other("temp cleanup unverified"));
            }
            self.cleanup.verified.fetch_add(1, Ordering::Relaxed);
            self.file.take();
            Ok(())
        })();
        if result.is_err() {
            self.cleanup.failed.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

impl Write for OwnedTemp {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("disarmed temp"))?
            .write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("disarmed temp"))?
            .flush()
    }
}
impl Drop for OwnedTemp {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.cleanup.fallback.fetch_add(1, Ordering::Relaxed);
            if crate::locked_state_dir::held_for(&self.path).is_some() {
                let _ = self.discard();
            } else {
                self.cleanup.failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// Compatibility adapter for the inherited leaf tests; exercises the same owner.
#[cfg(test)]
struct TempRecord<'a> {
    inner: OwnedTemp,
    counters: &'a mut StoreCounters,
}
#[cfg(test)]
impl<'a> TempRecord<'a> {
    fn prepare(dir: &Path, path: &Path, counters: &'a mut StoreCounters) -> io::Result<Self> {
        Ok(Self {
            inner: OwnedTemp::prepare(dir, path, Arc::default())?,
            counters,
        })
    }
    fn discard(&mut self) -> io::Result<()> {
        let result = self.inner.discard();
        self.update();
        result
    }
    fn update(&mut self) {
        self.counters.temp_discard_verified = self.inner.cleanup.verified.load(Ordering::Relaxed);
        self.counters.temp_discard_failed = self.inner.cleanup.failed.load(Ordering::Relaxed);
        self.counters.temp_drop_fallback = self.inner.cleanup.fallback.load(Ordering::Relaxed);
    }
}
#[cfg(test)]
impl std::ops::Deref for TempRecord<'_> {
    type Target = OwnedTemp;
    fn deref(&self) -> &OwnedTemp {
        &self.inner
    }
}
#[cfg(test)]
impl std::ops::DerefMut for TempRecord<'_> {
    fn deref_mut(&mut self) -> &mut OwnedTemp {
        &mut self.inner
    }
}
#[cfg(test)]
impl Drop for TempRecord<'_> {
    fn drop(&mut self) {
        if self.inner.file.is_some() {
            self.inner.cleanup.fallback.fetch_add(1, Ordering::Relaxed);
            let _ = self.inner.discard();
            // Avoid a second fallback when a replaced pathname cannot be removed.
            self.inner.file.take();
        }
        self.update();
    }
}

/// The M1 caller shares the owned leaf engine and its source-slot counters.
fn write_atomic<W: SingleWriter>(
    writer: &W,
    dir: &Path,
    path: &Path,
    bytes: &[u8],
    prior: Option<Stamp>,
    cleanup: Arc<TempCleanupCounts>,
) -> io::Result<Stamp> {
    // M1's stack-bound writer can unwind before returning. It remains a real
    // proof for this short scope; the native stage uses the unborrowed owner.
    struct Attempt<'a, W: SingleWriter> {
        temp: OwnedTemp,
        writer: &'a W,
    }
    impl<W: SingleWriter> Drop for Attempt<'_, W> {
        fn drop(&mut self) {
            if self.temp.file.is_some() {
                self.temp.cleanup.fallback.fetch_add(1, Ordering::Relaxed);
                if self.temp.path.starts_with(self.writer.state_dir()) {
                    let _ = self.temp.discard();
                } else {
                    self.temp.cleanup.failed.fetch_add(1, Ordering::Relaxed);
                }
                self.temp.file.take();
            }
        }
    }
    let mut attempt = Attempt {
        temp: OwnedTemp::prepare_atomic(dir, path, cleanup)?,
        writer,
    };
    let result = (|| {
        #[cfg(test)]
        reach(CrashPoint::BeforeTempWrite);
        attempt.temp.write_all(bytes)?;
        #[cfg(test)]
        reach(CrashPoint::TempWritten);
        attempt.temp.flush()?;
        attempt.temp.commit(path, prior)
    })();
    if let Err(write) = result {
        if let Err(cleanup) = attempt.temp.discard() {
            // The fallback may establish absence after a transient failure.
            // Try it explicitly so the disposition depends on the actual final
            // cleanup result, rather than a sampled global counter.
            attempt
                .temp
                .cleanup
                .fallback
                .fetch_add(1, Ordering::Relaxed);
            if attempt.temp.discard().is_err() {
                // Both cleanup boundaries have run. Closing the descriptor
                // leaves only the proven temp name for the existing GC owner;
                // do not attempt a third cleanup from Drop.
                attempt.temp.file.take();
                return Err(io::Error::other(WriteCleanupFailure { write, cleanup }));
            }
        }
        return Err(write);
    }
    result
}

#[derive(Debug)]
struct WriteCleanupFailure {
    write: io::Error,
    cleanup: io::Error,
}
impl std::fmt::Display for WriteCleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No paths or provider data enter the diagnostics carrier.
        write!(
            f,
            "record write and cleanup failed ({:?}, {:?})",
            self.write.kind(),
            self.cleanup.kind()
        )
    }
}
impl std::error::Error for WriteCleanupFailure {}
fn write_cleanup_failed(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|error| error.is::<WriteCleanupFailure>())
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    test_hooks::before_dir_sync(dir)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir)?
        .sync_all()
}

/// Little-endian envelope: magic, format version, allowlist digest, source,
/// key/context/scope/entry digests, generation, certificate, body length,
/// body, then a SHA-256 trailer over everything before it.
fn encode(record: &DurableRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_V3_BYTES + record.record.body.len() + TRAILER_BYTES);
    encode_header(
        &mut out,
        &record.record,
        record.format,
        record.index_generation,
    );
    out.extend_from_slice(&record.record.body);
    let trailer: Digest32 = Sha256::digest(&out).into();
    out.extend_from_slice(&trailer);
    out
}

/// Everything before the body, ending with the body length: exactly
/// the selected representation header length.
struct HeaderParts<'a> {
    binding: &'a Binding,
    certificate: &'a DurableCertificate,
    allowlist: &'a Digest32,
    acquisition: Option<AcquisitionFields>,
    format: u16,
    generation: u64,
    body_len: usize,
}
fn encode_header(out: &mut Vec<u8>, record: &PendingRecord, format: u16, generation: u64) {
    write_header(
        out,
        HeaderParts {
            binding: &record.binding,
            certificate: &record.certificate,
            allowlist: &record.allowlist,
            acquisition: record.acquisition,
            format,
            generation,
            body_len: record.body.len(),
        },
    )
    .expect("Vec header write");
}
fn write_header(out: &mut dyn Write, fields: HeaderParts<'_>) -> io::Result<()> {
    let HeaderParts {
        binding,
        certificate,
        allowlist,
        acquisition,
        format,
        generation,
        body_len,
    } = fields;
    out.write_all(&MAGIC)?;
    out.write_all(&format.to_le_bytes())?;
    out.write_all(allowlist)?;
    out.write_all(&[binding.source.tag()])?;
    for part in [
        &binding.key,
        &binding.context,
        &binding.scope,
        &binding.entry,
    ] {
        out.write_all(part)?;
    }
    out.write_all(&generation.to_le_bytes())?;
    if format == FORMAT_V3 {
        let acquisition = acquisition.expect("v3 requires captured acquisition provenance");
        out.write_all(&acquisition.acquired_revision.to_le_bytes())?;
        out.write_all(&[match acquisition.protocol {
            crate::snapshots::AcquisitionProtocol::Legacy => 0,
            crate::snapshots::AcquisitionProtocol::WriteAhead => 1,
        }])?;
    }
    for value in [certificate.device, certificate.inode, certificate.length] {
        out.write_all(&value.to_le_bytes())?;
    }
    out.write_all(&certificate.modified.0.to_le_bytes())?;
    out.write_all(&certificate.modified.1.to_le_bytes())?;
    out.write_all(&certificate.birth_nanos.to_le_bytes())?;
    out.write_all(&certificate.sealed_offset.to_le_bytes())?;
    out.write_all(&certificate.sample_len.to_le_bytes())?;
    out.write_all(&certificate.head_sha256)?;
    out.write_all(&certificate.boundary_sha256)?;
    out.write_all(&certificate.verified_unix_seconds.to_le_bytes())?;
    out.write_all(&[u8::from(certificate.audit_debt_unix_seconds.is_some())])?;
    out.write_all(
        &certificate
            .audit_debt_unix_seconds
            .unwrap_or(0)
            .to_le_bytes(),
    )?;
    out.write_all(&(body_len as u32).to_le_bytes())?;
    Ok(())
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.array()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.array()?))
    }
}

/// The version is checked before the trailer: a newer layout is not ours to
/// judge. Everything else must pass the trailer and decode exactly.
fn decode(bytes: &[u8]) -> Result<DurableRecord, Refusal> {
    let (format, pin, source, _) = dispatch(bytes)?;
    if retired_pin(source, format, &pin) {
        return Err(Refusal::Repin);
    }

    let source = bytes
        .get(42)
        .and_then(|tag| DurableSource::from_tag(*tag))
        .ok_or(Refusal::Undecodable)?;
    let key = bytes
        .get(43..75)
        .and_then(|b| b.try_into().ok())
        .ok_or(Refusal::Undecodable)?;
    let mut h = decode_header(bytes, &key, source)?;
    verify(bytes, source)?;
    let start = header_len(h.format, source, &h.record.allowlist)?;
    h.record.body = bytes[start..bytes.len() - TRAILER_BYTES].to_vec();
    Ok(DurableRecord {
        record: h.record,
        index_generation: h.generation,
        format: h.format,
        envelope_audit_debt: h.audit_debt,
        wire: Some(WireIdentity {
            encoded_len: bytes.len() as u64,
            trailer: bytes[bytes.len() - TRAILER_BYTES..]
                .try_into()
                .map_err(|_| Refusal::Corrupt)?,
        }),
    })
}

/// Test-only filesystem faults and deterministic GC ordering.
#[cfg(test)]
pub(crate) mod test_hooks {
    use super::{reach, CrashPoint};
    use std::cell::RefCell;
    use std::io;
    use std::path::Path;

    type Hook = Box<dyn FnMut(&Path, &Path) -> io::Result<()>>;
    type DirHook = Box<dyn FnMut(&Path) -> io::Result<()>>;
    type AccessHook = Box<dyn FnMut(&Path, &str) -> io::Result<()>>;
    pub(crate) type TransitionHook = Box<dyn FnMut(CrashPoint, &Path) -> io::Result<()>>;

    thread_local! {
        static TRANSITION: RefCell<Option<TransitionHook>> = const { RefCell::new(None) };
        static WRITE_FAILURE: RefCell<Option<&'static str>> = const { RefCell::new(None) };
        static BEFORE_RENAME: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_DIR_SYNC: RefCell<Option<DirHook>> = const { RefCell::new(None) };
        static BEFORE_ACCESS: RefCell<Option<AccessHook>> = const { RefCell::new(None) };
        static RECORDS_FIRST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static BEFORE_UNLINK: RefCell<Option<DirHook>> = const { RefCell::new(None) };
        static UID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    }

    pub(crate) fn set_before_access(hook: Option<AccessHook>) {
        BEFORE_ACCESS.with(|slot| *slot.borrow_mut() = hook);
    }
    pub(super) fn before_access(path: &Path, operation: &str) -> io::Result<()> {
        BEFORE_ACCESS.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(path, operation),
            None => Ok(()),
        })
    }
    pub(crate) fn set_gc_records_first(value: bool) {
        RECORDS_FIRST.with(|slot| slot.set(value));
    }
    pub(super) fn gc_entries(entries: std::fs::ReadDir) -> Vec<io::Result<std::fs::DirEntry>> {
        let mut entries: Vec<_> = entries.collect();
        if RECORDS_FIRST.with(std::cell::Cell::get) {
            entries.sort_by_key(|entry| {
                entry.as_ref().ok().map(|entry| {
                    let name = entry.file_name();
                    (!name.to_string_lossy().ends_with(".rec"), name)
                })
            });
        }
        entries
    }
    pub(crate) fn set_write_failure(stage: Option<&'static str>) {
        WRITE_FAILURE.with(|s| *s.borrow_mut() = stage);
    }
    pub(super) fn write_failure(stage: &'static str) -> io::Result<()> {
        WRITE_FAILURE.with(|s| {
            if *s.borrow() == Some(stage) {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        })
    }

    pub(crate) fn set_before_unlink(hook: Option<DirHook>) {
        BEFORE_UNLINK.with(|h| *h.borrow_mut() = hook);
    }
    pub(super) fn before_unlink(path: &Path) -> io::Result<()> {
        BEFORE_UNLINK.with(|h| match h.borrow_mut().as_mut() {
            Some(hook) => hook(path),
            None => Ok(()),
        })
    }

    pub(crate) fn replace_transition_hook(hook: Option<TransitionHook>) -> Option<TransitionHook> {
        TRANSITION.with(|slot| slot.replace(hook))
    }
    pub(crate) fn transition_edge(point: CrashPoint, path: &Path) -> io::Result<()> {
        reach(point);
        TRANSITION.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(point, path),
            None => Ok(()),
        })
    }

    /// The uid the store treats as its own (a foreign owner without root).
    pub(crate) fn set_uid(uid: Option<u32>) {
        UID.with(|slot| slot.set(uid));
    }
    pub(super) fn uid() -> Option<u32> {
        UID.with(std::cell::Cell::get)
    }

    pub(crate) fn set_before_rename(hook: Option<Hook>) {
        BEFORE_RENAME.with(|slot| *slot.borrow_mut() = hook);
    }
    pub(crate) fn set_before_dir_sync(hook: Option<DirHook>) {
        BEFORE_DIR_SYNC.with(|slot| *slot.borrow_mut() = hook);
    }
    pub(super) fn before_rename(temp: &Path, path: &Path) -> io::Result<()> {
        transition_edge(CrashPoint::BeforeRename, path)?;
        BEFORE_RENAME.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(temp, path),
            None => Ok(()),
        })
    }
    pub(super) fn before_dir_sync(dir: &Path) -> io::Result<()> {
        transition_edge(CrashPoint::BeforeDirectorySync, dir)?;
        BEFORE_DIR_SYNC.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(dir),
            None => Ok(()),
        })
    }
}

#[cfg(test)]
#[path = "durable_tail_store_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "durable_tail_store/released_decoders_tests.rs"]
mod released_decoders_tests;
