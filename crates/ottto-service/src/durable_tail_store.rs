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
//! - Each write is temp file (0600, create-new), fsync, rename, then one
//!   directory and parent fsync per record. A torn, truncated or flipped record fails its
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

use crate::transcript_acquisition::DurableCertificate;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) mod active;
pub(crate) use active::{ActiveLease, ActiveOverBudget, LeaseWait, ACTIVE_BYTES};

/// Envelope format. Bump on any envelope or certificate layout change.
pub(crate) const FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 8] = *b"ottto-dt";
/// One record never exceeds the RAM cache's per-entry bound
/// (`transcript_cache::ENTRY_BYTES`): the store keeps only what RAM can.
pub(crate) const RECORD_BYTES: usize = crate::transcript_cache::ENTRY_BYTES;
/// Verification memo precision, independent of disk admission.
pub(crate) const MAX_RECORDS: usize = crate::transcript_cache::CACHE_ENTRIES;
/// Dirty records written per index save; the rest stay dirty for the next.
pub(crate) const MAX_BATCH: usize = 32;
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
const INPUT_ENVELOPE: usize = RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES + 1;
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

/// A record before the store stamps it with a committed generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingRecord {
    pub(crate) binding: Binding,
    pub(crate) certificate: DurableCertificate,
    /// The codec's allowlisted encoding; opaque to the store.
    pub(crate) body: Vec<u8>,
    /// The codec's allowlist digest, carried in the envelope.
    pub(crate) allowlist: Digest32,
}

/// A record as stored: the pending record plus the generation of the index
/// save it followed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableRecord {
    pub(crate) record: PendingRecord,
    pub(crate) index_generation: u64,
    pub(crate) format: u16,
    /// Validated v1 compatibility debt; never checkpoint authority.
    pub(crate) envelope_audit_debt: Option<u64>,
}

/// Exact verified predecessor; no caller can manufacture or clone its authority.
pub(crate) struct MutationWitness {
    key: Digest32,
    content: Digest32,
    stamp: Stamp,
    format: u16,
    generation: u64,
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
        } else if have.source == DurableSource::Codex
            && self.index_generation > expected.committed_generation
        {
            Err(Ineligible::GenerationAhead)
        } else if have.source == DurableSource::Codex && have.entry != want.entry {
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
    /// Failed physical attempt boundaries: setup, inventory, statvfs.
    pub(crate) store_write_failed: [u64; 3],
    /// Per-pass read I/O.
    pub(crate) bytes_read: u64,
    pub(crate) records_read: u64,
    pub(crate) mutation_unproved: u64,
    pub(crate) missing: u64,
    pub(crate) format_hold: [u64; 8],
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
    pub(crate) gc_temps_deleted: u64,
    /// GC reads only record headers (`HEADER_BYTES` each), never bodies.
    pub(crate) gc_records_read: u64,
    pub(crate) gc_bytes_read: u64,
    /// Records deleted because their selection was held or reverted.
    pub(crate) records_invalidated: u64,
    /// Peak transient encode/decode buffer, in bytes.
    pub(crate) peak_codec_bytes: u64,
}

/// Fixed-size key/content/target identities for the strict Claude caller.
type BatchAcks = [Option<(Digest32, Digest32, Stamp)>; MAX_BATCH];
const BATCH_ACK_BYTES: usize = std::mem::size_of::<BatchAcks>();

/// What one post-save batch did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
}

/// One store directory. The in-RAM map of last durable content digests
/// decides dirtiness, so a clean record is never rewritten.
pub(crate) struct DurableTailStore {
    dir: PathBuf,
    source: DurableSource,
    durable: BTreeMap<Digest32, (Option<Digest32>, Stamp, bool)>,
    counters: StoreCounters,
    /// The store-level fault that made this store memory-only for the process.
    disabled: Option<&'static str>,
    /// This pass: directory checked and [records loaded, T14 rebuilds].
    checked: bool,
    pass: [u64; 2],
    /// Process-lifetime attempts, removed only after a successful replacement.
    rebuilt: BTreeMap<Digest32, Rebuild>,
    startup_synced: bool,
    pending: BTreeMap<Digest32, (Option<Stamp>, u64, Digest32, u8)>,
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
pub(crate) const INVENTORY_BOUND: usize = 2 * MAX_RECORDS;
/// T14 rebuilds one pass allows before the store is disabled: more than
/// `max(T14_BREAKER, 2% of the records loaded)`.
pub(crate) const T14_BREAKER: u64 = 20;
const REBUILT_BOUND: usize = 64;
// Three actual failures for one receipt bound this hold; lease waits do not count.
const RECEIPT_RECONCILE_FAILURES: u8 = 3;
// A memo entry stays within the 128 bytes per record `STORES_RESIDENT_BOUND` charges.
const _: () = assert!(std::mem::size_of::<(Digest32, (Option<Digest32>, Stamp, bool))>() <= 128);

impl DurableTailStore {
    pub(crate) fn new(dir: PathBuf, source: DurableSource) -> Self {
        Self {
            dir,
            durable: BTreeMap::new(),
            source,
            counters: StoreCounters::default(),
            disabled: None,
            checked: false,
            pass: [0; 2],
            rebuilt: BTreeMap::new(),
            startup_synced: false,
            pending: BTreeMap::new(),
        }
    }

    /// A new pass: the directory is checked again and the T14 breaker resets.
    pub(crate) fn begin_pass(&mut self) {
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

    /// Metadata-only: Claude observes the native read of a key with no record.
    pub(crate) fn absent(&self, key: &Digest32) -> bool {
        self.disabled.is_none()
            && inspect_path(&self.record_path(key))
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
    }

    pub(crate) fn counters(&self) -> StoreCounters {
        StoreCounters {
            receipt_pending_records: self.pending.len() as u64,
            ..self.counters
        }
    }

    /// The counters since the last call, which resets them. The disk totals
    /// are a level, not a flow, and are kept.
    #[cfg(test)]
    pub(crate) fn take_pass(&mut self) -> StoreCounters {
        let pass = self.counters();
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
        let writable = writer
            .or_else(|| {
                crate::locked_state_dir::held_for(&self.dir).map(|w| w as &dyn SingleWriter)
            })
            .is_some_and(|w| self.check_writer(w).is_ok());
        if !self.usable(writer) {
            return Ok(None);
        }
        let path = self.record_path(key);
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
            let mut header = Vec::with_capacity(HEADER_BYTES);
            Read::by_ref(&mut file)
                .take(HEADER_BYTES as u64)
                .read_to_end(&mut header)
                .map_err(|e| self.read_failure(e, Refusal::Undecodable))?;
            let n = header.len();
            if work == "delete" {
                self.counters.gc_records_read += 1;
                self.counters.gc_bytes_read += n as u64;
            } else {
                self.counters.guard_header_bytes += n as u64;
            }
            let mut binding = decode_header(&header, key, self.source)?;
            // After any repair: its ctime moved.
            let Some(metadata) = self.inspect_file(&file) else {
                return Ok(None);
            };
            let stamp = Stamp::of(&metadata);
            binding.stamp = Some(stamp);
            if !metadata.is_file()
                || metadata.len() > (RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES) as u64
            {
                return Err(Refusal::Corrupt);
            }
            if let Some((content, old, _)) = self.durable.get(key) {
                if *old == stamp && (work != "overwrite" || content.is_some()) {
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
            verify(&bytes, self.source)?;
            if work == "overwrite" {
                binding.content = Some(stored_digest(&bytes));
            }
            if self.durable.len() < MAX_RECORDS || self.durable.contains_key(key) {
                self.durable.insert(*key, (None, stamp, false));
            }
            Ok(Some(binding))
        })();
        if self.disabled.is_some() {
            return Ok(None);
        }
        if let Err(reason) = result {
            self.durable.remove(key);
            self.counters.format_hold[reason as usize] += 1;
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
        if self.pending.contains_key(key) {
            return Err(Refusal::ReceiptPending);
        }
        let result = self.classify(key, "guard", None);
        self.pass[0] += u64::from(!matches!(result, Ok(None)));
        match result {
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
        if self.pending.contains_key(key) {
            return ReadOutcome::Refused(Refusal::ReceiptPending);
        }
        self.read_known(key, None)
    }
    fn read_known(&mut self, key: &Digest32, writer: Option<&dyn SingleWriter>) -> ReadOutcome {
        match self.classify(key, "guard", writer) {
            Err(reason) => return ReadOutcome::Refused(reason),
            Ok(None) => {
                self.counters.missing += 1;
                return ReadOutcome::Missing;
            }
            Ok(Some(_)) => {}
        }
        let bytes = match read_private(&self.record_path(key)) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return ReadOutcome::Missing,
            Err(e) if e.kind() != io::ErrorKind::InvalidData => {
                self.disable("record_access");
                return ReadOutcome::Missing;
            }
            _ => return ReadOutcome::Refused(Refusal::Corrupt),
        };
        self.counters.records_read += 1;
        self.counters.bytes_read += bytes.len() as u64;
        self.counters.max_record_bytes = self.counters.max_record_bytes.max(bytes.len() as u64);
        self.note_codec(bytes.capacity() + bytes.len().saturating_sub(HEADER_BYTES));
        match decode(&bytes) {
            Ok(record) => {
                if let Some((content, _, _)) = self.durable.get_mut(key) {
                    *content = Some(stored_digest(&bytes));
                }
                ReadOutcome::Found(Box::new(record))
            }
            Err(reason) => ReadOutcome::Refused(reason),
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }
    pub(crate) fn receipt_pending(&self, key: &Digest32) -> bool {
        self.pending.contains_key(key)
    }

    pub(crate) fn reconcile_pending(
        &mut self,
        writer: &dyn SingleWriter,
        key: &Digest32,
    ) -> io::Result<bool> {
        self.check_writer(writer)?;
        if self.disabled.is_some() {
            return Err(io::Error::other("store disabled"));
        }
        let result = self.reconcile_pending_inner(writer, key);
        if result.is_err() {
            if let Some(pending) = self.pending.get_mut(key) {
                pending.3 = pending.3.saturating_add(1);
                if pending.3 >= RECEIPT_RECONCILE_FAILURES {
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
    ) -> io::Result<bool> {
        if !self.usable(Some(writer)) {
            return Err(io::Error::other("store disabled"));
        }
        let Some((prior, generation, content, _)) = self.pending.get(key).copied() else {
            return Ok(true);
        };
        let path = self.record_path(key);
        let stamp = || fs::symlink_metadata(&path).ok().map(|m| Stamp::of(&m));
        let before = stamp();
        self.durable.remove(key); // Reconcile must fully verify, even a memo hit.
        let receipted = match self.read_known(key, Some(writer)) {
            ReadOutcome::Found(record) if before == stamp() => {
                if record.index_generation == generation && record_digest(&record) == content {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(&path)?;
                    if Some(Stamp::of(&file.metadata()?)) != before {
                        return Err(io::Error::other("survivor changed"));
                    }
                    file.sync_all()?;
                    true
                } else if prior.is_some() && before == prior && record.format == FORMAT_VERSION {
                    if stamp() != before {
                        return Err(io::Error::other("predecessor changed"));
                    }
                    remove_if_present(&path)?;
                    false
                } else {
                    return Err(io::Error::other("unadjudicated survivor"));
                }
            }
            ReadOutcome::Missing if before.is_none() && self.disabled.is_none() => false,
            _ => return Err(io::Error::other("unverified survivor")),
        };
        self.sync_store()?;
        if (receipted && stamp() != before)
            || (!receipted
                && !fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
        {
            return Err(io::Error::other("survivor changed"));
        }
        self.pending.remove(key);
        if receipted {
            self.counters.receipt_reconciled += 1;
        } else {
            self.counters.durable_write_failed_published += 1;
        }
        Ok(receipted)
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

    /// Only a fully verified original binding may authorize a Claude mutation.
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
            || record.record.binding.entry != expected.binding.entry
            || record.index_generation > expected.committed_generation
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
            content: digest,
            stamp: *stamp,
            format: record.format,
            generation: record.index_generation,
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
        self.revoke(&record.record.binding.key);
        if record.eligible(expected).is_err()
            || record.record.binding.entry != expected.binding.entry
            || record.index_generation > expected.committed_generation
            || proof.key != record.record.binding.key
            || proof.format != record.format
            || proof.generation != record.index_generation
            || proof.content != record_digest(record)
            || !self.witness_current(proof)
        {
            return;
        }
        if self.durable.len() >= MAX_RECORDS && !self.durable.contains_key(&proof.key) {
            let Some(key) = self
                .durable
                .iter()
                .find_map(|(k, (_, _, allowed))| (!allowed).then_some(*k))
            else {
                return;
            };
            self.durable.remove(&key); // Never evict a current mutation permission.
        }
        self.durable
            .insert(proof.key, (Some(proof.content), proof.stamp, true));
    }
    fn authorized(&mut self, key: &Digest32) -> bool {
        let allowed = self.source != DurableSource::ClaudeCode
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
    /// Each record syncs the store and parent; ambiguous outcomes stay pending.
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
        // The caller's bodies stay live for the whole batch.
        let pending_bytes = pending
            .iter()
            .map(|record| record.body.len())
            .sum::<usize>();
        for record in pending {
            if matches!(
                self.rebuilt.get(&record.binding.key),
                Some(Rebuild::Authorized | Rebuild::NotReplaced)
            ) {
                continue;
            }
            if self.pending.contains_key(&record.binding.key)
                && self.reconcile_pending(writer, &record.binding.key).is_err()
            {
                let stamp = fs::symlink_metadata(self.record_path(&record.binding.key))
                    .ok()
                    .map(|m| Stamp::of(&m));
                let same = self
                    .pending
                    .get(&record.binding.key)
                    .is_some_and(|(prior, ..)| prior.is_some() && *prior == stamp);
                if !(same
                    && matches!(
                        self.classify(&record.binding.key, "overwrite", Some(writer)),
                        Err(Refusal::Corrupt)
                    ))
                {
                    receipt.deferred_keys.push(record.binding.key);
                    continue;
                }
            }
            // A rebuild may replace its corrupt predecessor once, after save.
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
                    Ok(Some(_)) if !self.authorized(&record.binding.key) => continue,
                    Ok(Some(old)) => (old.stamp, old.content),
                    Ok(None) => (None, None),
                };
            let content = content_digest(&record);
            if previous_content == Some(content) {
                receipt.clean += 1;
            } else {
                dirty.push((record, content, prior));
            }
        }
        if !self.usable(Some(writer)) {
            return Ok(BatchReceipt::default());
        }
        if dirty.is_empty() {
            self.counters.records_clean += receipt.clean as u64;
            return Ok(receipt);
        }
        ensure_private_dir(&self.dir).inspect_err(|_| self.counters.store_write_failed[0] += 1)?;
        self.checked = false;
        if !self.usable(Some(writer)) {
            return Ok(receipt);
        }
        let (mut on_disk, mut unlisted) = self
            .scan_disk()
            .inspect_err(|_| self.counters.store_write_failed[1] += 1)?;
        let mut attempted = 0;
        for (record, content, prior) in dirty {
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
            if !on_disk.contains_key(&key)
                && on_disk.len() as u64 + unlisted[0] >= INVENTORY_BOUND as u64
            {
                self.counters.store_write_skipped[1] += 1;
                receipt.deferred_keys.push(key);
                continue;
            }
            let stored = DurableRecord {
                envelope_audit_debt: record.certificate.audit_debt_unix_seconds,
                record,
                index_generation: committed_generation,
                format: self.source.properties().format,
            };
            if stored.record.body.len() > BODY_BYTES {
                // Preserve the verified predecessor until an ordinary
                // replacement succeeds, including on budget refusal.
                self.durable.remove(&key);
                receipt.budget_refused += 1;
                continue;
            }
            let bytes = encode(&stored);
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
                self.disable("obligation_overflow");
                break;
            }
            if ack_bytes != 0 {
                receipt
                    .committed
                    .get_or_insert_with(|| Box::new([None; MAX_BATCH]));
            }
            attempted += 1;
            self.pending
                .insert(key, (prior, committed_generation, content, 0));
            if write_atomic(&self.dir, &path, &bytes, prior)
                .and_then(|_| self.sync_store())
                .is_err()
            {
                match self.reconcile_pending(writer, &key) {
                    Ok(true) => {}
                    Ok(false) => {
                        on_disk.remove(&key);
                        continue;
                    }
                    Err(_) => {
                        self.counters.receipt_pending_held += 1;
                        receipt.deferred_keys.push(key);
                        continue;
                    }
                }
            } else {
                self.pending.remove(&key);
            }
            self.rebuilt.remove(&key);
            on_disk.insert(key, bytes.len() as u64);
            let stamp = Stamp::of(&fs::symlink_metadata(&path)?);
            if self.durable.len() < MAX_RECORDS || self.durable.contains_key(&key) {
                self.durable.insert(key, (Some(content), stamp, true));
            }
            if let Some(acks) = receipt.committed.as_mut() {
                acks[receipt.written] = Some((key, content, stamp));
            }
            receipt.written += 1;
            receipt.bytes_written += bytes.len() as u64;
            self.counters.max_record_bytes = self.counters.max_record_bytes.max(bytes.len() as u64);
        }
        self.counters.batches += 1;
        self.counters.records_written += receipt.written as u64;
        self.counters.records_clean += receipt.clean as u64;
        self.counters.records_deferred += receipt.deferred as u64;
        self.counters.budget_refused += receipt.budget_refused as u64;
        self.counters.bytes_written += receipt.bytes_written;
        self.set_disk_level(&on_disk, unlisted);
        Ok(receipt)
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
        self.check_writer(writer)?;
        if !self.usable(Some(writer)) {
            return Ok(());
        }
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
        let mut seen = 0_usize;
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
            seen += 1;
            let len = entry.metadata().map_or(0, |m| m.len());
            if seen > INVENTORY_BOUND {
                self.counters.uninventoried_records += 1;
                unlisted_bytes += len;
                continue;
            }
            if self.pending.contains_key(&key) {
                on_disk.insert(key, len);
                continue;
            }
            let verdict = match self.classify(&key, "delete", Some(writer)) {
                Ok(Some(_)) if !self.authorized(&key) => Some(len),
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
                            Some(Some(scope)) => *scope == binding.scope,
                            Some(None) => true,
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
                    remove_if_present(&path)?;
                    self.durable.remove(&key);
                    self.counters.gc_records_deleted += 1;
                    deleted = true;
                }
            }
        }
        self.durable.retain(|key, _| on_disk.contains_key(key));
        if deleted {
            self.sync_store()?;
        }
        self.set_disk_level(
            &on_disk,
            [self.counters.uninventoried_records, unlisted_bytes],
        );
        Ok(())
    }

    /// The record keys on disk now, at most `INVENTORY_BOUND`: GC's caller
    /// looks up only these keys, never materializing the whole index.
    pub(crate) fn inventory(&self) -> io::Result<BTreeSet<Digest32>> {
        if self.disabled.is_some() {
            return Ok(BTreeSet::new());
        }
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
            {
                keys.insert(key);
                if keys.len() >= INVENTORY_BOUND {
                    break;
                }
            }
        }
        Ok(keys)
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
            if !self.pending.contains_key(key)
                && matches!(self.classify(key, "delete", Some(writer)), Ok(Some(_)))
                && self.authorized(key)
            {
                remove_if_present(&path)?;
                removed += 1;
            }
            self.durable.remove(key);
        }
        if removed > 0 {
            self.sync_store()?;
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
            if on_disk.len() < INVENTORY_BOUND {
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

/// What makes a record dirty: everything but the generation stamp, so a
/// later save of an unchanged entry rewrites nothing.
/// Hashes the header and the body in place: no copy of the body (its only
/// scratch is the `HEADER_BYTES` header).
fn content_digest(record: &PendingRecord) -> Digest32 {
    let mut header = Vec::with_capacity(HEADER_BYTES);
    encode_header(&mut header, record, 0);
    content_digest_parts(&header, &record.body)
}

fn content_digest_parts(header: &[u8], body: &[u8]) -> Digest32 {
    digest("ottto-dt-content:v2", &[header, body])
}

/// Memo the verified STORED representation, not the decoded certificate
/// whose compatibility debt was dropped.
fn stored_digest(bytes: &[u8]) -> Digest32 {
    let mut header = [0; HEADER_BYTES];
    header.copy_from_slice(&bytes[..HEADER_BYTES]);
    header[171..179].fill(0); // committed generation is not content
    content_digest_parts(&header, &bytes[HEADER_BYTES..bytes.len() - TRAILER_BYTES])
}

/// `stored_digest` of a decoded record: its envelope debt goes back into the
/// header (debt tag, due, then the body length end it).
fn record_digest(stored: &DurableRecord) -> Digest32 {
    let mut header = Vec::with_capacity(HEADER_BYTES);
    encode_header(&mut header, &stored.record, 0);
    let debt = HEADER_BYTES - 12;
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

fn parse_hex_digest(text: &str) -> Option<Digest32> {
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
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
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
    let available = (stat.f_bavail as u64).checked_mul(stat.f_frsize);
    let volume = (stat.f_blocks as u64).checked_mul(stat.f_frsize);
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

/// `Ok(None)` when absent. Refuses a non-regular file, a file readable by
/// group or others, and a file over the record bound.
fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    #[cfg(test)]
    if let Err(error) = test_hooks::before_access(path, "restore_open") {
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(test)]
    test_hooks::before_access(path, "restore_metadata")?;
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "durable store record not owner-only",
        ));
    }
    if !metadata.is_file() || metadata.len() > (RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES) as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unusable durable store record",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(metadata.len()).read_to_end(&mut bytes)?;
    Ok(Some(bytes))
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
    let Some((record, pid)) = name.and_then(|n| n.rsplit_once('.')) else {
        return false;
    };
    let pid = pid.parse::<i32>().ok().filter(|pid| *pid > 0);
    let named = record
        .strip_suffix(RECORD_SUFFIX)
        .and_then(parse_hex_digest);
    // This process's temps are orphans too: GC holds the store exclusively.
    let ours = pid.is_some_and(|pid| pid.unsigned_abs() == std::process::id());
    // SAFETY: signal zero only probes the process; it sends no signal.
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
}
fn decode_header(bytes: &[u8], key: &Digest32, source: DurableSource) -> Result<Header, Refusal> {
    let mut c = Cursor(bytes);
    if c.array::<8>() != Some(MAGIC) {
        return Err(Refusal::Undecodable);
    }
    let format = c.u16().ok_or(Refusal::Undecodable)?;
    if format > FORMAT_VERSION {
        return Err(Refusal::NewerFormat);
    }
    let allowlist = c.array::<32>().ok_or(Refusal::Undecodable)?;
    let tag = c.u8().ok_or(Refusal::Undecodable)?;
    let admitted = DurableSource::from_tag(tag).ok_or(Refusal::Unknown)?;
    let row = admitted.properties();
    if format != row.format || Some(allowlist) != parse_hex_digest(row.allowlist_pin) {
        return Err(Refusal::Unknown);
    }
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
            },
            generation,
            format,
            body_len: c.u32()? as usize,
            audit_debt: None,
            stamp: None,
            content: None,
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
    let start = HEADER_BYTES;
    if end.checked_sub(start) != Some(h.body_len) {
        return Err(bad);
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

/// Temp file (create-new, 0600), write, fsync, rename. The caller syncs the
/// directory and its parent before issuing a receipt.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8], prior: Option<Stamp>) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "record name"))?;
    let temp = dir.join(format!(".{name}.{}{TEMP_SUFFIX}", std::process::id()));
    remove_if_present(&temp)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(test)]
        test_hooks::before_rename(&temp, path)?;
        let actual = match fs::symlink_metadata(path) {
            Ok(metadata) => Some(Stamp::of(&metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if actual != prior {
            return Err(io::Error::other("predecessor changed"));
        }
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
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
    let mut out = Vec::with_capacity(HEADER_BYTES + record.record.body.len() + TRAILER_BYTES);
    encode_parts(&mut out, &record.record, record.index_generation);
    let trailer: Digest32 = Sha256::digest(&out).into();
    out.extend_from_slice(&trailer);
    out
}

fn encode_parts(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    encode_header(out, record, generation);
    out.extend_from_slice(&record.body);
}

/// Everything before the body, ending with the body length: exactly
/// `HEADER_BYTES`.
fn encode_header(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    let binding = &record.binding;
    let certificate = &record.certificate;
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&binding.source.properties().format.to_le_bytes());
    out.extend_from_slice(&record.allowlist);
    out.push(binding.source.tag());
    for part in [
        &binding.key,
        &binding.context,
        &binding.scope,
        &binding.entry,
    ] {
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&generation.to_le_bytes());
    for value in [certificate.device, certificate.inode, certificate.length] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&certificate.modified.0.to_le_bytes());
    out.extend_from_slice(&certificate.modified.1.to_le_bytes());
    out.extend_from_slice(&certificate.birth_nanos.to_le_bytes());
    out.extend_from_slice(&certificate.sealed_offset.to_le_bytes());
    out.extend_from_slice(&certificate.sample_len.to_le_bytes());
    out.extend_from_slice(&certificate.head_sha256);
    out.extend_from_slice(&certificate.boundary_sha256);
    out.extend_from_slice(&certificate.verified_unix_seconds.to_le_bytes());
    out.push(u8::from(certificate.audit_debt_unix_seconds.is_some()));
    out.extend_from_slice(
        &certificate
            .audit_debt_unix_seconds
            .unwrap_or(0)
            .to_le_bytes(),
    );
    out.extend_from_slice(&(record.body.len() as u32).to_le_bytes());
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
    h.record.body = bytes[HEADER_BYTES..bytes.len() - TRAILER_BYTES].to_vec();
    Ok(DurableRecord {
        record: h.record,
        index_generation: h.generation,
        format: h.format,
        envelope_audit_debt: h.audit_debt,
    })
}

/// Test-only filesystem faults and deterministic GC ordering.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;
    use std::io;
    use std::path::Path;

    type Hook = Box<dyn FnMut(&Path, &Path) -> io::Result<()>>;
    type DirHook = Box<dyn FnMut(&Path) -> io::Result<()>>;
    type AccessHook = Box<dyn FnMut(&Path, &str) -> io::Result<()>>;

    thread_local! {
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
        BEFORE_RENAME.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(temp, path),
            None => Ok(()),
        })
    }
    pub(super) fn before_dir_sync(dir: &Path) -> io::Result<()> {
        BEFORE_DIR_SYNC.with(|slot| match slot.borrow_mut().as_mut() {
            Some(hook) => hook(dir),
            None => Ok(()),
        })
    }
}

#[cfg(test)]
#[path = "durable_tail_store_tests.rs"]
pub(crate) mod tests;
