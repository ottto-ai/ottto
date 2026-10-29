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
//!   directory fsync per batch. A torn, truncated or flipped record fails its
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

/// Envelope format. Bump on any envelope or certificate layout change.
pub(crate) const FORMAT_VERSION: u16 = 1;
const MAGIC: [u8; 8] = *b"ottto-dt";
/// One record never exceeds the RAM cache's per-entry bound
/// (`transcript_cache::ENTRY_BYTES`): the store keeps only what RAM can.
pub(crate) const RECORD_BYTES: usize = crate::transcript_cache::ENTRY_BYTES;
/// At most as many records as the RAM cache has entries.
pub(crate) const MAX_RECORDS: usize = crate::transcript_cache::CACHE_ENTRIES;
/// The store's own disk cap, stated separately from any RAM bound.
pub(crate) const STORE_BYTES: u64 = 32 * 1024 * 1024;
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

/// The sources M1 keeps. Pi is never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DurableSource {
    ClaudeCode,
    Codex,
}
impl DurableSource {
    fn tag(self) -> u8 {
        match self {
            Self::ClaudeCode => 1,
            Self::Codex => 2,
        }
    }
    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::ClaudeCode),
            2 => Some(Self::Codex),
            _ => None,
        }
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
pub(crate) fn scope_digest(
    file_scope: &str,
    allowlist: &Digest32,
    identity_contract: &str,
    counting_view: &str,
) -> Digest32 {
    digest(
        "ottto-dt-scope:v1",
        &[
            file_scope.as_bytes(),
            FORMAT_VERSION.to_le_bytes().as_slice(),
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
}

/// Preservation classes: unknown representations (U) precede known corruption (T14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    NewerFormat,
    Unknown,
    Undecodable,
    Unbindable,
    Corrupt,
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
        } else if self.index_generation > expected.committed_generation {
            Err(Ineligible::GenerationAhead)
        } else if have.entry != want.entry {
            Err(Ineligible::EntryChanged)
        } else {
            Ok(())
        }
    }
}

/// Content-free counts for the budget receipts. One pass is one restore
/// read phase or one post-save write phase; `take_pass` resets them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// Budget refusals: a record over `RECORD_BYTES` or a store over
    /// `STORE_BYTES`. The entry is Full after restart.
    pub(crate) budget_refused: u64,
    /// Per-pass read I/O.
    pub(crate) bytes_read: u64,
    pub(crate) records_read: u64,
    pub(crate) missing: u64,
    pub(crate) format_hold: [u64; 5],
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
}

/// One store directory. The in-RAM map of last durable content digests
/// decides dirtiness, so a clean record is never rewritten.
pub(crate) struct DurableTailStore {
    dir: PathBuf,
    source: DurableSource,
    durable: BTreeMap<Digest32, (Option<Digest32>, Stamp)>,
    counters: StoreCounters,
    /// The store-level fault that made this store memory-only for the process.
    disabled: Option<&'static str>,
    /// This pass: directory checked and [records loaded, T14 rebuilds].
    checked: bool,
    pass: [u64; 2],
    /// Process-lifetime attempts, removed only after a successful replacement.
    rebuilt: BTreeMap<Digest32, Rebuild>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rebuild {
    Authorized,  // Scheduling deferral has not spent the Full allowance.
    Started,     // The rebuild may offer its own replacement after save.
    Offered,     // Started and included in this post-save batch's pending records.
    NotReplaced, // Memory-only with RAM; otherwise a census-safe hold.
}

/// The most record files one GC or inventory pass looks at. Twice the
/// admission cap, so a full store plus its replacements always fits; any
/// file past it is left untouched and counted.
pub(crate) const INVENTORY_BOUND: usize = 2 * MAX_RECORDS;
/// T14 rebuilds one pass allows before the store is disabled: more than
/// `max(T14_BREAKER, 2% of the records loaded)`.
pub(crate) const T14_BREAKER: u64 = 20;
const REBUILT_BOUND: usize = 64;
// A memo entry stays within the 128 bytes per record `STORES_RESIDENT_BOUND` charges.
const _: () = assert!(std::mem::size_of::<(Digest32, (Option<Digest32>, Stamp))>() <= 128);

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
        }
    }

    /// A new pass: the directory is checked again and the T14 breaker resets.
    pub(crate) fn begin_pass(&mut self) {
        self.checked = false;
        self.pass = [0; 2];
    }

    pub(crate) fn disabled(&self) -> Option<&'static str> {
        self.disabled
    }

    fn disable(&mut self, cause: &'static str) {
        if self.disabled.is_none() {
            self.disabled = Some(cause);
        }
        self.durable.clear();
    }

    /// The store-level check, once per pass: a directory we own gets 0700
    /// back; anything else disables the store (absent is fine).
    fn usable(&mut self) -> bool {
        if !self.checked && self.disabled.is_none() {
            self.checked = true;
            match inspect_path(&self.dir) {
                Ok(metadata) if !metadata.is_dir() => self.disable("not_directory"),
                Ok(metadata) => {
                    self.repair(&self.dir.clone(), &metadata, 0o700);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => self.disable("directory_access"),
            }
        }
        self.disabled.is_none()
    }

    /// Our own entry gets `mode` back (counted); a foreign owner or a failed
    /// repair disables the store.
    fn repair(&mut self, path: &Path, metadata: &fs::Metadata, mode: u32) -> bool {
        if metadata.uid() != our_uid() {
            self.disable("foreign_owner");
        } else if metadata.permissions().mode() & 0o777 != mode {
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

    pub(crate) fn counters(&self) -> StoreCounters {
        self.counters
    }

    /// The counters since the last call, which resets them. The disk totals
    /// are a level, not a flow, and are kept.
    #[cfg(test)]
    pub(crate) fn take_pass(&mut self) -> StoreCounters {
        let pass = self.counters;
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
    fn classify(&mut self, key: &Digest32, work: &str) -> Result<Option<Binding>, Refusal> {
        if !self.usable() {
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
                        Ok(m) => m.is_file() && self.repair(&path, &m, 0o600),
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
            if !self.repair(&path, &metadata, 0o600) {
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
            self.counters.guard_header_bytes += n as u64;
            let binding = decode_header(&header, key, self.source)?;
            // After any repair: its ctime moved.
            let Some(metadata) = self.inspect_file(&file) else {
                return Ok(None);
            };
            let stamp = Stamp::of(&metadata);
            if !metadata.is_file()
                || metadata.len() > (RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES) as u64
            {
                return Err(Refusal::Corrupt);
            }
            if self.durable.get(key).is_some_and(|(_, old)| *old == stamp) {
                return Ok(Some(binding));
            }
            #[cfg(test)]
            test_hooks::before_access(&path, "body")
                .map_err(|e| self.read_failure(e, Refusal::Corrupt))?;
            let mut bytes = header;
            file.take((RECORD_BYTES + TRAILER_BYTES + 1) as u64)
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
            if self.durable.len() < MAX_RECORDS || self.durable.contains_key(key) {
                self.durable.insert(*key, (None, stamp));
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
    pub(crate) fn hold(&mut self, key: &Digest32) -> Option<Refusal> {
        let result = self.classify(key, "guard");
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
                None
            }
            Err(Refusal::Corrupt) if self.rebuilt[key] == Rebuild::Authorized => None,
            Ok(_) => None,
            Err(reason) => Some(reason),
        }
    }

    pub(crate) fn full_hold(&mut self, key: &Digest32, start: bool) -> Option<Refusal> {
        let held = self.hold(key);
        if start
            && held.is_none()
            && self.disabled.is_none()
            && self.rebuilt.get(key) == Some(&Rebuild::Authorized)
        {
            self.rebuilt.insert(*key, Rebuild::Started);
            self.counters.t14_rebuild_full_started += 1;
        }
        held
    }

    pub(crate) fn read(&mut self, key: &Digest32, allowlist: &Digest32) -> ReadOutcome {
        match self.classify(key, "guard") {
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
        match decode(&bytes, allowlist) {
            Ok(record) => {
                if let Some((content, _)) = self.durable.get_mut(key) {
                    *content = Some(content_digest(&record.record));
                }
                ReadOutcome::Found(Box::new(record))
            }
            Err(reason) => ReadOutcome::Refused(reason),
        }
    }

    /// The post-save write. Call only after `ScanIndex::save` succeeded, with
    /// that save's committed generation and only entries that save kept.
    /// Clean records (same content as the last durable write) are skipped;
    /// at most `MAX_BATCH` dirty records are written, the rest are deferred.
    /// One directory fsync covers the batch.
    pub(crate) fn write_after_save<W: SingleWriter>(
        &mut self,
        writer: &W,
        committed_generation: u64,
        pending: Vec<PendingRecord>,
    ) -> io::Result<BatchReceipt> {
        // A paused rebuild absent from pending must survive this save.
        for record in &pending {
            if self.rebuilt.get(&record.binding.key) == Some(&Rebuild::Started) {
                self.rebuilt.insert(record.binding.key, Rebuild::Offered);
            }
        }
        let result = self.write_batch(writer, committed_generation, pending);
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
        pending: Vec<PendingRecord>,
    ) -> io::Result<BatchReceipt> {
        self.check_writer(writer)?;
        let mut receipt = BatchReceipt::default();
        let mut dirty = Vec::new();
        if !self.usable() {
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
            // A rebuild may replace its corrupt predecessor once, after save.
            let corrupt = match self.classify(&record.binding.key, "overwrite") {
                Err(Refusal::Corrupt) => true,
                Err(_) => {
                    self.counters.store_write_skipped[0] += 1;
                    continue;
                }
                Ok(_) => false,
            };
            let content = content_digest(&record);
            if self
                .durable
                .get(&record.binding.key)
                .is_some_and(|(old, _)| *old == Some(content))
            {
                receipt.clean += 1;
            } else {
                dirty.push((record, content, corrupt));
            }
        }
        if !self.usable() {
            return Ok(BatchReceipt::default());
        }
        if dirty.is_empty() {
            self.counters.records_clean += receipt.clean as u64;
            return Ok(receipt);
        }
        ensure_private_dir(&self.dir)?;
        let (mut on_disk, mut unlisted) = self.scan_disk()?;
        let mut changed = false;
        for (record, content, corrupt) in dirty {
            if receipt.written + receipt.budget_refused >= MAX_BATCH {
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
                && on_disk.len() as u64 + unlisted[0] > INVENTORY_BOUND as u64
            {
                self.counters.store_write_skipped[1] += 1;
                receipt.deferred_keys.push(key);
                continue;
            }
            let stored = DurableRecord {
                record,
                index_generation: committed_generation,
            };
            let bytes = encode(&stored);
            self.note_codec(pending_bytes + bytes.capacity());
            let previous = on_disk.get(&key).copied().unwrap_or(0);
            let total = on_disk
                .values()
                .sum::<u64>()
                .saturating_add(unlisted[1])
                .saturating_sub(previous)
                .saturating_add(bytes.len() as u64);
            if bytes.len() > RECORD_BYTES
                || total > STORE_BYTES
                || (previous == 0 && on_disk.len() >= MAX_RECORDS)
            {
                // A stale record for this key would bind to an older entry
                // only; drop it so the refusal costs no disk. A T14 record
                // stays until a rebuild replaces it.
                if previous != 0 && !corrupt {
                    remove_if_present(&path)?;
                    on_disk.remove(&key);
                    changed = true;
                }
                self.durable.remove(&key);
                receipt.budget_refused += 1;
                continue;
            }
            write_atomic(&self.dir, &path, &bytes)?;
            self.rebuilt.remove(&key);
            changed = true;
            on_disk.insert(key, bytes.len() as u64);
            let stamp = Stamp::of(&fs::symlink_metadata(&path)?);
            if self.durable.len() < MAX_RECORDS || self.durable.contains_key(&key) {
                self.durable.insert(key, (Some(content), stamp));
            }
            receipt.written += 1;
            receipt.bytes_written += bytes.len() as u64;
            self.counters.max_record_bytes = self.counters.max_record_bytes.max(bytes.len() as u64);
        }
        if changed {
            sync_dir(&self.dir)?;
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
        _allowlist: &Digest32,
        keep: &BTreeMap<Digest32, Option<Digest32>>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        if !self.usable() {
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
            self.counters.gc_records_read += 1;
            self.counters.gc_bytes_read += HEADER_BYTES as u64;
            let verdict = match self.classify(&key, "delete") {
                Ok(Some(binding)) => {
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
            sync_dir(&self.dir)?;
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
        if !self.usable() {
            return Ok(0);
        }
        for key in keys {
            let path = self.record_path(key);
            if matches!(self.classify(key, "delete"), Ok(Some(_))) {
                remove_if_present(&path)?;
                removed += 1;
            }
            self.durable.remove(key);
        }
        if removed > 0 {
            sync_dir(&self.dir)?;
            self.counters.records_invalidated += removed as u64;
            let (on_disk, unlisted) = self.scan_disk()?;
            self.set_disk_level(&on_disk, unlisted);
        }
        Ok(removed)
    }

    fn check_writer<W: SingleWriter>(&self, writer: &W) -> io::Result<()> {
        if self.dir.starts_with(writer.state_dir()) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable store is outside the locked state directory",
            ))
        }
    }

    /// Record files and their sizes, as on disk now: the first
    /// `INVENTORY_BOUND` by key, the rest only counted and summed.
    fn scan_disk(&self) -> io::Result<(BTreeMap<Digest32, u64>, [u64; 2])> {
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
    digest(
        "ottto-dt-content:v2",
        &[header.as_slice(), record.body.as_slice()],
    )
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
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // `mkdir` masks the mode with the umask; pin it.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
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
        .custom_flags(libc::O_NOFOLLOW)
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp(u64);
impl Stamp {
    /// Process-local memo key over (dev, ino, size, mtime, ctime).
    fn of(m: &fs::Metadata) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        [m.dev(), m.ino(), m.len()].hash(&mut hasher);
        [m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()].hash(&mut hasher);
        Self(hasher.finish())
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

fn decode_header(header: &[u8], key: &Digest32, source: DurableSource) -> Result<Binding, Refusal> {
    let mut c = Cursor(header);
    if c.array::<8>() != Some(MAGIC) {
        return Err(Refusal::Undecodable);
    }
    let version = c.u16().ok_or(Refusal::Undecodable)?;
    if version > FORMAT_VERSION {
        return Err(Refusal::NewerFormat);
    }
    if version != FORMAT_VERSION {
        return Err(Refusal::Unknown);
    }
    let allowlist = c.array::<32>().ok_or(Refusal::Undecodable)?;
    let tag = c.u8().ok_or(Refusal::Undecodable)?;
    // Both pinned v1 writers (72205c6c and 4f143c16/ffc6c846) have these same lists.
    let pin = match tag {
        1 => "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
        2 => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
        _ => return Err(Refusal::Unknown),
    };
    if Some(allowlist) != parse_hex_digest(pin) {
        return Err(Refusal::Unknown);
    }
    let binding = (|| {
        Some(Binding {
            source: DurableSource::from_tag(tag)?,
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
    Ok(binding)
}

fn verify(bytes: &[u8], source: DurableSource) -> Result<(), Refusal> {
    let bad = Refusal::Corrupt;
    if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
        return Err(bad);
    }
    let end = bytes.len() - TRAILER_BYTES;
    // Trailer FIRST: structural duplicate checks on unsorted maps/sets can be quadratic.
    if bytes[end..] != Sha256::digest(&bytes[..end])[..] {
        return Err(bad);
    }
    let mut c = Cursor(&bytes[HEADER_BYTES - 4..HEADER_BYTES]);
    if c.u32().map(|n| n as usize) != Some(end - HEADER_BYTES) {
        return Err(bad);
    }
    let debt = HEADER_BYTES - 4 - 9;
    if !matches!(bytes[debt], 0 | 1) || (bytes[debt] == 0 && bytes[debt + 1..debt + 9] != [0; 8]) {
        return Err(bad);
    }
    crate::snapshots::verify_durable_body(&bytes[HEADER_BYTES..end], source)
        .then_some(())
        .ok_or(bad)
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Temp file (create-new, 0600), write, fsync, rename. The caller syncs the
/// directory once per batch.
fn write_atomic(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
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
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(test)]
        test_hooks::before_rename(&temp, path)?;
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
    File::open(dir)?.sync_all()
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
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
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
fn decode(bytes: &[u8], allowlist: &Digest32) -> Result<DurableRecord, Refusal> {
    let source = bytes
        .get(42)
        .and_then(|tag| DurableSource::from_tag(*tag))
        .ok_or(Refusal::Undecodable)?;
    let key: Digest32 = bytes
        .get(43..75)
        .and_then(|b| b.try_into().ok())
        .ok_or(Refusal::Undecodable)?;
    decode_header(bytes, &key, source)?;
    verify(bytes, source)?;
    let body_end = bytes.len() - TRAILER_BYTES;
    let mut cursor = Cursor(&bytes[10..body_end]);
    let record_allowlist = cursor.array::<32>().ok_or(Refusal::Corrupt)?;
    let decoded = (|| {
        let source = DurableSource::from_tag(cursor.u8()?)?;
        let binding = Binding {
            source,
            key: cursor.array()?,
            context: cursor.array()?,
            scope: cursor.array()?,
            entry: cursor.array()?,
        };
        let index_generation = cursor.u64()?;
        let certificate = DurableCertificate {
            device: cursor.u64()?,
            inode: cursor.u64()?,
            length: cursor.u64()?,
            modified: (cursor.i64()?, cursor.i64()?),
            birth_nanos: cursor.u64()?,
            sealed_offset: cursor.u64()?,
            sample_len: cursor.u32()?,
            head_sha256: cursor.array()?,
            boundary_sha256: cursor.array()?,
            verified_unix_seconds: cursor.u64()?,
            audit_debt_unix_seconds: {
                let present = cursor.u8()?;
                let due = cursor.u64()?;
                match present {
                    0 if due == 0 => None,
                    1 => Some(due),
                    _ => return None,
                }
            },
        };
        let body_len = cursor.u32()? as usize;
        let body = cursor.take(body_len)?.to_vec();
        cursor.0.is_empty().then_some(DurableRecord {
            record: PendingRecord {
                binding,
                certificate,
                body,
                allowlist: record_allowlist,
            },
            index_generation,
        })
    })();
    let record = decoded.ok_or(Refusal::Corrupt)?;
    if record_allowlist != *allowlist {
        return Err(Refusal::Unknown);
    }
    Ok(record)
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
        static BEFORE_RENAME: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_DIR_SYNC: RefCell<Option<DirHook>> = const { RefCell::new(None) };
        static BEFORE_ACCESS: RefCell<Option<AccessHook>> = const { RefCell::new(None) };
        static RECORDS_FIRST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
mod tests;
