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
//! - A newer format is ignored and kept (downgrade ignores); an older format
//!   or a changed field allowlist is refused and garbage collected.
//! - No local path, transcript text, raw sample or raw identifier enters a
//!   record envelope: the index key and the entry selection are digests, and
//!   the certificate is content-free (`DurableCertificate`). Nothing here is
//!   uploaded.
//! - Writes and GC require the state-directory single-writer lock
//!   (`SingleWriter`); this layer adds no lock of its own.
#![cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.

use crate::transcript_acquisition::DurableCertificate;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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
const HEADER_BYTES: usize = 8 // magic
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

/// The single-writer seam. The state-directory lock (#801's `StateDirLock`)
/// implements it; nothing else may. A second daemon cannot take the lock,
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

/// The SHA-256 of a codec's compiled field list, in order. A changed list
/// refuses every older record (`Refusal::AllowlistChanged`).
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

/// Why a stored record cannot be used at all, before any binding check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Short, torn, bad magic, bad trailer or undecodable: GC deletes it.
    Corrupt,
    /// Written by a newer binary. Ignored and kept (downgrade ignores).
    NewerFormat,
    /// Written by an older binary: dropped.
    OlderFormat,
    /// Written under another codec field list: dropped.
    AllowlistChanged,
    /// Over `RECORD_BYTES`, not a regular file, or not owner-only.
    Unusable,
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
    pub(crate) refused_corrupt: u64,
    pub(crate) refused_newer: u64,
    pub(crate) refused_older: u64,
    pub(crate) refused_allowlist: u64,
    pub(crate) refused_unusable: u64,
    /// GC deletions: records and stale temp files.
    pub(crate) gc_records_deleted: u64,
    pub(crate) gc_temps_deleted: u64,
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
    durable: BTreeMap<Digest32, Digest32>,
    counters: StoreCounters,
}

impl DurableTailStore {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            durable: BTreeMap::new(),
            counters: StoreCounters::default(),
        }
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn counters(&self) -> StoreCounters {
        self.counters
    }

    /// The counters since the last call, which resets them. The disk totals
    /// are a level, not a flow, and are kept.
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

    /// Read one key. A refused record is reported, never repaired here; GC
    /// owns deletion.
    pub(crate) fn read(&mut self, key: &Digest32, allowlist: &Digest32) -> ReadOutcome {
        let path = self.record_path(key);
        let bytes = match read_private(&path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                self.counters.missing += 1;
                return ReadOutcome::Missing;
            }
            Err(_) => {
                self.counters.refused_unusable += 1;
                return ReadOutcome::Refused(Refusal::Unusable);
            }
        };
        self.counters.records_read += 1;
        self.counters.bytes_read += bytes.len() as u64;
        self.counters.max_record_bytes = self.counters.max_record_bytes.max(bytes.len() as u64);
        self.note_codec(bytes.capacity());
        match decode(&bytes, allowlist) {
            Ok(record) if record.record.binding.key == *key => {
                // A valid record on disk is the durable content for its key.
                self.durable.insert(*key, content_digest(&record.record));
                ReadOutcome::Found(Box::new(record))
            }
            Ok(_) => {
                self.counters.refused_corrupt += 1;
                ReadOutcome::Refused(Refusal::Corrupt)
            }
            Err(refusal) => {
                match refusal {
                    Refusal::Corrupt => self.counters.refused_corrupt += 1,
                    Refusal::NewerFormat => self.counters.refused_newer += 1,
                    Refusal::OlderFormat => self.counters.refused_older += 1,
                    Refusal::AllowlistChanged => self.counters.refused_allowlist += 1,
                    Refusal::Unusable => self.counters.refused_unusable += 1,
                }
                ReadOutcome::Refused(refusal)
            }
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
        self.check_writer(writer)?;
        let mut receipt = BatchReceipt::default();
        let mut dirty = Vec::new();
        for record in pending {
            let content = content_digest(&record);
            if self.durable.get(&record.binding.key) == Some(&content) {
                receipt.clean += 1;
            } else {
                dirty.push((record, content));
            }
        }
        if dirty.is_empty() {
            self.counters.records_clean += receipt.clean as u64;
            return Ok(receipt);
        }
        ensure_private_dir(&self.dir)?;
        let mut on_disk = self.scan_disk()?;
        let mut changed = false;
        for (record, content) in dirty {
            if receipt.written + receipt.budget_refused >= MAX_BATCH {
                receipt.deferred += 1;
                receipt.deferred_keys.push(record.binding.key);
                continue;
            }
            let key = record.binding.key;
            let path = self.record_path(&key);
            let stored = DurableRecord {
                record,
                index_generation: committed_generation,
            };
            let bytes = encode(&stored);
            self.note_codec(bytes.capacity());
            let previous = on_disk.get(&key).copied().unwrap_or(0);
            let total = on_disk
                .values()
                .sum::<u64>()
                .saturating_sub(previous)
                .saturating_add(bytes.len() as u64);
            if bytes.len() > RECORD_BYTES
                || total > STORE_BYTES
                || (previous == 0 && on_disk.len() >= MAX_RECORDS)
            {
                // A stale record for this key would bind to an older entry
                // only; drop it so the refusal costs no disk.
                if previous != 0 {
                    remove_if_present(&path)?;
                    on_disk.remove(&key);
                    changed = true;
                }
                self.durable.remove(&key);
                receipt.budget_refused += 1;
                continue;
            }
            write_atomic(&self.dir, &path, &bytes)?;
            changed = true;
            on_disk.insert(key, bytes.len() as u64);
            self.durable.insert(key, content);
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
        self.set_disk_level(&on_disk);
        Ok(receipt)
    }

    /// Garbage collection after a successful save: delete stale temp files,
    /// corrupt, older-format and other-allowlist records, records from
    /// another context (account or namespace change) and records whose key
    /// is not kept or whose scope is not the kept one. A key kept with an
    /// unknown scope (`None`: its file was not decided this pass) keeps its
    /// record; restore still refuses it on a scope mismatch. Newer-format
    /// records are left for the binary that wrote them.
    pub(crate) fn gc<W: SingleWriter>(
        &mut self,
        writer: &W,
        live_context: &Digest32,
        allowlist: &Digest32,
        keep: &BTreeMap<Digest32, Option<Digest32>>,
    ) -> io::Result<()> {
        self.check_writer(writer)?;
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.durable.clear();
                self.set_disk_level(&BTreeMap::new());
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let mut deleted = false;
        let mut on_disk = BTreeMap::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let path = entry.path();
            if name.starts_with('.') && name.ends_with(TEMP_SUFFIX) {
                remove_if_present(&path)?;
                self.counters.gc_temps_deleted += 1;
                deleted = true;
                continue;
            }
            let Some(key) = name.strip_suffix(RECORD_SUFFIX).and_then(parse_hex_digest) else {
                continue;
            };
            let verdict = match read_private(&path) {
                Ok(Some(bytes)) => {
                    let len = bytes.len() as u64;
                    match decode(&bytes, allowlist) {
                        Ok(record) => {
                            let binding = &record.record.binding;
                            let live = binding.key == key
                                && binding.context == *live_context
                                && match keep.get(&key) {
                                    Some(Some(scope)) => *scope == binding.scope,
                                    Some(None) => true,
                                    None => false,
                                };
                            live.then_some(len)
                        }
                        Err(Refusal::NewerFormat) => Some(len),
                        Err(_) => None,
                    }
                }
                Ok(None) => continue,
                Err(_) => None,
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
        self.set_disk_level(&on_disk);
        Ok(())
    }

    /// Index reset or uninstall: remove the whole store.
    pub(crate) fn remove_all<W: SingleWriter>(&mut self, writer: &W) -> io::Result<()> {
        self.check_writer(writer)?;
        match fs::remove_dir_all(&self.dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.durable.clear();
        self.set_disk_level(&BTreeMap::new());
        Ok(())
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

    /// Record files and their sizes, as on disk now.
    fn scan_disk(&self) -> io::Result<BTreeMap<Digest32, u64>> {
        let mut on_disk = BTreeMap::new();
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
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                on_disk.insert(key, metadata.len());
            }
        }
        Ok(on_disk)
    }

    fn set_disk_level(&mut self, on_disk: &BTreeMap<Digest32, u64>) {
        self.counters.disk_records = on_disk.len() as u64;
        self.counters.disk_bytes = on_disk.values().sum();
    }

    fn note_codec(&mut self, bytes: usize) {
        self.counters.peak_codec_bytes = self.counters.peak_codec_bytes.max(bytes as u64);
    }
}

/// What makes a record dirty: everything but the generation stamp, so a
/// later save of an unchanged entry rewrites nothing.
fn content_digest(record: &PendingRecord) -> Digest32 {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + record.body.len());
    encode_parts(&mut bytes, record, 0);
    digest("ottto-dt-content:v1", &[bytes.as_slice()])
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
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > (RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES) as u64
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
    out.extend_from_slice(&record.body);
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
    let mut cursor = Cursor(bytes);
    if cursor.array::<8>() != Some(MAGIC) {
        return Err(Refusal::Corrupt);
    }
    let version = cursor.u16().ok_or(Refusal::Corrupt)?;
    if version > FORMAT_VERSION {
        return Err(Refusal::NewerFormat);
    }
    if version < FORMAT_VERSION {
        return Err(Refusal::OlderFormat);
    }
    let body_end = bytes
        .len()
        .checked_sub(TRAILER_BYTES)
        .filter(|end| *end >= MAGIC.len() + 2)
        .ok_or(Refusal::Corrupt)?;
    let trailer: Digest32 = Sha256::digest(&bytes[..body_end]).into();
    if bytes[body_end..] != trailer {
        return Err(Refusal::Corrupt);
    }
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
        return Err(Refusal::AllowlistChanged);
    }
    Ok(record)
}

/// Test-only fault points inside the atomic write.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;
    use std::io;
    use std::path::Path;

    type Hook = Box<dyn FnMut(&Path, &Path) -> io::Result<()>>;
    type DirHook = Box<dyn FnMut(&Path) -> io::Result<()>>;

    thread_local! {
        static BEFORE_RENAME: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_DIR_SYNC: RefCell<Option<DirHook>> = const { RefCell::new(None) };
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
