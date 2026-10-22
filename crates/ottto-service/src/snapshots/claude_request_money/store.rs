//! The P1 money ledger's own store, and the shadow's writer.
//!
//! The ledger (telemetry `otel:`, message-only `mh:`, family `fam:` and
//! sweep `sweep:` records, #664's census codec) never lives in the scan
//! index: the index's bytes, its live allowances, its save and its
//! validation are the same whether the shadow is armed or not. The ledger is
//! one in-memory copy per support directory, persisted under
//! `<support>/claude-request-ledger/` as 256 hash-sharded JSON maps (shard =
//! first byte of SHA-256 of the key) and `meta.json` (the sweep records).
//! Only changed shards are rewritten, a bounded number per page.
//!
//! Crash order (Sol R3-2), one rule: when the telemetry certificate went to
//! zero, a meta whose certificates are all ZERO is written as its own write
//! before any data shard (whatever the in-memory meta says by then: a later
//! sweep may already have advanced it). A meta carrying a certificate is
//! only ever a final write, after every data shard dirty when it was taken
//! is on disk and no shard of the directory has a failed write. So a saved
//! `complete_through` never covers a record the disk does not hold. A zero
//! meta that fails to write holds back every later data shard of its
//! directory, from any batch, until one lands; a dropped one is retaken.
//! A missing or corrupt shard at load is debt, never a silent loss.
//!
//! One writer thread serializes diagnostic rows, writes ledger shards and
//! loads the ledger. The writer persists an intent before publication. Live
//! offers and bound holds poll a writer receipt on subsequent pages before
//! POST or index commit; the sync lock never waits for disk. Its outbox is bounded in batches and in admitted
//! bytes; each batch carries the admission of its own buffers (released
//! when it is written, dropped or refused), and the load admits each
//! shard's bytes and a structural bound of its decoded records before
//! reading it (Sol R3-4). A full outbox drops the batch (counted; its shards
//! stay dirty, its memos never move and its day owes a false coverage row).
//! Results come back to the next page.
//!
//! Resident bound (daemon parent): at most `LEDGER_MAX_RECORDS` records,
//! each `RECORD_RESIDENT_OVERHEAD_BYTES` beyond its payload, and a payload
//! (keys, hashes, facts) held in at most twice its serialized bytes, which
//! the census budget caps: `LEDGER_RESIDENT_BOUND_BYTES`.

use super::super::claude_request_census::{
    decode_ledger_shard, ClaudeLedgerSweep, ClaudeRequestCensus, ClaudeRequestCensusInsert,
    ClaudeRequestCensusRecord, MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES,
    MIN_ENTRY_SERIALIZED_BYTES, RECORD_RESIDENT_OVERHEAD_BYTES, SWEEP_KEY_PREFIX,
};
use super::{ClaudeFamilyMemo, JsonlBatch, JsonlOutcome, ShadowReservation};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(crate) const LEDGER_DIR: &str = "claude-request-ledger";
const DATA_SHARDS: usize = 256;
/// The meta shard's slot (the `sweep:` records).
const META: usize = DATA_SHARDS;
const SHARDS: usize = DATA_SHARDS + 1;
/// Batches waiting for the writer.
const OUTBOX: usize = 4;
/// Admitted bytes of the batches waiting for (or in) the writer: a batch
/// that would pass it is dropped like one that finds the outbox full.
pub(crate) const OUTBOX_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Records one ledger holds; a new key past it is refused (debt where it
/// carries claims), so the resident bound holds.
pub(crate) const LEDGER_MAX_RECORDS: usize = 65_536;
/// What one support directory's ledger can hold resident, at most.
pub(crate) const LEDGER_RESIDENT_BOUND_BYTES: usize = LEDGER_MAX_RECORDS
    * RECORD_RESIDENT_OVERHEAD_BYTES
    + 2 * MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES;
/// Dirty shard bytes one page serializes. A shard larger than this is never
/// one page's work: it stays dirty (counted) and no certificate is written
/// over it; the load refuses a file larger than this as damage.
const SAVE_BYTES_PER_PAGE: usize = 8 * 1024 * 1024;
/// The load waits this long, in steps, for each shard's admission; then it
/// gives up (nothing is lost: the next page asks for the load again).
const LOAD_ADMIT_ATTEMPTS: u32 = 100;
const LOAD_ADMIT_WAIT: Duration = Duration::from_millis(20);

/// The admission of loading a shard file of `len` bytes: the raw bytes, one
/// record's raw value while it decodes, the decoded payload (hashes, facts
/// and keys, each at most twice its serialized bytes) and every record's
/// overhead, for as many records as the bytes can hold.
fn load_charge(len: usize) -> usize {
    let records = (len / MIN_ENTRY_SERIALIZED_BYTES + 1).min(LEDGER_MAX_RECORDS);
    len.saturating_mul(4)
        .saturating_add(records.saturating_mul(RECORD_RESIDENT_OVERHEAD_BYTES))
}

fn shard_of(key: &str) -> usize {
    if key.starts_with(SWEEP_KEY_PREFIX) {
        META
    } else {
        usize::from(Sha256::digest(key.as_bytes())[0])
    }
}

fn shard_path(dir: &Path, shard: usize) -> PathBuf {
    if shard == META {
        dir.join("meta.json")
    } else {
        dir.join(format!("shard-{shard:02x}.json"))
    }
}

/// The ledger of one support directory.
pub(crate) struct ClaudeLedger {
    census: ClaudeRequestCensus,
    /// Serialized bytes each shard holds (its entries), kept exact.
    shard_bytes: Vec<usize>,
    /// Shards changed since their last write was handed to the writer.
    dirty: Vec<bool>,
    /// A certificate went to zero: a zero meta goes before any data shard.
    meta_debt: bool,
    /// Where the next page's bounded save starts (fair rotation).
    next_save: usize,
    /// Dirty shards the last save skipped as larger than a page's bound.
    pub(crate) oversized_shards: u64,
    /// The load found a missing or corrupt shard.
    pub(crate) load_damaged: bool,
    /// Where the `mh:` round-robin resumes (process memory only: pruning
    /// is housekeeping, a stale record is never a holder).
    pub(crate) message_cursor: String,
    pub(crate) synthetic_cursor: String,
    pending_checkpoint: Option<PendingCheckpoint>,
    barrier_needed: bool,
    custody_epoch: u64,
    durable_custody_epoch: u64,
}

fn custody_key(key: &str) -> bool {
    [
        "due:", "dirty:", "offer:", "hold:", "watch:", "unbuilt:", "adopt:", "union:", "ever:",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

impl ClaudeLedger {
    fn empty(dirty: bool) -> Self {
        Self {
            census: ClaudeRequestCensus::default(),
            shard_bytes: vec![0; SHARDS],
            dirty: vec![dirty; SHARDS],
            meta_debt: false,
            next_save: 0,
            oversized_shards: 0,
            load_damaged: false,
            message_cursor: String::new(),
            synthetic_cursor: String::new(),
            pending_checkpoint: None,
            barrier_needed: dirty,
            custody_epoch: 0,
            durable_custody_epoch: 0,
        }
    }

    pub(crate) fn census(&self) -> &ClaudeRequestCensus {
        &self.census
    }

    pub(crate) fn get(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.census.get(key)
    }

    fn account(&mut self, shard: usize, before: usize) {
        let after = self.census.serialized_total();
        let bytes = &mut self.shard_bytes[shard];
        *bytes = (*bytes + after).saturating_sub(before);
        self.dirty[shard] = true;
    }

    pub(crate) fn insert(
        &mut self,
        key: String,
        record: ClaudeRequestCensusRecord,
    ) -> ClaudeRequestCensusInsert {
        if self.census.record_count() >= LEDGER_MAX_RECORDS && self.census.get(&key).is_none() {
            return ClaudeRequestCensusInsert::Refused;
        }
        if custody_key(&key) && self.get(&key) != Some(&record) {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
        }
        let shard = shard_of(&key);
        let before = self.census.serialized_total();
        let outcome = self.census.insert(key, record);
        self.account(shard, before);
        outcome
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if self.census.get(key).is_none() {
            return;
        }
        if custody_key(key) {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
        }
        let shard = shard_of(key);
        let before = self.census.serialized_total();
        self.census.remove(key);
        self.account(shard, before);
    }

    /// Remove and return `key`'s record (its buffers move to the caller).
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let shard = shard_of(key);
        let before = self.census.serialized_total();
        let record = self.census.take(key)?;
        self.account(shard, before);
        Some(record)
    }

    /// A certificate went to zero: the next save writes a zero meta before
    /// any data shard.
    pub(crate) fn note_meta_debt(&mut self) {
        self.meta_debt = true;
        self.dirty[META] = true;
    }

    pub(crate) fn dirty_shards(&self) -> usize {
        self.dirty.iter().filter(|dirty| **dirty).count()
    }

    /// Serialize the dirty shards of this page's bounded save. The data
    /// shards come in a fair rotation up to `SAVE_BYTES_PER_PAGE`. A zero
    /// meta (every certificate 0) rides first when a certificate went to
    /// zero; the current meta rides last only when no data shard stays
    /// dirty. None when nothing is dirty, its buffers are not admitted or the
    /// page deadline passes while serializing (everything stays dirty). The
    /// deadline is checked before every record, so the walk stops within one
    /// record's serialization of it (at most `SAVE_BYTES_PER_PAGE`).
    pub(crate) fn take_save(
        &mut self,
        deadline: Instant,
    ) -> Option<(ClaudeLedgerSave, ShadowReservation)> {
        if Instant::now() >= deadline || writer().is_none() {
            return None;
        }
        let mut selected = vec![false; DATA_SHARDS];
        let mut bytes = 0_usize;
        let mut next_save = self.next_save;
        self.oversized_shards = 0;
        for step in 0..DATA_SHARDS {
            let shard = (self.next_save + step) % DATA_SHARDS;
            if !self.dirty[shard] {
                continue;
            }
            let need = self.shard_bytes[shard] + 2;
            if need > SAVE_BYTES_PER_PAGE {
                self.oversized_shards += 1;
                continue;
            }
            if bytes + need > SAVE_BYTES_PER_PAGE {
                break;
            }
            selected[shard] = true;
            bytes += need;
            next_save = (shard + 1) % DATA_SHARDS;
        }
        let data_left = (0..DATA_SHARDS).any(|shard| self.dirty[shard] && !selected[shard]);
        let zero_first = self.meta_debt;
        let meta_last = self.dirty[META] && !data_left;
        let metas = usize::from(zero_first) + usize::from(meta_last);
        bytes += metas * (self.shard_bytes[META] + 2);
        if !selected.contains(&true) && metas == 0 {
            return None;
        }
        let reservation = ShadowReservation::admit(bytes)?;
        let open = |size: usize| {
            let mut buffer = Vec::with_capacity(size + 2);
            buffer.push(b'{');
            buffer
        };
        let mut buffers = BTreeMap::<usize, Vec<u8>>::new();
        for (shard, chosen) in selected.iter().enumerate() {
            if *chosen {
                buffers.insert(shard, open(self.shard_bytes[shard]));
            }
        }
        if !buffers.is_empty() {
            for (key, record) in self.census.records() {
                if Instant::now() >= deadline {
                    return None;
                }
                if key.starts_with(SWEEP_KEY_PREFIX) {
                    continue;
                }
                if let Some(buffer) = buffers.get_mut(&shard_of(key)) {
                    push_entry(buffer, key, record);
                }
            }
        }
        let mut zero = zero_first.then(|| open(self.shard_bytes[META]));
        let mut current = meta_last.then(|| open(self.shard_bytes[META]));
        for (key, record) in self.census.records_with_prefix(SWEEP_KEY_PREFIX) {
            if Instant::now() >= deadline {
                return None;
            }
            if let Some(buffer) = current.as_mut() {
                push_entry(buffer, key, record);
            }
            if let Some(buffer) = zero.as_mut() {
                match record.sweep() {
                    Some((cursor, start, sweep)) => push_entry(
                        buffer,
                        key,
                        &ClaudeRequestCensusRecord::sweep_record(*cursor, start, zeroed(sweep)),
                    ),
                    None => push_entry(buffer, key, record),
                }
            }
        }
        let close = |mut buffer: Vec<u8>| {
            buffer.push(b'}');
            buffer
        };
        let mut save = ClaudeLedgerSave::default();
        for (shard, buffer) in buffers {
            self.dirty[shard] = false;
            save.shards.push((shard, close(buffer)));
        }
        if let Some(buffer) = zero {
            // The current meta stays dirty until a final write carries it.
            self.meta_debt = false;
            save.meta_first = Some(close(buffer));
            save.meta_debt = true;
        }
        if let Some(buffer) = current {
            self.dirty[META] = false;
            save.meta_last = Some(close(buffer));
        }
        self.next_save = next_save;
        Some((save, reservation))
    }

    /// A batch that did not reach the disk: its shards are dirty again (a
    /// zero meta among them is owed again).
    fn restore(&mut self, failed_shards: &[usize], meta: Option<bool>) {
        // A preceding queued batch may fail after this checkpoint was taken.
        // Restoring that debt changes the epoch even if its dirty bits were
        // already cleared into a later queued command.
        if !failed_shards.is_empty() || meta.is_some() {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
            self.barrier_needed = true;
        }
        for shard in failed_shards {
            self.dirty[*shard] = true;
        }
        if let Some(debt) = meta {
            self.dirty[META] = true;
            self.meta_debt |= debt;
        }
    }
}

fn push_entry(buffer: &mut Vec<u8>, key: &str, record: &ClaudeRequestCensusRecord) {
    if buffer.len() > 1 {
        buffer.push(b',');
    }
    // Writing into a Vec cannot fail; a failure would only shorten the
    // shard, which its load then rejects as corrupt.
    let _ = serde_json::to_writer(&mut *buffer, key);
    buffer.push(b':');
    let _ = serde_json::to_writer(&mut *buffer, record);
}

/// A sweep state as the zero meta saves it: no certificate, and a sweep
/// that held one carries debt (a restart from it certifies nothing).
fn zeroed(sweep: ClaudeLedgerSweep) -> ClaudeLedgerSweep {
    ClaudeLedgerSweep {
        complete_through: 0,
        debt: sweep.debt.max(u64::from(sweep.complete_through > 0)),
    }
}

/// One page's serialized shards.
#[derive(Debug, Default)]
pub(crate) struct ClaudeLedgerSave {
    shards: Vec<(usize, Vec<u8>)>,
    meta_first: Option<Vec<u8>>,
    meta_last: Option<Vec<u8>>,
    meta_debt: bool,
}

impl ClaudeLedgerSave {
    pub(crate) fn shards(&self) -> usize {
        self.shards.len() + usize::from(self.meta_first.is_some() || self.meta_last.is_some())
    }

    pub(crate) fn bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|(_, bytes)| bytes.len())
            .chain(self.meta_first.iter().map(Vec::len))
            .chain(self.meta_last.iter().map(Vec::len))
            .sum()
    }
}

/// A family memo that moves only when its rows were written.
#[derive(Debug, Clone)]
pub(crate) struct PendingMemo {
    pub(crate) key: String,
    pub(crate) revision: [u8; 32],
    pub(crate) observed_unix: u64,
    pub(crate) memo: ClaudeFamilyMemo,
}

/// One page's batch for the writer.
pub(crate) struct WriteJob {
    pub(crate) support_dir: PathBuf,
    pub(crate) pending_intent: Option<PathBuf>,
    pub(crate) jsonl: JsonlBatch,
    pub(crate) memos: Vec<PendingMemo>,
    pub(crate) save: Option<ClaudeLedgerSave>,
    /// The admission of the batch's buffers, released when it is written.
    pub(crate) reservations: Vec<ShadowReservation>,
}

/// What the writer did with one batch.
pub(crate) struct WriteResult {
    pub(crate) jsonl: JsonlOutcome,
    pub(crate) memos: Vec<PendingMemo>,
    failed_shards: Vec<usize>,
    /// The meta shard was not written (with its debt flag).
    meta_unwritten: Option<bool>,
}

type PendingCheckpoint = (
    Receiver<(Vec<usize>, Option<bool>)>,
    Vec<usize>,
    Option<bool>,
    u64,
    bool,
);

type CheckpointPayload = (
    PathBuf,
    ClaudeLedgerSave,
    ShadowReservation,
    SyncSender<(Vec<usize>, Option<bool>)>,
);

enum Job {
    Load(PathBuf),
    Write(Box<WriteJob>),
    Flush(SyncSender<()>),
    #[cfg(test)]
    Stall {
        entered: SyncSender<()>,
        release: Receiver<()>,
    },
    Checkpoint(Box<CheckpointPayload>, ShadowReservation),
}

enum Slot {
    Loading,
    Ready(Box<ClaudeLedger>),
    Busy,
}

static LEDGERS: Mutex<BTreeMap<PathBuf, Slot>> = Mutex::new(BTreeMap::new());
static RESULTS: Mutex<BTreeMap<PathBuf, Vec<WriteResult>>> = Mutex::new(BTreeMap::new());
struct Writer {
    sender: Mutex<SyncSender<Job>>,
    thread: std::thread::JoinHandle<()>,
}
static WRITER: OnceLock<Option<Writer>> = OnceLock::new();

fn writer() -> Option<&'static Mutex<SyncSender<Job>>> {
    WRITER
        .get_or_init(|| {
            let (sender, receiver) = sync_channel(OUTBOX);
            std::thread::Builder::new()
                .name("claude-money-shadow-writer".to_owned())
                .spawn(move || run_writer(receiver))
                .ok()
                .map(|thread| Writer {
                    sender: Mutex::new(sender),
                    thread,
                })
        })
        .as_ref()
        .filter(|writer| !writer.thread.is_finished())
        .map(|writer| &writer.sender)
}

/// Admitted bytes of the batches handed to the writer and not yet written.
static QUEUED_BYTES: AtomicUsize = AtomicUsize::new(0);

impl WriteJob {
    /// What the batch holds admitted while it waits and is written.
    fn queued_bytes(&self) -> usize {
        self.reservations.iter().map(ShadowReservation::bytes).sum()
    }
}

impl Job {
    fn queued_bytes(&self) -> usize {
        match self {
            Self::Write(job) => job.queued_bytes(),
            Self::Checkpoint(payload, allocation) => payload.2.bytes() + allocation.bytes(),
            _ => 0,
        }
    }
}

fn submit(job: Job) -> Result<(), Job> {
    #[cfg(test)]
    if REFUSE_WRITES_FOR_TEST.with(std::cell::Cell::get) && matches!(&job, Job::Write(_)) {
        return Err(job);
    }
    let Some(sender) = writer() else {
        return Err(job);
    };
    let Ok(sender) = sender.lock() else {
        return Err(job);
    };
    let bytes = job.queued_bytes();
    let queued = QUEUED_BYTES.fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
        queued
            .checked_add(bytes)
            .filter(|total| *total <= OUTBOX_MAX_BYTES)
    });
    if queued.is_err() {
        return Err(job);
    }
    sender.try_send(job).map_err(|error| {
        QUEUED_BYTES.fetch_sub(bytes, Ordering::AcqRel);
        match error {
            TrySendError::Full(job) | TrySendError::Disconnected(job) => job,
        }
    })
}

/// The page's hold on its support directory's ledger; returned on drop.
pub(crate) struct ClaudeLedgerGuard {
    support_dir: PathBuf,
    ledger: Option<Box<ClaudeLedger>>,
}

impl std::ops::Deref for ClaudeLedgerGuard {
    type Target = ClaudeLedger;
    fn deref(&self) -> &ClaudeLedger {
        self.ledger.as_deref().expect("held ledger")
    }
}

impl std::ops::DerefMut for ClaudeLedgerGuard {
    fn deref_mut(&mut self) -> &mut ClaudeLedger {
        self.ledger.as_deref_mut().expect("held ledger")
    }
}

impl Drop for ClaudeLedgerGuard {
    fn drop(&mut self) {
        if let (Some(ledger), Ok(mut ledgers)) = (self.ledger.take(), LEDGERS.lock()) {
            ledgers.insert(self.support_dir.clone(), Slot::Ready(ledger));
        }
    }
}

pub(crate) enum ClaudeLedgerAcquire {
    Ready(ClaudeLedgerGuard),
    /// The writer is loading it: this page has no ledger.
    Loading,
    /// No writer, or another page holds it.
    Unavailable,
}

/// The support directory's ledger. A directory with no saved ledger starts
/// empty (every shard dirty, so the first save writes them all); a saved one
/// is loaded by the writer while pages skip.
pub(crate) fn acquire(support_dir: &Path) -> ClaudeLedgerAcquire {
    if writer().is_none() {
        return ClaudeLedgerAcquire::Unavailable;
    }
    let Ok(mut ledgers) = LEDGERS.lock() else {
        return ClaudeLedgerAcquire::Unavailable;
    };
    match ledgers.remove(support_dir) {
        Some(Slot::Ready(ledger)) => {
            ledgers.insert(support_dir.to_path_buf(), Slot::Busy);
            ClaudeLedgerAcquire::Ready(ClaudeLedgerGuard {
                support_dir: support_dir.to_path_buf(),
                ledger: Some(ledger),
            })
        }
        Some(slot @ (Slot::Loading | Slot::Busy)) => {
            let loading = matches!(slot, Slot::Loading);
            ledgers.insert(support_dir.to_path_buf(), slot);
            if loading {
                ClaudeLedgerAcquire::Loading
            } else {
                ClaudeLedgerAcquire::Unavailable
            }
        }
        None if !support_dir.join(LEDGER_DIR).exists() => {
            ledgers.insert(support_dir.to_path_buf(), Slot::Busy);
            ClaudeLedgerAcquire::Ready(ClaudeLedgerGuard {
                support_dir: support_dir.to_path_buf(),
                ledger: Some(Box::new(ClaudeLedger::empty(true))),
            })
        }
        None => match submit(Job::Load(support_dir.to_path_buf())) {
            Ok(()) => {
                ledgers.insert(support_dir.to_path_buf(), Slot::Loading);
                ClaudeLedgerAcquire::Loading
            }
            Err(_) => ClaudeLedgerAcquire::Unavailable,
        },
    }
}

/// Hand a page's batch to the writer. On a full outbox the batch comes back
/// and its shards are dirty again.
pub(crate) fn submit_batch(ledger: &mut ClaudeLedger, job: WriteJob) -> Result<(), Box<WriteJob>> {
    let submitted = submit(Job::Write(Box::new(job)));
    match submitted {
        Ok(()) => Ok(()),
        Err(Job::Write(job)) => {
            super::owe_coverage(&job.support_dir, job.jsonl.now, false);
            if let Some(save) = &job.save {
                let failed = save
                    .shards
                    .iter()
                    .map(|(shard, _)| *shard)
                    .collect::<Vec<_>>();
                let meta = (save.meta_first.is_some() || save.meta_last.is_some())
                    .then_some(save.meta_debt);
                ledger.restore(&failed, meta);
            }
            Err(job)
        }
        Err(_) => unreachable!("a write job comes back as itself"),
    }
}

/// Hand a batch with no ledger (a page refused before it held one).
pub(crate) fn submit_unledgered(job: WriteJob) -> Result<(), Box<WriteJob>> {
    match submit(Job::Write(Box::new(job))) {
        Ok(()) => Ok(()),
        Err(Job::Write(job)) => {
            super::owe_coverage(&job.support_dir, job.jsonl.now, false);
            Err(job)
        }
        Err(_) => unreachable!("a write job comes back as itself"),
    }
}

/// The writer's results for `support_dir` since the last call, applied to
/// its ledger: unwritten shards are dirty again; memos come back to the
/// caller, which moves the published ones.
pub(crate) fn take_results(support_dir: &Path, ledger: &mut ClaudeLedger) -> Vec<WriteResult> {
    let results = RESULTS
        .lock()
        .ok()
        .and_then(|mut results| results.remove(support_dir))
        .unwrap_or_default();
    for result in &results {
        ledger.restore(&result.failed_shards, result.meta_unwritten);
    }
    results
}

fn run_writer(receiver: Receiver<Job>) {
    // Per support directory: shards whose last write failed (no sweep
    // advance is written over them), and whether a debt-carrying meta failed
    // (no data shard is written until one lands).
    let mut failed = BTreeMap::<PathBuf, WriterState>::new();
    let mut recovered = BTreeSet::new();
    while let Ok(job) = receiver.recv() {
        match job {
            Job::Load(support_dir) => {
                let ledger = load(&support_dir);
                if let Ok(mut ledgers) = LEDGERS.lock() {
                    match ledger {
                        Some(ledger) => {
                            ledgers.insert(support_dir, Slot::Ready(Box::new(ledger)));
                        }
                        // Not admitted: unloaded again, the next page asks.
                        None => {
                            LOADS_REFUSED.fetch_add(1, Ordering::Relaxed);
                            ledgers.remove(&support_dir);
                        }
                    }
                }
            }
            Job::Write(job) => {
                // A process can die before a queued batch starts. Re-seal
                // retained days with existing rows before publishing any new
                // coverage in this process; no caller-side fsync is needed.
                if recovered.insert(job.support_dir.clone()) {
                    super::recover_queued_coverage(&job.support_dir, job.jsonl.now);
                }
                let bytes = job.queued_bytes();
                let failed = failed.entry(job.support_dir.clone()).or_default();
                let (support_dir, result) = write(*job, failed);
                QUEUED_BYTES.fetch_sub(bytes, Ordering::AcqRel);
                if let Ok(mut results) = RESULTS.lock() {
                    results.entry(support_dir).or_default().push(result);
                }
            }
            Job::Checkpoint(payload, allocation) => {
                let (support_dir, save, reservation, done) = *payload;
                let state = failed.entry(support_dir.clone()).or_default();
                let result = write_save(&support_dir.join(LEDGER_DIR), &save, state);
                QUEUED_BYTES.fetch_sub(reservation.bytes() + allocation.bytes(), Ordering::AcqRel);
                drop(reservation);
                drop(allocation);
                let _ = done.send(result);
            }
            #[cfg(test)]
            Job::Stall { entered, release } => {
                let _ = entered.send(());
                let _ = release.recv();
            }
            Job::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
    let staged = path.with_extension("json.tmp");
    let written = std::fs::File::create(&staged).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    written
        .and_then(|()| std::fs::rename(&staged, path))
        // Persist the name before any data shard can replace a zero meta.
        .and_then(|()| {
            std::fs::File::open(path.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ledger file has no parent",
                )
            })?)?
            .sync_all()
        })
        .is_ok()
}

/// What the writer remembers of one directory's failed writes.
#[derive(Debug, Default)]
pub(crate) struct WriterState {
    failed: BTreeSet<usize>,
    /// A meta carrying debt failed: until one lands, no data shard (and no
    /// meta advance) is written, whichever batch it comes in.
    debt_unwritten: bool,
}

fn write(mut job: WriteJob, failed: &mut WriterState) -> (PathBuf, WriteResult) {
    // Only the writer performs durable intent I/O. Before it publishes any
    // shard or row the recoverable intent must be on disk.
    job.pending_intent = write_intent(&job.support_dir, job.jsonl.now);
    if job.pending_intent.is_none() {
        super::owe_coverage(&job.support_dir, job.jsonl.now, true);
        let failed_shards = job
            .save
            .as_ref()
            .map(|save| save.shards.iter().map(|(s, _)| *s).collect())
            .unwrap_or_default();
        let meta_unwritten = job.save.as_ref().and_then(|save| {
            (save.meta_first.is_some() || save.meta_last.is_some()).then_some(save.meta_debt)
        });
        return (
            job.support_dir,
            WriteResult {
                jsonl: JsonlOutcome::default(),
                memos: Vec::new(),
                failed_shards,
                meta_unwritten,
            },
        );
    }
    let WriteJob {
        support_dir,
        pending_intent,
        jsonl,
        memos,
        save,
        reservations,
    } = job;
    let jsonl = super::write_jsonl(&support_dir, &jsonl);
    let (failed_shards, meta_unwritten) = save.map_or((Vec::new(), None), |save| {
        write_save(&support_dir.join(LEDGER_DIR), &save, failed)
    });
    if jsonl.published && failed_shards.is_empty() && meta_unwritten.is_none() {
        if let Some(intent) = pending_intent {
            let _ = std::fs::remove_file(intent);
        }
    } else if let Some(now) = job_now(&pending_intent) {
        super::owe_coverage(&support_dir, now, true);
        if super::day_stamp(now)
            .is_some_and(|day| super::owed_path(&support_dir.join("diagnostics"), &day).exists())
        {
            if let Some(intent) = pending_intent {
                let _ = std::fs::remove_file(intent);
            }
        }
    }
    let result = WriteResult {
        jsonl,
        memos,
        failed_shards,
        meta_unwritten,
    };
    drop(reservations);
    (support_dir, result)
}

/// Write one page's shards in crash order: a meta carrying debt first (no
/// data shard goes while it is not on disk), then the data shards, then a
/// meta advance only when no shard of the directory has a failed write.
/// Returns the shards not written and, when the meta was not, its debt flag.
fn write_save(
    dir: &Path,
    save: &ClaudeLedgerSave,
    state: &mut WriterState,
) -> (Vec<usize>, Option<bool>) {
    let mut unwritten = Vec::new();
    let mut meta_unwritten = None;
    let mut blocked = std::fs::create_dir_all(dir).is_err();
    if let Some(meta) = &save.meta_first {
        if blocked || !write_atomic(&shard_path(dir, META), meta) {
            blocked = true;
            meta_unwritten = Some(save.meta_debt);
            state.debt_unwritten |= save.meta_debt;
        } else {
            state.debt_unwritten = false;
        }
    }
    // An earlier batch's debt is not on disk yet: nothing goes before it.
    blocked |= state.debt_unwritten;
    for (shard, bytes) in &save.shards {
        if !blocked && write_atomic(&shard_path(dir, *shard), bytes) {
            state.failed.remove(shard);
        } else {
            state.failed.insert(*shard);
            unwritten.push(*shard);
        }
    }
    if let Some(meta) = &save.meta_last {
        if blocked || !state.failed.is_empty() || !write_atomic(&shard_path(dir, META), meta) {
            // A zero meta that failed before keeps its debt flag.
            meta_unwritten.get_or_insert(false);
        }
    }
    (unwritten, meta_unwritten)
}

/// Loads given up because their admission never came (process memory).
static LOADS_REFUSED: AtomicU64 = AtomicU64::new(0);

pub(crate) fn loads_refused() -> u64 {
    LOADS_REFUSED.load(Ordering::Relaxed)
}

/// Admit `bytes`, waiting (in steps) for pages and batches to release
/// theirs; None when it never comes.
fn admit_waiting(bytes: usize) -> Option<ShadowReservation> {
    for attempt in 0..LOAD_ADMIT_ATTEMPTS {
        if let Some(reservation) = ShadowReservation::admit(bytes) {
            return Some(reservation);
        }
        if attempt + 1 < LOAD_ADMIT_ATTEMPTS {
            std::thread::sleep(LOAD_ADMIT_WAIT);
        }
    }
    None
}

/// Read every shard, each admitted (its bytes and decoded records) before
/// it is read; None when an admission never comes (the partial ledger is
/// dropped). A shard that is missing (when anything was saved), larger than
/// a save ever writes, unreadable, malformed, lossy or holding a foreign key
/// is damage: the ledger marks it and the shadow drops its telemetry
/// certificate. So is every record past `LEDGER_MAX_RECORDS` over all shards
/// (Sol R5-1: each shard's decoder limit alone admits more).
fn load(support_dir: &Path) -> Option<ClaudeLedger> {
    load_capped(support_dir, LEDGER_MAX_RECORDS)
}

fn load_capped(support_dir: &Path, max_records: usize) -> Option<ClaudeLedger> {
    let dir = support_dir.join(LEDGER_DIR);
    let mut ledger = ClaudeLedger::empty(false);
    let mut missing = Vec::new();
    let mut present = 0_usize;
    for shard in 0..SHARDS {
        let limit = SAVE_BYTES_PER_PAGE as u64;
        let opened = std::fs::File::open(shard_path(&dir, shard)).and_then(|file| {
            let len = file.metadata()?.len();
            Ok((file, len))
        });
        let mut _admitted = None;
        let bytes = match opened {
            Ok((_, len)) if len > limit => {
                ledger.load_damaged = true;
                ledger.dirty[shard] = true;
                continue;
            }
            Ok((file, len)) => {
                _admitted = Some(admit_waiting(load_charge(len as usize))?);
                let mut bytes = Vec::with_capacity(len as usize);
                match file.take(limit + 1).read_to_end(&mut bytes) {
                    Ok(_) if bytes.len() as u64 <= limit => bytes,
                    _ => {
                        ledger.load_damaged = true;
                        ledger.dirty[shard] = true;
                        continue;
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(shard);
                continue;
            }
            Err(_) => {
                ledger.load_damaged = true;
                ledger.dirty[shard] = true;
                continue;
            }
        };
        present += 1;
        let decoded = decode_ledger_shard(&bytes)
            .filter(|census| census.records().all(|(key, _)| shard_of(key) == shard));
        let Some(decoded) = decoded else {
            ledger.load_damaged = true;
            ledger.dirty[shard] = true;
            continue;
        };
        let before = ledger.census.serialized_total();
        if !ledger.census.absorb(decoded, max_records) {
            ledger.load_damaged = true;
        }
        ledger.account(shard, before);
        ledger.dirty[shard] = false;
    }
    if present > 0 && !missing.is_empty() {
        ledger.load_damaged = true;
    }
    for shard in missing {
        ledger.dirty[shard] = true;
    }
    Some(ledger)
}

/// Wait until the writer has done everything handed to it so far.
pub(crate) fn flush() {
    let _ = flush_acknowledged();
}

fn flush_acknowledged() -> bool {
    flush_acknowledged_by(Instant::now() + flush_timeout())
}

fn flush_acknowledged_by(deadline: Instant) -> bool {
    let (done, wait) = sync_channel(1);
    let Some(sender) = WRITER
        .get()
        .and_then(Option::as_ref)
        .filter(|writer| !writer.thread.is_finished())
        .map(|writer| &writer.sender)
    else {
        return false;
    };
    let mut job = Job::Flush(done);
    loop {
        let attempt = sender.lock().ok().map(|sender| sender.try_send(job));
        match attempt {
            Some(Ok(())) => break,
            Some(Err(TrySendError::Full(returned))) if Instant::now() < deadline => {
                job = returned;
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return false,
        }
    }
    wait.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .is_ok()
}

/// Forget the in-memory ledger of `support_dir` (a restart): the next page
/// loads it from disk.
#[cfg(test)]
pub(crate) fn forget_for_test(support_dir: &Path) {
    flush();
    if let Ok(mut ledgers) = LEDGERS.lock() {
        ledgers.remove(support_dir);
    }
    if let Ok(mut results) = RESULTS.lock() {
        results.remove(support_dir);
    }
}

/// A restart that reloads the saved ledger before the next page (the page
/// then runs on it rather than being refused while it loads). Returns its
/// record count.
#[cfg(test)]
pub(crate) fn reload_for_test(support_dir: &Path) -> Option<usize> {
    forget_for_test(support_dir);
    drop(acquire(support_dir));
    with_ledger_for_test(support_dir, |ledger| ledger.census().record_count())
}

/// Run `read` over the ledger of `support_dir` (after the writer is idle).
#[cfg(test)]
pub(crate) fn with_ledger_for_test<T>(
    support_dir: &Path,
    read: impl FnOnce(&mut ClaudeLedger) -> T,
) -> Option<T> {
    flush();
    let mut ledgers = LEDGERS.lock().ok()?;
    match ledgers.get_mut(support_dir)? {
        Slot::Ready(ledger) => Some(read(ledger)),
        _ => None,
    }
}

#[cfg(test)]
impl ClaudeLedger {
    /// A new ledger, as a support directory with none saved starts.
    pub(crate) fn new_for_test() -> Self {
        Self::empty(true)
    }
}

/// One page's bounded save of `ledger`, written synchronously (the writer's
/// crash order); `failed` is the writer's memory of the directory. Returns
/// (shards in the save, the meta went first, shards not written).
#[cfg(test)]
pub(crate) fn save_page_for_test(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    failed: &mut WriterState,
) -> Option<(usize, bool, usize)> {
    let (save, _reservation) = ledger.take_save(Instant::now() + Duration::from_secs(60))?;
    let (unwritten, meta) = write_save(&support_dir.join(LEDGER_DIR), &save, failed);
    ledger.restore(&unwritten, meta);
    Some((save.shards(), save.meta_first.is_some(), unwritten.len()))
}

#[cfg(test)]
pub(crate) fn load_for_test(support_dir: &Path) -> ClaudeLedger {
    load(support_dir).expect("the load is admitted")
}

/// A load under a smaller record cap (the real one needs 65,536 records).
#[cfg(test)]
pub(crate) fn load_capped_for_test(support_dir: &Path, max_records: usize) -> ClaudeLedger {
    load_capped(support_dir, max_records).expect("the load is admitted")
}

#[cfg(test)]
pub(crate) fn try_load_for_test(support_dir: &Path) -> Option<ClaudeLedger> {
    load(support_dir)
}

#[cfg(test)]
pub(crate) fn shard_path_for_test(support_dir: &Path, key: &str) -> PathBuf {
    shard_path(&support_dir.join(LEDGER_DIR), shard_of(key))
}

#[cfg(test)]
pub(crate) fn take_save_for_test(ledger: &mut ClaudeLedger) -> Option<ClaudeLedgerSave> {
    ledger
        .take_save(Instant::now() + Duration::from_secs(60))
        .map(|(save, _reservation)| save)
}

#[cfg(test)]
pub(crate) fn take_save_by_for_test(
    ledger: &mut ClaudeLedger,
    deadline: Instant,
) -> Option<ClaudeLedgerSave> {
    ledger.take_save(deadline).map(|(save, _reservation)| save)
}

#[cfg(test)]
pub(crate) fn write_save_for_test(
    support_dir: &Path,
    save: &ClaudeLedgerSave,
    state: &mut WriterState,
) -> (Vec<usize>, Option<bool>) {
    write_save(&support_dir.join(LEDGER_DIR), save, state)
}

/// The ledger takes back saves that did not reach the disk (as the writer's
/// results would report them).
#[cfg(test)]
pub(crate) fn restore_for_test(ledger: &mut ClaudeLedger, saves: &[&ClaudeLedgerSave]) {
    for save in saves {
        let shards = save
            .shards
            .iter()
            .map(|(shard, _)| *shard)
            .collect::<Vec<_>>();
        let meta =
            (save.meta_first.is_some() || save.meta_last.is_some()).then_some(save.meta_debt);
        ledger.restore(&shards, meta);
    }
}

/// Stable, content-free identity of a physical member's local scheduling debt.
pub(in crate::snapshots) fn money_key(prefix: &str, index_key: &str) -> String {
    format!("{prefix}{:x}", Sha256::digest(index_key.as_bytes()))
}

impl ClaudeLedger {
    pub(super) fn put_money(&mut self, key: String, record: ClaudeRequestCensusRecord) -> bool {
        if self.get(&key) == Some(&record) {
            return true;
        }
        self.insert(key, record) == ClaudeRequestCensusInsert::Stored
    }
}

/// Complete a custody epoch before a new live offer or bound hold advances.
/// Diagnostic memos may keep changing while a receipt is in flight; they do
/// not invalidate durable due/dirty/offer/watch authority. A partial save or
/// failed shard never acknowledges the epoch. No caller-side disk wait.
pub(super) fn checkpoint(support_dir: &Path, ledger: &mut ClaudeLedger) -> bool {
    checkpoint_until(
        support_dir,
        ledger,
        Instant::now() + Duration::from_millis(100),
    )
}

pub(super) fn checkpoint_until(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    deadline: Instant,
) -> bool {
    // No wait and no durable I/O on the caller. A later page reacquires the
    // ledger and checks the completed writer receipt before POST or commit.
    if let Some((wait, shards, meta, epoch, complete)) = ledger.pending_checkpoint.take() {
        match wait.try_recv() {
            Ok((failed, meta)) => {
                let durable = complete && failed.is_empty() && meta.is_none();
                ledger.restore(&failed, meta);
                ledger.barrier_needed = !durable;
                if durable {
                    ledger.durable_custody_epoch = epoch;
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ledger.pending_checkpoint = Some((wait, shards, meta, epoch, complete));
                return false;
            }
            Err(_) => {
                ledger.restore(&shards, meta);
                return false;
            }
        }
    }
    super::apply_results(
        support_dir,
        ledger,
        &mut super::ClaudeRequestMoneyShadowCounts::default(),
    );
    if !ledger.barrier_needed && ledger.custody_epoch == ledger.durable_custody_epoch {
        return true;
    }
    // Admit the boxed command and its directory before allocating either.
    let Some(allocation) = ShadowReservation::admit(
        std::mem::size_of::<CheckpointPayload>()
            .saturating_add(support_dir.as_os_str().len())
            .saturating_add(1024),
    ) else {
        return false;
    };
    let saved = if ledger.dirty_shards() == 0 {
        ShadowReservation::admit(0).map(|reservation| (ClaudeLedgerSave::default(), reservation))
    } else {
        ledger.take_save(deadline)
    };
    let Some((save, reservation)) = saved else {
        return false;
    };
    let shards = save
        .shards
        .iter()
        .map(|(shard, _)| *shard)
        .collect::<Vec<_>>();
    let meta = (save.meta_first.is_some() || save.meta_last.is_some()).then_some(save.meta_debt);
    let epoch = ledger.custody_epoch;
    let complete = ledger.dirty_shards() == 0;
    let (done, wait) = sync_channel(1);
    if submit(Job::Checkpoint(
        Box::new((support_dir.to_path_buf(), save, reservation, done)),
        allocation,
    ))
    .is_err()
    {
        ledger.restore(&shards, meta);
        return false;
    }
    ledger.pending_checkpoint = Some((wait, shards, meta, epoch, complete));
    false
}

#[cfg(test)]
pub(crate) fn checkpoint_for_test(support_dir: &Path, ledger: &mut ClaudeLedger) -> bool {
    for _ in 0..8 {
        let durable = checkpoint(support_dir, ledger);
        if durable && ledger.dirty_shards() == 0 {
            return true;
        }
        if ledger.dirty_shards() > 0 {
            ledger.barrier_needed = true;
        }
        flush();
    }
    false
}

/// Snapshot the ready ledger without taking custody from a running page.
/// The scope is explicit; no account/destination can see another ledger.
pub(super) fn scheduled(support_dir: &Path, index_key: &str, now: u64) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    let dirty = ledger.get(&money_key("dirty:", index_key));
    if ledger
        .get(&money_key("hold:", index_key))
        .is_some_and(|hold| {
            hold.window() > now
                && dirty.map_or(true, |dirty| {
                    dirty.window() <= hold.window().saturating_sub(1800)
                })
        })
    {
        return false;
    }
    ["due:", "dirty:", "hold:"].iter().any(|prefix| {
        ledger
            .get(&money_key(prefix, index_key))
            .is_some_and(|record| record.window() <= now)
    })
}

pub(super) fn hold_rereadable(support_dir: &Path, key: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    ledger.get(&money_key("hold:", key)).is_some()
        && ["due:", "dirty:"]
            .iter()
            .any(|prefix| ledger.get(&money_key(prefix, key)).is_some())
}

pub(super) fn hold_revision_bound(support_dir: &Path, revision: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    ledger
        .get(&format!("hold:body:{revision}"))
        .is_some_and(|record| {
            super::super::claude_request_census::fingerprint_matches(record, revision)
        })
}

pub(super) fn blocking_file(support_dir: &Path, index_key: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    ledger
        .get(&money_key("unbuilt:", index_key))
        .is_some_and(|record| record.window() & super::UNBUILT_RELEASED == 0)
}

pub(super) fn has_offer(support: &Path, key: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support) else {
        return false;
    };
    let found = ledger
        .census()
        .records_with_prefix(&format!("{}:", money_key("offer:", key)))
        .next()
        .is_some();
    found
}

#[cfg(test)]
pub(super) fn checkpoint_pending(support_dir: &Path) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return true;
    };
    match ledgers.get(support_dir) {
        Some(Slot::Ready(ledger)) => ledger.pending_checkpoint.is_some(),
        _ => false,
    }
}

pub(super) fn adoption_paused(support_dir: &Path, prefix: &str, now: u64) -> bool {
    let pause = |state: u64| {
        static ALARMED: AtomicU64 = AtomicU64::new(0);
        if ALARMED.fetch_or(state, Ordering::Relaxed) & state == 0 {
            eprintln!("claude_request_money adoption_paused_state={state}");
        }
        true
    };
    let Ok(ledgers) = LEDGERS.lock() else {
        return pause(1);
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return pause(1);
    };
    if ledger.pending_checkpoint.is_some() || ledger.dirty_shards() > 0 || ledger.barrier_needed {
        return pause(1);
    }
    if ledger
        .get(&format!("{prefix}route"))
        .is_some_and(|record| record.window() > now)
    {
        return pause(2);
    }
    let Some(record) = ledger.get(&format!("{prefix}rates")) else {
        return false;
    };
    let revision = record.money_revision();
    let values = revision
        .chunks_exact(8)
        .map(|bytes| u64::from_be_bytes(bytes.try_into().expect("rate")))
        .collect::<Vec<_>>();
    let [total, local, holds, refused] = values[..] else {
        return pause(1);
    };
    let paused = total & (1_u64 << 63) != 0
        || total > 0
            && (local.saturating_mul(100) > total
                || refused.saturating_mul(100) >= total.saturating_mul(5)
                || holds.saturating_mul(100) > total.saturating_sub(local));
    paused && pause(4)
}

/// A paused slice gets one recovery candidate after thirty minutes. Route
/// and unknown/pending accounting remain closed. The next outcome renews it.
pub(super) fn adoption_probe_due(support_dir: &Path, prefix: &str, now: u64) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    ledger.pending_checkpoint.is_none()
        && !ledger.barrier_needed
        && ledger.dirty_shards() == 0
        && !ledger
            .get(&format!("{prefix}route"))
            .is_some_and(|record| record.window() > now)
        && ledger.get(&format!("{prefix}rates")).is_some_and(|record| {
            record.money_revision()[0] & 0x80 == 0 && now >= record.window().saturating_add(1800)
        })
}

pub(super) fn intent_run_id() -> &'static str {
    static RUN: OnceLock<String> = OnceLock::new();
    RUN.get_or_init(|| {
        format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|time| time.as_nanos())
                .unwrap_or(0)
        )
    })
}

#[cfg(test)]
thread_local! {
    static REFUSE_WRITES_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn write_intent(support_dir: &Path, now: u64) -> Option<PathBuf> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let day = super::day_stamp(now)?;
    let dir = support_dir.join("diagnostics");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!(
        ".{}{day}.{}.{}.pending",
        super::JSONL_PREFIX,
        intent_run_id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    write_atomic(&path, now.to_string().as_bytes()).then_some(path)
}

fn job_now(intent: &Option<PathBuf>) -> Option<u64> {
    super::read_marker_time(intent.as_ref()?)
}

fn flush_timeout() -> Duration {
    #[cfg(test)]
    if let Some(timeout) = TEST_FLUSH_TIMEOUT.with(std::cell::Cell::get) {
        return timeout;
    }
    Duration::from_secs(5)
}

#[cfg(test)]
thread_local! {
    static TEST_FLUSH_TIMEOUT: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) struct FlushTimeoutForTest(Option<Duration>);
#[cfg(test)]
impl Drop for FlushTimeoutForTest {
    fn drop(&mut self) {
        TEST_FLUSH_TIMEOUT.with(|timeout| timeout.set(self.0));
    }
}
#[cfg(test)]
pub(crate) fn flush_timeout_for_test(timeout: Duration) -> FlushTimeoutForTest {
    FlushTimeoutForTest(TEST_FLUSH_TIMEOUT.with(|current| current.replace(Some(timeout))))
}

#[cfg(test)]
pub(crate) struct WriterStallForTest(SyncSender<()>);
#[cfg(test)]
impl Drop for WriterStallForTest {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}
#[cfg(test)]
pub(crate) fn stall_writer_for_test() -> WriterStallForTest {
    let (entered, wait) = sync_channel(1);
    let (release, paused) = sync_channel(1);
    let guard = WriterStallForTest(release);
    assert!(submit(Job::Stall {
        entered,
        release: paused
    })
    .is_ok());
    wait.recv_timeout(Duration::from_secs(5))
        .expect("writer entered the injected stall");
    guard
}

#[cfg(test)]
mod refused_intent_tests {
    use super::*;
    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn refused_outbox_jobs_leave_debt_without_caller_disk_io() {
        let support = std::env::temp_dir().join(format!(
            "ottto-money-intent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        struct Reset(PathBuf);
        impl Drop for Reset {
            fn drop(&mut self) {
                REFUSE_WRITES_FOR_TEST.with(|flag| flag.set(false));
                super::super::forget_owed_coverage_for_test(&self.0);
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _reset = Reset(support.clone());
        REFUSE_WRITES_FOR_TEST.with(|flag| flag.set(true));
        let now = 1_790_000_000;
        let day = super::super::day_stamp(now).unwrap();
        let mut ledger = ClaudeLedger::new_for_test();
        for with_ledger in [false, true] {
            for _ in 0..24 {
                let job = WriteJob {
                    support_dir: support.clone(),
                    pending_intent: None,
                    jsonl: super::super::JsonlBatch {
                        now,
                        families: Vec::new(),
                        coverage: super::super::CoverageRow::owed(now),
                        buffer_bytes: 0,
                    },
                    memos: Vec::new(),
                    save: None,
                    reservations: Vec::new(),
                };
                let refused = if with_ledger {
                    submit_batch(&mut ledger, job)
                } else {
                    submit_unledgered(job)
                };
                let Err(refused) = refused else {
                    panic!("synthetic full outbox");
                };
                assert!(
                    refused.pending_intent.is_none(),
                    "coalesced debt owns this refusal"
                );
            }
        }
        assert!(
            !support.join("diagnostics").exists(),
            "full writer cannot cause synchronous durable work"
        );
        assert!(super::super::COVERAGE_OWED
            .lock()
            .unwrap()
            .get(&support)
            .unwrap()
            .contains_key(&day));
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn checkpoint_retries_a_preceding_queued_custody_write_failure() {
        let scratch = crate::test_scratch::ScratchDir::new("money-prior-write-receipt");
        let support = scratch.join("support");
        let key = "dirty:prior-write";
        let mut ledger = ClaudeLedger::new_for_test();
        ledger.put_money(
            key.into(),
            ClaudeRequestCensusRecord::money_debt([1; 32], 0),
        );
        let blocked = shard_path_for_test(&support, key).with_extension("json.tmp");
        std::fs::create_dir_all(&blocked).unwrap();
        let (save, funds) = ledger
            .take_save(Instant::now() + Duration::from_secs(2))
            .unwrap();
        let job = WriteJob {
            support_dir: support.clone(),
            pending_intent: None,
            jsonl: super::super::JsonlBatch {
                now: 1_790_000_000,
                families: Vec::new(),
                coverage: super::super::CoverageRow::owed(1_790_000_000),
                buffer_bytes: 0,
            },
            memos: Vec::new(),
            save: Some(save),
            reservations: vec![funds],
        };
        assert!(submit_batch(&mut ledger, job).is_ok());
        assert!(!checkpoint(&support, &mut ledger));
        flush();
        assert!(
            !checkpoint(&support, &mut ledger),
            "an empty successful fence cannot hide the preceding failed custody save"
        );
        flush();
        std::fs::remove_dir_all(blocked).unwrap();
        assert!(checkpoint_for_test(&support, &mut ledger));
        assert!(load_for_test(&support).get(key).is_some());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn diagnostic_memo_does_not_recreate_a_durable_custody_barrier() {
        let scratch = crate::test_scratch::ScratchDir::new("money-custody-receipt");
        let mut ledger = ClaudeLedger::new_for_test();
        ledger.put_money(
            "dirty:fixture".into(),
            ClaudeRequestCensusRecord::money_debt([1; 32], 0),
        );
        assert!(!checkpoint(&scratch, &mut ledger));
        flush();
        ledger.insert(
            "fam:diagnostic".into(),
            ClaudeRequestCensusRecord::money_debt([9; 32], 1),
        );
        assert!(
            checkpoint(&scratch, &mut ledger),
            "unrelated diagnostic debt cannot prevent POST forever"
        );
        ledger.put_money(
            "dirty:fixture".into(),
            ClaudeRequestCensusRecord::money_debt([2; 32], 0),
        );
        assert!(
            !checkpoint(&scratch, &mut ledger),
            "changed custody needs its own receipt"
        );
        assert!(checkpoint_for_test(&scratch, &mut ledger));
        assert_eq!(
            load_for_test(&scratch)
                .get("dirty:fixture")
                .unwrap()
                .money_revision(),
            [2; 32]
        );
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn stalled_writer_never_blocks_checkpoint_or_shadow_handoff() {
        let scratch = crate::test_scratch::ScratchDir::new("money-resumable-writer");
        let support = scratch.join("support");
        let mut ledger = ClaudeLedger::new_for_test();
        ledger.put_money(
            "dirty:fixture".into(),
            ClaudeRequestCensusRecord::money_debt([1; 32], 0),
        );
        let stalled = stall_writer_for_test();
        let started = Instant::now();
        assert!(!checkpoint(&support, &mut ledger));
        assert!(!checkpoint(&support, &mut ledger));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(
            !support.join(LEDGER_DIR).exists(),
            "caller performs no durable write"
        );
        drop(stalled);
        assert!(checkpoint_for_test(&support, &mut ledger));
        assert!(load_for_test(&support).get("dirty:fixture").is_some());
    }

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn checkpoint_persists_memos_returned_by_a_pending_writer_batch() {
        let scratch = crate::test_scratch::ScratchDir::new("money-checkpoint-pending-memo");
        let support = scratch.join("support");
        let mut ledger = ClaudeLedger::new_for_test();
        let key = "fam:checkpoint-pending".to_owned();
        let revision = [9; 32];
        let memo = ClaudeFamilyMemo {
            snapshot: 7,
            ..Default::default()
        };
        let stalled = stall_writer_for_test();
        let job = WriteJob {
            support_dir: support.clone(),
            pending_intent: None,
            jsonl: super::super::JsonlBatch {
                now: 1_790_000_000,
                families: Vec::new(),
                coverage: super::super::CoverageRow::owed(1_790_000_000),
                buffer_bytes: 0,
            },
            memos: vec![PendingMemo {
                key: key.clone(),
                revision,
                observed_unix: 1_790_000_000,
                memo,
            }],
            save: None,
            reservations: Vec::new(),
        };
        assert!(submit_batch(&mut ledger, job).is_ok());
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(stalled);
        });
        assert!(checkpoint_for_test(&support, &mut ledger));
        release.join().unwrap();
        assert_eq!(ledger.dirty_shards(), 0);
        assert_eq!(
            ledger.get(&key).unwrap().family_memo(),
            Some((&revision, memo))
        );
        let reloaded = load_for_test(&support);
        assert_eq!(
            reloaded.get(&key).unwrap().family_memo(),
            Some((&revision, memo))
        );
        super::super::forget_owed_coverage_for_test(&support);
    }
}
