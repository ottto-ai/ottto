//! The P1 money ledger's own store, and the shadow's writer.
//!
//! The ledger (telemetry `otel:`, message-only `mh:`, family `fam:` and
//! sweep `sweep:` records, #664's census codec) never lives in the scan
//! index: the index's bytes, its live allowances, its save and its
//! validation are the same whether the shadow is armed or not. The ledger is
//! one in-memory copy per support directory, persisted under
//! `<support>/claude-request-ledger/` as 256 hash-sharded JSON maps (shard =
//! first byte of SHA-256 of the key) and `meta.json` (the sweep records).
//! Only changed shards are rewritten. Saves are coalesced (at most one per
//! `SAVE_MIN_INTERVAL`, each at most `SAVE_BYTES_PER_PAGE`) and capped per
//! UTC day at `SAVE_DAILY_BYTES` of attempted bytes (data shards, both metas
//! and every retry), counted in `save-budget.json` before each save is
//! written so a restart resumes the day's count. Past the cap, dirty state
//! stays resident (within the ledger's bound) until the next day; a crash
//! then loses only unsaved progress, which errs toward rereading and
//! rewriting.
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
//! One writer thread does every file write of the shadow (diagnostics JSONL
//! rows, serialized there, and ledger shards) and the ledger load, outside
//! `SNAPSHOT_SYNC_LOCK`. While it has work (or debt held only in memory) a
//! durable run marker says so; it persists that debt before it removes the
//! marker, so a marker found when a process starts is an unclean run whose
//! days owe a false row (`super::note_unclean_run`). Its outbox is bounded in batches and in admitted
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
use super::{
    ClaudeFamilyMemo, ClaudeFamilyPublication, JsonlBatch, JsonlOutcome, ShadowReservation,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
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
/// Dirty shard bytes one save serializes. A shard larger than this is never
/// one save's work: it stays dirty (counted) and no certificate is written
/// over it; the load refuses a file larger than this as damage.
pub(crate) const SAVE_BYTES_PER_PAGE: usize = 8 * 1024 * 1024;
/// At most one save this often (plus the first of a process).
pub(crate) const SAVE_MIN_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// Attempted save bytes per UTC day.
pub(crate) const SAVE_DAILY_BYTES: usize = 64 * 1024 * 1024;
/// The day's attempted save bytes, beside the shards.
const SAVE_BUDGET_FILE: &str = "save-budget.json";
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
    /// When this process last took a save (None: not yet).
    last_save: Option<Instant>,
    /// The UTC day (`yyyymmdd`) of `save_bytes_today`.
    save_day: u64,
    /// Save bytes attempted on `save_day` (persisted before each save).
    pub(crate) save_bytes_today: u64,
    /// Non-refundable quota credit persisted by the writer before use.
    save_credit: usize,
    credit_pending: bool,
    /// Why the last page took no save while shards were dirty.
    pub(crate) save_held: Option<SaveHeld>,
    /// Families with a row in a batch whose result has not come back (process
    /// memory): none of them is "unchanged" until it does.
    in_flight: BTreeMap<String, u32>,
}

/// Why a page with dirty shards took no save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveHeld {
    /// The last save is younger than `SAVE_MIN_INTERVAL`.
    Interval,
    /// The day's `SAVE_DAILY_BYTES` would be passed.
    DailyCap,
    CreditPending,
}

/// What one page's save may take: the UTC day and the coalescing interval.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SavePolicy<'a> {
    pub(crate) support_dir: &'a Path,
    pub(crate) deadline: Instant,
    pub(crate) utc_day: u64,
    pub(crate) min_interval: Duration,
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
            last_save: None,
            save_day: 0,
            save_bytes_today: 0,
            save_credit: 0,
            credit_pending: false,
            save_held: None,
            in_flight: BTreeMap::new(),
        }
    }

    /// The families of a handed-off batch's rows.
    pub(crate) fn note_in_flight<'k>(&mut self, keys: impl Iterator<Item = &'k str>) {
        for key in keys {
            *self.in_flight.entry(key.to_owned()).or_default() += 1;
        }
    }

    /// A batch's result came back (or it was never queued).
    pub(crate) fn settle_in_flight<'k>(&mut self, keys: impl Iterator<Item = &'k str>) {
        for key in keys {
            if let Some(count) = self.in_flight.get_mut(key) {
                *count -= 1;
                if *count == 0 {
                    self.in_flight.remove(key);
                }
            }
        }
    }

    pub(crate) fn in_flight(&self, key: &str) -> bool {
        self.in_flight.contains_key(key)
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

    /// Serialize the dirty shards of this page's save, when one is due
    /// (`SAVE_MIN_INTERVAL` since this process's last) and the day's
    /// `SAVE_DAILY_BYTES` has room. A zero meta (every certificate 0) rides
    /// first when a certificate went to zero; the data shards come in a fair
    /// rotation up to `SAVE_BYTES_PER_PAGE` and the day's room; the current
    /// meta rides last only when no data shard stays dirty. Its bytes count
    /// as attempted when it is taken, whatever happens to them. None when
    /// nothing is dirty or due, its buffers are not admitted or the page
    /// deadline passes while serializing (everything stays dirty). The
    /// deadline is checked before every record, so the walk stops within one
    /// record's serialization of it (at most `SAVE_BYTES_PER_PAGE`).
    pub(crate) fn take_save(
        &mut self,
        policy: SavePolicy<'_>,
    ) -> Option<(ClaudeLedgerSave, ShadowReservation)> {
        self.save_held = None;
        if Instant::now() >= policy.deadline || self.dirty_shards() == 0 {
            return None;
        }
        if self
            .last_save
            .is_some_and(|last| last.elapsed() < policy.min_interval)
        {
            self.save_held = Some(SaveHeld::Interval);
            return None;
        }
        if policy.utc_day > self.save_day {
            self.save_day = policy.utc_day;
            self.save_bytes_today = 0;
            self.save_credit = 0;
        }
        if self.save_credit == 0 {
            self.request_credit(policy.support_dir, policy.utc_day);
            return None;
        }
        let room = SAVE_BYTES_PER_PAGE.min(self.save_credit);
        // The day's room, not the save's bound, decides what stays dirty.
        let day_bound = room < SAVE_BYTES_PER_PAGE;
        let meta_bytes = self.shard_bytes[META] + 2;
        let zero_first = self.meta_debt;
        let mut bytes = usize::from(zero_first) * meta_bytes;
        let mut selected = vec![false; DATA_SHARDS];
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
            if bytes + need > room {
                break;
            }
            selected[shard] = true;
            bytes += need;
            next_save = (shard + 1) % DATA_SHARDS;
        }
        let data_left = (0..DATA_SHARDS).any(|shard| self.dirty[shard] && !selected[shard]);
        let meta_last = self.dirty[META] && !data_left && bytes + meta_bytes <= room;
        bytes += usize::from(meta_last) * meta_bytes;
        // A zero meta goes before any data shard, or nothing goes.
        if bytes > room || !selected.contains(&true) && !zero_first && !meta_last {
            if day_bound {
                // A shard cannot use the remaining credit. Abandon it without
                // refund and ask the writer for a fresh, durable reservation.
                self.save_credit = 0;
                self.request_credit(policy.support_dir, policy.utc_day);
            }
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
                if Instant::now() >= policy.deadline {
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
            if Instant::now() >= policy.deadline {
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
        // Credit was synced on the writer thread before the producer saw
        // it. Queued/dropped saves and restart never refund that reservation.
        self.save_credit -= bytes;
        self.last_save = Some(Instant::now());
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

    fn request_credit(&mut self, support_dir: &Path, day: u64) {
        if self.credit_pending {
            self.save_held = Some(SaveHeld::CreditPending);
        } else if self.save_bytes_today >= SAVE_DAILY_BYTES as u64 {
            self.save_held = Some(SaveHeld::DailyCap);
        } else if submit(Job::Reserve(support_dir.to_path_buf(), day)).is_ok() {
            self.credit_pending = true;
            self.save_held = Some(SaveHeld::CreditPending);
        }
    }

    /// A batch that did not reach the disk: its shards are dirty again (a
    /// zero meta among them is owed again).
    fn restore(&mut self, failed_shards: &[usize], meta: Option<bool>) {
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

/// A family memo that moves only when its batch was published (written,
/// flushed and synced): its scheduling time and publication always, its
/// money basis only from a complete body.
#[derive(Debug, Clone)]
pub(crate) struct PendingMemo {
    pub(crate) key: String,
    /// A complete body's union revision and money (the next removal
    /// basis); None keeps the stored basis.
    pub(crate) basis: Option<([u8; 32], ClaudeFamilyMemo)>,
    pub(crate) observed_unix: u64,
    pub(crate) published: ClaudeFamilyPublication,
    /// The batch carries a row of the family (else it was unchanged).
    pub(crate) row: bool,
}

/// One page's batch for the writer.
pub(crate) struct WriteJob {
    pub(crate) support_dir: PathBuf,
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
    /// The writer's time on the batch.
    pub(crate) writer_us: u64,
}

enum Job {
    Reserve(PathBuf, u64),
    Wake,
    Load(PathBuf),
    Write(Box<WriteJob>),
    #[cfg(test)]
    Flush(SyncSender<()>),
    #[cfg(test)]
    Pause(SyncSender<()>, Receiver<()>),
    /// A restart of the writer's state of a directory (a new process).
    #[cfg(test)]
    Restart(PathBuf),
}

enum Slot {
    Loading,
    Ready(Box<ClaudeLedger>),
    Busy,
}

static LEDGERS: Mutex<BTreeMap<PathBuf, Slot>> = Mutex::new(BTreeMap::new());
#[derive(Clone, Copy)]
struct Credit {
    day: u64,
    reserved: u64,
    bytes: usize,
}
static CREDITS: Mutex<BTreeMap<PathBuf, Credit>> = Mutex::new(BTreeMap::new());

/// Only the writer (and synchronous store fixtures) calls this. Charge an
/// entire <=8 MiB ticket before granting it. Unspent ticket bytes are lost
/// on restart, so accounting is deliberately conservative.
fn reserve_credit(support_dir: &Path, day: u64) -> Credit {
    let dir = support_dir.join(LEDGER_DIR);
    let (saved_day, saved_bytes) = load_budget(&dir);
    let used = if day > saved_day { 0 } else { saved_bytes };
    let amount = SAVE_BYTES_PER_PAGE.min(SAVE_DAILY_BYTES.saturating_sub(used as usize));
    let total = used.saturating_add(amount as u64);
    let granted = day >= saved_day
        && amount > 0
        && std::fs::create_dir_all(&dir).is_ok()
        && write_atomic(
            &dir.join(SAVE_BUDGET_FILE),
            format!("{{\"day\":{day},\"bytes\":{total}}}").as_bytes(),
        );
    Credit {
        day: saved_day.max(day),
        reserved: if granted {
            total
        } else {
            SAVE_DAILY_BYTES as u64
        },
        bytes: if granted { amount } else { 0 },
    }
}

pub(super) fn wake_writer() {
    let _ = submit(Job::Wake);
}

static RESULTS: Mutex<BTreeMap<PathBuf, Vec<WriteResult>>> = Mutex::new(BTreeMap::new());
static WRITER: OnceLock<Option<Mutex<SyncSender<Job>>>> = OnceLock::new();

fn writer() -> Option<&'static Mutex<SyncSender<Job>>> {
    WRITER
        .get_or_init(|| {
            let (sender, receiver) = sync_channel(OUTBOX);
            std::thread::Builder::new()
                .name("claude-money-shadow-writer".to_owned())
                .spawn(move || run_writer(receiver))
                .ok()
                .map(|_| Mutex::new(sender))
        })
        .as_ref()
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
            _ => 0,
        }
    }
}

fn submit(job: Job) -> Result<(), Job> {
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
    ledger.note_in_flight(
        job.memos
            .iter()
            .filter(|memo| memo.row)
            .map(|memo| memo.key.as_str()),
    );
    match submit(Job::Write(Box::new(job))) {
        Ok(()) => Ok(()),
        Err(Job::Write(job)) => {
            ledger.settle_in_flight(
                job.memos
                    .iter()
                    .filter(|memo| memo.row)
                    .map(|memo| memo.key.as_str()),
            );
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
        Err(Job::Write(job)) => Err(job),
        Err(_) => unreachable!("a write job comes back as itself"),
    }
}

/// The writer's results for `support_dir` since the last call, applied to
/// its ledger: unwritten shards are dirty again; memos come back to the
/// caller, which moves the published ones.
pub(crate) fn take_results(support_dir: &Path, ledger: &mut ClaudeLedger) -> Vec<WriteResult> {
    if let Some(credit) = CREDITS
        .lock()
        .ok()
        .and_then(|mut credits| credits.remove(support_dir))
    {
        ledger.credit_pending = false;
        if credit.day >= ledger.save_day {
            ledger.save_day = credit.day;
            ledger.save_bytes_today = credit.reserved;
            ledger.save_credit = credit.bytes;
        }
    }
    let results = RESULTS
        .lock()
        .ok()
        .and_then(|mut results| results.remove(support_dir))
        .unwrap_or_default();
    for result in &results {
        ledger.restore(&result.failed_shards, result.meta_unwritten);
        ledger.settle_in_flight(
            result
                .memos
                .iter()
                .filter(|memo| memo.row)
                .map(|memo| memo.key.as_str()),
        );
    }
    results
}

fn run_writer(receiver: Receiver<Job>) {
    // Per support directory: shards whose last write failed (no sweep
    // advance is written over them), whether a debt-carrying meta failed
    // (no data shard is written until one lands), and its run marker.
    let mut failed = BTreeMap::<PathBuf, WriterState>::new();
    loop {
        let job = match receiver.try_recv() {
            Ok(job) => job,
            Err(TryRecvError::Empty) => {
                super::persist_coverage_debt();
                match receiver.recv() {
                    Ok(job) => job,
                    Err(_) => break,
                }
            }
            Err(TryRecvError::Disconnected) => break,
        };
        match job {
            Job::Reserve(dir, day) => {
                let credit = reserve_credit(&dir, day);
                if let Ok(mut credits) = CREDITS.lock() {
                    credits.insert(dir, credit);
                }
            }
            Job::Wake => super::persist_coverage_debt(),
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
                let bytes = job.queued_bytes();
                let failed = failed.entry(job.support_dir.clone()).or_default();
                let lost_ack = job.jsonl.fault == super::PageFault::LostAck;
                let (support_dir, result) = write(*job, failed);
                QUEUED_BYTES.fetch_sub(bytes, Ordering::AcqRel);
                if let (false, Ok(mut results)) = (lost_ack, RESULTS.lock()) {
                    results.entry(support_dir).or_default().push(result);
                }
            }
            #[cfg(test)]
            Job::Pause(ready, resume) => {
                let _ = ready.send(());
                let _ = resume.recv();
            }
            #[cfg(test)]
            Job::Flush(done) => {
                super::persist_coverage_debt();
                let _ = done.send(());
            }
            #[cfg(test)]
            Job::Restart(support_dir) => {
                failed.remove(&support_dir);
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
        .and_then(|()| std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all())
        .is_ok()
}

/// What the writer remembers of one directory: its failed writes and its
/// run.
#[derive(Debug, Default)]
pub(crate) struct WriterState {
    failed: BTreeSet<usize>,
    /// A meta carrying debt failed: until one lands, no data shard (and no
    /// meta advance) is written, whichever batch it comes in.
    debt_unwritten: bool,
    run_days: Option<(u64, u64)>,
}

fn write(job: WriteJob, failed: &mut WriterState) -> (PathBuf, WriteResult) {
    let started = Instant::now();
    let WriteJob {
        support_dir,
        mut jsonl,
        mut memos,
        save,
        reservations,
    } = job;
    let ready = match failed.run_days {
        Some((first, last)) if jsonl.now >= first && jsonl.now <= last => true,
        previous => {
            let recovered = previous.is_some() || super::note_unclean_run(&support_dir, jsonl.now);
            let days = previous.map_or(
                (jsonl.now / 86_400 * 86_400, jsonl.now + 86_400),
                |(first, last)| (first.min(jsonl.now), last.max(jsonl.now + 86_400)),
            );
            if recovered && super::open_run_marker(&support_dir, days) {
                failed.run_days = Some(days);
                true
            } else {
                false
            }
        }
    };
    let outcome = if ready {
        super::write_jsonl(&support_dir, &mut jsonl)
    } else {
        super::owe_coverage(&support_dir, jsonl.now, true);
        super::JsonlOutcome {
            failed: 1,
            ..Default::default()
        }
    };
    for (memo, family) in memos
        .iter_mut()
        .filter(|memo| memo.row)
        .zip(&mut jsonl.families)
    {
        memo.published.digest = super::semantic_digest(family);
        if !family.row.coverage_complete {
            memo.basis = None;
        }
    }
    let save_failed = !ready || jsonl.fault == super::PageFault::SaveFailure;
    let jsonl = outcome;
    let (failed_shards, meta_unwritten) = save.map_or((Vec::new(), None), |save| {
        if save_failed {
            (
                save.shards.iter().map(|(shard, _)| *shard).collect(),
                Some(save.meta_debt),
            )
        } else {
            write_save(&support_dir.join(LEDGER_DIR), &save, failed)
        }
    });
    let result = WriteResult {
        jsonl,
        memos,
        failed_shards,
        meta_unwritten,
        writer_us: started.elapsed().as_micros() as u64,
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
    (ledger.save_day, ledger.save_bytes_today) = load_budget(&dir);
    Some(ledger)
}

/// The day's attempted save bytes a save persisted (none: (0, 0)).
fn load_budget(dir: &Path) -> (u64, u64) {
    #[derive(serde::Deserialize)]
    struct Budget {
        day: u64,
        bytes: u64,
    }
    let path = dir.join(SAVE_BUDGET_FILE);
    let exhausted = (super::utc_day(super::now_unix()), SAVE_DAILY_BYTES as u64);
    match std::fs::metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, 0),
        Ok(meta) if meta.len() <= 256 => std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Budget>(&bytes).ok())
            .map_or(exhausted, |budget| {
                (budget.day, budget.bytes.min(SAVE_DAILY_BYTES as u64))
            }),
        _ => exhausted,
    }
}

/// Wait until the writer has done everything handed to it so far.
#[cfg(test)]
pub(crate) fn flush() {
    let (done, wait) = sync_channel(1);
    let Some(sender) = writer() else {
        return;
    };
    let sent = sender
        .lock()
        .ok()
        .is_some_and(|sender| sender.send(Job::Flush(done)).is_ok());
    if sent {
        let _ = wait.recv();
    }
}

/// Block the writer so a fixture can fill its bounded outbox deterministically.
#[cfg(test)]
pub(crate) struct PausedWriter(SyncSender<()>);
#[cfg(test)]
impl Drop for PausedWriter {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}
#[cfg(test)]
pub(crate) fn pause_for_test() -> PausedWriter {
    let (ready, entered) = sync_channel(0);
    let (resume, wait) = sync_channel(0);
    writer()
        .expect("writer")
        .lock()
        .unwrap()
        .send(Job::Pause(ready, wait))
        .unwrap_or_else(|_| panic!("pause writer"));
    entered.recv().unwrap();
    PausedWriter(resume)
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

/// A new process for `support_dir`: its ledger and the writer's memory of
/// it are forgotten (the next write checks the run marker again).
#[cfg(test)]
pub(crate) fn restart_for_test(support_dir: &Path) {
    forget_for_test(support_dir);
    if let Some(sender) = writer() {
        if let Ok(sender) = sender.lock() {
            let _ = sender.send(Job::Restart(support_dir.to_path_buf()));
        }
    }
    flush();
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

#[cfg(test)]
fn test_budget_dir() -> &'static Path {
    Box::leak(
        std::env::temp_dir()
            .join(format!(
                "ottto-save-budget-{}-{:?}",
                std::process::id(),
                super::next_snapshot()
            ))
            .into_boxed_path(),
    )
}

#[cfg(test)]
fn credit_for_test(ledger: &mut ClaudeLedger, policy: SavePolicy<'_>) {
    if ledger.save_credit == 0 && ledger.save_bytes_today < SAVE_DAILY_BYTES as u64 {
        let credit = reserve_credit(policy.support_dir, policy.utc_day);
        ledger.save_day = credit.day;
        ledger.save_bytes_today = credit.reserved;
        ledger.save_credit = credit.bytes;
    }
}

/// Prime asynchronous durable credit for direct synchronous page fixtures.
/// Production pages only request credit and continue; they never wait.
#[cfg(test)]
pub(crate) fn prime_credit_for_test(support_dir: &Path, day: u64) {
    if let ClaudeLedgerAcquire::Ready(mut ledger) = acquire(support_dir) {
        if ledger.save_credit == 0 && !ledger.credit_pending {
            ledger.request_credit(support_dir, day);
        }
        drop(ledger);
        flush();
    }
}

/// A save every call, on today's budget.
#[cfg(test)]
pub(crate) fn policy_for_test(deadline: Instant) -> SavePolicy<'static> {
    SavePolicy {
        support_dir: test_budget_dir(),
        deadline,
        utc_day: super::utc_day(super::now_unix()),
        min_interval: Duration::ZERO,
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
    let policy = SavePolicy {
        support_dir,
        ..policy_for_test(Instant::now() + Duration::from_secs(60))
    };
    credit_for_test(ledger, policy);
    let (save, _reservation) = ledger.take_save(policy)?;
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
    let policy = policy_for_test(Instant::now() + Duration::from_secs(60));
    credit_for_test(ledger, policy);
    ledger.take_save(policy).map(|(save, _reservation)| save)
}

#[cfg(test)]
pub(crate) fn take_save_by_for_test(
    ledger: &mut ClaudeLedger,
    deadline: Instant,
) -> Option<ClaudeLedgerSave> {
    let policy = policy_for_test(deadline);
    credit_for_test(ledger, policy);
    ledger.take_save(policy).map(|(save, _reservation)| save)
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

#[cfg(test)]
mod bounded_save_tests {
    use super::*;

    #[test]
    #[serial_test::serial(claude_request_money_shadow)]
    fn queued_or_dropped_save_reservation_survives_restart_and_corruption_seals_day() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-budget-reserve-{}",
            super::super::next_snapshot()
        ));
        let mut ledger = ClaudeLedger::empty(true);
        let policy = SavePolicy {
            support_dir: &dir,
            ..policy_for_test(Instant::now() + Duration::from_secs(30))
        };
        credit_for_test(&mut ledger, policy);
        let (save, reservation) = ledger.take_save(policy).expect("reserved save");
        let charged = ledger.save_bytes_today;
        assert!(charged >= save.bytes() as u64 && charged <= SAVE_DAILY_BYTES as u64);
        drop((save, reservation, ledger)); // crash before outbox or acknowledgement
        assert_eq!(load_budget(&dir.join(LEDGER_DIR)).1, charged);
        let bytes = format!(
            "{{\"day\":{},\"bytes\":{SAVE_DAILY_BYTES}}}",
            policy.utc_day
        );
        assert!(write_atomic(
            &dir.join(LEDGER_DIR).join(SAVE_BUDGET_FILE),
            bytes.as_bytes()
        ));
        let mut resumed = ClaudeLedger::empty(true);
        (resumed.save_day, resumed.save_bytes_today) = load_budget(&dir.join(LEDGER_DIR));
        assert!(resumed.take_save(policy).is_none());
        assert_eq!(resumed.save_held, Some(SaveHeld::DailyCap));
        assert!(write_atomic(
            &dir.join(LEDGER_DIR).join(SAVE_BUDGET_FILE),
            b"broken"
        ));
        assert_eq!(
            load_budget(&dir.join(LEDGER_DIR)).1,
            SAVE_DAILY_BYTES as u64
        );
        println!("MONEY_P1B_IO reserved_bytes={charged} save_cap={SAVE_BYTES_PER_PAGE} daily_cap={SAVE_DAILY_BYTES} restart_refund=0");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
