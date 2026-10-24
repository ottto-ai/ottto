//! The P1 money ledger's own store, and the shadow's writer.
//!
//! One versioned file carrier per physical transcript path and one telemetry
//! carrier per root own evidence and optional delivery/lifecycle fields. Control
//! and the packed, monotone ever-indexed set add two records. Transcript R stays
//! in ScanIndex with its existing codec, allowance and selected-save owner.
//! Carriers persist under `<support>/claude-request-custody-v2/` in 256 data
//! shards and `meta.json` (Control). Field query spellings are compatibility
//! views; they never add durable records. Old `claude-request-ledger/` files are
//! read-only recovery input. Missing, damaged or older custody requires a fresh
//! verified traversal before literal offers; unknown history closes synthetic
//! work. Only changed shards are rewritten, in bounded slices.
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
//! existing structural overhead credit and twice the serialized payload cover
//! native carrier/field nodes, keys, packed hashes and facts under the unchanged
//! byte admission: `LEDGER_RESIDENT_BOUND_BYTES`. Controls measure the actual
//! carrier layout separately, including spare offer/control vector capacity.

use super::super::claude_request_census::{
    decode_ledger_shard, ClaudeLedgerSweep, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES, MIN_ENTRY_SERIALIZED_BYTES,
    RECORD_RESIDENT_OVERHEAD_BYTES, SWEEP_KEY_PREFIX,
};
use super::custody::{Custody, CONTROL};
use super::{ClaudeFamilyMemo, JsonlBatch, JsonlOutcome, ShadowReservation};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(crate) const LEDGER_DIR: &str = "claude-request-custody-v2";
const LEGACY_LEDGER_DIR: &str = "claude-request-ledger";
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
/// gives up without losing custody; ordinary collection permits a later retry.
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
    if key == CONTROL || key.starts_with(SWEEP_KEY_PREFIX) {
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
    census: Custody,
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
    promotion_pending: bool,
    custody_epoch: u64,
    durable_custody_epoch: u64,
    live_refused: bool,
    pub(super) metadata_cursor: String,
    pub(super) metadata_checkpoint: bool,
}

fn custody_key(key: &str) -> bool {
    !key.starts_with("fam:")
}

impl ClaudeLedger {
    fn empty(dirty: bool) -> Self {
        let mut ledger = Self {
            census: Custody::default(),
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
            promotion_pending: false,
            custody_epoch: 0,
            durable_custody_epoch: 0,
            live_refused: false,
            metadata_cursor: String::new(),
            metadata_checkpoint: false,
        };
        for (key, value) in ledger.census.entries() {
            ledger.shard_bytes[shard_of(key)] =
                super::custody::serialized_len(key) + super::custody::serialized_len(&value) + 2;
        }
        ledger
    }

    fn recount_shards(&mut self) {
        self.shard_bytes.fill(0);
        for (key, value) in self.census.entries() {
            self.shard_bytes[shard_of(key)] +=
                super::custody::serialized_len(key) + super::custody::serialized_len(&value) + 2;
        }
    }

    pub(crate) fn census(&self) -> &Custody {
        &self.census
    }

    pub(super) fn epoch(&self) -> u64 {
        self.custody_epoch
    }
    pub(super) fn recovering(&self) -> bool {
        self.census.recovery()
    }
    pub(super) fn synthetic_closed(&self) -> bool {
        self.census.synthetic_closed()
    }

    pub(super) fn note_rebuilt(&mut self, path: &str) {
        let before = self.census.serialized_total();
        if self.census.rebuilt(path) {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
            self.account(
                shard_of(&format!("file:{:x}", Sha256::digest(path.as_bytes()))),
                before,
            );
        }
    }
    pub(super) fn finish_rebuild(&mut self, index: &super::super::ScanIndex, complete: bool) {
        if complete && self.census.recovery() && self.census.rebuild_complete(index) {
            let before = self.census.serialized_total();
            self.census.finish_recovery();
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
            self.account(META, before);
        }
    }
    pub(super) fn bind_file(
        &mut self,
        path: &str,
        root: String,
        member: String,
        birth: Option<super::super::claude_request_census::ClaudeRequestBirth>,
    ) -> bool {
        let changed = !self.census.binding_matches(path, &root, &member, birth);
        let carrier = format!("file:{:x}", Sha256::digest(path.as_bytes()));
        let before = self.census.serialized_total();
        if !self.census.bind_file(path, root, member, birth) {
            return false;
        }
        if changed {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
            self.account(shard_of(&carrier), before);
        }
        true
    }

    pub(super) fn put_entity(
        &mut self,
        owner: &str,
        key: String,
        record: ClaudeRequestCensusRecord,
        entity: super::custody::EntityBinding,
    ) -> bool {
        if self.census.entity_matches(owner, &key, &record, &entity) {
            return true;
        }
        let carrier = if let Some(root) = owner.strip_prefix("synthetic:") {
            format!("telemetry:{root}")
        } else {
            format!("file:{:x}", Sha256::digest(owner.as_bytes()))
        };
        let before = self.census.serialized_total();
        if self.census.insert_entity(owner, key, record, entity)
            != ClaudeRequestCensusInsert::Stored
        {
            return false;
        }
        self.custody_epoch = self.custody_epoch.wrapping_add(1);
        self.account(shard_of(&carrier), before);
        true
    }
    pub(super) fn promote(&mut self, index: &super::super::ScanIndex, deadline: Instant) -> bool {
        let retire = self.pending_checkpoint.is_none()
            && self.custody_epoch == self.durable_custody_epoch
            && !self.promotion_pending;
        let Some((changes, complete)) = self.census.promote(index, retire, deadline) else {
            return false;
        };
        for change in changes {
            let shard = shard_of(&change.carrier);
            self.shard_bytes[shard] = self.shard_bytes[shard]
                .saturating_sub(change.before)
                .saturating_add(change.after);
            self.dirty[shard] = true;
            if change.custody {
                self.custody_epoch = self.custody_epoch.wrapping_add(1);
            }
            self.promotion_pending = true;
            self.barrier_needed = true;
        }
        complete
    }
    pub(super) fn has_pending_checkpoint(&self) -> bool {
        self.pending_checkpoint.is_some()
    }
    pub(super) fn promotions_pending(&self) -> bool {
        self.promotion_pending
    }

    pub(crate) fn get(&self, key: &str) -> Option<super::custody::RecordRef<'_>> {
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
        let previous = self.get(&key);
        if previous.is_some_and(|old| old.matches(&record))
            || key.starts_with("ever:") && previous.is_some()
        {
            return ClaudeRequestCensusInsert::Stored;
        }
        let changed = custody_key(&key);
        let Some(carrier) = self.census.carrier_key(&key) else {
            return ClaudeRequestCensusInsert::Refused;
        };
        let shard = shard_of(&carrier);
        let before = self.census.serialized_total();
        let outcome = self.census.insert(key, record);
        if outcome == ClaudeRequestCensusInsert::Stored && changed {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
        }
        if outcome == ClaudeRequestCensusInsert::Stored {
            self.account(shard, before);
        }
        outcome
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if key.starts_with("ever:")
            || key.starts_with("hold:body:")
            || self.census.get(key).is_none()
        {
            return;
        }
        if custody_key(key) {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
        }
        let Some(carrier) = self.census.carrier_key(key) else {
            return;
        };
        let shard = shard_of(&carrier);
        let before = self.census.serialized_total();
        self.census.remove(key);
        self.account(shard, before);
    }

    /// Remove and return `key`'s record (its buffers move to the caller).
    pub(crate) fn take(&mut self, key: &str) -> Option<ClaudeRequestCensusRecord> {
        let carrier = self.census.carrier_key(key)?;
        let shard = shard_of(&carrier);
        let before = self.census.serialized_total();
        let record = self.census.take(key)?;
        if custody_key(key) {
            self.custody_epoch = self.custody_epoch.wrapping_add(1);
        }
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
            for (key, record) in self.census.entries() {
                if Instant::now() >= deadline {
                    return None;
                }
                if key == CONTROL {
                    continue;
                }
                if let Some(buffer) = buffers.get_mut(&shard_of(key)) {
                    push_entry(buffer, key, &record);
                }
            }
        }
        let mut zero = zero_first.then(|| open(self.shard_bytes[META]));
        let mut current = meta_last.then(|| open(self.shard_bytes[META]));
        if Instant::now() >= deadline {
            return None;
        }
        if let Some(buffer) = current.as_mut() {
            let (_, control) = self
                .census
                .entries()
                .find(|(key, _)| key.as_str() == CONTROL)?;
            push_entry(buffer, CONTROL, &control);
        }
        if let Some(buffer) = zero.as_mut() {
            push_entry(buffer, CONTROL, &self.census.zero_control());
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

fn push_entry(buffer: &mut Vec<u8>, key: &str, record: &impl serde::Serialize) {
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
pub(super) fn zeroed(sweep: ClaudeLedgerSweep) -> ClaudeLedgerSweep {
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
    Recovery(Box<dyn FnOnce() + Send>, ShadowReservation),
}

enum Slot {
    Loading,
    /// A completed load could not admit its saved shards. Keep the refusal
    /// visible until ordinary collection permits another admission attempt.
    LoadRefused,
    Ready(Box<ClaudeLedger>),
    Busy(bool),
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
            Self::Recovery(_, allocation) => allocation.bytes(),
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
    /// No writer, another page holds it, or its load completed with refusal.
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
            ledgers.insert(support_dir.to_path_buf(), Slot::Busy(ledger.live_refused()));
            ClaudeLedgerAcquire::Ready(ClaudeLedgerGuard {
                support_dir: support_dir.to_path_buf(),
                ledger: Some(ledger),
            })
        }
        Some(Slot::LoadRefused) => {
            ledgers.insert(support_dir.to_path_buf(), Slot::LoadRefused);
            ClaudeLedgerAcquire::Unavailable
        }
        Some(slot @ (Slot::Loading | Slot::Busy(_))) => {
            let loading = matches!(slot, Slot::Loading);
            ledgers.insert(support_dir.to_path_buf(), slot);
            if loading {
                ClaudeLedgerAcquire::Loading
            } else {
                ClaudeLedgerAcquire::Unavailable
            }
        }
        None if !money_io!(Metadata, support_dir.join(LEDGER_DIR).exists())
            && !money_io!(Metadata, support_dir.join(LEGACY_LEDGER_DIR).exists()) =>
        {
            ledgers.insert(support_dir.to_path_buf(), Slot::Busy(false));
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
            Job::Recovery(operation, allocation) => {
                operation();
                QUEUED_BYTES.fetch_sub(allocation.bytes(), Ordering::AcqRel);
            }
            Job::Load(support_dir) => {
                let ledger = load(&support_dir);
                if let Ok(mut ledgers) = LEDGERS.lock() {
                    match ledger {
                        Some(ledger) => {
                            ledgers.insert(support_dir, Slot::Ready(Box::new(ledger)));
                        }
                        // This receipt is terminal, not another pending load.
                        // Keep disk custody untouched and permit ordinary
                        // collection before a new live admission attempt.
                        None => {
                            LOADS_REFUSED.fetch_add(1, Ordering::Relaxed);
                            ledgers.insert(support_dir, Slot::LoadRefused);
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

/// Recovery uses the existing bounded writer/outbox, never another worker or
/// a filesystem wait while the sync owner holds its lock.
pub(crate) fn recovery_job<T: Send + 'static>(
    bytes: usize,
    operation: impl FnOnce() -> T + Send + 'static,
) -> Option<Receiver<T>> {
    let funds = ShadowReservation::admit(bytes)?;
    let (done, result) = sync_channel(1);
    submit(Job::Recovery(
        Box::new(move || {
            let _ = done.send(operation());
        }),
        funds,
    ))
    .ok()?;
    Some(result)
}

pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
    let staged = path.with_extension("json.tmp");
    let written = money_io!(Open, std::fs::File::create(&staged)).and_then(|mut file| {
        money_io!(Write, file.write_all(bytes))?;
        money_io!(Sync, file.sync_all())
    });
    written
        .and_then(|()| money_io!(Mutate, std::fs::rename(&staged, path)))
        // Persist the name before any data shard can replace a zero meta.
        .and_then(|()| {
            let parent = money_io!(
                Open,
                std::fs::File::open(path.parent().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "ledger file has no parent",
                    )
                })?)
            )?;
            money_io!(Sync, parent.sync_all())
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
                jsonl: JsonlOutcome {
                    failed: 1,
                    ..JsonlOutcome::default()
                },
                memos: job.memos,
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
    if (jsonl.published || (jsonl.sealed > 0 && jsonl.failed == 0))
        && failed_shards.is_empty()
        && meta_unwritten.is_none()
    {
        if let Some(intent) = pending_intent {
            let _ = money_io!(Mutate, std::fs::remove_file(intent));
        }
    } else if let Some(now) = job_now(&pending_intent) {
        super::owe_coverage(&support_dir, now, true);
        if super::day_stamp(now).is_some_and(|day| {
            money_io!(
                Metadata,
                super::owed_path(&support_dir.join("diagnostics"), &day).exists()
            )
        }) {
            if let Some(intent) = pending_intent {
                let _ = money_io!(Mutate, std::fs::remove_file(intent));
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
    let mut blocked = money_io!(Mutate, std::fs::create_dir_all(dir)).is_err();
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
    if !money_io!(Metadata, dir.exists())
        && money_io!(Metadata, support_dir.join(LEGACY_LEDGER_DIR).exists())
    {
        let history_unknown = recover_legacy(support_dir, &mut ledger)?;
        ledger
            .census
            .mark_recovery(history_unknown || ledger.census.orphan_holds());
        ledger.load_damaged = true;
        ledger.dirty.fill(true);
        ledger.barrier_needed = true;
        ledger.recount_shards();
        return Some(ledger);
    }

    let mut missing = Vec::new();
    let mut present = 0_usize;
    let mut control_seen = false;
    let mut history_seen = false;
    for shard in 0..SHARDS {
        let limit = SAVE_BYTES_PER_PAGE as u64;
        let opened =
            money_io!(Open, std::fs::File::open(shard_path(&dir, shard))).and_then(|file| {
                let len = money_io!(Metadata, file.metadata())?.len();
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
                match money_io!(Read, file.take(limit + 1).read_to_end(&mut bytes)) {
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
        let decoded = super::custody::decode_shard(&bytes);
        let Some(decoded) = decoded else {
            ledger.load_damaged = true;
            ledger.dirty[shard] = true;
            continue;
        };
        let before = ledger.census.serialized_total();
        let mut damaged = false;
        for (key, value) in decoded {
            let is_control = key == CONTROL;
            let is_history = key == super::custody::EVER;
            if shard_of(&key) != shard || !ledger.census.absorb_entry(key, value.get(), max_records)
            {
                ledger.load_damaged = true;
                damaged = true;
            } else {
                control_seen |= is_control;
                history_seen |= is_history;
            }
        }
        ledger.account(shard, before);
        ledger.dirty[shard] = damaged;
    }
    if present > 0 && (!missing.is_empty() || !control_seen || !history_seen)
        || present == 0 && dir.exists()
    {
        ledger.load_damaged = true;
    }
    for shard in missing {
        ledger.dirty[shard] = true;
    }
    // A valid generation already published the legacy import, even while
    // its fresh traversal is unfinished. Keep per-file rebuild progress and
    // cleared fields across restart; only actual damage reopens old input.
    if ledger.load_damaged && money_io!(Metadata, support_dir.join(LEGACY_LEDGER_DIR).exists()) {
        let history_unknown = recover_legacy(support_dir, &mut ledger)?;
        ledger
            .census
            .mark_recovery(history_unknown || ledger.census.orphan_holds());
        ledger.dirty.fill(true);
        ledger.barrier_needed = true;
    }
    if ledger.load_damaged {
        ledger
            .census
            .mark_recovery(!history_seen && !support_dir.join(LEGACY_LEDGER_DIR).exists());
        ledger.dirty.fill(true);
        ledger.barrier_needed = true;
    }
    ledger.recount_shards();
    Some(ledger)
}

/// Import recovery input without changing its directory. Existing new-format
/// fields win; an earlier unbuilt clock/release and current-context route hold
/// cannot disappear merely because a migration was interrupted.
fn recover_legacy(support_dir: &Path, ledger: &mut ClaudeLedger) -> Option<bool> {
    let old = support_dir.join(LEGACY_LEDGER_DIR);
    let mut unknown = false;
    for shard in 0..SHARDS {
        let path = shard_path(&old, shard);
        let Ok(metadata) = money_io!(Metadata, std::fs::metadata(&path)) else {
            unknown = true;
            continue;
        };
        if metadata.len() as usize > SAVE_BYTES_PER_PAGE {
            unknown = true;
            continue;
        }
        let _funds = admit_waiting(load_charge(metadata.len() as usize))?;
        let Some(records) = money_io!(ReadFile, std::fs::read(&path))
            .ok()
            .and_then(|bytes| decode_ledger_shard(&bytes))
        else {
            unknown = true;
            continue;
        };
        for (key, record) in records.into_records() {
            if key.starts_with("unbuilt:") {
                if let Some(current) = ledger.get(&key) {
                    let released = (record.window() | current.window()) & super::UNBUILT_RELEASED;
                    let first = (record.window() & !super::UNBUILT_RELEASED)
                        .min(current.window() & !super::UNBUILT_RELEASED);
                    // Preserve the live revision/cycle while merging the irreversible
                    // release bit and earliest first-held clock from recovery input.
                    let merged = ClaudeRequestCensusRecord::money_debt(
                        current.money_revision(),
                        first | released,
                    );
                    if ledger.insert(key, merged) != ClaudeRequestCensusInsert::Stored {
                        unknown = true;
                    }
                    continue;
                }
            }
            let replace = match ledger.get(&key) {
                None => true,
                Some(current) if key.starts_with("unbuilt:") => {
                    (record.window() & !super::UNBUILT_RELEASED)
                        < (current.window() & !super::UNBUILT_RELEASED)
                        || record.window() & super::UNBUILT_RELEASED != 0
                            && current.window() & super::UNBUILT_RELEASED == 0
                }
                Some(current) if key.starts_with("adopt:entity:") && key.ends_with(":route") => {
                    record.window() > current.window()
                }
                _ => false,
            };
            if replace && ledger.insert(key, record) != ClaudeRequestCensusInsert::Stored {
                unknown = true;
            }
        }
    }
    let _funds = admit_waiting(ledger.census.record_count().saturating_mul(128))?;
    ledger.census.coalesce_recovered_holds();
    Some(unknown)
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
    // A restart waits for the writer to finish the queued saves and the
    // reload itself; a full ledger takes longer than one page's flush bound
    // in a debug build.
    let _flush = flush_timeout_for_test(Duration::from_secs(60));
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
    let ClaudeLedgerAcquire::Ready(mut ledger) = acquire(support_dir) else {
        return None;
    };
    // Run fixture code outside LEDGERS: a failing assertion must not poison
    // the daemon-wide registry and turn later independent controls unavailable.
    Some(read(&mut ledger))
}

/// Whether the ledger of `support_dir` is in custody recovery (a damaged
/// load whose rebuild has not completed).
#[cfg(test)]
pub(crate) fn recovering_for_test(support_dir: &Path) -> bool {
    with_ledger_for_test(support_dir, |ledger| ledger.recovering()).expect("the ledger is loaded")
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
    let carrier = Custody::default()
        .carrier_key(key)
        .unwrap_or_else(|| key.into());
    shard_path(&support_dir.join(LEDGER_DIR), shard_of(&carrier))
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
pub(crate) fn money_key(prefix: &str, index_key: &str) -> String {
    if let Some(root) = index_key.strip_prefix("synthetic:") {
        return format!("{prefix}otel:{root}");
    }
    if prefix == "watch:r:" && index_key.starts_with("otel:") {
        return format!("{prefix}{index_key}");
    }
    let index_key = if prefix == "watch:m:" {
        index_key.strip_prefix("mh:").unwrap_or(index_key)
    } else {
        index_key
    };
    format!("{prefix}{:x}", Sha256::digest(index_key.as_bytes()))
}

/// Only an actual writer/load receipt may suspend a live continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MoneyReceipt {
    Ready,
    Pending,
    Refused,
}

impl ClaudeLedger {
    /// An actual custody change or queued receipt, unlike diagnostic memo
    /// dirtiness. The initial empty-ledger barrier alone is not a prior job.
    pub(super) fn unacknowledged_custody(&self) -> bool {
        self.pending_checkpoint.is_some() || self.custody_epoch != self.durable_custody_epoch
    }

    fn live_refused(&self) -> bool {
        self.live_refused
    }

    pub(super) fn put_money(&mut self, key: String, record: ClaudeRequestCensusRecord) -> bool {
        if self.get(&key).is_some_and(|old| old.matches(&record)) {
            return true;
        }
        // Custody admission is transactional: it restores the previous field
        // on refusal. Taking first would drop an otherwise empty carrier's
        // logical binding and publication identity before every replacement.
        self.insert(key, record) == ClaudeRequestCensusInsert::Stored
    }
}

pub(crate) fn live_refused(support: &Path) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return true;
    };
    match ledgers.get(support) {
        Some(Slot::Ready(ledger)) => ledger.live_refused(),
        Some(Slot::Busy(refused)) => *refused,
        Some(Slot::LoadRefused) => true,
        _ => false,
    }
}

pub(crate) fn allow_live(support: &Path) {
    if let Ok(mut ledgers) = LEDGERS.lock() {
        if matches!(ledgers.get(support), Some(Slot::LoadRefused)) {
            // The saved ledger remains on disk; next admission loads it anew.
            ledgers.remove(support);
        } else if let Some(Slot::Ready(ledger)) = ledgers.get_mut(support) {
            ledger.live_refused = false;
        }
    }
}

pub(crate) fn refuse_live(support: &Path) {
    if let Ok(mut ledgers) = LEDGERS.lock() {
        if let Some(Slot::Ready(ledger)) = ledgers.get_mut(support) {
            // Reclamation or unrelated record shrinkage cannot skip the
            // ordinary-collection turn promised after terminal refusal.
            ledger.live_refused = true;
        }
    }
}

/// Complete a custody epoch before a new live offer or bound hold advances.
/// Diagnostic memos may keep changing while a receipt is in flight; they do
/// not invalidate durable due/dirty/offer/watch authority. A partial save or
/// failed shard never acknowledges the epoch. No caller-side disk wait.
///
/// The serialization walk covers every carrier of a ledger that may sit at
/// its record cap, so it gets the page budget the shadow uses for that walk.
pub(super) fn checkpoint(support_dir: &Path, ledger: &mut ClaudeLedger) -> bool {
    checkpoint_until(
        support_dir,
        ledger,
        Instant::now() + super::PAGE_MAX_ELAPSED,
    )
}

pub(super) fn checkpoint_until(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    deadline: Instant,
) -> bool {
    checkpoint_receipt_until(support_dir, ledger, deadline) == MoneyReceipt::Ready
}

pub(super) fn checkpoint_receipt(support_dir: &Path, ledger: &mut ClaudeLedger) -> MoneyReceipt {
    checkpoint_receipt_until(
        support_dir,
        ledger,
        Instant::now() + super::PAGE_MAX_ELAPSED,
    )
}

pub(super) fn checkpoint_receipt_until(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    deadline: Instant,
) -> MoneyReceipt {
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
                    ledger.promotion_pending = false;
                } else if !failed.is_empty() || meta.is_some() {
                    return MoneyReceipt::Refused;
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                ledger.pending_checkpoint = Some((wait, shards, meta, epoch, complete));
                return MoneyReceipt::Pending;
            }
            Err(_) => {
                ledger.restore(&shards, meta);
                return MoneyReceipt::Refused;
            }
        }
    }
    super::apply_results(
        support_dir,
        ledger,
        &mut super::ClaudeRequestMoneyShadowCounts::default(),
    );
    if !ledger.barrier_needed
        && ledger.custody_epoch == ledger.durable_custody_epoch
        && !(ledger.promotion_pending && ledger.dirty_shards() > 0)
    {
        return MoneyReceipt::Ready;
    }
    // Admit the boxed command and its directory before allocating either.
    let Some(allocation) = ShadowReservation::admit(
        std::mem::size_of::<CheckpointPayload>()
            .saturating_add(support_dir.as_os_str().len())
            .saturating_add(1024),
    ) else {
        return MoneyReceipt::Refused;
    };
    let saved = if ledger.dirty_shards() == 0 {
        ShadowReservation::admit(0).map(|reservation| (ClaudeLedgerSave::default(), reservation))
    } else {
        ledger.take_save(deadline)
    };
    let Some((save, reservation)) = saved else {
        return MoneyReceipt::Refused;
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
        return MoneyReceipt::Refused;
    }
    ledger.pending_checkpoint = Some((wait, shards, meta, epoch, complete));
    MoneyReceipt::Pending
}

#[cfg(test)]
pub(crate) fn checkpoint_for_test(support_dir: &Path, ledger: &mut ClaudeLedger) -> bool {
    for _ in 0..8 {
        let durable = checkpoint_receipt_until(
            support_dir,
            ledger,
            Instant::now() + Duration::from_secs(60),
        ) == MoneyReceipt::Ready;
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

pub(super) fn rebuild_due(support_dir: &Path, index_key: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support_dir) else {
        return false;
    };
    ledger.census.rebuild_needed(index_key)
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
    // Recovery reuses the existing due selector so unchanged saved files are
    // actually opened and rebuilt. Their holds/deadlines remain intact and
    // still gate literal submission; this grants only evidence collection.
    if ledger.census.rebuild_needed(index_key) {
        return true;
    }
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
            super::super::claude_request_census::decode_fingerprint(revision)
                == Some(record.money_revision())
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
    ledger.census.offer_count_for(key) > 0
}

pub(super) fn recovery_offer(
    support: &Path,
    key: &str,
    fingerprint: &str,
) -> Option<super::RecoveryOffer> {
    let ledgers = LEDGERS.lock().ok()?;
    let Slot::Ready(ledger) = ledgers.get(support)? else {
        return None;
    };
    if ledger.recovering() {
        return None;
    }
    let offer = ledger.get(&format!("{}:{fingerprint}", money_key("offer:", key)))?;
    Some((offer.money_revision(), offer.window()))
}

pub(super) fn recovery_debt_is_covered_in(
    ledger: &ClaudeLedger,
    key: &str,
    (revision, offered_at): super::RecoveryOffer,
) -> bool {
    !ledger.recovering()
        && ["dirty:", "due:"].iter().all(|prefix| {
            ledger.get(&money_key(prefix, key)).map_or(true, |debt| {
                debt.money_revision() == revision && debt.window() <= offered_at
            })
        })
}

pub(super) fn recovery_debt_is_covered(
    support: &Path,
    key: &str,
    offer: super::RecoveryOffer,
) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support) else {
        return false;
    };
    recovery_debt_is_covered_in(ledger, key, offer)
}

/// Selected-file proof must not discard an immutable offer binding while its
/// matching original debt still awaits the ordinary money settlement step.
pub(super) fn recovery_offer_debt_retired(
    support: &Path,
    key: &str,
    (revision, offered_at): super::RecoveryOffer,
) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return false;
    };
    let Some(Slot::Ready(ledger)) = ledgers.get(support) else {
        return false;
    };
    !ledger.recovering()
        && ["dirty:", "due:"].iter().all(|prefix| {
            ledger.get(&money_key(prefix, key)).map_or(true, |debt| {
                debt.money_revision() != revision || debt.window() > offered_at
            })
        })
}

#[cfg(test)]
pub(crate) fn recovery_debt_debug_for_test(support: &Path, key: &str) -> String {
    let ledgers = LEDGERS.lock().unwrap();
    let Some(Slot::Ready(ledger)) = ledgers.get(support) else {
        return "ledger_not_ready".into();
    };
    let debts = ["dirty:", "due:"].map(|prefix| {
        ledger
            .get(&money_key(prefix, key))
            .map(|r| (format!("{:02x?}", &r.money_revision()[..4]), r.window()))
    });
    format!("recovering={} debts={debts:?}", ledger.recovering())
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

pub(super) fn unresolved_adoption_context(support_dir: &Path) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return true;
    };
    match ledgers.get(support_dir) {
        Some(Slot::Ready(ledger)) => {
            ledger.load_damaged
                || ledger.recovering()
                || ledger.unacknowledged_custody()
                || ledger.barrier_needed
                || ledger.census().has_adoption_controls()
        }
        _ => true,
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
    if ledger.load_damaged
        || ledger.recovering()
        || ledger.unacknowledged_custody()
        || ledger.barrier_needed
    {
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
    // Legacy UNKNOWN-only rates are superseded by batch custody. A legacy
    // missing body is an unresolved outcome, never reconstructed for replay.
    let total = total & !(1_u64 << 63);
    let paused = total > 0
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
    !ledger.load_damaged
        && !ledger.recovering()
        && !ledger.unacknowledged_custody()
        && !ledger.barrier_needed
        && !ledger
            .get(&format!("{prefix}route"))
            .is_some_and(|record| record.window() > now)
        && ledger
            .get(&format!("{prefix}rates"))
            .is_some_and(|record| now >= record.window().saturating_add(1800))
}

pub(crate) fn recovery_released(support: &Path, lineage: &str) -> bool {
    let Ok(ledgers) = LEDGERS.lock() else {
        return true;
    };
    match ledgers.get(support) {
        Some(Slot::Ready(ledger)) => ledger
            .get(&format!("adopt:entity:recovery-release:{lineage}"))
            .is_some_and(|record| record.window() > 0),
        _ => true,
    }
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
    money_io!(Mutate, std::fs::create_dir_all(&dir)).ok()?;
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
    fn completed_load_refusal_enables_collection_then_recovers_without_losing_debt() {
        let _flush = flush_timeout_for_test(Duration::from_secs(10));
        let scratch = crate::test_scratch::ScratchDir::new("money-load-admission-receipt");
        let support = scratch.join("support");
        let _live = super::super::LiveForTest::new(&support);
        let ClaudeLedgerAcquire::Ready(mut ledger) = acquire(&support) else {
            panic!("new ledger");
        };
        assert!(ledger.put_money(
            "due:sentinel".into(),
            ClaudeRequestCensusRecord::money_debt([7; 32], 0)
        ));
        assert!(checkpoint_for_test(&support, &mut ledger));
        drop(ledger);
        forget_for_test(&support);
        let cap = ShadowReservation::admit(
            super::super::SHADOW_MEMORY_CEILING_BYTES - super::super::reserved_for_test(),
        )
        .unwrap();
        assert!(matches!(acquire(&support), ClaudeLedgerAcquire::Loading));
        flush(); // Actual saved-shard load exhausts the existing admission attempts.
        assert!(matches!(
            acquire(&support),
            ClaudeLedgerAcquire::Unavailable
        ));
        assert!(
            !super::super::request_owned_live(&support),
            "completed refusal selects ordinary collection"
        );
        assert_eq!(
            super::super::reclaim_metadata(&support, &crate::snapshots::ScanIndex::default()),
            MoneyReceipt::Refused
        );
        assert!(
            matches!(
                LEDGERS.lock().unwrap().get(&support),
                Some(Slot::LoadRefused)
            ),
            "polling cannot silently enqueue another load"
        );
        drop(cap);
        assert!(
            !super::super::request_owned_live(&support),
            "resource release alone does not skip ordinary collection"
        );
        allow_live(&support); // The actual finish calls this after ordinary success.
        assert!(matches!(acquire(&support), ClaudeLedgerAcquire::Loading));
        flush();
        let ClaudeLedgerAcquire::Ready(ledger) = acquire(&support) else {
            panic!("recovered load");
        };
        assert_eq!(
            ledger.get("due:sentinel").unwrap().money_revision(),
            [7; 32],
            "refused loading never replaces disk custody with an empty ledger"
        );
        drop(ledger);
        forget_for_test(&support);
    }

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
        money_io!(Mutate, std::fs::create_dir_all(&blocked)).unwrap();
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
