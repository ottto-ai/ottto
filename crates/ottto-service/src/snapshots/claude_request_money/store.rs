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
//! Crash order: a meta change that adds telemetry debt (a lost certificate)
//! is written before any data shard of its batch; a meta change that
//! advances a sweep is written only after every data shard is on disk. So a
//! saved `complete_through` never covers a record the disk does not hold.
//! A missing or corrupt shard at load is debt, never a silent loss.
//!
//! One writer thread does every file write of the shadow (diagnostics JSONL
//! and ledger shards) and the ledger load, outside `SNAPSHOT_SYNC_LOCK`. Its
//! outbox is bounded; each batch carries the admission of its own buffers.
//! A full outbox drops the batch (counted; its shards stay dirty and its
//! memos never move). Results come back to the next page.

use super::super::claude_request_census::{
    decode_ledger_shard, ClaudeRequestCensus, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    SWEEP_KEY_PREFIX,
};
use super::{ClaudeFamilyMemo, JsonlBatch, JsonlOutcome, ShadowReservation};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

pub(crate) const LEDGER_DIR: &str = "claude-request-ledger";
const DATA_SHARDS: usize = 256;
/// The meta shard's slot (the `sweep:` records).
const META: usize = DATA_SHARDS;
const SHARDS: usize = DATA_SHARDS + 1;
/// Batches waiting for the writer.
const OUTBOX: usize = 4;
/// Dirty shard bytes one page serializes (at least one shard).
const SAVE_BYTES_PER_PAGE: usize = 8 * 1024 * 1024;

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
    /// The meta shard carries new debt: written before any data shard.
    meta_debt: bool,
    /// Families whose memo is in a batch not yet acknowledged.
    pending_families: BTreeSet<String>,
    /// Where the next page's bounded save starts (fair rotation).
    next_save: usize,
    /// The load found a missing or corrupt shard.
    pub(crate) load_damaged: bool,
    /// Where the `mh:` round-robin resumes (process memory only: pruning
    /// is housekeeping, a stale record is never a holder).
    pub(crate) message_cursor: String,
}

impl ClaudeLedger {
    fn empty(dirty: bool) -> Self {
        Self {
            census: ClaudeRequestCensus::default(),
            shard_bytes: vec![0; SHARDS],
            dirty: vec![dirty; SHARDS],
            meta_debt: false,
            pending_families: BTreeSet::new(),
            next_save: 0,
            load_damaged: false,
            message_cursor: String::new(),
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

    /// The meta shard now carries debt (a lost certificate): it is written
    /// before the data shards of the batch that carries it.
    pub(crate) fn note_meta_debt(&mut self) {
        self.meta_debt = true;
        self.dirty[META] = true;
    }

    pub(crate) fn family_pending(&self, key: &str) -> bool {
        self.pending_families.contains(key)
    }

    pub(crate) fn dirty_shards(&self) -> usize {
        self.dirty.iter().filter(|dirty| **dirty).count()
    }

    /// Serialize the dirty shards of this page's bounded save. The data
    /// shards come in a fair rotation up to `SAVE_BYTES_PER_PAGE` (at least
    /// one); the meta shard rides first when it carries debt, last when no
    /// data shard stays dirty, else it waits. None when nothing is dirty or
    /// its buffers are not admitted (everything stays dirty).
    pub(crate) fn take_save(&mut self) -> Option<(ClaudeLedgerSave, ShadowReservation)> {
        let mut selected = vec![false; SHARDS];
        let mut bytes = 0_usize;
        let mut count = 0_usize;
        let start = self.next_save;
        for step in 0..DATA_SHARDS {
            let shard = (start + step) % DATA_SHARDS;
            if !self.dirty[shard] {
                continue;
            }
            let need = self.shard_bytes[shard] + 2;
            if count > 0 && bytes + need > SAVE_BYTES_PER_PAGE {
                break;
            }
            selected[shard] = true;
            bytes += need;
            count += 1;
            self.next_save = (shard + 1) % DATA_SHARDS;
        }
        let data_left = (0..DATA_SHARDS).any(|shard| self.dirty[shard] && !selected[shard]);
        let meta = self.dirty[META] && (self.meta_debt || !data_left);
        if meta {
            selected[META] = true;
            bytes += self.shard_bytes[META] + 2;
            count += 1;
        }
        if count == 0 {
            return None;
        }
        let reservation = ShadowReservation::admit(bytes)?;
        let mut buffers = BTreeMap::<usize, Vec<u8>>::new();
        for (shard, chosen) in selected.iter().enumerate() {
            if *chosen {
                let mut buffer = Vec::with_capacity(self.shard_bytes[shard] + 2);
                buffer.push(b'{');
                buffers.insert(shard, buffer);
            }
        }
        for (key, record) in self.census.records() {
            let Some(buffer) = buffers.get_mut(&shard_of(key)) else {
                continue;
            };
            if buffer.len() > 1 {
                buffer.push(b',');
            }
            // Writing into a Vec cannot fail; a failure would only shorten
            // the shard, which its load then rejects as corrupt.
            let _ = serde_json::to_writer(&mut *buffer, key);
            buffer.push(b':');
            let _ = serde_json::to_writer(&mut *buffer, record);
        }
        let mut save = ClaudeLedgerSave::default();
        for (shard, mut buffer) in buffers {
            buffer.push(b'}');
            self.dirty[shard] = false;
            if shard != META {
                save.shards.push((shard, buffer));
            } else if self.meta_debt {
                save.meta_first = Some(buffer);
            } else {
                save.meta_last = Some(buffer);
            }
        }
        save.meta_debt = std::mem::take(&mut self.meta_debt) && save.meta_first.is_some();
        Some((save, reservation))
    }

    /// A batch that did not reach the disk: its shards are dirty again and
    /// its memos never moved.
    fn restore(&mut self, failed_shards: &[usize], meta: Option<bool>, memos: &[PendingMemo]) {
        for shard in failed_shards {
            self.dirty[*shard] = true;
        }
        if let Some(debt) = meta {
            self.dirty[META] = true;
            self.meta_debt |= debt;
        }
        for memo in memos {
            self.pending_families.remove(&memo.key);
        }
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

enum Job {
    Load(PathBuf),
    Write(Box<WriteJob>),
    #[cfg(test)]
    Flush(SyncSender<()>),
}

enum Slot {
    Loading,
    Ready(Box<ClaudeLedger>),
    Busy,
}

static LEDGERS: Mutex<BTreeMap<PathBuf, Slot>> = Mutex::new(BTreeMap::new());
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

fn submit(job: Job) -> Result<(), Job> {
    let Some(sender) = writer() else {
        return Err(job);
    };
    let Ok(sender) = sender.lock() else {
        return Err(job);
    };
    sender.try_send(job).map_err(|error| match error {
        TrySendError::Full(job) | TrySendError::Disconnected(job) => job,
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

/// Hand a page's batch to the writer; marks its memos pending. On a full
/// outbox the batch comes back (the caller restores the ledger).
pub(crate) fn submit_batch(ledger: &mut ClaudeLedger, job: WriteJob) -> Result<(), Box<WriteJob>> {
    let keys = job
        .memos
        .iter()
        .map(|memo| memo.key.clone())
        .collect::<Vec<_>>();
    match submit(Job::Write(Box::new(job))) {
        Ok(()) => {
            ledger.pending_families.extend(keys);
            Ok(())
        }
        Err(Job::Write(job)) => {
            if let Some(save) = &job.save {
                let failed = save
                    .shards
                    .iter()
                    .map(|(shard, _)| *shard)
                    .collect::<Vec<_>>();
                let meta = (save.meta_first.is_some() || save.meta_last.is_some())
                    .then_some(save.meta_debt);
                ledger.restore(&failed, meta, &[]);
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
    let results = RESULTS
        .lock()
        .ok()
        .and_then(|mut results| results.remove(support_dir))
        .unwrap_or_default();
    for result in &results {
        ledger.restore(&result.failed_shards, result.meta_unwritten, &result.memos);
    }
    results
}

fn run_writer(receiver: Receiver<Job>) {
    // Shards whose last write failed, per support directory: no sweep
    // advance is written over them.
    let mut failed = BTreeMap::<PathBuf, BTreeSet<usize>>::new();
    while let Ok(job) = receiver.recv() {
        match job {
            Job::Load(support_dir) => {
                let ledger = load(&support_dir);
                if let Ok(mut ledgers) = LEDGERS.lock() {
                    ledgers.insert(support_dir, Slot::Ready(Box::new(ledger)));
                }
            }
            Job::Write(job) => {
                let failed = failed.entry(job.support_dir.clone()).or_default();
                let (support_dir, result) = write(*job, failed);
                if let Ok(mut results) = RESULTS.lock() {
                    results.entry(support_dir).or_default().push(result);
                }
            }
            #[cfg(test)]
            Job::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
    let staged = path.with_extension("json.tmp");
    let written = std::fs::File::create(&staged).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    written
        .and_then(|()| std::fs::rename(&staged, path))
        .is_ok()
}

fn write(job: WriteJob, failed: &mut BTreeSet<usize>) -> (PathBuf, WriteResult) {
    let WriteJob {
        support_dir,
        jsonl,
        memos,
        save,
        reservations,
    } = job;
    let jsonl = super::write_jsonl(&support_dir, &jsonl);
    let (failed_shards, meta_unwritten) = save.map_or((Vec::new(), None), |save| {
        write_save(&support_dir.join(LEDGER_DIR), &save, failed)
    });
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
    failed: &mut BTreeSet<usize>,
) -> (Vec<usize>, Option<bool>) {
    let mut unwritten = Vec::new();
    let mut meta_unwritten = None;
    let mut blocked = std::fs::create_dir_all(dir).is_err();
    if let Some(meta) = &save.meta_first {
        if blocked || !write_atomic(&shard_path(dir, META), meta) {
            blocked = true;
            meta_unwritten = Some(save.meta_debt);
        }
    }
    for (shard, bytes) in &save.shards {
        if !blocked && write_atomic(&shard_path(dir, *shard), bytes) {
            failed.remove(shard);
        } else {
            failed.insert(*shard);
            unwritten.push(*shard);
        }
    }
    if let Some(meta) = &save.meta_last {
        if blocked || !failed.is_empty() || !write_atomic(&shard_path(dir, META), meta) {
            meta_unwritten = Some(false);
        }
    }
    (unwritten, meta_unwritten)
}

/// Read every shard. A shard that is missing (when anything was saved),
/// unreadable, malformed, lossy or holding a foreign key is damage: the
/// ledger marks it and the shadow drops its telemetry certificate.
fn load(support_dir: &Path) -> ClaudeLedger {
    let dir = support_dir.join(LEDGER_DIR);
    let mut ledger = ClaudeLedger::empty(false);
    let mut missing = Vec::new();
    let mut present = 0_usize;
    for shard in 0..SHARDS {
        let bytes = match std::fs::File::open(shard_path(&dir, shard)) {
            Ok(file) => {
                let mut bytes = Vec::new();
                let limit = super::super::claude_request_census::MAX_RAW_BYTES as u64 + 1;
                match file.take(limit).read_to_end(&mut bytes) {
                    Ok(_) => bytes,
                    Err(_) => {
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
        if !ledger.census.absorb(decoded) {
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
    ledger
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
/// crash order); `failed` is the directory's failed-shard memory. Returns
/// (shards in the save, the meta went first, shards not written).
#[cfg(test)]
pub(crate) fn save_page_for_test(
    support_dir: &Path,
    ledger: &mut ClaudeLedger,
    failed: &mut BTreeSet<usize>,
) -> Option<(usize, bool, usize)> {
    let (save, _reservation) = ledger.take_save()?;
    let (unwritten, meta) = write_save(&support_dir.join(LEDGER_DIR), &save, failed);
    ledger.restore(&unwritten, meta, &[]);
    Some((save.shards(), save.meta_first.is_some(), unwritten.len()))
}

#[cfg(test)]
pub(crate) fn load_for_test(support_dir: &Path) -> ClaudeLedger {
    load(support_dir)
}

#[cfg(test)]
pub(crate) fn shard_path_for_test(support_dir: &Path, key: &str) -> PathBuf {
    shard_path(&support_dir.join(LEDGER_DIR), shard_of(key))
}
