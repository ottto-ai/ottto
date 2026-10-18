//! Resumable Codex reads. One RAM job slot is shared by background and manual
//! scans: a Codex singleton larger than the per-page budget is read across
//! pages by pausing its native parser here between scan objects. Per-page
//! byte budgets bound both that cursor job and the ordinary singleton reads.
//! A held-singleton memo skips re-reading a file whose hold an append cannot
//! cure. Nothing here retains transcript bytes or decoded rows beyond the
//! paused parser's own bounded state; every resident byte is charged once in
//! `SharedCache::heap_bound`.
use super::super::*;
use super::{SharedCache, STATE_BYTES};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::Scope;
use std::os::unix::fs::FileExt;

/// Decoded bytes one cursor job may consume per page (B).
const CURSOR_PASS_BYTES: u64 = 64 * 1024 * 1024;
/// Aggregate decoded bytes per page for ordinary Codex singleton reads
/// (B_s = B; no further constant).
const SINGLETON_PASS_BYTES: u64 = CURSOR_PASS_BYTES;
/// A cursor read's overlong-line skip yields after this many skipped bytes.
const SKIP_CHUNK_BYTES: usize = 1024 * 1024;
/// Consecutive invalidations of one cursor job key after which that file is
/// read unpaged again, exactly as before (the pre-certificate floor).
const MAX_JOB_INVALIDATIONS: u32 = 3;
const INVALIDATION_KEYS: usize = 64;
const MEMO_ENTRIES: usize = 256;
const WITNESS_BYTES: u64 = 4 * 1024;
/// Bumped when a join or singleton proof rule changes; it is part of every
/// memo key, so a bump wakes every memoized hold without a timed retry.
const CODEX_JOIN_PROOF_VERSION: &str = "codex_join_proof:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct Limits {
    cursor: u64,
    singleton: u64,
    skip_chunk: usize,
}

impl Limits {
    pub(in crate::snapshots) fn current() -> Self {
        #[cfg(test)]
        if let Some(limits) = TEST_LIMITS.with(std::cell::Cell::get) {
            return limits;
        }
        Self {
            cursor: CURSOR_PASS_BYTES,
            singleton: SINGLETON_PASS_BYTES,
            skip_chunk: SKIP_CHUNK_BYTES,
        }
    }
}

#[cfg(test)]
thread_local! {
    static TEST_LIMITS: std::cell::Cell<Option<Limits>> = const { std::cell::Cell::new(None) };
}

/// Scaled budgets for tests only; production constants are never changed.
#[cfg(test)]
pub(in crate::snapshots) fn with_test_limits<T>(
    cursor: u64,
    singleton: u64,
    skip_chunk: usize,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_LIMITS.with(|limits| limits.set(None));
        }
    }
    TEST_LIMITS.with(|limits| {
        limits.set(Some(Limits {
            cursor,
            singleton,
            skip_chunk,
        }))
    });
    let _reset = Reset;
    run()
}

/// Decoded bytes consumed in this scan object (one page).
#[derive(Debug, Default)]
pub(in crate::snapshots) struct PageBudget {
    cursor_decoded: u64,
    singleton_decoded: u64,
}
crate::heap_layout_bound::fields!(PageBudget; cursor_decoded, singleton_decoded);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum StartPlan {
    /// Ordinary in-page read, charged to the singleton budget.
    Singleton,
    /// Paged `SingletonFull` job in the shared slot, charged to the cursor.
    Cursor,
    /// Back to `pending_candidates` with its original selection flags.
    Defer,
}

impl PageBudget {
    pub(in crate::snapshots) fn charge(&mut self, cursor: bool, bytes: u64) {
        let counter = if cursor {
            &mut self.cursor_decoded
        } else {
            &mut self.singleton_decoded
        };
        *counter = counter.saturating_add(bytes);
    }

    pub(in crate::snapshots) fn cursor_exhausted(&self, limits: Limits) -> bool {
        self.cursor_decoded >= limits.cursor
    }

    /// `expected` is the read this file needs now: its length for a full
    /// read, the appended extent for a tail, zero when unchanged.
    pub(in crate::snapshots) fn plan(
        &self,
        limits: Limits,
        expected: u64,
        slot_free: bool,
        paging_given_up: bool,
    ) -> StartPlan {
        if expected > limits.singleton {
            if paging_given_up {
                StartPlan::Singleton
            } else if slot_free && !self.cursor_exhausted(limits) {
                StartPlan::Cursor
            } else {
                StartPlan::Defer
            }
        } else if expected == 0
            || self.singleton_decoded.saturating_add(expected) <= limits.singleton
        {
            StartPlan::Singleton
        } else {
            StartPlan::Defer
        }
    }
}

/// Opened-object facts of the held descriptor, captured at job open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct OpenStamp {
    dev: u64,
    ino: u64,
    extent: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
crate::heap_layout_bound::fields!(OpenStamp; dev, ino, extent, modified, changed);

impl OpenStamp {
    pub(in crate::snapshots) fn capture(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            extent: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    /// Same object, no shrink, and no equal-length in-place change. Growth
    /// is compatible: appended bytes are outside the frozen extent.
    fn append_compatible(&self, now: &Self) -> bool {
        self.dev == now.dev && self.ino == now.ino && (now.extent > self.extent || now == self)
    }
}

/// Cursor job facts carried by the active file between pages.
#[derive(Debug)]
pub(in crate::snapshots) struct JobMeta {
    key: String,
    namespace: String,
    stamp_open: OpenStamp,
    dependencies: Option<String>,
    owner: Option<String>,
    counting: &'static str,
    pages: u32,
}
crate::heap_layout_bound::fields!(JobMeta; key, namespace, stamp_open, dependencies, owner,
    counting, pages);

impl JobMeta {
    pub(in crate::snapshots) fn stamp_open(&self) -> &OpenStamp {
        &self.stamp_open
    }
}

/// The counting decision recorded at job start and compared at every resume
/// (revalidation item 8). Every Codex session counts under the legacy rule
/// until the counting writer's version decision is on `main`; that change
/// replaces this function and nothing else here.
fn counting_decision(_accumulator: &SnapshotAccumulator) -> &'static str {
    "legacy"
}

/// Exactly one paused job exists process-wide.
enum Slot {
    Empty,
    Paused(Box<OwnedActiveFile>),
    ActiveElsewhere { token: u64 },
}

#[derive(Debug, Default)]
struct Counters {
    jobs_started: u64,
    jobs_paused: u64,
    jobs_resumed: u64,
    jobs_completed: u64,
    jobs_invalidated: u64,
    jobs_lost: u64,
    unpaged_fallbacks: u64,
    deferred: u64,
    memo_hits: u64,
    memo_records: u64,
}
crate::heap_layout_bound::fields!(Counters; jobs_started, jobs_paused, jobs_resumed,
    jobs_completed, jobs_invalidated, jobs_lost, unpaged_fallbacks, deferred, memo_hits,
    memo_records);

pub(in crate::snapshots) struct CursorState {
    slot: Slot,
    slot_key: Option<String>,
    /// Requested-layout charge of the paused job, measured when it paused.
    slot_charge: usize,
    next_token: u64,
    memo: SingletonMemo,
    invalidations: BTreeMap<String, u32>,
    counters: Counters,
}

impl Default for CursorState {
    fn default() -> Self {
        Self {
            slot: Slot::Empty,
            slot_key: None,
            slot_charge: 0,
            next_token: 1,
            memo: SingletonMemo::default(),
            invalidations: BTreeMap::new(),
            counters: Counters::default(),
        }
    }
}

impl HeapLayoutBound for CursorState {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            slot,
            slot_key,
            slot_charge,
            next_token,
            memo,
            invalidations,
            counters,
        } = self;
        // The paused job was walked once when it paused; its charge stays
        // fixed while it sits here because nothing mutates a paused parser.
        match slot {
            Slot::Empty | Slot::ActiveElsewhere { .. } => c.add(0)?,
            Slot::Paused(_) => c.add(*slot_charge)?,
        }
        slot_key.heap_bound(c)?;
        next_token.heap_bound(c)?;
        memo.heap_bound(c)?;
        invalidations.heap_bound(c)?;
        counters.heap_bound(c)
    }
}

/// Ownership of the slot by one scan object while its job is active there.
/// Dropping an armed lease (a dropped scan frame) frees the slot; the job's
/// path is still in `pending_candidates`, so the next page restarts it.
pub(in crate::snapshots) struct CursorLease {
    cache: Arc<SharedCache>,
    token: u64,
    armed: bool,
}

impl HeapLayoutBound for CursorLease {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // The shared cache is charged once, through the scan's sampling context.
        c.add(0)
    }
}

impl Drop for CursorLease {
    fn drop(&mut self) {
        if self.armed {
            self.cache.with_cursor(|cursor| {
                if matches!(cursor.slot, Slot::ActiveElsewhere { token } if token == self.token) {
                    cursor.slot = Slot::Empty;
                    cursor.slot_key = None;
                    cursor.counters.jobs_lost += 1;
                }
            });
        }
    }
}

impl CursorLease {
    /// Park the job in the slot until a later page resumes it. Returns the
    /// job when its charge cannot be bounded; the caller then reads on
    /// unpaged, as before, instead of holding an unbounded paused state.
    pub(in crate::snapshots) fn pause(
        mut self,
        mut job: OwnedActiveFile,
    ) -> std::result::Result<(), Box<(Self, OwnedActiveFile)>> {
        // Live source-wide inputs are reinstalled from the resuming scan.
        let inputs = job.parser.take_live_reduction_inputs();
        let Some(charge) = crate::heap_layout_bound::bound(&job, STATE_BYTES) else {
            job.parser.restore_live_reduction_inputs(inputs);
            self.cache
                .with_cursor(|cursor| cursor.counters.unpaged_fallbacks += 1);
            return Err(Box::new((self, job)));
        };
        drop(inputs);
        if let Some(meta) = job.cursor.as_mut() {
            meta.pages = meta.pages.saturating_add(1);
        }
        let token = self.token;
        let mut job = Some(job);
        self.cache.with_cursor(|cursor| {
            if matches!(cursor.slot, Slot::ActiveElsewhere { token: held } if held == token) {
                cursor.slot = Slot::Paused(Box::new(job.take().expect("job moved once")));
                cursor.slot_charge = charge;
                cursor.counters.jobs_paused += 1;
            }
        });
        self.armed = false;
        match job {
            // The slot no longer names this lease (it cannot happen while the
            // lease is armed); keep the bytes read instead of discarding them.
            Some(mut job) => {
                if let Some(meta) = job.cursor.as_mut() {
                    meta.pages = meta.pages.saturating_sub(1);
                }
                Err(Box::new((self, job)))
            }
            None => Ok(()),
        }
    }

    /// The job reached EOF (whatever the publication outcome). `clean` is
    /// false when the source changed in a way this read cannot certify.
    pub(in crate::snapshots) fn complete(mut self, key: &str, clean: bool) {
        self.cache.with_cursor(|cursor| {
            if matches!(cursor.slot, Slot::ActiveElsewhere { token } if token == self.token) {
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
            }
            if clean {
                cursor.counters.jobs_completed += 1;
                cursor.invalidations.remove(key);
            } else {
                note_invalidation(cursor, key);
            }
        });
        self.armed = false;
    }
}

fn note_invalidation(cursor: &mut CursorState, key: &str) {
    cursor.counters.jobs_invalidated += 1;
    if !cursor.invalidations.contains_key(key) && cursor.invalidations.len() >= INVALIDATION_KEYS {
        // Bounded RAM: forgetting a count only grants that file three more
        // paged attempts before it falls back to the unpaged read.
        if let Some(oldest) = cursor.invalidations.keys().next().cloned() {
            cursor.invalidations.remove(&oldest);
        }
    }
    let count = cursor.invalidations.entry(key.to_owned()).or_default();
    *count = count.saturating_add(1);
}

impl SharedCache {
    fn with_cursor<T>(&self, run: impl FnOnce(&mut CursorState) -> T) -> Option<T> {
        self.cursor.lock().ok().map(|mut cursor| run(&mut cursor))
    }

    /// Requested-layout charge of the paused job, for insert admission.
    pub(super) fn cursor_charge(&self) -> usize {
        self.with_cursor(|cursor| match cursor.slot {
            Slot::Paused(_) => cursor.slot_charge,
            Slot::Empty | Slot::ActiveElsewhere { .. } => 0,
        })
        .unwrap_or(0)
    }

    /// Cache reset: drop a paused job and every memo entry. An active job
    /// keeps its slot; its lease releases it.
    pub(super) fn cursor_clear(&self) {
        self.with_cursor(|cursor| {
            if matches!(cursor.slot, Slot::Paused(_)) {
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
                cursor.slot_charge = 0;
                cursor.counters.jobs_lost += 1;
            }
            cursor.memo = SingletonMemo::default();
        });
    }

    pub(in crate::snapshots) fn cursor_slot_free(&self) -> bool {
        self.with_cursor(|cursor| matches!(cursor.slot, Slot::Empty))
            .unwrap_or(false)
    }

    /// The file a paused or active job owns. Selection must not read it as
    /// an ordinary file while the job exists.
    pub(in crate::snapshots) fn cursor_job_key(&self) -> Option<String> {
        self.with_cursor(|cursor| match cursor.slot {
            Slot::Empty => None,
            Slot::Paused(_) | Slot::ActiveElsewhere { .. } => cursor.slot_key.clone(),
        })
        .flatten()
    }

    pub(in crate::snapshots) fn cursor_paging_given_up(&self, key: &str) -> bool {
        self.with_cursor(|cursor| {
            cursor
                .invalidations
                .get(key)
                .is_some_and(|count| *count >= MAX_JOB_INVALIDATIONS)
        })
        .unwrap_or(false)
    }

    pub(in crate::snapshots) fn cursor_note_deferred(&self) {
        self.with_cursor(|cursor| cursor.counters.deferred += 1);
    }

    /// Start a `SingletonFull` job for `job`: claim the empty slot, freeze the
    /// extent and enable the chunked skip on its reader.
    pub(in crate::snapshots) fn cursor_start(
        self: &Arc<Self>,
        job: &mut OwnedActiveFile,
        namespace: &Scope,
        dependencies: Option<String>,
        owner: Option<String>,
    ) -> Option<CursorLease> {
        // Resume revalidates every priority decision; without the witness
        // set (unsampled or overflowed) the file is read unpaged instead.
        job.parser.accumulator.codex_observed_priority_turns.as_ref()?;
        let stamp_open = OpenStamp::capture(job.parser.reader.reader.get_ref()).ok()?;
        let key = local_index_key(&job.candidate.path);
        let token = self.with_cursor(|cursor| {
            if !matches!(cursor.slot, Slot::Empty) {
                return None;
            }
            let token = cursor.next_token;
            cursor.next_token = cursor.next_token.wrapping_add(1).max(1);
            cursor.slot = Slot::ActiveElsewhere { token };
            cursor.slot_key = Some(key.clone());
            cursor.counters.jobs_started += 1;
            Some(token)
        })??;
        let limits = Limits::current();
        job.parser.reader.set_chunked_skip(limits.skip_chunk);
        job.parser.reader.set_extent_limit(stamp_open.extent);
        job.cursor = Some(JobMeta {
            key,
            namespace: namespace.0.clone(),
            counting: counting_decision(&job.parser.accumulator),
            stamp_open,
            dependencies,
            owner,
            pages: 1,
        });
        Some(CursorLease {
            cache: Arc::clone(self),
            token,
            armed: true,
        })
    }

    /// Take the paused job for this scan namespace and claim the slot.
    pub(in crate::snapshots) fn cursor_resume(
        self: &Arc<Self>,
        namespace: &Scope,
    ) -> Option<(OwnedActiveFile, CursorLease)> {
        let (job, token) = self.with_cursor(|cursor| {
            let Slot::Paused(job) = &cursor.slot else {
                return None;
            };
            if job
                .cursor
                .as_ref()
                .map_or(true, |meta| meta.namespace != namespace.0)
            {
                // The account, destination or reduction settings changed
                // since the pause: that job can never resume. Free the slot;
                // its path is still pending, so this namespace restarts it.
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
                cursor.slot_charge = 0;
                cursor.counters.jobs_lost += 1;
                return None;
            }
            let token = cursor.next_token;
            cursor.next_token = cursor.next_token.wrapping_add(1).max(1);
            let Slot::Paused(job) =
                std::mem::replace(&mut cursor.slot, Slot::ActiveElsewhere { token })
            else {
                unreachable!("checked paused slot");
            };
            cursor.slot_charge = 0;
            cursor.counters.jobs_resumed += 1;
            Some((job, token))
        })??;
        Some((
            *job,
            CursorLease {
                cache: Arc::clone(self),
                token,
                armed: true,
            },
        ))
    }

    /// A resumed job failed revalidation: count it against its key and free
    /// the slot. Its path is still pending, so a later page restarts it.
    pub(in crate::snapshots) fn cursor_invalidate(&self, mut lease: CursorLease, key: &str) {
        self.with_cursor(|cursor| {
            if matches!(cursor.slot, Slot::ActiveElsewhere { token } if token == lease.token) {
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
            }
            note_invalidation(cursor, key);
        });
        lease.armed = false;
    }

    pub(in crate::snapshots) fn memo_lookup(&self, key: &str) -> Option<MemoEntry> {
        self.with_cursor(|cursor| cursor.memo.entries.get(key).cloned())
            .flatten()
    }

    pub(in crate::snapshots) fn memo_hit(&self, key: &str) {
        self.with_cursor(|cursor| {
            cursor.counters.memo_hits += 1;
            cursor.memo.touch(key);
        });
    }

    pub(in crate::snapshots) fn memo_record(&self, key: String, entry: MemoEntry) {
        self.with_cursor(|cursor| {
            if cursor.memo.insert(key, entry) {
                cursor.counters.memo_records += 1;
            }
        });
    }

    pub(in crate::snapshots) fn memo_forget(&self, key: &str) {
        self.with_cursor(|cursor| cursor.memo.remove(key));
    }
}

/// Return a page-selected Codex file to `pending_candidates` with the
/// selection flags it had, unless it is already pending.
pub(in crate::snapshots) fn requeue(
    index: &mut ScanIndex,
    flags: &BTreeMap<String, (bool, bool)>,
    candidate: &CandidateFile,
) {
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    if traversal
        .pending_candidates
        .iter()
        .any(|pending| pending.path == candidate.path)
    {
        return;
    }
    let (census_member, watcher_hint) = flags
        .get(&local_index_key(&candidate.path))
        .copied()
        .unwrap_or((true, false));
    traversal.pending_candidates.push_back(ScanTraversalPath {
        scan_root: candidate.scan_root.clone(),
        path: candidate.path.clone(),
        census_member,
        watcher_hint,
    });
}

/// The cursor attempt for this file ended in this page: remove the path that
/// held the census, as an ordinary read would have. Retries then follow the
/// existing residue and failure handling.
pub(in crate::snapshots) fn dequeue(index: &mut ScanIndex, candidate: &CandidateFile) {
    if let Some(traversal) = index.traversal.as_mut() {
        traversal
            .pending_candidates
            .retain(|pending| pending.path != candidate.path);
    }
}

/// Inventory members sharing this file's owner (1 for a singleton, 0 when
/// the file has no header witness).
pub(in crate::snapshots) fn owner_members(
    inventory: Option<&codex_file_join::HeaderInventory>,
    path: &Path,
) -> usize {
    let Some(inventory) = inventory else {
        return 0;
    };
    let Some(owner) = inventory.owner_for_path(path) else {
        return 0;
    };
    inventory
        .headers
        .iter()
        .filter(|header| header.owner == owner)
        .count()
}

/// Facts of the scan that resumes a paused job (revalidation checklist).
pub(in crate::snapshots) struct ResumeInputs<'a> {
    pub(in crate::snapshots) codex: &'a CodexTitleMetadata,
    pub(in crate::snapshots) claude: &'a ClaudeTitleMetadata,
    pub(in crate::snapshots) support: Option<&'a Path>,
    pub(in crate::snapshots) traces: Option<Arc<CodexTurnTraceMap>>,
    pub(in crate::snapshots) parents:
        Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    pub(in crate::snapshots) inventory: Option<&'a codex_file_join::HeaderInventory>,
    /// The acquisition scope recomputed under the resuming scan's index.
    pub(in crate::snapshots) scope: Option<Scope>,
}

/// Singleton subset of the revalidation checklist, run at every resume:
/// same object without shrink or in-place edit (growth is outside the frozen
/// extent), unchanged reduction dependencies and scope, still a singleton,
/// this cycle's traces and parent ledgers installed, every priority decision
/// so far still valid, and the same counting decision.
pub(in crate::snapshots) fn revalidate(
    job: &mut OwnedActiveFile,
    inputs: ResumeInputs<'_>,
) -> bool {
    let Some(meta) = job.cursor.as_ref() else {
        return false;
    };
    let Ok(now) = OpenStamp::capture(job.parser.reader.reader.get_ref()) else {
        return false;
    };
    if !meta.stamp_open.append_compatible(&now)
        || sampled_scan::reduction_dependencies(
            SnapshotSource::Codex,
            &job.candidate,
            inputs.codex,
            inputs.claude,
            inputs.support,
        ) != meta.dependencies
        || job.sampling.as_ref().map(|active| &active.scope) != inputs.scope.as_ref()
        || counting_decision(&job.parser.accumulator) != meta.counting
    {
        return false;
    }
    let Some(inventory) = inputs.inventory.filter(|inventory| inventory.complete) else {
        return false;
    };
    let members = inventory
        .headers
        .iter()
        .filter(|header| Some(&header.owner) == meta.owner.as_ref())
        .count();
    if meta.owner.is_some() && members > 1 {
        // A continuation appeared: the owner is now a group, never a singleton.
        return false;
    }
    let accumulator = &mut job.parser.accumulator;
    accumulator.codex_turn_traces = inputs.traces;
    accumulator.codex_parent_ownership_ledgers = inputs.parents;
    // A discarded witness set (too many turns) cannot prove earlier
    // priority decisions still hold: restart instead.
    accumulator
        .codex_observed_priority_turns
        .as_ref()
        .is_some_and(|observed| {
            observed.iter().all(|(turn, priority)| {
                *priority
                    == accumulator
                        .codex_turn_traces
                        .as_ref()
                        .is_some_and(|traces| traces.is_priority_turn(turn))
            })
        })
}

/// A hold whose cause no appended byte can remove: an ambiguous fork, or a
/// broken native ordinal stream. Both flags only ever move toward held.
pub(in crate::snapshots) fn held_monotone(accumulator: &SnapshotAccumulator) -> bool {
    match accumulator.codex_ownership_boundary {
        CodexOwnershipBoundary::AmbiguousFork => true,
        CodexOwnershipBoundary::NativeCreatedThread | CodexOwnershipBoundary::Ordinal { .. } => {
            !accumulator.codex_ordinal_sequence_valid
        }
        _ => false,
    }
}

/// Head and boundary samples before the refused offset. A sample match is a
/// premise, not an exact whole-prefix proof; a miss only costs a re-read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct LiveWitness {
    dev: u64,
    ino: u64,
    offset: u64,
    head: String,
    boundary: String,
}
crate::heap_layout_bound::fields!(LiveWitness; dev, ino, offset, head, boundary);

impl LiveWitness {
    pub(in crate::snapshots) fn read(file: &File, offset: u64) -> Option<Self> {
        let stamp = OpenStamp::capture(file).ok()?;
        if offset == 0 || stamp.extent < offset {
            return None;
        }
        let sample = |start: u64, end: u64| -> Option<String> {
            let mut bytes = vec![0_u8; usize::try_from(end - start).ok()?];
            file.read_exact_at(&mut bytes, start).ok()?;
            Some(format!("{:x}", Sha256::digest(&bytes)))
        };
        Some(Self {
            dev: stamp.dev,
            ino: stamp.ino,
            offset,
            head: sample(0, offset.min(WITNESS_BYTES))?,
            boundary: sample(offset.saturating_sub(WITNESS_BYTES), offset)?,
        })
    }
}

/// What a held singleton disclosed when it was parsed; a memo hit discloses
/// exactly this again through `disclose_terminal_codex_debt`.
#[derive(Clone, Debug)]
pub(in crate::snapshots) struct Disclosure {
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence: bool,
    pub(in crate::snapshots) state_only_blocked_session_ids: Vec<String>,
    pub(in crate::snapshots) diagnostic_reason: FileReason,
    pub(in crate::snapshots) parsed_snapshot_count: usize,
}
crate::heap_layout_bound::fields!(Disclosure; ownership_incomplete_file_count,
    zero_snapshot_usage_evidence, state_only_blocked_session_ids, diagnostic_reason,
    parsed_snapshot_count);

#[derive(Clone, Debug)]
pub(in crate::snapshots) struct MemoEntry {
    digest: String,
    live: LiveWitness,
    /// Parent ref and its ledger identity: a new or changed parent ledger
    /// is peer evidence that can cure an ambiguous-fork hold.
    parent: Option<(String, Option<String>)>,
    disclosure: Disclosure,
    /// Unix seconds at record. The witness samples cannot see an in-place
    /// repair elsewhere in the prefix, so a hit expires after the sampled
    /// audit interval and the file is read in full again.
    recorded_at: u64,
    used: u64,
    charge: usize,
}
crate::heap_layout_bound::fields!(MemoEntry; digest, live, parent, disclosure, recorded_at, used,
    charge);

impl MemoEntry {
    pub(in crate::snapshots) fn new(
        digest: String,
        live: LiveWitness,
        parent: Option<(String, Option<String>)>,
        disclosure: Disclosure,
    ) -> Self {
        Self {
            digest,
            live,
            parent,
            disclosure,
            recorded_at: super::now_seconds(),
            used: 0,
            charge: 0,
        }
    }

    pub(in crate::snapshots) fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }

    pub(in crate::snapshots) fn parent_ref(&self) -> Option<&str> {
        self.parent.as_ref().map(|(parent, _)| parent.as_str())
    }

    /// Every wake dependency is unchanged, the live witness still holds at
    /// the refused offset, and the entry is younger than the audit interval.
    /// Growth past that offset is a hit.
    pub(in crate::snapshots) fn matches(
        &self,
        digest: &str,
        file: &File,
        parent_ledger: Option<String>,
    ) -> bool {
        self.digest == digest
            && super::now_seconds().saturating_sub(self.recorded_at)
                < crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS
            && self
                .parent
                .as_ref()
                .map_or(true, |(_, ledger)| *ledger == parent_ledger)
            && LiveWitness::read(file, self.live.offset).as_ref() == Some(&self.live)
    }
}

#[derive(Default)]
struct SingletonMemo {
    entries: BTreeMap<String, MemoEntry>,
    clock: u64,
}

impl HeapLayoutBound for SingletonMemo {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // Entries carry the charge measured at insertion, so a cache-wide
        // walk stays one visit per entry under the shared visit limit.
        crate::heap_layout_bound::tree_nodes::<String, MemoEntry>(self.entries.len(), c)?;
        let bytes = self
            .entries
            .values()
            .try_fold(0_usize, |sum, entry| sum.checked_add(entry.charge))?;
        c.add(bytes)
    }
}

impl SingletonMemo {
    fn insert(&mut self, key: String, mut entry: MemoEntry) -> bool {
        self.clock = self.clock.wrapping_add(1);
        entry.used = self.clock;
        let Some(heap) =
            crate::heap_layout_bound::bound(&(key.clone(), entry.clone()), STATE_BYTES)
        else {
            // Unsupported layout or unbounded: hold no memo, keep re-reading.
            self.entries.remove(&key);
            return false;
        };
        entry.charge = heap.saturating_sub(std::mem::size_of::<(String, MemoEntry)>());
        self.entries.insert(key, entry);
        while self.entries.len() > MEMO_ENTRIES {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&victim);
        }
        true
    }

    fn touch(&mut self, key: &str) {
        self.clock = self.clock.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(key) {
            entry.used = self.clock;
        }
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

/// The memo key for a singleton: parser, identity and proof versions, the
/// file's logical key and opened `{dev, ino}` (never its growing length),
/// the receipt scope, the counting decision, and the wake dependencies
/// (path-scoped sidecar facts and header witness, the global sidecar census
/// flags, and how many inventory members its owner has).
#[allow(clippy::too_many_arguments)]
pub(in crate::snapshots) fn memo_digest(
    index: &ScanIndex,
    candidate: &CandidateFile,
    file: &File,
    dependencies: &str,
    codex: &CodexTitleMetadata,
    owner_members: usize,
    counting: &str,
) -> Option<String> {
    let stamp = OpenStamp::capture(file).ok()?;
    Some(sha256_hex(&[
        "codex_singleton_memo:v1",
        CODEX_JOIN_PROOF_VERSION,
        SnapshotSource::Codex.parser_version(),
        SnapshotSource::Codex.scan_identity_version(),
        &local_index_key(&candidate.path),
        &stamp.dev.to_string(),
        &stamp.ino.to_string(),
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none"),
        counting,
        dependencies,
        if codex.created_thread_census_unscoped_incomplete {
            "created_incomplete"
        } else {
            "created_complete"
        },
        if codex.state_census_unscoped_incomplete || codex.sidecar_census_unscoped_incomplete {
            "sidecar_incomplete"
        } else {
            "sidecar_complete"
        },
        &owner_members.to_string(),
    ]))
}

pub(in crate::snapshots) fn memo_counting_decision() -> &'static str {
    counting_decision(&SnapshotAccumulator::new(SnapshotSource::Codex))
}

/// The one writer of a held singleton's terminal-debt disclosure on a memo
/// hit. It records exactly what the native finish path records for the same
/// held parse: residue key, blocked owners, ownership-incomplete and
/// zero-usage counts, and an incomplete finalization entry. A different
/// census ruling for terminal debt changes this function only.
pub(in crate::snapshots) struct DisclosureTargets<'a> {
    pub(in crate::snapshots) census: &'a mut ScanCensus,
    pub(in crate::snapshots) residue_index_keys: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) residue_blocked_session_ids: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) codex_state_only_blocked_session_ids: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) pending_finalization: &'a mut Vec<PendingIndexFinalization>,
}

pub(in crate::snapshots) fn disclose_terminal_codex_debt(
    disclosure: &Disclosure,
    candidate: &CandidateFile,
    previous: (Option<String>, Option<String>),
    index: &mut ScanIndex,
    targets: DisclosureTargets<'_>,
) {
    let index_key = local_index_key(&candidate.path);
    targets.residue_index_keys.insert(index_key.clone());
    for session_id in &disclosure.state_only_blocked_session_ids {
        let session_id = resolve_codex_identity(session_id.as_str());
        targets
            .residue_blocked_session_ids
            .insert(session_id.clone());
        targets
            .codex_state_only_blocked_session_ids
            .insert(session_id.clone());
        index
            .codex_state_only_blocked_session_ids
            .insert(session_id);
    }
    targets.pending_finalization.push(PendingIndexFinalization {
        sampled_audit_verified: false,
        codex_pending_recovery: index
            .files
            .get(&index_key)
            .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
        index_key,
        source_file_fingerprint: candidate.source_file_fingerprint.clone(),
        previous_snapshot_fingerprint: previous.0,
        previous_upload_body_witness: previous.1,
        parse_complete: false,
        diagnostic_reason: disclosure.diagnostic_reason,
        parsed_snapshot_count: disclosure.parsed_snapshot_count,
        effective_upload_body_witness_revision: index.active_effective_upload_body_witness_revision,
    });
    targets.census.ownership_incomplete_file_count += disclosure.ownership_incomplete_file_count;
    targets.census.zero_snapshot_usage_evidence_count +=
        usize::from(disclosure.zero_snapshot_usage_evidence);
}

#[cfg(test)]
#[path = "codex_cursor_tests.rs"]
mod tests;
