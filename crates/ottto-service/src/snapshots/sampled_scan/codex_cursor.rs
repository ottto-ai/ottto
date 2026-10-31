//! Resumable Codex reads. One RAM job slot is shared by background and manual
//! scans: a Codex singleton larger than the per-page budget is read across
//! pages by pausing its native parser here between scan objects. Per-page
//! byte budgets bound both that cursor job and the ordinary singleton reads.
//! A finished job commits only through its sealed-prefix certificate
//! (`ReadPlan::commit_sealed_prefix`); a job that cannot pause within the
//! state budget ends as strict `JoinStateBound` debt, never as an unbounded
//! read. A held-singleton memo skips re-reading a file whose hold an append
//! cannot cure. Nothing here retains transcript bytes or decoded rows beyond
//! the paused parser's own bounded state; every resident byte is charged
//! once in `SharedCache::heap_bound`, and a copy refusal never drops the
//! paused job, the memo or the parked records.
//!
//! Large files take the slot in rotation (oldest waiter first, never-served
//! files ahead of served ones), and a file whose attempt completed in this
//! census generation is processed for it: its next large read waits for the
//! next generation, so no job holds the strict census open forever.
//!
//! The cursor is a build property: when `layout_supported()` is false no
//! job starts and every file reads in its page exactly as before.
use super::super::*;
use super::{SharedCache, STATE_BYTES};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::{
    AuditDebt, Checkpoint, FullReason, LossyPrefixIdentity, PrefixRefusal, Scope,
    AUDIT_INTERVAL_SECONDS, SAMPLE_BYTES,
};
use std::os::unix::fs::FileExt;

/// Decoded bytes one cursor job may consume per page (B).
const CURSOR_PASS_BYTES: u64 = 64 * 1024 * 1024;
/// Aggregate decoded bytes per page for ordinary Codex singleton reads
/// (B_s = B; no further constant).
const SINGLETON_PASS_BYTES: u64 = CURSOR_PASS_BYTES;
/// A cursor read's overlong-line skip yields after this many skipped bytes.
const SKIP_CHUNK_BYTES: usize = 1024 * 1024;
/// A live cursor job's copy-budget charge is walked again after this many
/// consumed bytes (E3): at most 16 walks per page (B / 4 MiB), plus the
/// pause and completion walks, against one per line before.
pub(in crate::snapshots) const CHARGE_REFRESH_BYTES: u64 = 4 * 1024 * 1024;
/// Consecutive invalidated attempts of one file after which its attempt ends
/// as strict `MemberChanged` debt (D2). Growth never invalidates: appended
/// bytes belong to the next tail; unavailable evidence never counts (K9).
const MEMBER_CHANGED_AFTER: u32 = 3;
const INVALIDATION_KEYS: usize = 64;
const PARKED_KEYS: usize = 64;
/// The paused reader buffer keeps at least this much capacity.
const PAUSED_BUFFER_BYTES: usize = 64 * 1024;
const MEMO_ENTRIES: usize = 256;
/// Bytes one memo lookup or record reads from the held file (head and
/// boundary samples). Charged to the page's singleton budget (M3).
pub(in crate::snapshots) const SAMPLE_READ_BYTES: u64 = 2 * SAMPLE_BYTES as u64;
/// A paused job is stale, and another namespace may evict it, once this many
/// cursor pages passed without its own namespace resuming it (K10).
const NAMESPACE_STALE_PAGES: u64 = 16;
/// U1a-2a (cc row 4, rev 6 §5.1): free room a proof step needs beyond the
/// scan's walked state and the running job's last walked charge.
pub(in crate::snapshots) const PROOF_STEP_HEADROOM_BYTES: usize = 1 << 20;
/// E2: a paused job whose revalidation evidence stays unavailable for this
/// many consecutive resume pages ends (slot freed, path processed for the
/// generation with a retryable cause, prior body kept). Small, like
/// `MEMBER_CHANGED_AFTER`: ending costs only the job's progress, while a
/// held slot starves every other large file.
const UNAVAILABLE_RESUMES: u32 = 3;
/// A deferred large file keeps its rotation turn while it was seen within
/// this many cursor pages; its first-wait page is forgotten after
/// `WAITER_FORGET_PAGES`.
const WAITER_ACTIVE_PAGES: u64 = 16;
const WAITER_FORGET_PAGES: u64 = 64;
const ROTATION_KEYS: usize = 64;
/// Owners with B's blocked-owner provenance (§d.1.3, L-1).
const JOIN_OWNERS: usize = 64;
/// Consecutive funding yields that alarm and make an archive's residue
/// `AdmissionStarved`.
const ARCHIVE_STARVED_YIELDS: u8 = 12;
/// Tracked archive streak keys; the lowest digest is forgotten past it.
const ARCHIVE_STREAK_KEYS: usize = 256;
/// Thread CPU an archive pass may spend across its ordinary and
/// continuation pages.
const ARCHIVE_PASS_CPU_MICROS: u64 = 30_000_000;
/// Consecutive passes with unknown thread CPU after which archive work
/// proceeds under the remaining page, power and work gates, alarmed per pass.
const ARCHIVE_UNKNOWN_CPU_PASSES: u32 = 12;
#[cfg(not(test))]
static UNKNOWN_CPU_PASSES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(test)]
thread_local! {
    static UNKNOWN_CPU_PASSES: std::sync::atomic::AtomicU32 =
        const { std::sync::atomic::AtomicU32::new(0) };
}
/// Process-wide RAM streak (the index reloads every pass); a test thread
/// keeps its own.
fn unknown_cpu_passes<T>(f: impl FnOnce(&std::sync::atomic::AtomicU32) -> T) -> T {
    #[cfg(test)]
    {
        UNKNOWN_CPU_PASSES.with(f)
    }
    #[cfg(not(test))]
    f(&UNKNOWN_CPU_PASSES)
}
/// Bumped when a join or singleton proof rule changes; it is part of every
/// memo key, so a bump wakes every memoized hold without a timed retry.
/// U1a-2a (D6(a)): also part of `codex_parent_proof_scope`.
pub(in crate::snapshots) const CODEX_JOIN_PROOF_VERSION: &str = "codex_join_proof:v2";

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

    /// Files above this size are read by the cursor, never as one pass.
    pub(in crate::snapshots) fn singleton(&self) -> u64 {
        self.singleton
    }

    /// U1a-2a (row 33): a resumable read's overlong-skip chunk (a proof
    /// job's readers use the cursor's).
    pub(in crate::snapshots) fn skip_chunk(&self) -> usize {
        self.skip_chunk
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

/// Stage 1 K8, tests only: [`with_test_limits`] for `snapshot_sync` tests.
#[cfg(test)]
pub(crate) fn with_test_limits_for_test<T>(
    cursor: u64,
    singleton: u64,
    skip_chunk: usize,
    run: impl FnOnce() -> T,
) -> T {
    with_test_limits(cursor, singleton, skip_chunk, run)
}

/// Stage 1 K8, tests only: the cursor byte budget in force on this thread,
/// so a test can tell which thread's test limits a page sees (W10).
#[cfg(test)]
pub(crate) fn cursor_limit_for_test() -> u64 {
    Limits::current().cursor
}

#[cfg(test)]
thread_local! {
    static TEST_STATE_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// The state budget a paused job must fit beside the cursor state (K6).
/// Tests may scale it down (`with_test_state_budget`); production never.
fn state_budget() -> usize {
    #[cfg(test)]
    if let Some(bytes) = TEST_STATE_BUDGET.with(std::cell::Cell::get) {
        return bytes;
    }
    STATE_BYTES
}

/// F4b: the one checked budget every cursor admission measures against:
/// the state budget less the side ledger's fixed heap reservation
/// (`side_ledger::SIDE_LEDGER_BYTES`), which `SharedCache::heap_bound` and
/// every retained insert also charge. A constant: no side-ledger lock is taken
/// under the retained or cursor lock. The ledger's inline tables are inside
/// `size_of::<SharedCache>()`, which none of these per-part sums measure, so
/// nothing is charged twice. `None` (a budget below the reservation): no
/// admission is feasible, so nothing is evicted.
fn admission_budget() -> Option<usize> {
    state_budget().checked_sub(super::side_ledger::SIDE_LEDGER_BYTES)
}

/// Scaled state budget for tests only (a pause that cannot fit).
#[cfg(test)]
pub(in crate::snapshots) fn with_test_state_budget<T>(bytes: usize, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_STATE_BUDGET.with(|budget| budget.set(None));
        }
    }
    TEST_STATE_BUDGET.with(|budget| budget.set(Some(bytes)));
    let _reset = Reset;
    run()
}

/// Decoded bytes consumed in this scan object (one page).
#[derive(Debug, Default)]
pub(in crate::snapshots) struct PageBudget {
    cursor_decoded: u64,
    singleton_decoded: u64,
    disabled_disclosed: bool,
    page_noted: bool,
    resume_claimed: bool,
    /// U1a-2a (rev 3 §2.4 step 0): the proof hook ran on this scan object.
    proof_claimed: bool,
    /// Process counters at this scan's page tick: the start of its
    /// diagnostics window (`SharedCache::cursor_diagnostics`). Boxed so the
    /// by-value scan object stays small.
    window_start: Option<Box<Counters>>,
    /// Resume-only frame: no selection, proof hook, side-due work or sweep.
    continuation: bool,
    /// Stage 1 (§6): a continuation page's ordinary interval
    /// (StateMissing's input); `None` is unknown coverage.
    ordinary_equivalent: Option<InlineDuration>,
    /// Stage 1 (K6): a continuation page's cooperative deadline, on the pace
    /// clock. Past it the pause arm pauses the job as at an exhausted budget,
    /// but no ticket is minted (`continuation_ticket` still requires the
    /// exhausted budget). Never set on an ordinary page.
    deadline: Option<InlineInstant>,
    /// G1: watcher hints this page's start enqueued as next-generation
    /// evidence, counted in `deferred_next_generation` at the page tick.
    next_generation_hints: u64,
}
crate::heap_layout_bound::fields!(PageBudget; cursor_decoded, singleton_decoded,
    disabled_disclosed, page_noted, resume_claimed, proof_claimed, window_start, continuation,
    ordinary_equivalent, deadline, next_generation_hints);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum StartPlan {
    /// Ordinary in-page read, charged to the singleton budget.
    Singleton,
    /// Paged `SingletonFull` job in the shared slot, charged to the cursor.
    Cursor,
    /// Back to `pending_candidates` with its original selection flags.
    Defer,
    /// Larger than the singleton budget on a build without the cursor:
    /// today's in-page read (C4).
    Unpaged,
    /// This file's cursor attempt already completed in this census
    /// generation (K7 fence): it is processed for this generation and its
    /// next large read waits for the next one, so it is not requeued.
    Fenced,
}

/// What the Stage 1 guard reads at a singleton's large start
/// (`SharedCache::cursor_plan_paced`): the file as opened now, and the index
/// whose receipt and replay scope keys its pace slot (`pace_key`).
#[derive(Clone, Copy)]
pub(in crate::snapshots) struct PaceProbe<'a> {
    pub(in crate::snapshots) file: &'a File,
    pub(in crate::snapshots) index: &'a ScanIndex,
}

/// Why `cursor_start` did not start a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum StartRefusal {
    /// Another scan object holds the slot: defer to a later page.
    Busy,
    /// No acquisition (owning header, state/sidecar census or reduction
    /// dependencies unavailable this page): defer as `InProgress`, never
    /// unreadable and never an unpaged read (K9).
    InputsUnavailable,
    /// The held file's stamp could not be read: a retryable read failure.
    Unstartable,
}

/// Archive catch-up pacing for one ordinary page and its continuation
/// pages: RAM-only on `ScanIndex`, carried by the continuation inputs, never
/// durable authority. A refusal never resets it; unknown CPU denies until
/// `ARCHIVE_UNKNOWN_CPU_PASSES` consecutive passes.
#[derive(Clone, Debug, Default)]
pub(crate) struct ArchivePass {
    pub(crate) started: bool,
    pub(crate) cpu: u64,
    pub(crate) work: u64,
    pub(crate) power: bool,
    /// A step of this pass had unknown thread CPU.
    pub(crate) cpu_unknown: bool,
    pub(crate) prep_after: Option<String>,
}
crate::heap_layout_bound::fields!(ArchivePass; started, cpu, work, power, cpu_unknown, prep_after);

impl ArchivePass {
    /// A new ordinary pass: fresh counters and the prepare-time power gate;
    /// the cached-archive walk position carries over.
    pub(crate) fn prepare(&mut self) {
        *self = Self {
            prep_after: self.prep_after.take(),
            power: crate::snapshot_sync::archive_power_ready(),
            ..Self::default()
        };
    }

    /// Archive work may start now: prepare-time and live power, the pass's
    /// CPU and work (continuation's contention threshold), and `remaining`
    /// page bytes.
    pub(crate) fn ready(&self, remaining: u64) -> bool {
        self.power
            && crate::snapshot_sync::archive_acquisition_power_ready(self.power)
            && self.cpu < ARCHIVE_PASS_CPU_MICROS
            && (!self.cpu_unknown
                || unknown_cpu_passes(|passes| passes.load(std::sync::atomic::Ordering::Relaxed))
                    >= ARCHIVE_UNKNOWN_CPU_PASSES)
            && remaining > 0
            && crate::snapshot_sync::archive_work_ready(self.work)
    }

    /// One step's thread CPU (`None`: unknown) and wall time. CPU counts
    /// once archive work started. Unknown CPU denies the pass; each such pass
    /// counts once, a known step resets the streak, and passes at or past
    /// the bound alarm and proceed under the remaining gates.
    pub(crate) fn observe(&mut self, cpu: Option<u64>, wall: u64) {
        match cpu {
            Some(cpu) => {
                unknown_cpu_passes(|passes| passes.store(0, std::sync::atomic::Ordering::Relaxed));
                if self.started {
                    self.cpu = self.cpu.saturating_add(cpu);
                }
            }
            None if !self.cpu_unknown => {
                self.cpu_unknown = true;
                let passes = unknown_cpu_passes(|passes| {
                    passes.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                })
                .saturating_add(1);
                if passes >= ARCHIVE_UNKNOWN_CPU_PASSES {
                    crate::local_resource_diagnostics::traversal_point(
                        "codex_zst_unknown_cpu_fallback",
                        "codex",
                        &serde_json::json!({"consecutive_unknown_cpu_passes": passes}),
                    );
                }
            }
            None => {}
        }
        self.work = self.work.saturating_add(wall);
    }
}

impl PageBudget {
    /// `ArchivePass::ready` with this page's singleton bytes.
    pub(in crate::snapshots) fn archive_ready(&self, pass: &ArchivePass) -> bool {
        pass.ready(self.singleton_remaining(Limits::current()))
    }
}

impl PageBudget {
    /// A page whose start enqueued `hints` watcher hints as next-generation
    /// evidence (G1).
    pub(in crate::snapshots) fn with_next_generation_hints(hints: u64) -> Self {
        Self {
            next_generation_hints: hints,
            ..Self::default()
        }
    }

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

    /// Stage 1 (K6): the pause arm's condition: the exhausted budget, or a
    /// continuation page past its deadline. An ordinary page has no
    /// deadline, so this is `cursor_exhausted` there.
    pub(in crate::snapshots) fn cursor_stop(&self, limits: Limits) -> bool {
        self.cursor_exhausted(limits) || self.deadline_passed()
    }

    /// Stage 1 (K6): a continuation page whose deadline has passed.
    pub(in crate::snapshots) fn deadline_passed(&self) -> bool {
        self.deadline
            .is_some_and(|InlineInstant(deadline)| pace_now() >= deadline)
    }

    /// Singleton-budget bytes this page may still read (group probes, R2-N2).
    pub(in crate::snapshots) fn singleton_remaining(&self, limits: Limits) -> u64 {
        limits.singleton.saturating_sub(self.singleton_decoded)
    }

    /// `expected` is the read this file needs now: its length for a full
    /// read, the appended extent for a tail, zero when unchanged.
    /// `cursor_enabled` is `layout_supported()`.
    pub(in crate::snapshots) fn plan(
        &self,
        limits: Limits,
        expected: u64,
        slot_free: bool,
        cursor_enabled: bool,
    ) -> StartPlan {
        if expected > limits.singleton {
            if !cursor_enabled {
                StartPlan::Unpaged
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

    /// Count `cursor_disabled_unsupported_layout` once per scan object.
    pub(in crate::snapshots) fn disclose_disabled(&mut self, cache: &SharedCache) {
        if !std::mem::replace(&mut self.disabled_disclosed, true) {
            cache.with_cursor(|cursor| cursor.counters.cursor_disabled_unsupported_layout += 1);
        }
    }

    /// At most one resume attempt per scan object (E2): true only the first
    /// time. A deferred job is never resumed again in the same page.
    pub(in crate::snapshots) fn claim_resume(&mut self) -> bool {
        !std::mem::replace(&mut self.resume_claimed, true)
    }

    /// U1a-2a (rev 3 §2.4 step 0, rev 11 §6.1): at most one proof hook per
    /// scan object: true only the first time.
    pub(in crate::snapshots) fn claim_proof(&mut self) -> bool {
        !std::mem::replace(&mut self.proof_claimed, true)
    }

    /// Stage 1 (E): this scan object is a continuation page.
    pub(in crate::snapshots) fn continuation(&self) -> bool {
        self.continuation
    }

    /// Stage 1 (E): mark this scan object a continuation page, before its
    /// first step, standing for `ordinary_equivalent` of the ordinary
    /// cadence (`None`: unknown, so its resumed attempt loses acceleration).
    pub(in crate::snapshots) fn set_continuation(
        &mut self,
        ordinary_equivalent: Option<std::time::Duration>,
    ) {
        self.continuation = true;
        self.ordinary_equivalent = ordinary_equivalent.map(InlineDuration);
    }

    /// Stage 1 (K6): a continuation page's cooperative deadline. Ignored on
    /// an ordinary page, which never has one.
    pub(in crate::snapshots) fn set_continuation_deadline(&mut self, deadline: std::time::Instant) {
        if self.continuation {
            self.deadline = Some(InlineInstant(deadline));
        }
    }

    /// Stage 1 (§6): the ordinary interval this continuation page stands for.
    pub(in crate::snapshots) fn ordinary_equivalent(&self) -> Option<std::time::Duration> {
        self.ordinary_equivalent
            .map(|InlineDuration(duration)| duration)
    }

    /// Advance the cursor page clock once per scan object (K7, K10). The
    /// diagnostics window opens under this same lock (no extra lock).
    ///
    /// Stage 1 (E): a continuation page opens its diagnostics window but
    /// never ticks the clock, so waiters keep their turn and a paused job's
    /// staleness counts ordinary pages only. It neither reads nor clears the
    /// proof-due record: a continuation page never reaches the proof hook.
    pub(in crate::snapshots) fn note_page(&mut self, cache: &SharedCache, namespace: &Scope) {
        if self.continuation {
            if !std::mem::replace(&mut self.page_noted, true) {
                self.window_start = cache.with_cursor(|cursor| {
                    let start = Box::new(cursor.counters);
                    cursor.counters.deferred_next_generation = cursor
                        .counters
                        .deferred_next_generation
                        .saturating_add(self.next_generation_hints);
                    start
                });
            }
            return;
        }
        if !std::mem::replace(&mut self.page_noted, true) {
            let mut skipped = false;
            self.window_start = cache.with_cursor(|cursor| {
                // U1a-2a (cc row 8): this namespace's previous page had proof
                // work due but never reached the proof hook. Another
                // namespace's page neither counts nor clears it. The count is
                // diagnostic only: no pacing or admission reads it.
                if let Some((due_namespace, reached)) = cursor.proof_due.as_mut() {
                    if *due_namespace == namespace.0 {
                        skipped = !std::mem::replace(reached, false);
                    }
                }
                cursor.rotation.page = cursor.rotation.page.saturating_add(1);
                cursor.proof_rotation.page = cursor.rotation.page;
                let start = Box::new(cursor.counters);
                cursor.counters.deferred_next_generation = cursor
                    .counters
                    .deferred_next_generation
                    .saturating_add(self.next_generation_hints);
                start
            });
            if skipped {
                record_proof_drop();
            }
        }
    }
}

/// U1a-2a (cc row 4, rev 5/6 §5.1, R2-B1): the most a running proof job
/// may hold before a step: `STATE_BYTES − bound(context) −
/// PROOF_STEP_HEADROOM_BYTES`, the copy-budget computation
/// (`copy_budget_parts`) with the running job in place of the active file.
/// `bound(context)` includes the shared cache (cursor state, retained
/// copies, side ledger) but not the running job (out of the holder). Cycles
/// are serialized under `SNAPSHOT_SYNC_LOCK`, so it sees every live main
/// state. None: the context is unbounded or leaves no headroom.
pub(in crate::snapshots) fn proof_room(context: &super::Context) -> Option<usize> {
    crate::heap_layout_bound::bound(context, STATE_BYTES)
        .and_then(|resident| STATE_BYTES.checked_sub(resident))
        .and_then(|room| room.checked_sub(PROOF_STEP_HEADROOM_BYTES))
}

/// Opened-object facts of the held descriptor, captured at job open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::snapshots) struct OpenStamp {
    dev: u64,
    ino: u64,
    extent: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
crate::heap_layout_bound::fields!(OpenStamp; dev, ino, extent, modified, changed);

/// The cursor/acquisition content key, without metadata-only ctime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct ContentStamp {
    dev: u64,
    ino: u64,
    extent: u64,
    modified: (i64, i64),
}
crate::heap_layout_bound::fields!(ContentStamp; dev, ino, extent, modified);
impl ContentStamp {
    pub(in crate::snapshots) fn extent(&self) -> u64 {
        self.extent
    }
    pub(in crate::snapshots) fn same_content(&self, other: &Self) -> bool {
        self == other
    }
}

impl OpenStamp {
    pub(in crate::snapshots) fn capture(file: &File) -> std::io::Result<Self> {
        Ok(Self::of(&file.metadata()?))
    }

    pub(in crate::snapshots) fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            extent: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    pub(in crate::snapshots) fn candidate(candidate: &super::super::CandidateFile) -> Option<Self> {
        let [dev, ino] = candidate.physical_identity?;
        Some(Self {
            dev,
            ino,
            extent: candidate.size_bytes,
            modified: (
                (candidate.modified_unix_nanos / 1_000_000_000) as i64,
                (candidate.modified_unix_nanos % 1_000_000_000) as i64,
            ),
            changed: (
                (candidate.fingerprint_changed_nanos / 1_000_000_000) as i64,
                (candidate.fingerprint_changed_nanos % 1_000_000_000) as i64,
            ),
        })
    }

    /// The object `path` names now, without following a final symlink.
    pub(in crate::snapshots) fn of_path(path: &Path) -> Option<Self> {
        fs::symlink_metadata(path)
            .ok()
            .map(|metadata| Self::of(&metadata))
    }

    /// Same object, no shrink, and no equal-length in-place change. Growth
    /// is compatible: appended bytes are outside the frozen extent. The rule
    /// is the shared `transcript_acquisition::append_compatible`.
    pub(in crate::snapshots) fn append_compatible(&self, now: &Self) -> bool {
        crate::transcript_acquisition::append_compatible(self, now)
    }

    fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// `transcript_acquisition::FileStamp::same_content`'s rule: the same
    /// object, extent and nanosecond mtime; never ctime.
    pub(in crate::snapshots) fn same_content(&self, other: &Self) -> bool {
        self.content_stamp().same_content(&other.content_stamp())
    }

    pub(in crate::snapshots) fn content_stamp(&self) -> ContentStamp {
        ContentStamp {
            dev: self.dev,
            ino: self.ino,
            extent: self.extent,
            modified: self.modified,
        }
    }

    /// The memo and parked wake rule, on stamps `SharedCache::retained_stamp`
    /// qualified: growth, or exactly the stamp. There a ctime-only change
    /// whose content inputs and birth still match already carries the
    /// stored ctime, and a birth or evidence mismatch keeps the live ctime,
    /// so ctime is the birth witness here and stays compared. Not
    /// `append_compatible`, which never compares ctime (E1 S3). Codex
    /// parent-proof authority (the side record's parsed-stamp guard and the
    /// proof wakes, on raw path stamps) keeps this rule too: there ctime is
    /// the only witness of a same-inode replacement or an mtime-restored
    /// rewrite until a birth fence exists (E1 S3b).
    pub(in crate::snapshots) fn wake_compatible(&self, now: &Self) -> bool {
        self.same_object(now) && (now.extent > self.extent || self == now)
    }

    pub(in crate::snapshots) fn extent(&self) -> u64 {
        self.extent
    }

    pub(in crate::snapshots) fn dev_ino(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

impl crate::transcript_acquisition::StampIdentity for OpenStamp {
    fn same_object(&self, other: &Self) -> bool {
        OpenStamp::same_object(self, other)
    }
    fn same_content(&self, other: &Self) -> bool {
        OpenStamp::same_content(self, other)
    }
    fn length(&self) -> u64 {
        self.extent
    }
}

/// Compact cross-scan evidence. The first six words are ctime, birth,
/// mtime, length, device and inode; four hold the opened identity, and the
/// last fences reuse of already-read samples at the most recent live ctime.
/// No transcript bytes or heap allocation. Active-parser stamps stay live.
#[derive(Clone, Copy)]
struct WakeIdentity([u64; 11]);

impl WakeIdentity {
    fn identity(&self) -> String {
        self.0[6..10]
            .iter()
            .map(|word| format!("{word:016x}"))
            .collect()
    }

    fn same_content_inputs(&self, stamp: &OpenStamp, birth: u64) -> bool {
        birth != 0
            && self.0[2] != 0
            && self.0[1] == birth
            && self.0[2] == stamp_modified_nanos(stamp)
            && self.0[3] == stamp.extent
            && self.0[4] == stamp.dev
            && self.0[5] == stamp.ino
    }
}

fn stamp_modified_nanos(stamp: &OpenStamp) -> u64 {
    stamp
        .modified
        .0
        .try_into()
        .ok()
        .and_then(|seconds: u64| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(stamp.modified.1.try_into().ok()?))
        .unwrap_or_default()
}

/// Each key owns exactly its capacity; values are inline. A walk charges
/// container nodes and all key capacities in two visits, independent of count.
#[derive(Default)]
struct WakeIdentities(BTreeMap<String, (WakeIdentity, u64)>);
impl HeapLayoutBound for WakeIdentities {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        crate::heap_layout_bound::tree_nodes::<String, (WakeIdentity, u64)>(self.0.len(), c)?;
        let keys = self
            .0
            .keys()
            .try_fold(0usize, |sum, key| sum.checked_add(key.capacity()))?;
        c.add(keys)
    }
}

impl SharedCache {
    /// A cheap content-qualified identity for retained wake decisions only.
    /// Missing/evicted evidence or any content/object mismatch keeps live ctime.
    /// Samples use pread so neither a parser nor a boot reader is repositioned.
    pub(in crate::snapshots) fn retained_open(
        &self,
        path: &Path,
        file: &File,
    ) -> Option<(OpenStamp, String, String)> {
        let metadata = file.metadata().ok()?;
        let width = FILE_CONTENT_SAMPLE_BYTES as u64;
        let read = |at, len| {
            let mut bytes = vec![0; len];
            file.read_exact_at(&mut bytes, at).ok()?;
            Some(bytes)
        };
        let samples = OpenedContentSamples {
            head: read(0, metadata.len().min(width) as usize)?,
            tail: if metadata.len() > width {
                Some(read(metadata.len() - width, FILE_CONTENT_SAMPLE_BYTES)?)
            } else {
                None
            },
        };
        self.retained_sampled(path, file, &metadata, &samples)
    }

    /// Reuse the candidate opener's samples. Its live identity and the
    /// cross-scan identity are computed from exactly the same bytes.
    pub(in crate::snapshots) fn retained_sampled(
        &self,
        path: &Path,
        file: &File,
        metadata: &fs::Metadata,
        samples: &OpenedContentSamples,
    ) -> Option<(OpenStamp, String, String)> {
        let key = local_index_key(path);
        let previous = self
            // Remove the old row before any refresh can fail. Failed sampling,
            // accounting or retained-lock acquisition must leave no eligible
            // stale identity behind; the live fallback only costs a retry.
            .with_cursor(|cursor| cursor.wake.0.remove(&key).map(|entry| entry.0))
            .flatten();
        let mut stamp = OpenStamp::of(metadata);
        let birth = metadata
            .created()
            .ok()
            .and_then(unix_nanos)
            .unwrap_or_default();
        let object = OpenedObjectStat {
            device: stamp.dev,
            inode: stamp.ino,
            changed_seconds: stamp.changed.0,
            changed_nanos: stamp.changed.1,
            birth_nanos: (birth != 0).then_some(birth),
            modified_nanos: Some(stamp_modified_nanos(&stamp)),
        };
        let live_identity = opened_object_identity_from(stamp.extent, Some(&object), samples);
        let mut identity = live_identity.clone();
        if let Some(old) =
            previous.filter(|old| old.0[0] != 0 && old.same_content_inputs(&stamp, birth))
        {
            let qualified = opened_object_identity_from(
                stamp.extent,
                Some(&object.with_changed_unix_nanos(old.0[0])),
                samples,
            );
            if qualified == old.identity() {
                stamp.changed = (
                    (old.0[0] / 1_000_000_000) as i64,
                    (old.0[0] % 1_000_000_000) as i64,
                );
                identity = qualified;
            }
        }
        // Changes during sampling never establish a retained witness.
        if OpenStamp::capture(file).ok()? != OpenStamp::of(metadata)
            || file
                .metadata()
                .ok()?
                .created()
                .ok()
                .and_then(unix_nanos)
                .unwrap_or_default()
                != birth
        {
            return None;
        }
        let changed = OpenedObjectStat {
            changed_seconds: stamp.changed.0,
            changed_nanos: stamp.changed.1,
            ..object
        }
        .changed_unix_nanos();
        let mut words = [
            changed,
            birth,
            stamp_modified_nanos(&stamp),
            stamp.extent,
            stamp.dev,
            stamp.ino,
            0,
            0,
            0,
            0,
            object.changed_unix_nanos(),
        ];
        for (slot, hex) in words[6..10]
            .iter_mut()
            .zip(identity.as_bytes().chunks_exact(16))
        {
            *slot = u64::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        }
        let witness = WakeIdentity(words);
        // Retained -> cursor is the shared-cache lock order. Optional admission
        // stays within the existing STATE_BYTES admission; failure leaves
        // this path without a reusable witness.
        if let Ok(mut retained) = self.retained() {
            self.with_cursor(|cursor| {
                let used = cursor.tick();
                if let Some(entry) = cursor.wake.0.get_mut(&key) {
                    *entry = (witness, used);
                    return;
                }
                if cursor.wake.0.len() >= MEMO_ENTRIES {
                    if let Some(oldest) = cursor
                        .wake
                        .0
                        .iter()
                        .min_by_key(|(_, (_, tick))| tick)
                        .map(|(key, _)| key.clone())
                    {
                        cursor.wake.0.remove(&oldest);
                    }
                }
                let charge =
                    crate::heap_layout_bound::tree_node_bytes::<String, (WakeIdentity, u64)>()
                        .and_then(|node| node.checked_add(key.capacity()));
                if charge.is_some_and(|charge| {
                    admit_locked(&mut retained, cursor, charge, false, Admitter::Main)
                }) {
                    cursor.wake.0.insert(key, (witness, used));
                }
            });
        }
        Some((stamp, identity, live_identity))
    }

    pub(in crate::snapshots) fn retained_stamp_identity(
        &self,
        candidate: &CandidateFile,
        fallback: &str,
    ) -> String {
        self.with_cursor(|cursor| {
            cursor
                .wake
                .0
                .get(&local_index_key(&candidate.path))
                .filter(|(hint, _)| {
                    hint.0[3] == candidate.size_bytes
                        && hint.0[2] == candidate.modified_unix_nanos
                        && candidate.physical_identity == Some([hint.0[4], hint.0[5]])
                        && candidate.fingerprint_birth_nanos != 0
                        && hint.0[1] == candidate.fingerprint_birth_nanos
                })
                .map(|(hint, _)| hint.identity())
        })
        .flatten()
        .unwrap_or_else(|| fallback.to_owned())
    }

    /// A stamp just proved live by the parser/boot; canonicalize only its
    /// cross-scan copy. The cache's witness was established by retained_open.
    pub(in crate::snapshots) fn retained_stamp(
        &self,
        path: &Path,
        mut stamp: OpenStamp,
    ) -> OpenStamp {
        self.with_cursor(|cursor| {
            if let Some((hint, _)) = cursor.wake.0.get(&local_index_key(path)) {
                let raw_changed = OpenedObjectStat {
                    device: stamp.dev,
                    inode: stamp.ino,
                    changed_seconds: stamp.changed.0,
                    changed_nanos: stamp.changed.1,
                    birth_nanos: None,
                    modified_nanos: None,
                }
                .changed_unix_nanos();
                if raw_changed != 0
                    && hint.0[10] == raw_changed
                    && hint.0[2] == stamp_modified_nanos(&stamp)
                    && hint.0[3] == stamp.extent
                    && hint.0[4] == stamp.dev
                    && hint.0[5] == stamp.ino
                {
                    stamp.changed = (
                        (hint.0[0] / 1_000_000_000) as i64,
                        (hint.0[0] % 1_000_000_000) as i64,
                    );
                }
            }
        });
        stamp
    }
}

/// The identity a cursor job proved against its held FD when its prefix
/// certificate passed (S12). Only `finish_job` sets it, and only on
/// `Certified` (never on a lossy `Uncertified`); `finish` then accepts a grown
/// object only while the held FD is still this dev/ino and at least the
/// frozen extent long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct SealedPrefix {
    dev: u64,
    ino: u64,
    extent: u64,
}
crate::heap_layout_bound::fields!(SealedPrefix; dev, ino, extent);

impl JobMeta {
    pub(in crate::snapshots) fn census_trusted(&self) -> bool {
        self.census_trusted
    }

    /// The job started in `index`'s current census generation (K7), so it
    /// froze its extent after that generation's `census_window_end`.
    pub(in crate::snapshots) fn in_generation(&self, index: &ScanIndex) -> bool {
        self.fence.is_some() && self.fence == census_token(index)
    }

    /// Record a walked charge (`usize::MAX` when the walk refused) taken at
    /// reader position `consumed` with reader buffer capacity `buffer`.
    pub(in crate::snapshots) fn record_charge(
        &mut self,
        charge: usize,
        consumed: u64,
        buffer: usize,
    ) {
        self.charge = Some((charge, consumed, buffer));
    }
}

/// E3 from a walked `(charge, consumed, buffer)`; see `charge_estimate`.
/// `feeds` accumulators take every consumed byte (a group's legacy tee is
/// the second, R2-N5).
fn estimate_charge(
    walked: Option<(usize, u64, usize)>,
    consumed: u64,
    buffer: usize,
    feeds: usize,
) -> Option<usize> {
    let (charge, at, buffer_at) = walked?;
    let since = consumed.checked_sub(at)?;
    if since >= CHARGE_REFRESH_BYTES {
        return None;
    }
    usize::try_from(since).ok().map(|since| {
        charge
            .saturating_add(since.saturating_mul(feeds))
            .saturating_add(buffer.saturating_sub(buffer_at))
    })
}

/// A job charged by bytes like a cursor job (E3): any cursor job, and a
/// group job read in one page (R2-M2). Its state is walked with
/// `completed_bound` at most once per `CHARGE_REFRESH_BYTES` of input, never
/// with the visit-limited `bound` per line, so a large group cannot refuse
/// the copy budget by visits alone and clear every retained singleton copy.
/// A group's input position is cumulative over its members (round 3,
/// R2-L3): a member swap needs no walk. Each swap also advances it by the
/// state the swap adds that no consumed byte pays for (`swap_charge`,
/// round 4), so the estimate stays an upper bound.
pub(in crate::snapshots) fn byte_charged(job: &OwnedActiveFile) -> bool {
    job.cursor.is_some() || job.group.is_some()
}

/// The E3 estimate of a byte-charged job, if its last walk is recent.
pub(in crate::snapshots) fn job_charge_estimate(
    job: &OwnedActiveFile,
    consumed: u64,
    buffer: usize,
) -> Option<usize> {
    let feeds = 1 + usize::from(job.group.as_ref().is_some_and(|group| group.has_tee()));
    let walked = match (job.cursor.as_ref(), job.group.as_ref()) {
        (Some(meta), _) => meta.charge,
        (None, Some(group)) => group.walked,
        (None, None) => return None,
    };
    estimate_charge(walked, job_position(job, consumed), buffer, feeds)
}

/// Fixed per-member state a group member swap adds (round 4, L3): the
/// applied receipt's B-tree slot share (a non-root node holds at least 5 of
/// its 11 entries), the legacy baseline's and the proof's `MemberSeen` Vec
/// slots (at most twice the element under doubling). A test checks it
/// against the layout.
pub(in crate::snapshots) const MEMBER_SWAP_CHARGE: u64 = 4 * 1024;

/// The E3 position charge of one member swap: `MEMBER_SWAP_CHARGE` plus the
/// walked bound of the variable records the swap retains (the applied
/// receipt, its key and the legacy baseline). An unbounded or overlong
/// record charges a whole refresh window, so the next step walks.
pub(in crate::snapshots) fn swap_charge(records: &[Option<usize>]) -> u64 {
    records
        .iter()
        .try_fold(MEMBER_SWAP_CHARGE, |sum, record| {
            sum.checked_add(u64::try_from((*record)?).ok()?)
        })
        .map_or(CHARGE_REFRESH_BYTES, |charge| {
            charge.min(CHARGE_REFRESH_BYTES)
        })
}

/// The job's input position for E3: the reader's `consumed`, plus the bytes
/// a group's completed member readers consumed and their swap charges
/// (R2-N4, R2-L3).
fn job_position(job: &OwnedActiveFile, consumed: u64) -> u64 {
    job.group.as_ref().map_or(consumed, |group| {
        consumed.saturating_add(group.consumed_before)
    })
}

/// Record a byte-charged job's walk (`usize::MAX` when it refused).
pub(in crate::snapshots) fn record_job_charge(
    job: &mut OwnedActiveFile,
    charge: usize,
    consumed: u64,
    buffer: usize,
) {
    let consumed = job_position(job, consumed);
    if let Some(meta) = job.cursor.as_mut() {
        meta.record_charge(charge, consumed, buffer);
    } else if let Some(group) = job.group.as_mut() {
        group.walked = Some((charge, consumed, buffer));
    }
}

impl SealedPrefix {
    pub(in crate::snapshots) fn holds(&self, file: &File) -> bool {
        OpenStamp::capture(file).is_ok_and(|now| {
            now.dev == self.dev && now.ino == self.ino && now.extent >= self.extent
        })
    }
}

/// The identity `finish` may accept for a grown object. `finish_job` or the
/// in-page grown route sets it in the reader's `sealed_prefix` slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum FinishGrant {
    /// A passed prefix certificate (S12): `Certified` only.
    Certified(SealedPrefix),
    /// Parent ruling 2: the certificate refused as `Lossy` alone, after a
    /// completed traversal of the frozen extent with parse/salvage loss
    /// only. It permits nothing but an UNCERTIFIED publication of a grown
    /// object; it is not a sealed-prefix certificate and mints no checkpoint,
    /// retention, verification, ownership proof or debt change.
    LossySameObject(LossyPrefixIdentity),
}

impl HeapLayoutBound for FinishGrant {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::Certified(prefix) => prefix.heap_bound(c),
            Self::LossySameObject(identity) => identity.heap_bound(c),
        }
    }
}

impl FinishGrant {
    /// C1, shared with Stage2-pre: callers must first pass the held-FD
    /// sealed-prefix certificate. This grants finish identity only; it does
    /// not grant a checkpoint, audit credit, proof or admission.
    pub(in crate::snapshots) fn certified(dev: u64, ino: u64, extent: u64) -> Self {
        Self::Certified(SealedPrefix { dev, ino, extent })
    }

    /// Revalidated at finalization against the held FD (`file`). The lossy
    /// grant also requires the selected `path` to still name the held object
    /// and the covered samples to re-read unchanged (no replacement, shrink
    /// or same-size edit).
    pub(in crate::snapshots) fn holds(&self, file: &mut File, path: &Path) -> bool {
        match self {
            Self::Certified(prefix) => prefix.holds(file),
            Self::LossySameObject(identity) => {
                path_names_object(file, path) && identity.holds(file)
            }
        }
    }
}

/// Cursor job facts carried by the active file between pages.
#[derive(Debug)]
pub(in crate::snapshots) struct JobMeta {
    key: String,
    namespace: String,
    stamp_open: OpenStamp,
    /// Unix seconds when this read opened: the certificate's `t_start`.
    started: u64,
    dependencies: Option<String>,
    owner: Option<String>,
    /// `counting_view` of the file's index entries at job start (K8).
    counting: String,
    /// The census generation this job started in (K7 fence).
    fence: Option<String>,
    /// The state and sidecar census were complete at start. A cursor-only
    /// job (N1) keeps no checkpoint, copy or verification at completion.
    census_trusted: bool,
    pages: u32,
    /// Consecutive resume pages whose evidence was unavailable (E2).
    unavailable_resumes: u32,
    /// First observation and resume count of a deferred correctness latch.
    custody_deferred: Option<(u64, u64)>,
    /// The last walked copy-budget charge, the reader position and the
    /// reader buffer capacity it was taken at (E3; see `charge_estimate`).
    charge: Option<(usize, u64, usize)>,
    /// E1: this read's withheld final record was applied at a genuine
    /// unchanged EOF on its completion step (`apply_eof_record`).
    eof_applied: bool,
    /// Stage 1 guard (§6): this attempt's pacing facts, inline.
    pace: JobPace,
}
crate::heap_layout_bound::fields!(JobMeta; key, namespace, stamp_open, started, dependencies,
    owner, counting, fence, census_trusted, pages, unavailable_resumes, custody_deferred, charge, eof_applied,
    pace);

/// Stage 1 guard (`stage1/c14c15-answer.md` §6): one cursor attempt's
/// pacing facts, inline in its `JobMeta`, so the job's own walk
/// (`paused_charge`, through `size_of_val`) charges them once; nothing here
/// owns heap. `equiv_secs` is the attempt's ordinary-equivalent duration up
/// to its last resumed page, kept as a checked `Duration` so an attempt with
/// no continuation page has exactly its elapsed time. `None` is unknown
/// coverage, which also clears `accelerate` for the rest of the attempt.
#[derive(Clone, Copy, Debug)]
pub(in crate::snapshots) struct JobPace {
    /// The attempt's `PaceTable` key (`pace_key`); zero for a group job,
    /// which is never paced and never accelerated.
    key: [u64; 2],
    started_mono: std::time::Instant,
    last_page_mono: std::time::Instant,
    equiv_secs: Option<std::time::Duration>,
    /// The attempt may ask for continuation pages (a ticket).
    accelerate: bool,
}

impl JobPace {
    /// An attempt starting at `now`, with no continuation pages yet.
    fn new(key: [u64; 2], now: std::time::Instant, accelerate: bool) -> Self {
        Self {
            key,
            started_mono: now,
            last_page_mono: now,
            equiv_secs: Some(std::time::Duration::ZERO),
            accelerate,
        }
    }
}

impl HeapLayoutBound for JobPace {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // A key, two `Instant`s, a `Duration` and a flag: nothing on the heap.
        c.add(0)
    }
}

/// A `Duration` held inline (no heap), for the page's ordinary equivalent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct InlineDuration(std::time::Duration);

impl HeapLayoutBound for InlineDuration {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}

/// An `Instant` held inline (no heap), for a continuation page's deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct InlineInstant(std::time::Instant);

impl HeapLayoutBound for InlineInstant {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}

/// The counting view of `candidate`'s index entries (K8): what a fresh
/// singleton parser would be configured with now. Recorded at job start,
/// recomputed from the current entries at every resume and at emission.
/// `"legacy"` while the counting cutover is inactive.
pub(in crate::snapshots) fn counting_view(candidate: &CandidateFile, index: &ScanIndex) -> String {
    crate::snapshots::codex_counting_version::singleton_view(candidate, index)
}

/// A group's counting view (§k.4, §5.2 rule 3; R1-M2; #603): what
/// `configure_group_once` would configure now from every member's index
/// entry (`codex_counting_version::group_view`, the same evidence as
/// `group_evidence` at boot). A counting change on any member, not only the
/// live one, changes it; `counting_reusable` decides resume and emission
/// against it exactly as for a singleton (any member's Legacy ACK takes
/// precedence).
pub(in crate::snapshots) fn group_counting_view<'a>(
    members: impl IntoIterator<Item = &'a CandidateFile>,
    index: &ScanIndex,
) -> String {
    crate::snapshots::codex_counting_version::group_view(members, index)
}

/// The counting view a job is decided under: a group's over all members.
pub(in crate::snapshots) fn job_counting_view(job: &OwnedActiveFile, index: &ScanIndex) -> String {
    match job.group.as_ref() {
        Some(group) => group_counting_view(&group.members, index),
        None => counting_view(&job.candidate, index),
    }
}

/// A group job's `scope_job` (§a.6, §p; R1-M1): the receipt scope (upload
/// context), the historical replay generation, and the parser, identity and
/// proof versions. Recorded at job start; a change at any resume or at
/// emission invalidates the job (receipts must not mix scopes).
pub(in crate::snapshots) fn group_scope(index: &ScanIndex) -> String {
    sha256_hex(&[
        "codex_group_scope:v1",
        CODEX_JOIN_PROOF_VERSION,
        SnapshotSource::Codex.parser_version(),
        SnapshotSource::Codex.scan_identity_version(),
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none"),
        index
            .historical_replay_generation
            .as_deref()
            .unwrap_or("none"),
    ])
}

/// The one counting reuse predicate for a restored accumulator, shared with
/// the retained-reduction `old.filter`: the paused job continues only under
/// the rule `current` would select. The paused accumulator carries the
/// configuration it was decided under, so `recorded` adds nothing to it.
fn counting_reusable(accumulator: &SnapshotAccumulator, _recorded: &str, current: &str) -> bool {
    crate::snapshots::codex_counting_version::reusable_under_view(accumulator, current)
}

/// The strict census generation a cursor attempt belongs to (K7): the
/// traversal's context and census window. A new traversal (a completed or
/// retried generation, or a changed scan context) is a new generation.
pub(in crate::snapshots) fn census_token(index: &ScanIndex) -> Option<String> {
    index.traversal.as_ref().map(|traversal| {
        sha256_hex(&[
            "codex_cursor_generation:v1",
            &traversal.context_fingerprint,
            &traversal.census_window_end,
        ])
    })
}

fn rotation_key(namespace: &str, key: &str) -> String {
    format!("{namespace}\0{key}")
}

/// Exactly one paused job exists process-wide.
enum Slot {
    Empty,
    Paused(Box<OwnedActiveFile>),
    ActiveElsewhere { token: u64 },
}

/// U1a-2a (cc row 1; rev 11 §5.3–§5.4, rev 12 §5.3): a proof job between
/// steps, RAM only (U1a-3 persists its resume). It is bound to the index it
/// was started from: a job resumes only for the same namespace, index path
/// and proof incarnation, and its deltas land only on entries whose `seq`
/// still matches.
pub(in crate::snapshots) struct ProofJob {
    pub(in crate::snapshots) namespace: String,
    pub(in crate::snapshots) index_path: PathBuf,
    pub(in crate::snapshots) incarnation: String,
    /// (child key, entry `seq`) of every entry the job was started for.
    pub(in crate::snapshots) entries: Vec<(String, u64)>,
    /// End of the next row a step must reach: a step whose leftover budget
    /// cannot reach it reads nothing (`proof_pages_no_budget`).
    pub(in crate::snapshots) next_row_end: u64,
    /// `rotation.page` at the last suspend or resume: another namespace may
    /// drop the job once it is `NAMESPACE_STALE_PAGES` old.
    pub(in crate::snapshots) touched_page: u64,
    /// The job's open readers (s row 33): P's and its children's held FDs,
    /// frozen at open. `None` only for a job with nothing to read.
    pub(in crate::snapshots) readers: Option<Box<crate::snapshots::CodexProofReaders>>,
}
crate::heap_layout_bound::fields!(ProofJob; namespace, index_path, incarnation, entries,
    next_row_end, touched_page, readers);

/// U1a-2a (owner note 3, parent r79): what a suspended job that was retired
/// (main's admission, insert, release or copy step, or another index's
/// stale take) leaves for its own index's next hook, which backs those
/// entries off (`take_retired_proof_seqs`): the job's binding (namespace,
/// index path, incarnation) as one digest and its entries' `seq`s. Fixed
/// size and inline in the cursor state (no heap), so a retirement frees
/// every byte of the job it retires; the readers are freed under the lock.
#[derive(Clone, Copy, Default)]
struct RetiredProof {
    binding: u128,
    seqs: [u64; RETIRED_PROOF_ENTRIES],
    len: usize,
}

/// The most entries one retired job keeps: a job holds at most the hook's
/// batch (`CODEX_PROOF_BATCH`, asserted there).
pub(in crate::snapshots) const RETIRED_PROOF_ENTRIES: usize = 4;

/// The retired jobs waiting for their index's hook: a ring of
/// `RETIRED_PROOFS` slots, a later retirement replacing the oldest.
#[derive(Default)]
struct RetiredProofs {
    slots: [RetiredProof; RETIRED_PROOFS],
    next: usize,
}
const RETIRED_PROOFS: usize = 4;

/// One digest of a job's binding (namespace, index path, incarnation),
/// length-prefixed so no two bindings share bytes.
fn retired_binding(namespace: &str, index_path: &Path, incarnation: &str) -> u128 {
    let mut hasher = Sha256::new();
    for part in [
        namespace.as_bytes(),
        index_path.as_os_str().as_encoded_bytes(),
        incarnation.as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut head = [0_u8; 16];
    head.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(head)
}

/// Retire the suspended job, if any (under the cursor lock; the job is
/// freed here, and a `ProofJob` drop takes no lock), keeping its binding
/// and entry `seq`s for its index's next hook. The caller counts the drop's
/// cause.
fn retire_holder(cursor: &mut CursorState) {
    if let ProofHolder::Suspended { job, .. } = std::mem::take(&mut cursor.proof) {
        let mut retired = RetiredProof {
            binding: retired_binding(&job.namespace, &job.index_path, &job.incarnation),
            ..RetiredProof::default()
        };
        for (slot, (_, seq)) in retired.seqs.iter_mut().zip(&job.entries) {
            *slot = *seq;
            retired.len += 1;
        }
        drop(job);
        let ring = &mut cursor.proof_retired;
        ring.slots[ring.next] = retired;
        ring.next = (ring.next + 1) % RETIRED_PROOFS;
    }
}

/// U1a-2a (cc row 1): the one suspended proof job, process-wide. A running
/// job is out of the holder, in the step's `ProofLease` (charged 0 here);
/// `Suspended` is charged its walked bound, measured once at suspend.
#[derive(Default)]
pub(in crate::snapshots) enum ProofHolder {
    #[default]
    None,
    Suspended {
        job: Box<ProofJob>,
        charge: usize,
    },
}
impl ProofHolder {
    /// The holder's charge in the cursor state's bound.
    fn charge(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Suspended { charge, .. } => *charge,
        }
    }
}
impl HeapLayoutBound for ProofHolder {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // The suspended box was walked once at suspend; nothing mutates it
        // while it sits here. Main's view (`bound_for_main`) charges the
        // holder as `None` (no heap), as `state_for_main` does.
        if MAIN_VIEW.with(std::cell::Cell::get) {
            return c.add(0);
        }
        c.add(self.charge())
    }
}

thread_local! {
    /// Set only for the duration of one `bound_for_main` walk.
    static MAIN_VIEW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Main copy view: omit suspended proof and optional header facts, retaining
/// the usual lock/visit refusal. `copy_budget_step` reclaims headers beside
/// active progress; `retire_proof_beside_copy` reclaims optional bytes before
/// copying/shape-F allocation. Measuring alone grants no allocation authority.
pub(in crate::snapshots) fn bound_for_main<T: HeapLayoutBound>(
    value: &T,
    limit: usize,
) -> Option<usize> {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            MAIN_VIEW.with(|view| view.set(self.0));
        }
    }
    let _restore = Restore(MAIN_VIEW.with(|view| view.replace(true)));
    crate::heap_layout_bound::bound(value, limit)
}

/// U1a-2a (cc row 1): what the proof hook may do with the holder.
pub(in crate::snapshots) enum ProofTake {
    /// This index's own suspended job, out of the holder for one step.
    Mine(ProofLease),
    /// Nothing is suspended (a stale or mismatched job was just dropped):
    /// the hook may start a job.
    Free,
    /// Another namespace's job is suspended and not stale: no proof work
    /// starts for this index this page.
    Busy,
}

/// U1a-2a (cc row 1, rev 6 §5.1): a proof job taken out of the holder for
/// one step, charged 0 in the cursor state while it runs (each reader step
/// checks `proof_room` first, R2-B1). It goes back only through `suspend` (free room
/// only); `finish` ends it; a lease dropped holding its job loses it,
/// counted, and its entries stay `Owed`.
pub(in crate::snapshots) struct ProofLease {
    cache: Arc<SharedCache>,
    job: Option<Box<ProofJob>>,
}
impl ProofLease {
    pub(in crate::snapshots) fn new(cache: &Arc<SharedCache>, job: Box<ProofJob>) -> Self {
        Self {
            cache: Arc::clone(cache),
            job: Some(job),
        }
    }

    pub(in crate::snapshots) fn job(&mut self) -> &mut ProofJob {
        self.job.as_mut().expect("a live proof lease holds its job")
    }

    /// Back into the holder as `Suspended`, measured now and admitted as
    /// `Admitter::Proof` (free room only: no retained copy, provenance or
    /// witness is released for it). Every reader buffer is shrunk first
    /// (`shrink_paused_buffer`, R2-B1), so one long line read this page is
    /// not charged while the job waits. Refused, or the holder already
    /// taken: the job is dropped (counted `side_proof_drops`; the hook
    /// records `MemoryRefused` on its entries). True when suspended.
    pub(in crate::snapshots) fn suspend(mut self) -> bool {
        let Some(mut job) = self.job.take() else {
            return false;
        };
        if let Some(readers) = job.readers.as_deref_mut() {
            readers.shrink_buffers();
        }
        let Some(charge) = crate::heap_layout_bound::bound(&*job, STATE_BYTES) else {
            record_proof_drop();
            return false;
        };
        let Ok(mut retained) = self.cache.retained() else {
            record_proof_drop();
            return false;
        };
        let refused = self.cache.with_cursor(|cursor| {
            if !matches!(cursor.proof, ProofHolder::None)
                || !admit_locked(&mut retained, cursor, charge, false, Admitter::Proof)
            {
                return Some(job);
            }
            job.touched_page = cursor.rotation.page;
            cursor.proof = ProofHolder::Suspended { job, charge };
            None
        });
        drop(retained);
        match refused {
            Some(None) => true,
            // Refused (the box is freed here, outside both locks) or the
            // cursor lock was poisoned.
            Some(Some(_)) | None => {
                record_proof_drop();
                false
            }
        }
    }

    /// The job finished (its deltas are applied or refused): nothing goes
    /// back to the holder.
    pub(in crate::snapshots) fn finish(mut self) {
        self.job = None;
    }
}
impl Drop for ProofLease {
    fn drop(&mut self) {
        if self.job.take().is_some() {
            record_proof_drop();
        }
    }
}

/// U1a-2a (cc rows 1–3, 5, 8): one proof item dropped or one proof page
/// skipped (`side_proof_drops`, lock-free; never `CodexCursorCounts`).
fn record_proof_drop() {
    crate::local_resource_diagnostics::codex_side_lifecycle::record(
        crate::local_resource_diagnostics::codex_side_lifecycle::Event::ProofDrop,
    );
}

/// U1a-2a (cc row 2; rev 10 §5.4, rev 11): who asks for cursor room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum Admitter {
    /// Every one of main's admissions. It decides as if no proof existed
    /// (`state_for_main`), then drops a suspended proof first when the
    /// admitted charge needs that room.
    Main,
    /// A proof job's suspend: free room only. It never releases a retained
    /// copy, never evicts provenance or witnesses, and never drops anything.
    Proof,
}

/// U1a-2a (cc row 2): the cursor state's bound as main measures it,
/// `bound(cursor) − bound(holder) + bound(ProofHolder::None)`: the
/// suspended proof's charge is left out (`None` holds nothing). Measured
/// with the proof's charge added to the limit, so a full state with a
/// proof still reads main's own part.
fn state_for_main(cursor: &CursorState) -> Option<usize> {
    let proof = cursor.proof.charge();
    crate::heap_layout_bound::bound(cursor, STATE_BYTES.checked_add(proof)?)?
        .checked_sub(proof)
        .filter(|state| *state <= STATE_BYTES)
}

/// U1a-2a (cc row 2): `Admitter::Proof`'s test: `charge` fits beside the
/// whole cursor state (any suspended proof included) and the retained
/// copies, inside `admission_budget`. Nothing is released or evicted.
fn proof_free_room(retained: &super::RetainedCache, cursor: &CursorState, charge: usize) -> bool {
    use crate::heap_layout_bound::bound;
    bound(cursor, STATE_BYTES)
        .zip(bound(retained, STATE_BYTES))
        .and_then(|(state, resident)| {
            admission_budget()?
                .checked_sub(state)?
                .checked_sub(resident)?
                .checked_sub(charge)
        })
        .is_some()
}

/// Diagnostic counterfactual only: retain every proof/claim/root and subtract
/// exactly the optional header entries. Never changes admission or reclaims.
fn decoder_fits_without_headers(
    retained: &super::RetainedCache,
    cursor: &CursorState,
    charge: usize,
) -> bool {
    use crate::heap_layout_bound::bound;
    (|| {
        let headers = cursor.headers.optional_bytes().filter(|bytes| *bytes > 0)?;
        let state = bound(cursor, STATE_BYTES.checked_add(headers)?)?.checked_sub(headers)?;
        let resident = bound(retained, STATE_BYTES)?;
        admission_budget()?
            .checked_sub(state)?
            .checked_sub(resident)?
            .checked_sub(charge)
    })()
    .is_some()
}

/// U1a-2a (cc rows 2–3): drop the suspended proof when the full state (the
/// proof included), the retained copies and `reserve` more bytes do not fit
/// `budget`: main's admission or insert, which measured without the proof,
/// needs that room. Under the retained and cursor locks, so nothing spends
/// the room between the decision and the drop. The box is freed here.
fn drop_suspended_proof_over(
    retained: &super::RetainedCache,
    cursor: &mut CursorState,
    reserve: usize,
    budget: Option<usize>,
) {
    if retire_suspended_proof_over(retained, cursor, reserve, budget) {
        record_proof_drop();
    }
}

/// `drop_suspended_proof_over`'s test and drop, uncounted: true when the
/// suspended proof was retired (its box freed here, under the cursor lock;
/// a `ProofJob` drop takes no lock). The caller counts the drop's cause.
fn retire_suspended_proof_over(
    retained: &super::RetainedCache,
    cursor: &mut CursorState,
    reserve: usize,
    budget: Option<usize>,
) -> bool {
    use crate::heap_layout_bound::bound;
    if matches!(cursor.proof, ProofHolder::None) {
        return false;
    }
    let fits = bound(&*cursor, STATE_BYTES)
        .zip(bound(retained, STATE_BYTES))
        .and_then(|(state, resident)| {
            budget?
                .checked_sub(state)?
                .checked_sub(resident)?
                .checked_sub(reserve)
        })
        .is_some();
    if !fits {
        retire_holder(cursor);
    }
    !fits
}

/// Content-free RAM counters. They reach the scan's one completion log
/// record through `SharedCache::cursor_diagnostics`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct Counters {
    pub(in crate::snapshots) jobs_started: u64,
    pub(in crate::snapshots) jobs_paused: u64,
    pub(in crate::snapshots) jobs_resumed: u64,
    /// Published with a sealed-prefix certificate (after `finish`).
    pub(in crate::snapshots) jobs_certified: u64,
    /// Lossy with intact samples, finished uncertified (after `finish`).
    /// Publication then follows main's completeness rule: retryable loss
    /// (a malformed or invalid line) publishes nothing and is not indexed.
    pub(in crate::snapshots) jobs_uncertified: u64,
    /// Restarted after a necessary invalidation; nothing committed.
    pub(in crate::snapshots) jobs_invalidated: u64,
    /// Ended as strict `MemberChanged` debt after repeated invalidations.
    pub(in crate::snapshots) jobs_member_changed: u64,
    /// Ended as strict `JoinStateBound` debt: the job did not fit the state
    /// budget even after releasing retained copies.
    pub(in crate::snapshots) jobs_state_bound: u64,
    pub(in crate::snapshots) jobs_lost: u64,
    /// Evidence unavailable at start, resume or emission (K9): deferred as
    /// `InProgress`, never counted as a member change.
    pub(in crate::snapshots) jobs_deferred_inputs: u64,
    /// Start refused because the held file's stamp could not be read.
    pub(in crate::snapshots) jobs_start_unstartable: u64,
    /// A tail reached its audit deadline before commit (M1): restarted as
    /// the full audit, uncounted.
    pub(in crate::snapshots) jobs_audit_restarted: u64,
    /// Committed, then the native finish refused publication (M4).
    pub(in crate::snapshots) jobs_finish_failed: u64,
    /// A dropped scan frame returned its intact job to the slot (K12).
    pub(in crate::snapshots) jobs_frame_returned: u64,
    pub(in crate::snapshots) deferred: u64,
    /// A large file waited because another is ahead in rotation (K7).
    pub(in crate::snapshots) deferred_rotation: u64,
    /// A large read after this generation's completed attempt, left for the
    /// next generation (K7 fence).
    pub(in crate::snapshots) deferred_next_generation: u64,
    /// A resume found a live job of another namespace in the slot (K10).
    pub(in crate::snapshots) namespace_busy: u64,
    pub(in crate::snapshots) cursor_disabled_unsupported_layout: u64,
    /// Certified at or after its audit deadline: the debt stays staged.
    pub(in crate::snapshots) audit_overdue: u64,
    /// Largest `now - due` of such a completion, in seconds.
    pub(in crate::snapshots) audit_overdue_max_age_seconds: u64,
    /// A completion on a file that did not grow withheld an unterminated
    /// final record (N2): debt staged, the record left to main's EOF path.
    pub(in crate::snapshots) sealed_fragment_withheld: u64,
    /// E1: a completion at genuine unchanged EOF applied its withheld final
    /// record with main's trailing-line rule (strict finish identity).
    /// Counted only once its `finish` succeeded.
    pub(in crate::snapshots) eof_record_applied: u64,
    /// E2: a paused job ended because its path no longer named the held
    /// object or its evidence stayed unavailable for `UNAVAILABLE_RESUMES`.
    pub(in crate::snapshots) jobs_unavailable_ended: u64,
    pub(in crate::snapshots) memo_hits: u64,
    pub(in crate::snapshots) memo_records: u64,
    pub(in crate::snapshots) parked_hits: u64,
    /// P2 (RAM only; not yet in the diagnostics projection): group cursor
    /// jobs started, group memo hits, entries skipped because a job owns
    /// them (L1), group attempts skipped by the generation fence, groups
    /// whose probe hit `PROBE_BYTES` or the boot's probe allowance
    /// (chronological order kept), and group refusals by `JoinRefusal` slot
    /// (§d.1.1; terminal debt except `ProbeBudgetOrder`, which is strict).
    pub(in crate::snapshots) groups_started: u64,
    pub(in crate::snapshots) group_memo_hits: u64,
    pub(in crate::snapshots) join_in_progress_members: u64,
    pub(in crate::snapshots) groups_fenced: u64,
    pub(in crate::snapshots) probe_bound: u64,
    pub(in crate::snapshots) join_terminal_debt: [u64; codex_file_join::JOIN_REFUSALS],
    /// PR-P (RAM/test only; not in the diagnostics projection, no export):
    /// parent witnesses refused at admission, forgotten by a feasible
    /// mandatory admission (one per witness), new namespaces refused past
    /// `ROTATION_KEYS`, restart slots evicted past `ROTATION_KEYS`, and match
    /// marks refused. Production sees their effects only through the census
    /// `parent_unresolvable` counts and `parent_restarts_in_scope`.
    pub(in crate::snapshots) parent_witness_refused: u64,
    pub(in crate::snapshots) parent_witness_evicted: u64,
    pub(in crate::snapshots) parent_namespace_refused: u64,
    pub(in crate::snapshots) parent_restart_slot_evicted: u64,
    pub(in crate::snapshots) parent_match_unmarked: u64,
    /// Stage 1 guard (RAM/test only; not in the diagnostics projection): a
    /// large ordinary start deferred before its last attempt's ordinary
    /// equivalent (§6). Owed, like any deferral: never a waiter, a skip, a
    /// loss or a completion, and no completeness meaning.
    pub(in crate::snapshots) deferred_paced: u64,
}
crate::heap_layout_bound::fields!(Counters; jobs_started, jobs_paused, jobs_resumed,
    jobs_certified, jobs_uncertified, jobs_invalidated, jobs_member_changed, jobs_state_bound,
    jobs_lost, jobs_deferred_inputs, jobs_start_unstartable, jobs_audit_restarted,
    jobs_finish_failed, jobs_frame_returned, deferred, deferred_rotation,
    deferred_next_generation, namespace_busy, cursor_disabled_unsupported_layout, audit_overdue,
    audit_overdue_max_age_seconds, sealed_fragment_withheld, eof_record_applied,
    jobs_unavailable_ended, memo_hits, memo_records, parked_hits, groups_started,
    group_memo_hits, join_in_progress_members, groups_fenced, probe_bound, join_terminal_debt,
    parent_witness_refused, parent_witness_evicted, parent_namespace_refused,
    parent_restart_slot_evicted, parent_match_unmarked, deferred_paced);

/// A `JoinStateBound` file waits here until its object or reduction
/// dependencies change. Its job ran out of a build constant
/// (`STATE_BYTES`) while reading a prefix that only grows, so an append
/// cannot cure it: growth keeps it parked; replacement, shrink, an in-place
/// edit or a dependency change wakes it. A capacity change is a new
/// process, which starts with no parked record. A `ProbeBudgetOrder` group
/// (round 3) parks the same way; `exact` when its refusal is append-curable
/// in the live member, so any change of that member's stamp wakes it.
#[derive(Clone, Debug)]
struct Parked {
    stamp: OpenStamp,
    dependencies: Option<String>,
    disclosure: Disclosure,
    used: u64,
    exact: bool,
}
crate::heap_layout_bound::fields!(Parked; stamp, dependencies, disclosure, used, exact);

/// Slot rotation and the census fence (K7, K10). Keys are
/// `namespace NUL index key`, so concurrent namespaces share one fair queue.
#[derive(Debug, Default)]
struct Rotation {
    /// Cursor page clock: one tick per Codex scan object of any namespace.
    page: u64,
    sequence: u64,
    /// Sequence of each file's last completed attempt: lower goes first,
    /// never-served files (absent, rank zero) first of all.
    served: BTreeMap<String, u64>,
    /// Large files waiting for the slot: (first page waited, last page seen,
    /// not a census member). A census member's read holds the strict census,
    /// so it takes the slot ahead of every re-read (G1).
    waiting: BTreeMap<String, (u64, u64, bool)>,
    /// Census generation of each file's last completed attempt.
    attempted: BTreeMap<String, (String, u64)>,
    /// Groups whose probes outran the page's remaining singleton budget
    /// (`ProbeBudgetOrder`, round 3): each takes a page of its own next.
    own_page: BTreeMap<String, u64>,
}
crate::heap_layout_bound::fields!(Rotation; page, sequence, served, waiting, attempted, own_page);

impl Rotation {
    fn rank(&self, key: &str) -> u64 {
        self.served.get(key).copied().unwrap_or(0)
    }

    /// True when no active waiter is ahead of a census member `key`.
    #[cfg(test)]
    fn turn(&self, key: &str) -> bool {
        self.turn_as(key, true)
    }

    /// True when no active waiter is ahead of `key`. Order: census members
    /// before re-reads (G1), then rank (last completed attempt, zero if never
    /// served), then first page waited (this page if `key` is not waiting).
    fn turn_as(&self, key: &str, census_member: bool) -> bool {
        let mine = (
            !census_member,
            self.rank(key),
            self.waiting
                .get(key)
                .map_or(self.page, |(first, _, _)| *first),
        );
        !self.waiting.iter().any(|(other, (first, seen, reread))| {
            other != key
                && self.page.saturating_sub(*seen) < WAITER_ACTIVE_PAGES
                && (*reread, self.rank(other), *first) < mine
        })
    }

    #[cfg(test)]
    fn wait(&mut self, key: &str) {
        self.wait_as(key, true);
    }

    fn wait_as(&mut self, key: &str, census_member: bool) {
        let page = self.page;
        self.waiting
            .retain(|_, (_, seen, _)| page.saturating_sub(*seen) < WAITER_FORGET_PAGES);
        if let Some((_, seen, reread)) = self.waiting.get_mut(key) {
            *seen = page;
            *reread = !census_member;
            return;
        }
        if self.waiting.len() >= ROTATION_KEYS {
            if let Some(victim) = self
                .waiting
                .iter()
                .min_by_key(|(_, (_, seen, _))| *seen)
                .map(|(key, _)| key.clone())
            {
                self.waiting.remove(&victim);
            }
        }
        self.waiting
            .insert(key.to_owned(), (page, page, !census_member));
    }

    fn fenced(&self, key: &str, fence: Option<&str>) -> bool {
        fence.is_some_and(|fence| {
            self.attempted
                .get(key)
                .is_some_and(|(generation, _)| generation == fence)
        })
    }

    /// An attempt ended (published, uncertified or terminal debt): the file
    /// stops waiting, goes behind every file served before it, and is
    /// processed for its census generation.
    fn complete(&mut self, key: &str, fence: Option<&str>) {
        self.waiting.remove(key);
        self.sequence = self.sequence.saturating_add(1);
        let sequence = self.sequence;
        bounded_insert(&mut self.served, key, sequence, |served| *served);
        if let Some(fence) = fence {
            bounded_insert(
                &mut self.attempted,
                key,
                (fence.to_owned(), sequence),
                |(_, sequence)| *sequence,
            );
        }
    }
}

/// Insert into a map of at most `ROTATION_KEYS` entries, evicting the least
/// recent. Forgetting a rank only moves that file ahead; forgetting a fence
/// only grants it one more attempt in the generation.
fn bounded_insert<V>(
    map: &mut BTreeMap<String, V>,
    key: &str,
    value: V,
    recency: impl Fn(&V) -> u64,
) {
    if !map.contains_key(key) && map.len() >= ROTATION_KEYS {
        if let Some(victim) = map
            .iter()
            .min_by_key(|(_, value)| recency(*value))
            .map(|(key, _)| key.clone())
        {
            map.remove(&victim);
        }
    }
    map.insert(key.to_owned(), value);
}

/// Stage 1 guard (§6): the longest deferral a changed revision waits, in
/// seconds (`new_off = min(1 h, equivalent)`).
const PACE_NEW_BYTES_SECS: u32 = 3_600;

#[cfg(test)]
thread_local! {
    /// Tests only: this thread's pace clock, and a forced failure of every
    /// checked elapsed-time computation (`pace_clock_failure_is_unknown`).
    static PACE_CLOCK: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
    static PACE_CLOCK_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests only: run `body` with the pace clock at `now` (`None`: the real
/// clock) and its checked elapsed times failing when `fail`.
#[cfg(test)]
pub(in crate::snapshots) fn with_pace_clock<T>(
    now: Option<std::time::Instant>,
    fail: bool,
    body: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<std::time::Instant>, bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            PACE_CLOCK.with(|clock| clock.set(self.0));
            PACE_CLOCK_FAIL.with(|failing| failing.set(self.1));
        }
    }
    let _reset = Reset(
        PACE_CLOCK.with(|clock| clock.replace(now)),
        PACE_CLOCK_FAIL.with(|failing| failing.replace(fail)),
    );
    body()
}

/// The pace clock: monotonic, excluding system sleep on macOS (a sleep only
/// lengthens a deferral).
fn pace_now() -> std::time::Instant {
    #[cfg(test)]
    if let Some(now) = PACE_CLOCK.with(std::cell::Cell::get) {
        return now;
    }
    std::time::Instant::now()
}

#[cfg(test)]
fn pace_clock_failed() -> bool {
    PACE_CLOCK_FAIL.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn pace_clock_failed() -> bool {
    false
}

/// Checked `later - earlier`. None (unknown coverage): a clock failure.
fn pace_elapsed(
    later: std::time::Instant,
    earlier: std::time::Instant,
) -> Option<std::time::Duration> {
    if pace_clock_failed() {
        return None;
    }
    later.checked_duration_since(earlier)
}

/// Checked `base + secs`. None (unknown coverage) only past the platform's
/// `Instant` range, which a `u32` of seconds after a real `Instant` cannot
/// reach on a 64-bit target; every None arm is still fail-closed.
fn pace_after(base: std::time::Instant, secs: u32) -> Option<std::time::Instant> {
    base.checked_add(std::time::Duration::from_secs(u64::from(secs)))
}

/// Whole seconds covering `duration` (rounded up, so narrowing never
/// shortens a deadline). None when they do not fit a `u32` offset.
fn pace_offset(duration: std::time::Duration) -> Option<u32> {
    let secs = duration
        .as_secs()
        .checked_add(u64::from(duration.subsec_nanos() > 0))?;
    u32::try_from(secs).ok()
}

/// The pace key of `key` (a singleton's index key) in `namespace` under the
/// receipt and replay `scope` (`group_scope`): the first 16 bytes of a
/// length-prefixed SHA-256 of the three. Another namespace, scope or path is
/// another key; a collision is caught by the slot's exact object fields
/// (`PaceTable::verdict`) and never borrows coverage.
pub(in crate::snapshots) fn pace_key(namespace: &str, scope: &str, key: &str) -> [u64; 2] {
    let digest = ticket_digest(
        b"pace_key",
        &[namespace.as_bytes(), scope.as_bytes(), key.as_bytes()],
    );
    let mut high = [0_u8; 8];
    let mut low = [0_u8; 8];
    high.copy_from_slice(&digest[..8]);
    low.copy_from_slice(&digest[8..16]);
    [u64::from_be_bytes(high), u64::from_be_bytes(low)]
}

/// One huge key's last attempt (§6): when it started, the revision it
/// started on, and the offsets after `last_start` before which its next
/// attempt may not start (`same_off` on the same revision, `new_off` on a
/// changed one). Both are zero until the attempt's ordinary equivalent
/// exceeds its elapsed time, which only a continuation page can make it do.
/// The key is two `u64`s, not a `u128` (align 16 would grow the slot).
#[derive(Clone, Debug)]
struct PaceSlot {
    key: [u64; 2],
    last_start: std::time::Instant,
    rev: OpenStamp,
    new_off: u32,
    same_off: u32,
}

/// Stage 1 guard state (§6, condition 4), inline in `CursorState` and so in
/// `size_of::<SharedCache>()`: no heap, never walked. Cursor admission
/// charges it through `bound(CursorState)` (`size_of_val`); the whole-cache
/// bound through the `Arc`'s `size_of::<SharedCache>()`; `context_overhead`
/// leaves it out, since its release math adds `state_for_main` beside it.
/// `unknown_until` is the latest deadline a lossy eviction or an unknown
/// coverage forgot: until then a key with no slot starts unaccelerated. A
/// restart is a fresh, empty table.
#[derive(Debug)]
pub(in crate::snapshots) struct PaceTable {
    slots: [Option<PaceSlot>; ROTATION_KEYS],
    unknown_until: Option<std::time::Instant>,
}

const _: () = assert!(std::mem::size_of::<Option<PaceSlot>>() <= 96);
const _: () = assert!(std::mem::size_of::<PaceTable>() <= 6_160);

impl Default for PaceTable {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            unknown_until: None,
        }
    }
}

impl HeapLayoutBound for PaceTable {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // Fixed slots of keys, `Instant`s, `OpenStamp`s and offsets.
        c.add(0)
    }
}

/// The guard's start rule for one large ordinary start (§6 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaceVerdict {
    /// Before the last attempt's ordinary-equivalent eligibility.
    Defer,
    /// Today's start; `accelerate` only with known coverage.
    Start { accelerate: bool },
}

impl PaceTable {
    fn position(&self, key: [u64; 2]) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.key == key))
    }

    /// When `slot` stops deferring anything. None: a clock failure.
    fn expiry(slot: &PaceSlot) -> Option<std::time::Instant> {
        pace_after(slot.last_start, slot.same_off.max(slot.new_off))
    }

    fn unknown_at(&self, now: std::time::Instant) -> bool {
        self.unknown_until.is_some_and(|until| now < until)
    }

    /// Raise `unknown_until` to `until` (never lowered).
    fn hold_unknown(&mut self, until: std::time::Instant) {
        self.unknown_until = Some(self.unknown_until.map_or(until, |held| held.max(until)));
    }

    /// The start rule for `key`, whose file is now `rev`. A slot of another
    /// object under the same key (a replaced file or a key collision) still
    /// defers its changed-revision offset and then starts unaccelerated: a
    /// mismatch never shortens a deferral and never borrows coverage. Any
    /// clock failure is unknown coverage: today's start, unaccelerated.
    fn verdict(&self, key: [u64; 2], rev: &OpenStamp, now: std::time::Instant) -> PaceVerdict {
        let Some(slot) = self
            .position(key)
            .and_then(|index| self.slots[index].as_ref())
        else {
            return PaceVerdict::Start {
                accelerate: !self.unknown_at(now),
            };
        };
        let same_object = slot.rev.dev == rev.dev && slot.rev.ino == rev.ino;
        let offset = if same_object && slot.rev == *rev {
            slot.same_off
        } else {
            slot.new_off
        };
        match pace_after(slot.last_start, offset) {
            Some(eligible) if now < eligible => PaceVerdict::Defer,
            Some(_) if same_object => PaceVerdict::Start { accelerate: true },
            // Another object: free only once the slot has expired.
            Some(_) => PaceVerdict::Start {
                accelerate: Self::expiry(slot).is_some_and(|expiry| now >= expiry)
                    && !self.unknown_at(now),
            },
            None => PaceVerdict::Start { accelerate: false },
        }
    }

    /// A free slot, else an expired one (lossless), else the one expiring
    /// first, whose deadline `unknown_until` then covers (lossy). None: a
    /// clock failure leaves no eviction provable.
    fn place(&mut self, now: std::time::Instant) -> Option<usize> {
        if let Some(free) = self.slots.iter().position(Option::is_none) {
            return Some(free);
        }
        let mut earliest: Option<(usize, std::time::Instant)> = None;
        for (index, slot) in self.slots.iter().enumerate() {
            let expiry = Self::expiry(slot.as_ref()?)?;
            if now >= expiry {
                return Some(index);
            }
            if earliest.map_or(true, |(_, first)| expiry < first) {
                earliest = Some((index, expiry));
            }
        }
        let (index, expiry) = earliest?;
        self.hold_unknown(expiry);
        Some(index)
    }

    /// `cursor_start` success: write the attempt's slot at `now`, with zero
    /// offsets. Its own key's slot is rewritten unless it is a live slot of
    /// another object (then none is written). False: no slot, so the
    /// attempt is unaccelerated.
    fn begin(&mut self, key: [u64; 2], rev: &OpenStamp, now: std::time::Instant) -> bool {
        let index = match self.position(key) {
            Some(index) => {
                let Some(slot) = self.slots[index].as_ref() else {
                    return false;
                };
                let same_object = slot.rev.dev == rev.dev && slot.rev.ino == rev.ino;
                if !same_object && !Self::expiry(slot).is_some_and(|expiry| now >= expiry) {
                    return false;
                }
                index
            }
            None => match self.place(now) {
                Some(index) => index,
                None => return false,
            },
        };
        self.slots[index] = Some(PaceSlot {
            key,
            last_start: now,
            rev: rev.clone(),
            new_off: 0,
            same_off: 0,
        });
        true
    }

    /// At every pause and end of the attempt `pace`: rewrite its slot's
    /// offsets from its ordinary equivalent so far (the accrued pages plus
    /// the ordinary time since the last one): `same_off = equivalent`,
    /// `new_off = min(1 h, equivalent)`, rounded up and never below the
    /// recorded ones. An equivalent not above the elapsed time (no
    /// continuation surplus) keeps them zero, so the guard never paces an
    /// attempt that had no continuation page. Unknown coverage (a clock
    /// failure, an overflow) forgets the slot, with `unknown_until` past its
    /// deadline and at least the changed-revision offset ahead; returns
    /// false then. An attempt without a slot changes nothing.
    fn record(&mut self, pace: &JobPace, now: std::time::Instant) -> bool {
        let Some(index) = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|slot| slot.key == pace.key && slot.last_start == pace.started_mono)
        }) else {
            return pace.equiv_secs.is_some();
        };
        let equivalent = pace
            .equiv_secs
            .and_then(|equiv| equiv.checked_add(pace_elapsed(now, pace.last_page_mono)?));
        let elapsed = pace_elapsed(now, pace.started_mono);
        let offsets = equivalent.zip(elapsed).and_then(|(equivalent, elapsed)| {
            if equivalent <= elapsed {
                return Some((0, 0));
            }
            let same = pace_offset(equivalent)?;
            Some((same, same.min(PACE_NEW_BYTES_SECS)))
        });
        let Some((same, new)) = offsets else {
            let expiry = self.slots[index]
                .take()
                .and_then(|slot| Self::expiry(&slot));
            for until in [expiry, pace_after(now, PACE_NEW_BYTES_SECS)]
                .into_iter()
                .flatten()
            {
                self.hold_unknown(until);
            }
            return false;
        };
        if let Some(slot) = self.slots[index].as_mut() {
            slot.same_off = slot.same_off.max(same);
            slot.new_off = slot.new_off.max(new);
        }
        true
    }
}

impl CursorState {
    /// `PaceTable::record` for `pace` now, under the cursor lock.
    fn pace_record(&mut self, pace: &JobPace) -> bool {
        self.pace.record(pace, pace_now())
    }
}

impl SharedCache {
    /// Archive `key`'s funding streak: a yield extends it (returned, capped
    /// past the threshold); funding or retirement (`!yielded`) forgets it.
    /// A restart starts every streak again.
    pub(in crate::snapshots) fn archive_streak(&self, key: &str, yielded: bool) -> u8 {
        let digest = ticket_digest(b"archive_streak", &[key.as_bytes()]);
        self.with_cursor(|cursor| {
            let streaks = &mut cursor.archive_streaks;
            let previous = streaks.remove(&digest).unwrap_or(0);
            if !yielded {
                return 0;
            }
            if streaks.len() == ARCHIVE_STREAK_KEYS {
                streaks.pop_first();
            }
            let count = previous.saturating_add(1).min(ARCHIVE_STARVED_YIELDS + 1);
            streaks.insert(digest, count);
            count
        })
        .unwrap_or(0)
    }

    /// Starved archive keys, optionally only `key`.
    pub(in crate::snapshots) fn archive_starved_count(&self, key: Option<&str>) -> usize {
        let digest = key.map(|key| ticket_digest(b"archive_streak", &[key.as_bytes()]));
        self.with_cursor(|cursor| {
            cursor
                .archive_streaks
                .iter()
                .filter(|(k, n)| **n >= ARCHIVE_STARVED_YIELDS && digest.map_or(true, |d| d == **k))
                .count()
        })
        .unwrap_or(0)
    }

    /// The yield that reaches the threshold alarms once.
    pub(in crate::snapshots) fn archive_yield(&self, key: &str) {
        if self.archive_streak(key, true) == ARCHIVE_STARVED_YIELDS {
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_admission_alarm",
                "codex",
                &serde_json::json!({"consecutive_yields": ARCHIVE_STARVED_YIELDS, "admission_starved_count": self.archive_starved_count(None)}),
            );
        }
    }
}

/// One owner's L-1 provenance: (LRU tick, member keys joined by '\0').
type JoinProvenance = (u64, String);

/// PR-P: a parent witnessed unusable: RAM-only, event-based evidence of why
/// ownership proof is unavailable. It admits nothing, releases nothing and
/// proves nothing; identity change, eviction or process restart loses it and
/// the parent is revalidated fail-closed. `identity: None` only for event (a)
/// identity causes (no current object); every other witness carries the
/// opened identity it was established at, so any change of the parent drops
/// it. `waits_on` is set only on a `DeferredRestart` wait record: the
/// parent's own pending parent, for cycle detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct ParentWitness {
    pub(in crate::snapshots) cause: CodexParentUnresolvable,
    pub(in crate::snapshots) identity: Option<String>,
    pub(in crate::snapshots) waits_on: Option<String>,
}
crate::heap_layout_bound::fields!(ParentWitness; cause, identity, waits_on);

/// Witnesses of one namespace, each with its stored heap charge (key and
/// strings, measured once at insert like `SingletonMemo`), so a cache-wide
/// walk is two visits whatever the count.
#[derive(Default)]
struct ParentWitnesses {
    entries: BTreeMap<String, (ParentWitness, usize)>,
    charge: usize,
}
impl HeapLayoutBound for ParentWitnesses {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        crate::heap_layout_bound::tree_nodes::<String, (ParentWitness, usize)>(
            self.entries.len(),
            c,
        )?;
        c.add(self.charge)
    }
}

/// PR-P per-namespace witnesses; RAM only. Never stale-pruned: bounded at
/// `ROTATION_KEYS` entries (an optional admission for a new namespace past
/// them is refused, `parent_namespace_full`), charged, and released early
/// only by a feasible mandatory admission under memory pressure
/// (`admit_locked`), in bounded batches. The restart counters live apart
/// (`ParentRestarts`).
struct NamespaceParents {
    /// `group_scope` the witnesses belong to; a change drops the entry.
    scope: String,
    /// `rotation.page` at the last access by any parent method.
    touched: u64,
    /// The traversal the witnesses were last matched against: the exact
    /// `(census_window_end, restarts at match)`.
    matched: Option<(String, u64)>,
    witnesses: ParentWitnesses,
}
crate::heap_layout_bound::fields!(NamespaceParents; scope, touched, matched, witnesses);

/// PR-P restart counter of one (namespace, scope). Inline only; keyed by
/// both, so a scope change is a new slot, never a reset.
#[derive(Clone, Copy, Debug, Default)]
struct RestartSlot {
    key: u64,
    restarts: u64,
    touched: u64,
}

/// A fixed inline table, reserved by construction. Nothing is inserted at
/// runtime, so the restart bound can never be refused, and no staleness rule
/// removes a slot: only LRU past `ROTATION_KEYS` (namespace, scope) pairs
/// does, and the re-entering pair starts spent.
struct ParentRestarts([Option<RestartSlot>; ROTATION_KEYS]);
impl Default for ParentRestarts {
    fn default() -> Self {
        Self([None; ROTATION_KEYS])
    }
}
impl HeapLayoutBound for ParentRestarts {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}
impl ParentRestarts {
    /// The slot of `key` (`parent_restart_key(namespace, scope)`), created as
    /// needed; refreshes `touched`. There is no reset branch: a new receipt
    /// scope or a replay is a new key, so a new slot and a new budget, unless
    /// the table is full. `true` when another pair's slot was evicted.
    fn touch(&mut self, key: u64, page: u64) -> (&mut RestartSlot, bool) {
        let at = self
            .0
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.key == key))
            .or_else(|| self.0.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                (0..ROTATION_KEYS)
                    .min_by_key(|&i| self.0[i].map_or(0, |slot| slot.touched))
                    .unwrap_or(0)
            });
        let evicted = self.0[at].is_some_and(|slot| slot.key != key);
        let slot = self.0[at].get_or_insert(RestartSlot {
            key,
            restarts: 0,
            touched: page,
        });
        if slot.key != key {
            // This key's spent budget may have been evicted with an earlier
            // slot. Start spent (fail closed: no restart, only latency), so
            // the bound holds unconditionally, re-entry included.
            *slot = RestartSlot {
                key,
                restarts: PARENT_RESTART_BUDGET,
                touched: page,
            };
        }
        slot.touched = page;
        (slot, evicted)
    }
}

/// Restart slots stay inline, so one (namespace, scope) is keyed by the
/// first eight bytes of the SHA-256 of the namespace's length (u64,
/// big-endian), the namespace, then the scope: the length prefix makes the
/// pair unambiguous. A collision only makes two pairs share one budget: a
/// budget is spent sooner, never refilled (fail closed, latency only).
fn parent_restart_key(namespace: &str, scope: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update((namespace.len() as u64).to_be_bytes());
    hasher.update(namespace.as_bytes());
    hasher.update(scope.as_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// Parent-resolution restarts per (process start, namespace, scope).
pub(in crate::snapshots) const PARENT_RESTART_BUDGET: u64 = 2;

/// A namespace's parent state, cloned out under the cursor lock.
pub(in crate::snapshots) struct ParentState {
    /// The restart count deciding the budget; a poisoned cursor reads it
    /// spent (fail closed).
    pub(in crate::snapshots) restarts: u64,
    /// N1: `restarts` was observed in the table. False on a poisoned cursor,
    /// whose fail-closed `restarts` is a decision, not a count: the
    /// diagnostics then omit `parent_restarts_in_scope`.
    pub(in crate::snapshots) restarts_observed: bool,
    pub(in crate::snapshots) matched: Option<(String, u64)>,
    pub(in crate::snapshots) witnesses: Vec<(String, ParentWitness)>,
}

/// A copy of `value` whose capacity is exactly its length (the requested-
/// layout contract every cursor charge relies on).
fn exact_copy(value: &str) -> String {
    let mut copy = String::with_capacity(value.len());
    copy.push_str(value);
    copy
}

static NEXT_CURSOR_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Existing cursor write intent, not a read receipt or a second store.
/// `entry` only escrows an existing allocation when no attributed key exists.
/// Only negative fields are overlaid on committed state.
// OS pathname bound, inline: binding is copied before optional funding,
// without allocating or inventing a digest/identity for the destination.
struct CustodyOrigin {
    bytes: [u8; 4096],
    len: usize,
}
impl CustodyOrigin {
    fn new(path: &Path) -> Self {
        let value = path.as_os_str().as_encoded_bytes();
        let mut origin = Self {
            bytes: [0; 4096],
            len: value.len(),
        };
        if value.len() <= origin.bytes.len() {
            origin.bytes[..value.len()].copy_from_slice(value);
        }
        origin
    }
    fn matches(&self, path: &Path) -> bool {
        self.len <= self.bytes.len()
            && self.bytes[..self.len] == *path.as_os_str().as_encoded_bytes()
    }
}
pub(in crate::snapshots) struct CustodyDecision {
    origin: CustodyOrigin,
    pub(in crate::snapshots) key: String,
    pub(in crate::snapshots) cause: crate::local_resource_diagnostics::CodexZstCause,
    pub(in crate::snapshots) owners: BTreeSet<String>,
    pub(in crate::snapshots) veto: BTreeSet<String>,
    pub(in crate::snapshots) entry: Option<ScanIndexEntry>,
}
impl HeapLayoutBound for CustodyDecision {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.key.heap_bound(c)?;
        self.owners.heap_bound(c)?;
        self.veto.heap_bound(c)?;
        self.entry.heap_bound(c)
    }
}
struct CustodyWrite {
    pending: Option<CustodyDecision>,
}
impl HeapLayoutBound for CustodyWrite {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.pending.heap_bound(c)
    }
}
/// Owns refusal across allocation and disk I/O, with no cursor lock held.
pub(in crate::snapshots) struct CustodySave {
    cache: Arc<SharedCache>,
    pub(in crate::snapshots) decision: Option<CustodyDecision>,
}
impl CustodySave {
    pub(in crate::snapshots) fn fund(&self, bytes: usize) -> Option<CustodyFunding> {
        self.cache
            .cursor_claim(bytes, true)
            .map(|credit| CustodyFunding(Some(credit)))
    }
    pub(in crate::snapshots) fn complete(mut self, index: &mut ScanIndex) {
        let d = self.decision.take().expect("owned decision");
        let entry = index
            .files
            .entry(d.key.clone())
            .or_insert_with(|| d.entry.unwrap_or_default());
        entry.codex_compressed_hold = Some(d.cause);
        index.codex_state_only_blocked_session_ids.extend(d.veto);
        index
            .codex_state_only_blocked_session_ids
            .extend(d.owners.iter().cloned());
        if !d.owners.is_empty() {
            index
                .codex_state_only_blocked_by_file
                .entry(d.key)
                .or_default()
                .extend(d.owners);
        }
        self.cache
            .with_cursor(|cursor| cursor.custody_unsaved = None);
    }
}
/// Existing cursor credit held across staging and disk save; refunded outside
/// the cursor lock on every outcome. No decoder admission is involved.
pub(in crate::snapshots) struct CustodyFunding(Option<CursorCredit>);
impl Drop for CustodyFunding {
    fn drop(&mut self) {
        if let Some(credit) = self.0.take() {
            credit.refund();
        }
    }
}
impl Drop for CustodySave {
    fn drop(&mut self) {
        if let Some(decision) = self.decision.take() {
            self.cache.with_cursor(|cursor| {
                cursor.custody_unsaved = Some(CustodyWrite {
                    pending: Some(decision),
                })
            });
        }
    }
}

pub(in crate::snapshots) struct CursorState {
    pub(in crate::snapshots) headers: codex_file_join::HeaderCache,
    slot: Slot,
    slot_key: Option<String>,
    /// Member keys of the slot's group job (empty for a singleton): selection
    /// skips them while the job exists (§d.1.2 c).
    slot_members: BTreeSet<String>,
    /// Owners B blocked for queued groups, with their exact member keys
    /// joined by '\0' (§d.1.3 provenance, L-1): the release's only deletion
    /// authority. RAM only; at most `JOIN_OWNERS`; admitted before it is built.
    join_owners: BTreeMap<String, JoinProvenance>,
    /// Bytes claimed by outstanding `CursorCredit`s: charged like resident
    /// state until settled, so no later admission can spend the same room.
    /// `usize::MAX` marks corrupt credit accounting: the state then measures
    /// unbounded and admits nothing (fail closed).
    reserved: usize,
    /// This state's identity; a credit settles only against the state that
    /// claimed it.
    id: u64,
    /// Requested-layout charge of the paused job, measured when it paused.
    slot_charge: usize,
    /// Cursor page when the paused job last paused or resumed (K10).
    slot_touched: u64,
    next_token: u64,
    /// LRU clock shared by the invalidation and parked records (L1).
    clock: u64,
    memo: SingletonMemo,
    wake: WakeIdentities,
    invalidations: BTreeMap<String, (u32, u64)>,
    /// One serialized negative write intent; survives job loss/save refusal.
    /// No read permission or consumed-progress receipt.
    custody_unsaved: Option<CustodyWrite>,
    parked: BTreeMap<String, Parked>,
    rotation: Rotation,
    counters: Counters,
    /// PR-P: parent witnesses per namespace (charged, LRU at `ROTATION_KEYS`).
    parents: BTreeMap<String, NamespaceParents>,
    /// PR-P: parent-resolution restart counters (inline, never charged).
    parent_restarts: ParentRestarts,
    /// U1a-2a (cc row 1): the one suspended proof job, never in `slot`.
    proof: ProofHolder,
    /// U1a-2a (owner note 3, r79): retired jobs' entry `seq`s, for their
    /// index's next hook (inline, no heap).
    proof_retired: RetiredProofs,
    /// U1a-2a (cc row 1): proof batches' rotation (the `Rotation` shape;
    /// its page follows `rotation.page`).
    proof_rotation: Rotation,
    /// U1a-2a (cc row 8): the namespace whose proof hook last found proof
    /// work due, and whether its current page reached the hook. One entry:
    /// a later namespace's due hook replaces it (under-counting only).
    proof_due: Option<(String, bool)>,
    /// Stage 1 guard (§6): huge keys' last attempts (inline, never walked).
    pace: PaceTable,
    /// Archive keys' consecutive funding yields (`archive_streak`), charged.
    archive_streaks: BTreeMap<[u8; 32], u8>,
}

impl Default for CursorState {
    fn default() -> Self {
        Self {
            headers: codex_file_join::HeaderCache::default(),
            slot: Slot::Empty,
            slot_key: None,
            slot_members: BTreeSet::new(),
            join_owners: BTreeMap::new(),
            reserved: 0,
            id: NEXT_CURSOR_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            slot_charge: 0,
            slot_touched: 0,
            next_token: 1,
            clock: 0,
            memo: SingletonMemo::default(),
            wake: WakeIdentities::default(),
            invalidations: BTreeMap::new(),
            custody_unsaved: None,
            parked: BTreeMap::new(),
            rotation: Rotation::default(),
            counters: Counters::default(),
            parents: BTreeMap::new(),
            parent_restarts: ParentRestarts::default(),
            proof: ProofHolder::None,
            proof_retired: RetiredProofs::default(),
            proof_rotation: Rotation::default(),
            proof_due: None,
            pace: PaceTable::default(),
            archive_streaks: BTreeMap::new(),
        }
    }
}

impl HeapLayoutBound for CursorState {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            headers,
            slot,
            slot_key,
            slot_members,
            join_owners,
            reserved,
            id: _,
            slot_charge,
            slot_touched,
            next_token,
            clock,
            memo,
            wake,
            invalidations,
            custody_unsaved,
            parked,
            rotation,
            counters,
            parents,
            parent_restarts,
            proof,
            // Inline (fixed-size `seq`s and digests): no heap.
            proof_retired: _,
            proof_rotation,
            proof_due,
            // Stage 1 guard: inline slots and deadline, no heap; charged once
            // through this state's `size_of_val` (`bound`).
            pace: _,
            archive_streaks,
        } = self;
        // The paused job was walked once when it paused; its charge stays
        // fixed while it sits here because nothing mutates a paused parser.
        match slot {
            Slot::Empty | Slot::ActiveElsewhere { .. } => c.add(0)?,
            Slot::Paused(_) => c.add(*slot_charge)?,
        }
        if MAIN_VIEW.with(std::cell::Cell::get) {
            codex_file_join::HeaderCache::default().charge(c)?;
        } else {
            headers.charge(c)?;
        }
        slot_key.heap_bound(c)?;
        slot_members.heap_bound(c)?;
        // Owner strings and joined member keys are visited (one each).
        join_owners.heap_bound(c)?;
        // Outstanding claims count as resident until settled.
        c.add(*reserved)?;
        slot_touched.heap_bound(c)?;
        next_token.heap_bound(c)?;
        clock.heap_bound(c)?;
        memo.heap_bound(c)?;
        wake.heap_bound(c)?;
        invalidations.heap_bound(c)?;
        custody_unsaved.heap_bound(c)?;
        parked.heap_bound(c)?;
        rotation.heap_bound(c)?;
        counters.heap_bound(c)?;
        // PR-P: witnesses are charged; the restart table is inline.
        parents.heap_bound(c)?;
        parent_restarts.heap_bound(c)?;
        // U1a-2a: a suspended proof is charged its walked bound.
        proof.heap_bound(c)?;
        proof_rotation.heap_bound(c)?;
        proof_due.heap_bound(c)?;
        archive_streaks.heap_bound(c)
    }
}

impl CursorState {
    fn tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }
}

/// Ownership of the slot by one scan object while its job is active there.
/// Dropping a lease without its job frees the slot; the job's path is still
/// in `pending_candidates`, so the next page restarts it. A dropped scan
/// frame returns its job through `ActiveFrame` instead (K12).
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
                    cursor.slot_members.clear();
                    cursor.counters.jobs_lost += 1;
                }
            });
        }
    }
}

/// The scan frame's active file and, while it is a cursor job, its slot
/// lease. Dropping a frame mid-job (an abandoned or refused page) returns
/// the intact job to the slot (K12), so a later page resumes it instead of
/// losing every page already read. The file is boxed so the scan object,
/// and every move of the active file in `OwnedSourceScan::step`, stays
/// pointer-sized (debug builds give each temporary its own stack slot).
#[derive(Default)]
pub(in crate::snapshots) struct ActiveFrame {
    file: Option<Box<OwnedActiveFile>>,
    lease: Option<CursorLease>,
}
crate::heap_layout_bound::fields!(ActiveFrame; file, lease);

impl ActiveFrame {
    pub(in crate::snapshots) fn new(
        file: Option<Box<OwnedActiveFile>>,
        lease: Option<CursorLease>,
    ) -> Self {
        Self { file, lease }
    }

    pub(in crate::snapshots) fn into_parts(
        mut self,
    ) -> (Option<Box<OwnedActiveFile>>, Option<CursorLease>) {
        (self.file.take(), self.lease.take())
    }
}

impl std::ops::Deref for ActiveFrame {
    type Target = Option<Box<OwnedActiveFile>>;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl std::ops::DerefMut for ActiveFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

impl Drop for ActiveFrame {
    fn drop(&mut self) {
        if let (Some(file), Some(lease)) = (self.file.take(), self.lease.take()) {
            if file.cursor.is_some() {
                lease.return_job(file);
            }
        }
    }
}

/// How a pause attempt ended.
pub(in crate::snapshots) enum PauseEnd {
    Paused,
    /// The paused state did not fit the state budget even after releasing
    /// retained copies. The job ended as strict `JoinStateBound` debt and is
    /// parked; the caller discloses it, keeps the prior body and releases
    /// the path. Never read unpaged.
    StateBound(Box<OwnedActiveFile>, Disclosure),
}

/// A committed attempt awaiting the native finish (M4). It counts as
/// certified or uncertified only once `finish` succeeded.
#[must_use]
pub(in crate::snapshots) struct Publication {
    certified: bool,
    /// `now - due` when it certified at or after its audit deadline.
    overdue_age: Option<u64>,
    /// E1 applied this read's withheld final record.
    eof_applied: bool,
}
impl Publication {
    /// Whether E1 applied the withheld final record, so the reduction is not
    /// the reduction through the certified prefix. Read before
    /// `cursor_published` consumes the publication; `eof_applied(job)` is not
    /// valid after `finish_job`.
    pub(in crate::snapshots) fn eof_applied(&self) -> bool {
        self.eof_applied
    }
}

/// A completed attempt on a file that did not grow withheld an unterminated
/// record after `offset` (N2). The sealed completion never counts it, so the
/// index must not treat the full length as read: the caller stages `debt`
/// and, when it retained the prefix copy, records the entry at `offset` so
/// the next page tails `[offset, L)` with main's EOF behavior.
#[derive(Clone, Copy, Debug)]
pub(in crate::snapshots) struct SealedFragment {
    pub(in crate::snapshots) offset: u64,
    pub(in crate::snapshots) debt: AuditDebt,
}

/// How a cursor job's attempt ended at its frozen extent (§e.2 with C1).
pub(in crate::snapshots) enum JobEnd {
    /// `[0, s)` is certified; `grown` is true when bytes were appended past
    /// the frozen extent (they belong to the next tail).
    Certified {
        checkpoint: Checkpoint,
        grown: bool,
        publication: Publication,
        fragment: Option<SealedFragment>,
    },
    /// Every object check held but the read was lossy: publish uncertified
    /// with debt staged, exactly like today's lossy full read. A grown file
    /// publishes only through ruling 2's same-object identity proof
    /// (`FinishGrant::LossySameObject`), revalidated in `finish`.
    Uncertified {
        grown: bool,
        publication: Publication,
        fragment: Option<SealedFragment>,
    },
    /// Nothing from this attempt is published or committed and its path
    /// stays pending: a necessary invalidation (replacement, shrink,
    /// same-size edit, held-FD sample mismatch, unknown witness, dependency
    /// or counting change; counted), a tail past its audit deadline (M1), or
    /// unavailable evidence (K9); the last two are uncounted.
    Restart,
    /// The attempt was invalidated `MEMBER_CHANGED_AFTER` times in a row:
    /// disclose this strict debt and release the path.
    MemberChanged(Disclosure),
}

/// The paused job's requested-layout charge (K1, N3): the whole job walked
/// with `completed_bound` (live source-wide inputs already removed), so every
/// collection element (turn-key witnesses, usage hours, capability buckets)
/// gets its own visit budget and the job is limited by bytes (`STATE_BYTES`)
/// alone, never by the walk's visit limit. A pause is a completion-only
/// composition: it runs once per page, never per line. None when the witness
/// map is absent (a job that could never revalidate) or the charge exceeds
/// `STATE_BYTES`.
pub(in crate::snapshots) fn paused_charge(job: &OwnedActiveFile) -> Option<usize> {
    job.parser
        .accumulator
        .codex_observed_priority_turns
        .as_ref()?;
    crate::heap_layout_bound::completed_bound(job, STATE_BYTES)
}

/// The pause walk is the resumed page's starting copy-budget charge (E3):
/// both exclude the live source-wide inputs.
fn record_paused_charge(job: &mut OwnedActiveFile, charge: usize) {
    let consumed = job_position(job, job.parser.reader.consumed_bytes());
    let buffer = job.parser.reader.buf.capacity();
    if let Some(meta) = job.cursor.as_mut() {
        meta.record_charge(charge, consumed, buffer);
    }
}

/// Request `max(len, 64 KiB)` reader-buffer capacity before a slot charge
/// (parent shrink ACK). Every live byte is kept (a paused skip holds none:
/// E4 took its salvage); the charge then walks the actual resulting capacity, which the
/// allocator may leave larger. Shrinking never certifies, publishes, clears
/// debt or grants read budget.
pub(in crate::snapshots) fn shrink_paused_buffer(buf: &mut Vec<u8>) {
    buf.shrink_to(buf.len().max(PAUSED_BUFFER_BYTES));
}

/// Stage 1 hunk A (`stage1/c14c15-answer.md` §1): the cursor binding of one
/// paused attempt, minted only at the single pause site and checked by
/// `SharedCache::cursor_continuation_ready` before a continuation page loads
/// its index. Fixed-size and inline (no heap). The namespace, rotation key
/// and census generation are bound by length-prefixed SHA-256 digests; the
/// attempt itself by its exact opened-object stamp and start second, and the
/// process-local cursor state by its identity. A digest match therefore never
/// readies a job on its own: the same opened object at the same start in the
/// same cursor state must also be paused there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CodexCursorTicket {
    /// `CursorState::id` of the cache that paused the job: a fresh cache (a
    /// process restart) never matches.
    epoch: u64,
    namespace: [u8; 32],
    key: [u8; 32],
    /// The job's census generation (K7 fence), when it has one.
    fence: Option<[u8; 32]>,
    stamp_open: OpenStamp,
    started: u64,
}

impl HeapLayoutBound for CodexCursorTicket {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        // Digests, `OpenStamp` and integers only: nothing on the heap.
        c.add(0)
    }
}

impl CodexCursorTicket {
    /// Stage 1 K8, tests only: a well-formed ticket that no cursor state ever
    /// paused (epoch `u64::MAX`), so it is never ready and names no members.
    #[cfg(test)]
    pub(crate) fn unready_for_test() -> Self {
        Self {
            epoch: u64::MAX,
            namespace: [0; 32],
            key: [0; 32],
            fence: None,
            stamp_open: OpenStamp {
                dev: 0,
                ino: 0,
                extent: 0,
                modified: (0, 0),
                changed: (0, 0),
            },
            started: 0,
        }
    }

    fn of(epoch: u64, meta: &JobMeta) -> Self {
        Self {
            epoch,
            namespace: ticket_digest(b"namespace", &[meta.namespace.as_bytes()]),
            key: ticket_digest(
                b"rotation_key",
                &[meta.namespace.as_bytes(), meta.key.as_bytes()],
            ),
            fence: meta
                .fence
                .as_deref()
                .map(|fence| ticket_digest(b"fence", &[fence.as_bytes()])),
            stamp_open: meta.stamp_open.clone(),
            started: meta.started,
        }
    }
}

fn ticket_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"codex_continuation_ticket:v1\0");
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Stage 1 (§6): whether this attempt may ask for continuation pages: it
/// started with known coverage (`PaceTable::verdict`, a recorded slot) and
/// its coverage stayed known since. Only false ever refuses; it reads the
/// job's own inline flag, so no lock is taken.
fn accelerated(meta: &JobMeta) -> bool {
    meta.pace.accelerate
}

/// Stage 1 (§6, E2): add one resumed page's ordinary-equivalent time to its
/// attempt and return it: the elapsed time since the job's last page, or on
/// a continuation page `max(elapsed, ordinary)`, where `ordinary` is the
/// interval the ordinary cadence would have used for that gap (StateMissing's
/// input; `None` is unknown). A clock failure, an overflow or an unknown
/// interval makes the attempt's coverage unknown for good and disables its
/// acceleration (no further ticket).
fn accrue_equivalent(
    meta: &mut JobMeta,
    continuation: bool,
    ordinary: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    let pace = &mut meta.pace;
    let now = pace_now();
    let added = pace_elapsed(now, pace.last_page_mono).and_then(|elapsed| {
        if continuation {
            ordinary.map(|ordinary| elapsed.max(ordinary))
        } else {
            Some(elapsed)
        }
    });
    pace.last_page_mono = now;
    pace.equiv_secs = pace
        .equiv_secs
        .zip(added)
        .and_then(|(equiv, added)| equiv.checked_add(added));
    if pace.equiv_secs.is_none() {
        pace.accelerate = false;
    }
    pace.equiv_secs.and(added)
}

/// Why `cursor_continuation_ready` refused a ticket. Every refusal sends the
/// next page to the ordinary cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum ReadyRefusal {
    /// The cursor state is poisoned.
    Unavailable,
    /// Another cursor state (a restarted cache), or the same file's attempt
    /// restarted (another opened object or start).
    Restarted,
    /// No paused job, or the paused job is another file or generation.
    Stale,
    /// The paused job belongs to another namespace.
    Foreign,
    /// The attempt is not accelerated: it started without known coverage,
    /// or its coverage became unknown.
    Unaccelerated,
}

/// The paused job `ticket` names, under the cursor lock (no IO).
fn ready_job<'a>(
    cursor: &'a CursorState,
    ticket: &CodexCursorTicket,
) -> std::result::Result<&'a OwnedActiveFile, ReadyRefusal> {
    if cursor.id != ticket.epoch {
        return Err(ReadyRefusal::Restarted);
    }
    let Slot::Paused(job) = &cursor.slot else {
        return Err(ReadyRefusal::Stale);
    };
    let Some(meta) = job.cursor.as_ref() else {
        return Err(ReadyRefusal::Stale);
    };
    let now = CodexCursorTicket::of(cursor.id, meta);
    if now.namespace != ticket.namespace {
        return Err(ReadyRefusal::Foreign);
    }
    if now.key != ticket.key || now.fence != ticket.fence {
        return Err(ReadyRefusal::Stale);
    }
    if now.stamp_open != ticket.stamp_open || now.started != ticket.started {
        return Err(ReadyRefusal::Restarted);
    }
    if !accelerated(meta) {
        return Err(ReadyRefusal::Unaccelerated);
    }
    Ok(job)
}

impl SharedCache {
    /// Stage 1 hunk A: the ticket of a job about to pause at the page's
    /// exhausted cursor budget, taken before `CursorLease::pause` consumes
    /// it; the caller keeps it only when the pause returns `Paused`. None for
    /// a file without a cursor job, a budget not exhausted, or an attempt not
    /// accelerated.
    ///
    /// Lock order (S1-b): the pause site holds no lock here. The lease is a
    /// slot token, not a lock; `accelerated` reads the job's own flag; the one
    /// `with_cursor` below takes only the cursor lock, with neither the
    /// retained nor the side lock held, and calls no locking helper inside
    /// (`CursorHeld` asserts a relock in debug builds).
    pub(in crate::snapshots) fn continuation_ticket(
        &self,
        job: &OwnedActiveFile,
        page: &PageBudget,
    ) -> Option<CodexCursorTicket> {
        if job.group.is_some() {
            if page.continuation()
                || (page.cursor_exhausted(Limits::current())
                    && job.cursor.as_ref().is_some_and(accelerated))
            {
                crate::local_resource_diagnostics::codex_continuation(Some("group_job"));
            }
            return None;
        }
        let meta = job.cursor.as_ref()?;
        if !page.cursor_exhausted(Limits::current()) || !accelerated(meta) {
            return None;
        }
        let epoch = self.with_cursor(|cursor| cursor.id)?;
        Some(CodexCursorTicket::of(epoch, meta))
    }

    /// `cursor_continuation_ready`: whether `ticket`'s attempt is still the
    /// paused job, for its namespace, in this cursor state, and accelerated.
    /// Under the cursor lock, with no IO.
    pub(in crate::snapshots) fn cursor_continuation_ready(
        &self,
        ticket: &CodexCursorTicket,
    ) -> std::result::Result<(), ReadyRefusal> {
        self.with_cursor(|cursor| ready_job(cursor, ticket).map(|_| ()))
            .unwrap_or(Err(ReadyRefusal::Unavailable))
    }

    /// Stage 1 (D): the index keys of a ready ticket's job members: the only
    /// paths a continuation page selects. None unless the ticket is ready.
    #[cfg(test)]
    pub(in crate::snapshots) fn continuation_members(
        &self,
        ticket: &CodexCursorTicket,
    ) -> Option<BTreeSet<String>> {
        self.with_cursor(|cursor| {
            ready_job(cursor, ticket).ok().map(|job| {
                job_files(job)
                    .into_iter()
                    .map(|file| local_index_key(&file.path))
                    .collect()
            })
        })?
    }

    /// Tests only: the ticket the paused job would carry if it were
    /// accelerated, whatever its `accelerate`.
    #[cfg(test)]
    pub(in crate::snapshots) fn paused_ticket_for_test(&self) -> Option<CodexCursorTicket> {
        self.with_cursor(|cursor| match &cursor.slot {
            Slot::Paused(job) => job
                .cursor
                .as_ref()
                .map(|meta| CodexCursorTicket::of(cursor.id, meta)),
            _ => None,
        })?
    }

    /// Tests only: the paused job's member index keys, whatever its ticket.
    #[cfg(test)]
    pub(in crate::snapshots) fn paused_members_for_test(&self) -> Option<BTreeSet<String>> {
        self.with_cursor(|cursor| match &cursor.slot {
            Slot::Paused(job) => Some(
                job_files(job)
                    .into_iter()
                    .map(|file| local_index_key(&file.path))
                    .collect(),
            ),
            _ => None,
        })?
    }
}

/// Resume-only access to the held cursor; never selects or starts a job.
pub(crate) struct CodexCursorPort {
    cache: Arc<SharedCache>,
}

impl CodexCursorPort {
    pub(crate) fn new(cache: Arc<SharedCache>) -> Self {
        Self { cache }
    }

    /// Hunk A: the ticket a just-finished Codex page's pause minted.
    pub(crate) fn ticket_for(&self, scan: &SourceScanResult) -> Option<CodexCursorTicket> {
        scan.continuation_ticket().cloned()
    }

    /// `cursor_continuation_ready`, before the page loads its index.
    pub(crate) fn ready(&self, ticket: &CodexCursorTicket) -> bool {
        self.cache.cursor_continuation_ready(ticket).is_ok()
    }

    /// Hunk D: the member index keys the continuation page selects
    /// (`OwnedSourceScan::new_continuation`); None unless `ready`.
    #[cfg(test)]
    pub(crate) fn members(&self, ticket: &CodexCursorTicket) -> Option<BTreeSet<String>> {
        self.cache.continuation_members(ticket)
    }
}

impl CursorLease {
    /// Park the job in the slot until a later page resumes it.
    pub(in crate::snapshots) fn pause(self, mut job: Box<OwnedActiveFile>) -> PauseEnd {
        if let Some(meta) = job.cursor.as_mut() {
            meta.pages = meta.pages.saturating_add(1);
        }
        self.suspend(job, |counters| counters.jobs_paused += 1)
    }

    /// The resumed job's revalidation evidence is unavailable this page
    /// (K9): not a member change. It returns to the slot uncounted, its
    /// path still pending (`InProgress`).
    pub(in crate::snapshots) fn defer(self, job: Box<OwnedActiveFile>) -> PauseEnd {
        self.suspend(job, |counters| counters.jobs_deferred_inputs += 1)
    }

    /// Charge the job (live source-wide inputs excluded; the resuming scan
    /// reinstalls them) and make room for it in the state budget by
    /// releasing least-recently-useful retained copies (K6). A job that does
    /// not fit ends as strict `JoinStateBound` debt.
    fn suspend(self, mut job: Box<OwnedActiveFile>, count: fn(&mut Counters)) -> PauseEnd {
        // The slot charge walks the reader buffer's capacity (S3); shrink it
        // first so one overlong record cannot pin `max_line_bytes`.
        shrink_paused_buffer(&mut job.parser.reader.buf);
        let inputs = job.parser.take_live_reduction_inputs();
        let tee_inputs = job.group.as_mut().and_then(|group| group.take_tee_inputs());
        let admitted = paused_charge(&job).and_then(|charge| self.cache.cursor_reserve(charge));
        let Some(credit) = admitted else {
            job.parser.restore_live_reduction_inputs(inputs);
            if let Some(group) = job.group.as_mut() {
                group.restore_tee_inputs(tee_inputs);
            }
            let owner = job.cursor.as_ref().and_then(|meta| meta.owner.clone());
            let disclosure = strict_disclosure(&job, owner, DebtReason::JoinStateBound);
            let stamp = job
                .group
                .as_ref()
                .and_then(|group| group.stamps.last())
                .or_else(|| job.cursor.as_ref().map(|meta| &meta.stamp_open))
                .cloned();
            let path = job
                .group
                .as_ref()
                .and_then(|group| group.members.last())
                .unwrap_or(&job.candidate)
                .path
                .as_path();
            let stamp = stamp.map(|stamp| self.cache.retained_stamp(path, stamp));
            self.end(|cursor| {
                cursor.counters.jobs_state_bound += 1;
                if let Some(meta) = job.cursor.as_ref() {
                    cursor.pace_record(&meta.pace);
                    cursor.invalidations.remove(&meta.key);
                    let used = cursor.tick();
                    // A group parks under its live member's boot stamp, the
                    // file its lookup opens (R2-H1); sealed members wake it
                    // through the identities in its dependencies.
                    let stamp = stamp.expect("a cursor job has a boot stamp");
                    park(
                        cursor,
                        meta.key.clone(),
                        Parked {
                            stamp,
                            dependencies: job
                                .group
                                .as_ref()
                                .and_then(|group| group.dependencies.clone())
                                .or_else(|| meta.dependencies.clone()),
                            disclosure: disclosure.clone(),
                            used,
                            exact: false,
                        },
                    );
                    cursor.rotation.complete(
                        &rotation_key(&meta.namespace, &meta.key),
                        meta.fence.as_deref(),
                    );
                }
            });
            return PauseEnd::StateBound(job, disclosure);
        };
        drop(inputs);
        drop(tee_inputs);
        record_paused_charge(&mut job, credit.bytes());
        self.store(job, credit, count);
        PauseEnd::Paused
    }

    /// Frame drop (K12): an intact job returns to the slot. A job that no
    /// longer fits is lost; its path is still pending, so it restarts.
    fn return_job(self, mut job: Box<OwnedActiveFile>) {
        shrink_paused_buffer(&mut job.parser.reader.buf);
        drop(job.parser.take_live_reduction_inputs());
        drop(job.group.as_mut().and_then(|group| group.take_tee_inputs()));
        match paused_charge(&job).and_then(|charge| self.cache.cursor_reserve(charge)) {
            Some(credit) => {
                record_paused_charge(&mut job, credit.bytes());
                self.store(job, credit, |counters| counters.jobs_frame_returned += 1);
            }
            None => self.end(|cursor| {
                // Stage 1: a lost attempt keeps its equivalent (§6).
                if let Some(meta) = job.cursor.as_ref() {
                    cursor.pace_record(&meta.pace);
                }
                cursor.counters.jobs_lost += 1;
            }),
        }
    }

    /// Move the job into the slot this lease holds, then disarm. The credit
    /// becomes `slot_charge` in the same critical section (atomic swap).
    fn store(self, job: Box<OwnedActiveFile>, credit: CursorCredit, count: fn(&mut Counters)) {
        let token = self.token;
        let cache = Arc::clone(&self.cache);
        let mut job = Some(job);
        let mut credit = Some(credit);
        self.end(|cursor| {
            // Stage 1 (§6): every pause rewrites the attempt's pace offsets;
            // unknown coverage disables its acceleration from here on.
            if let Some(meta) = job.as_mut().and_then(|job| job.cursor.as_mut()) {
                if !cursor.pace_record(&meta.pace) {
                    meta.pace.accelerate = false;
                }
            }
            if matches!(cursor.slot, Slot::ActiveElsewhere { token: held } if held == token) {
                cursor.slot = Slot::Paused(job.take().expect("job moved once"));
                let credit = credit.take().expect("credit settled once");
                cursor.slot_charge = credit.bytes();
                credit.settle(cursor);
                cursor.slot_touched = cursor.rotation.page;
                count(&mut cursor.counters);
            }
        });
        if let Some(job) = job.take() {
            // The slot no longer named this lease (impossible while armed).
            // The path is still pending, so the next page restarts the job.
            // The unretained job is freed BEFORE its claim is refunded, so no
            // other admission can spend those bytes while they are allocated.
            drop(job);
            cache.with_cursor(|cursor| cursor.counters.jobs_lost += 1);
        }
        if let Some(credit) = credit {
            credit.refund();
        }
    }

    /// Apply `update` under the slot lock, then free the slot if this lease
    /// still holds it (a pause has moved it to `Paused` by then), and disarm.
    fn end(mut self, update: impl FnOnce(&mut CursorState)) {
        let token = self.token;
        self.cache.with_cursor(|cursor| {
            update(cursor);
            if matches!(cursor.slot, Slot::ActiveElsewhere { token: held } if held == token) {
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
                cursor.slot_members.clear();
            }
        });
        self.armed = false;
    }

    /// The attempt ended outside the certificate (a read error): free the
    /// slot. The caller's existing failure handling owns the retry.
    pub(in crate::snapshots) fn release(self) {
        self.end(|_| {});
    }
}

/// Count one invalidated attempt; returns the consecutive count.
fn note_invalidation(cursor: &mut CursorState, key: &str) -> u32 {
    cursor.counters.jobs_invalidated += 1;
    let used = cursor.tick();
    if !cursor.invalidations.contains_key(key) && cursor.invalidations.len() >= INVALIDATION_KEYS {
        // Bounded RAM: forgetting the least recent count only grants that
        // file more restarts before it is disclosed as `MemberChanged`.
        if let Some(oldest) = cursor
            .invalidations
            .iter()
            .min_by_key(|(_, (_, used))| *used)
            .map(|(key, _)| key.clone())
        {
            cursor.invalidations.remove(&oldest);
        }
    }
    let (count, last) = cursor.invalidations.entry(key.to_owned()).or_default();
    *count = count.saturating_add(1);
    *last = used;
    *count
}

/// An invalidated attempt either restarts (false) or, at the threshold,
/// ends as `MemberChanged` (true, counted here).
fn invalidated(cursor: &mut CursorState, key: &str) -> bool {
    if note_invalidation(cursor, key) < MEMBER_CHANGED_AFTER {
        return false;
    }
    cursor.invalidations.remove(key);
    cursor.counters.jobs_member_changed += 1;
    true
}

fn park(cursor: &mut CursorState, key: String, parked: Parked) {
    if !cursor.parked.contains_key(&key) && cursor.parked.len() >= PARKED_KEYS {
        // Bounded RAM: evicting the least recent record only costs that file
        // one more bounded attempt before it is parked again.
        if let Some(oldest) = cursor
            .parked
            .iter()
            .min_by_key(|(_, parked)| parked.used)
            .map(|(key, _)| key.clone())
        {
            cursor.parked.remove(&oldest);
        }
    }
    cursor.parked.insert(key, parked);
}

/// End a cursor job at its frozen extent: certify the sealed prefix from the
/// held FD (`ReadPlan::commit_sealed_prefix`), record the attempt and free
/// the slot. `current_scope` and `counting_now` are recomputed now from the
/// current index (K8, K9). `census_trusted`: the state and sidecar census
/// were complete at start and are now.
pub(in crate::snapshots) fn finish_job(
    cache: &SharedCache,
    lease: Option<CursorLease>,
    job: &mut OwnedActiveFile,
    current_scope: Option<&Scope>,
    counting_now: &str,
    group_scope_now: &str,
    census_trusted: bool,
) -> JobEnd {
    let Some(meta) = job.cursor.take() else {
        return JobEnd::Restart;
    };
    let held = OpenStamp::capture(job.parser.reader.reader.get_ref()).ok();
    let read_to = read_end(job);
    // Only dev/ino of the path are compared; no byte is read from it.
    let path_same_object = held.as_ref().is_some_and(|held| {
        fs::symlink_metadata(&job.candidate.path)
            .is_ok_and(|path| path.dev() == held.dev && path.ino() == held.ino)
    });
    let grown = held
        .as_ref()
        .is_some_and(|held| held.extent > meta.stamp_open.extent);
    // E1: applied on the completion step, before the protected-tier gate
    // (`apply_eof_record`). Such a job gets no S12 grant below.
    let eof_applied = meta.eof_applied;
    let parser = &mut job.parser;
    let lossy = parser.reader.lossy_prefix()
        || parser.reader.failure.is_some()
        || !sampled_jsonl::loss_free_source_report(
            &parser.reader.report,
            parser.recognized_usage_drop_count,
            parser.accumulator.dropped_usage_record_count,
        );
    let consumed = parser.reader.consumed_bytes();
    let now = super::now_seconds();
    // A group's receipts and replay are bound to its start scope (R1-M1).
    let counting_holds = counting_reusable(&parser.accumulator, &meta.counting, counting_now)
        && job
            .group
            .as_ref()
            .map_or(true, |group| group.scope == group_scope_now);
    let mut frozen_end = None;
    let mut read_start = 0;
    let mut lossy_identity = None;
    // `Err(None)`: evidence unavailable at emission (K9), not a refusal.
    let result = match (parser.reader.acquisition.take(), current_scope) {
        (Some(_), Some(_)) if !counting_holds => Err(Some(PrefixRefusal::Dependency)),
        (Some(plan), Some(scope)) => {
            read_start = plan.start_offset();
            let consumed_end = read_start.saturating_add(consumed);
            frozen_end = parser
                .reader
                .extent_limit
                .map(|limit| plan.start_offset().saturating_add(limit));
            let (result, identity) = plan.commit_sealed_prefix_or_lossy_identity(
                parser.reader.reader.get_mut(),
                path_same_object,
                scope,
                meta.started,
                now,
                lossy,
                consumed_end,
            );
            lossy_identity = identity;
            result.map_err(Some)
        }
        (Some(_), None) => Err(None),
        (None, _) => Err(Some(PrefixRefusal::Invalidated(
            FullReason::InvalidCheckpoint,
        ))),
    };
    // R1-M1: under an untrusted census the scope follows census completeness,
    // so a dependency mismatch is unavailable evidence, not a member change.
    let result = match result {
        Err(Some(PrefixRefusal::Dependency)) if !census_trusted => Err(None),
        result => result,
    };
    // N2: on a quiescent file the withheld record will not be completed by
    // an append; its bytes stay owed. The deadline is the read's own audit
    // cadence (verified = start), so this never loops faster than audits.
    let fragment = (parser.reader.sealed_fragment() && !grown).then(|| SealedFragment {
        offset: read_start.saturating_add(parser.reader.last_complete_line_end()),
        debt: AuditDebt {
            due_unix_seconds: meta.started.saturating_add(AUDIT_INTERVAL_SECONDS),
        },
    });
    // A parentless created thread is proven only by its complete physical
    // stream, so `finish` holds it on the withheld record; the memo keeps
    // that hold from being re-read before the file changes.
    if let Some(fragment) =
        fragment.filter(|_| parser.accumulator.codex_parentless_created_thread())
    {
        job.hold_offset = job.hold_offset.or(Some(fragment.offset));
    }
    // R1-H1 (#630 review): a hold an append may cure is memoized on the held
    // file's exact stamp, which must not cover bytes this read never
    // consumed: they may already cure it. Such a hold records no entry, so
    // its next attempt reads them.
    if held.as_ref().map_or(true, |held| held.extent != read_to)
        && (growth_may_cure(&job.parser.accumulator) || job.parser.reader.sealed_fragment())
    {
        job.hold_offset = None;
    }
    let key = rotation_key(&meta.namespace, &meta.key);
    let mut member_changed = false;
    let update = |cursor: &mut CursorState| {
        // Stage 1 (§6): every end rewrites the attempt's pace offsets.
        cursor.pace_record(&meta.pace);
        match &result {
            Ok(_) | Err(Some(PrefixRefusal::Lossy)) => {
                cursor.invalidations.remove(&meta.key);
                cursor.rotation.complete(&key, meta.fence.as_deref());
                if fragment.is_some() {
                    cursor.counters.sealed_fragment_withheld += 1;
                }
            }
            Err(Some(PrefixRefusal::AuditDue)) => cursor.counters.jobs_audit_restarted += 1,
            Err(None) => cursor.counters.jobs_deferred_inputs += 1,
            Err(Some(PrefixRefusal::Invalidated(_) | PrefixRefusal::Dependency)) => {
                member_changed = invalidated(cursor, &meta.key);
                if member_changed {
                    cursor.rotation.complete(&key, meta.fence.as_deref());
                }
            }
        }
    };
    match lease {
        Some(lease) => lease.end(update),
        None => {
            cache.with_cursor(update);
        }
    }
    // Parent ruling 2: a lossy job's identity proof covers only a completed
    // traversal of the frozen extent, ending on a record boundary, whose loss
    // is parse/salvage loss main publishes. A read failure, an unfinished
    // read or a withheld record gets no proof, and an EOF-applied record
    // keeps strict finish identity (E1).
    let completed_traversal = job.parser.reader.finished
        && job.parser.reader.failure.is_none()
        && !job.parser.reader.sealed_fragment()
        && frozen_end == Some(read_start.saturating_add(consumed));
    let lossy_identity = lossy_identity.filter(|_| {
        completed_traversal && !eof_applied && matches!(result, Err(Some(PrefixRefusal::Lossy)))
    });
    if result.is_ok() && !eof_applied {
        // A passed certificate grants `finish` a grown object (S12).
        job.parser.reader.sealed_prefix = frozen_end
            .map(|extent| FinishGrant::certified(meta.stamp_open.dev, meta.stamp_open.ino, extent));
    } else if let Some(identity) = lossy_identity {
        // An uncertified job grants it only through ruling 2's proof,
        // revalidated in `finish`; otherwise it keeps main's strict finish
        // identity (a grown file fails publication and restarts).
        job.parser.reader.sealed_prefix = Some(FinishGrant::LossySameObject(identity));
    }
    match result {
        Ok(checkpoint) => {
            let overdue_age = checkpoint
                .audit_debt()
                .filter(|debt| debt.due_unix_seconds <= now)
                .map(|debt| now - debt.due_unix_seconds);
            JobEnd::Certified {
                checkpoint,
                grown,
                publication: Publication {
                    certified: true,
                    overdue_age,
                    eof_applied,
                },
                fragment,
            }
        }
        Err(Some(PrefixRefusal::Lossy)) => JobEnd::Uncertified {
            grown,
            publication: Publication {
                certified: false,
                overdue_age: None,
                eof_applied,
            },
            fragment,
        },
        Err(_) if member_changed => JobEnd::MemberChanged(strict_disclosure(
            job,
            meta.owner.clone(),
            DebtReason::MemberChanged,
        )),
        Err(_) => JobEnd::Restart,
    }
}

/// A priority replay restarted the job's read from byte zero (a full read
/// replacing a tail): re-freeze the new read in place so it keeps paging.
/// False when it cannot be frozen, or when the replay reopened the path
/// onto another object than the job's (K5); the caller then ends the
/// attempt and nothing publishes.
pub(in crate::snapshots) fn restart_in_place(job: &mut OwnedActiveFile) -> bool {
    #[cfg(test)]
    tests::TIER_REPLAYS.with(|v| v.set(v.get() + 1));
    let Some((frozen, start)) = job
        .parser
        .reader
        .acquisition
        .as_ref()
        .map(|plan| (plan.frozen_length(), plan.start_offset()))
    else {
        return false;
    };
    let Ok(stamp_open) = OpenStamp::capture(job.parser.reader.reader.get_ref()) else {
        return false;
    };
    if job
        .parser
        .accumulator
        .codex_observed_priority_turns
        .is_none()
    {
        return false;
    }
    let Some(meta) = job.cursor.as_mut() else {
        return false;
    };
    if !meta.stamp_open.same_object(&stamp_open) {
        // The held FD of the replay is another object: replacement during
        // the fallback must not publish under this job's identity.
        return false;
    }
    job.parser.accumulator.codex_priority_witnesses_uncapped = true;
    job.parser
        .reader
        .set_chunked_skip(Limits::current().skip_chunk);
    job.parser
        .reader
        .set_extent_limit(frozen.min(stamp_open.extent).saturating_sub(start));
    meta.stamp_open = stamp_open;
    meta.started = super::now_seconds();
    // The replay's own completion step decides E1 again.
    meta.eof_applied = false;
    true
}

/// E1 (K4 amendment, parent ACK), on the cursor job's completion step and
/// before the protected-tier replay gate (R1-H1), as main applies its
/// trailing line inside the read: at a genuine unchanged physical EOF (the
/// held FD is exactly the opened object: dev, ino, length, mtime, ctime;
/// and this read reached that length), the withheld final record is applied
/// from the bytes already buffered, with main's trailing-line rule. No byte
/// is read. A record that adds the file's first protected tier therefore
/// sends a sampled read through the full replay. Such a job gets no S12
/// grant (`finish_job`): strict finish identity covers the trailing bytes,
/// so an append or replacement before publication refuses as on main. A
/// grown file keeps the record withheld. Idempotent across re-entered
/// completion steps.
pub(in crate::snapshots) fn apply_eof_record(job: &mut OwnedActiveFile) {
    if eof_record_due(job) && job.parser.apply_sealed_fragment() {
        #[cfg(test)]
        tests::EOF_APPLIED.with(|v| v.set(v.get() + 1));
        mark_eof_applied(job);
    }
}

/// E1's predicate: a withheld record not yet applied, the held FD exactly
/// the opened object (dev, ino, length, mtime, ctime) and the read at that
/// length.
///
/// ctime stays here on purpose (E1 S3): an applied record gives up the S12
/// grant for main's strict finish identity, whose opened-object digest
/// still hashes ctime. Comparing content only would turn a ctime-only
/// change into a finish refusal and a restart instead of a withheld record.
/// It moves with that digest (the S3 follow-up).
fn eof_record_due(job: &OwnedActiveFile) -> bool {
    let Some(meta) = job.cursor.as_ref().filter(|meta| !meta.eof_applied) else {
        return false;
    };
    job.parser.reader.sealed_fragment()
        && read_end(job) == meta.stamp_open.extent
        && OpenStamp::capture(job.parser.reader.reader.get_ref())
            .ok()
            .as_ref()
            == Some(&meta.stamp_open)
}

/// E1 for a group job's live member (R2-N1): `eof_record_due`, the member
/// still exactly its `boot` object (so strict finish identity holds against
/// its boot identity), and a record main's trailing-line rule applies
/// without loss (`apply_physical_line`: within the line cap, UTF-8, blank
/// or one JSON value). A group refuses any line loss (R1-B1), so a
/// malformed final record stays withheld, as before.
pub(in crate::snapshots) fn group_eof_record_due(job: &OwnedActiveFile, boot: &OpenStamp) -> bool {
    let reader = &job.parser.reader;
    let mut bytes = reader.buf.as_slice();
    if bytes.last() == Some(&b'\r') {
        bytes = &bytes[..bytes.len() - 1];
    }
    eof_record_due(job)
        && job
            .cursor
            .as_ref()
            .is_some_and(|meta| &meta.stamp_open == boot)
        && matches!(reader.sealed_fragment, Some((false, _)))
        && std::str::from_utf8(bytes).is_ok_and(|line| {
            line.trim().is_empty() || serde_json::from_str::<serde_json::Value>(line).is_ok()
        })
}

/// The withheld record was applied (E1): the job gets no S12 grant.
pub(in crate::snapshots) fn mark_eof_applied(job: &mut OwnedActiveFile) {
    if let Some(meta) = job.cursor.as_mut() {
        meta.eof_applied = true;
    }
}

pub(in crate::snapshots) fn eof_applied(job: &OwnedActiveFile) -> bool {
    job.cursor.as_ref().is_some_and(|meta| meta.eof_applied)
}

/// The file offset where the job's reader stopped (a tail's reader counts
/// from its start).
pub(in crate::snapshots) fn read_end(job: &OwnedActiveFile) -> u64 {
    job.parser
        .reader
        .acquisition
        .as_ref()
        .map_or(0, crate::transcript_acquisition::ReadPlan::start_offset)
        .saturating_add(job.parser.reader.consumed_bytes())
}

/// Exact byte length of `local_index_key(path)` (`to_string_lossy`: each
/// valid UTF-8 run as is, one U+FFFD, 3 bytes, per invalid run). No
/// allocation. None for an empty key, a key with an embedded NUL (the
/// provenance separator; a `Path` can hold one even though no file can) or
/// overflow.
fn join_key_len(path: &Path) -> Option<usize> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    bytes.utf8_chunks().try_fold(0usize, |len, chunk| {
        len.checked_add(chunk.valid().len())?
            .checked_add(if chunk.invalid().is_empty() { 0 } else { 3 })
    })
}

/// Append exactly `local_index_key(path)`.
fn push_join_key(out: &mut String, path: &Path) {
    for chunk in path.as_os_str().as_encoded_bytes().utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
}

/// `stored == local_index_key(path)`, without building the key.
fn join_key_eq(stored: &str, path: &Path) -> bool {
    let mut rest = stored;
    for chunk in path.as_os_str().as_encoded_bytes().utf8_chunks() {
        let Some(after) = rest.strip_prefix(chunk.valid()) else {
            return false;
        };
        rest = after;
        if !chunk.invalid().is_empty() {
            let Some(after) = rest.strip_prefix(char::REPLACEMENT_CHARACTER) else {
                return false;
            };
            rest = after;
        }
    }
    rest.is_empty()
}

/// Length of the members' keys joined by '\0'. None (refuse the provenance)
/// for an empty list, any empty or NUL-bearing key, or overflow.
fn join_keys_len(members: &[CandidateFile]) -> Option<usize> {
    let mut members = members.iter();
    let first = join_key_len(&members.next()?.path)?;
    members.try_fold(first, |len, member| {
        len.checked_add(1)?.checked_add(join_key_len(&member.path)?)
    })
}

/// `stored` holds exactly these members, in order. No allocation.
fn same_join_members(stored: &str, members: &[CandidateFile]) -> bool {
    let mut stored = stored.split('\0');
    members.iter().all(|member| {
        stored
            .next()
            .is_some_and(|key| join_key_eq(key, &member.path))
    }) && stored.next().is_none()
}

/// A stored member list the release may act on: non-empty, no empty key.
/// `record_join_owner` never stores anything else; this guards the release
/// against malformed or partial provenance all the same.
fn join_members_well_formed(stored: &str) -> bool {
    !stored.is_empty() && stored.split('\0').all(|key| !key.is_empty())
}

/// Arm a group job's freshly opened member reader (P2). A sealed member
/// reads to its boot extent and is fenced by exact identity at its EOF. The
/// live (last) member must be the boot object, grown at most; it gets a fresh
/// acquisition (`Full`, no retained state: a group retains none) whose frozen
/// extent and certificate `finish_job` uses, like a singleton.
pub(in crate::snapshots) fn arm_group_member(
    job: &mut OwnedActiveFile,
    boot: &OpenStamp,
    live: Option<&Scope>,
) -> std::result::Result<(), codex_file_join::GroupEnd> {
    use codex_file_join::GroupEnd;
    let reader = &mut job.parser.reader;
    let now = OpenStamp::capture(reader.reader.get_ref()).map_err(|_| GroupEnd::Strict)?;
    if !boot.append_compatible(&now) {
        return Err(GroupEnd::Changed);
    }
    reader.set_chunked_skip(Limits::current().skip_chunk);
    match live {
        Some(scope) => {
            let plan = crate::transcript_acquisition::ReadPlan::prepare(
                reader.reader.get_mut(),
                None,
                scope,
                None,
                super::now_seconds(),
            )
            .map_err(|_| GroupEnd::Strict)?;
            let limit = plan
                .frozen_length()
                .min(now.extent)
                .saturating_sub(plan.start_offset());
            reader.acquisition = Some(plan);
            reader.set_extent_limit(limit);
        }
        None => reader.set_extent_limit(boot.extent),
    }
    if let Some(meta) = job.cursor.as_mut() {
        meta.stamp_open = now;
        meta.started = super::now_seconds();
        meta.eof_applied = false;
    }
    Ok(())
}

/// The live member's legacy baseline (P2) reads the job's frozen prefix:
/// it may finish a grown same object, like the job's own certificate.
pub(in crate::snapshots) fn frozen_grant(meta: &JobMeta, extent: u64) -> FinishGrant {
    FinishGrant::certified(meta.stamp_open.dev, meta.stamp_open.ino, extent)
}

/// The live member's grant after `finish_job` certified a group job.
pub(in crate::snapshots) fn certified_prefix(job: &OwnedActiveFile) -> Option<SealedPrefix> {
    match job.parser.reader.sealed_prefix.as_ref()? {
        FinishGrant::Certified(prefix) => Some(*prefix),
        FinishGrant::LossySameObject(_) => None,
    }
}

/// A group job ended as terminal debt (outcome R): free the slot, forget its
/// invalidations, and fence it for its generation.
pub(in crate::snapshots) fn end_group_lease(lease: CursorLease, job: &OwnedActiveFile) {
    let meta = job.cursor.as_ref();
    let rotation = meta.map(|meta| rotation_key(&meta.namespace, &meta.key));
    lease.end(|cursor| {
        if let (Some(meta), Some(rotation)) = (meta, rotation.as_ref()) {
            // Stage 1: a group has no pace slot; this records nothing.
            cursor.pace_record(&meta.pace);
            cursor.invalidations.remove(&meta.key);
            cursor.rotation.complete(rotation, meta.fence.as_deref());
        }
    });
}

/// The live member's acquisition evidence is unavailable (K9): free the
/// slot uncounted; the members stay pending and a later page boots again.
pub(in crate::snapshots) fn defer_group_lease(lease: CursorLease) {
    lease.end(|cursor| cursor.counters.jobs_deferred_inputs += 1);
}

/// M-1 `scope_job` of a group, with its wake dependencies (§d.4): parser,
/// identity and proof versions, owner, canonical member keys, every sealed
/// member's opened identity and the live member's `{dev, ino}` (never its
/// growing length), header digests, receipt scope, counting view, each
/// member's path reduction facts and the census flags.
#[allow(clippy::too_many_arguments)]
pub(in crate::snapshots) fn group_memo_digest(
    owner: &str,
    members: &[&CandidateFile],
    live: &OpenStamp,
    digests: &[&str],
    index: &ScanIndex,
    codex: &CodexTitleMetadata,
    receipt_scope: &str,
    identity: impl Fn(&CandidateFile) -> String,
) -> String {
    let mut parts = vec![
        "codex_group_memo:v1".to_owned(),
        CODEX_JOIN_PROOF_VERSION.to_owned(),
        SnapshotSource::Codex.parser_version().to_owned(),
        SnapshotSource::Codex.scan_identity_version().to_owned(),
        owner.to_owned(),
        receipt_scope.to_owned(),
        group_counting_view(members.iter().copied(), index),
        format!("{}:{}", live.dev, live.ino),
        if codex.created_thread_census_unscoped_incomplete {
            "created_incomplete".to_owned()
        } else {
            "created_complete".to_owned()
        },
        if codex.state_census_unscoped_incomplete || codex.sidecar_census_unscoped_incomplete {
            "sidecar_incomplete".to_owned()
        } else {
            "sidecar_complete".to_owned()
        },
    ];
    let sealed = members.len().saturating_sub(1);
    for (i, member) in members.iter().enumerate() {
        parts.push(local_index_key(&member.path));
        if i < sealed {
            parts.push(identity(member));
        }
        parts.push(codex.path_reduction_fingerprint(&member.path));
    }
    parts.extend(digests.iter().map(|digest| (*digest).to_owned()));
    sha256_hex_owned(&parts)
}

/// Reduction dependencies of a group job: every member's path facts, and
/// the opened identity of every member but the canonical last (`live`), so
/// a sealed member's change wakes a parked `JoinStateBound` record while the
/// live member's growth keeps it parked (R2-H1).
pub(in crate::snapshots) fn group_dependencies(
    members: &[CandidateFile],
    live: &Path,
    codex: &CodexTitleMetadata,
    identity: impl Fn(&CandidateFile) -> String,
) -> String {
    // Keyed by member path, so boot and canonical order agree.
    let mut members = members
        .iter()
        .map(|member| {
            (
                local_index_key(&member.path),
                codex.path_reduction_fingerprint(&member.path),
                if member.path == live {
                    String::new()
                } else {
                    identity(member)
                },
            )
        })
        .collect::<Vec<_>>();
    members.sort();
    let mut parts = vec!["codex_group_dependencies:v2".to_owned()];
    for (key, fingerprint, identity) in members {
        parts.push(key);
        parts.push(fingerprint);
        parts.push(identity);
    }
    sha256_hex_owned(&parts)
}

/// No temporary roster allocation for a custody check on a live job.
pub(in crate::snapshots) fn job_has_custody(job: &OwnedActiveFile, index: &ScanIndex) -> bool {
    std::iter::once(&job.candidate)
        .chain(job.group.iter().flat_map(|group| group.members.iter()))
        .any(|file| {
            index
                .files
                .get(&local_index_key(&file.path))
                .is_some_and(|entry| entry.codex_compressed_hold.is_some())
        })
}

/// Every file a job holds: a group's members, else the singleton's file.
pub(in crate::snapshots) fn job_files(job: &OwnedActiveFile) -> Vec<&CandidateFile> {
    match job.group.as_ref() {
        Some(group) => group.members.iter().collect(),
        None => vec![&job.candidate],
    }
}

thread_local! {
    /// This thread holds the cursor lock (inside `with_cursor`). Always
    /// compiled: a `CursorCredit` dropped while unwinding out of a cursor
    /// closure reads it to avoid relocking. Lock-order checks on it are
    /// debug-only (`debug_assert!`): controls, not proof.
    static CURSOR_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this thread holds the cursor lock.
pub(super) fn cursor_held() -> bool {
    CURSOR_HELD.with(std::cell::Cell::get)
}

/// Marks the cursor lock held for its scope. Reset on drop, so an unwind out
/// of a cursor closure (a `should_panic` test included) clears it.
struct CursorHeld;
impl CursorHeld {
    fn enter() -> Self {
        // One order: retained, then cursor. A cursor closure must never call
        // a locking `SharedCache` helper (no recursive locking).
        debug_assert!(
            !cursor_held(),
            "cursor lock taken while this thread holds it"
        );
        CURSOR_HELD.with(|held| held.set(true));
        Self
    }
}
impl Drop for CursorHeld {
    fn drop(&mut self) {
        CURSOR_HELD.with(|held| held.set(false));
    }
}

/// A claim on the state budget made by `SharedCache::cursor_reserve`,
/// counted in `CursorState::reserved` until settled. Linear: settle it once,
/// with `settle` inside the cursor critical section that makes its bytes
/// resident, or with `refund` outside any. A credit dropped unsettled (an
/// unwind) refunds itself unless this thread holds the cursor lock, which
/// the unwind is about to poison. A poisoned cursor is never settled: it
/// measures as the whole state budget (`cursor_resident`) and admits nothing
/// (`cursor_reserve`), so a stranded claim oversubscribes nothing.
///
/// Single-cache assumption (R2-L1): the held flag is per thread, not per
/// cache. Production has one process-owned `SharedCache`. A credit of cache B
/// that unwinds inside cache A's cursor closure skips its refund (relocking B
/// there would nest two cursor locks, which the one lock order forbids), so
/// B's claim stays stranded: fail closed (less admission), never
/// oversubscription. Settling against another cache's state is a programmer
/// error, caught by `settle`'s debug assert; release builds fail closed.
#[must_use = "a credit must be settled or refunded"]
pub(in crate::snapshots) struct CursorCredit {
    cache: Arc<SharedCache>,
    cursor: u64,
    bytes: usize,
    settled: bool,
}

impl CursorCredit {
    pub(in crate::snapshots) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Settle inside the critical section that made the bytes resident (or
    /// decided they never will be).
    fn settle(mut self, cursor: &mut CursorState) {
        debug_assert_eq!(
            cursor.id, self.cursor,
            "a credit settles only on its own cache"
        );
        self.settled = true;
        settle_claim(cursor, self.cursor, self.bytes);
    }

    /// Return the claim. Never call it while holding the cursor lock.
    fn refund(mut self) {
        self.settled = true;
        let (id, bytes) = (self.cursor, self.bytes);
        self.cache
            .with_cursor(|cursor| settle_claim(cursor, id, bytes));
    }
}

impl Drop for CursorCredit {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        debug_assert!(
            std::thread::panicking(),
            "a cursor credit was dropped without being settled"
        );
        if cursor_held() {
            return;
        }
        if let Ok(mut cursor) = self.cache.cursor.lock() {
            let _held = CursorHeld::enter();
            settle_claim(&mut cursor, self.cursor, self.bytes);
        }
    }
}

// Reserve under retained -> cursor BEFORE taking durable Stores; carry only
// the owner across I/O. Drop Stores before release, including unwind/early exits.
// Never account from encode/write. Free room only: no primary/proof eviction.
static DECODER_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(in crate::snapshots) struct DecoderOwner(Option<CursorCredit>);
impl DecoderOwner {
    pub(in crate::snapshots) fn acquire(cache: &Arc<SharedCache>, bytes: usize) -> Option<Self> {
        debug_assert!(!super::durable_tail::stores_held(), "reserve before Stores");
        use std::sync::atomic::Ordering::SeqCst;
        if DECODER_LIVE.swap(true, SeqCst) {
            return None;
        }
        match cache.cursor_claim(bytes, true) {
            Some(credit) => Some(Self(Some(credit))),
            None => {
                DECODER_LIVE.store(false, SeqCst);
                None
            }
        }
    }
    // Normal completion/error calls this after destroying the decoder.
    pub(in crate::snapshots) fn release(mut self) {
        debug_assert!(!super::durable_tail::stores_held(), "release after Stores");
        self.refund();
    }
    fn refund(&mut self) {
        if let Some(credit) = self.0.take() {
            credit.refund();
            DECODER_LIVE.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
impl Drop for DecoderOwner {
    fn drop(&mut self) {
        if self.0.is_some() {
            crate::local_resource_diagnostics::traversal_point(
                "codex_zst_owner",
                "codex",
                &BTreeMap::from([("leaked_release", 1_u64)]),
            );
        }
        if cursor_held() {
            // Strand the charged claim and singleton; never re-lock during Drop.
            if let Some(mut credit) = self.0.take() {
                credit.settled = true;
            }
            return;
        }
        self.refund(); // cancellation/unwind safety net, observable as a leak
    }
}

/// Checked: a claim that is not outstanding on this state is corrupt
/// accounting. Fail closed: the state measures unbounded from then on.
fn settle_claim(cursor: &mut CursorState, id: u64, bytes: usize) {
    match cursor
        .reserved
        .checked_sub(bytes)
        .filter(|_| cursor.id == id && cursor.reserved != usize::MAX)
    {
        Some(rest) => cursor.reserved = rest,
        None => {
            cursor.reserved = usize::MAX;
            debug_assert!(
                std::thread::panicking(),
                "cursor credit accounting is corrupt"
            );
        }
    }
}

/// The least recently recorded join provenance, dropped under the cursor
/// lock without copying its key. False when there is none.
fn evict_oldest_join_owner(cursor: &mut CursorState) -> bool {
    let Some(oldest) = cursor.join_owners.values().map(|(used, _)| *used).min() else {
        return false;
    };
    // Ticks are unique (`tick`), so this drops exactly one entry, in place.
    cursor.join_owners.retain(|_, (used, _)| *used != oldest);
    true
}

/// PR-P: the mandatory valve's last step, after all join provenance. One
/// bounded batch from the least-recently `touched` namespace: identity-cause
/// witnesses first (`identity: None`, one probe to restore), then the others
/// in key order (a re-read to restore), each freeing exactly its accounted
/// node and stored charge, until `deficit` bytes are freed or the namespace
/// is empty. An emptied entry (or one holding only a match mark) is then
/// dropped with its key, scope and mark. In place, no key copy, no heap walk.
/// The caller re-measures once per batch, so the valve costs at most one
/// state measurement per namespace. False when `parents` is empty or the
/// layout is unsupported (nothing evicted).
fn evict_lru_parent_witnesses(cursor: &mut CursorState, deficit: usize) -> bool {
    let Some(node) = crate::heap_layout_bound::tree_node_bytes::<String, (ParentWitness, usize)>()
    else {
        return false;
    };
    let Some(oldest) = cursor.parents.values().map(|entry| entry.touched).min() else {
        return false;
    };
    let mut freed = 0_usize;
    let mut evicted = 0_u64;
    let mut corrupt = false;
    if let Some(entry) = cursor
        .parents
        .values_mut()
        .find(|entry| entry.touched == oldest)
    {
        for identity_causes_only in [true, false] {
            let witnesses = &mut entry.witnesses;
            let charge = &mut witnesses.charge;
            witnesses.entries.retain(|_, (witness, stored)| {
                if freed >= deficit || (identity_causes_only && witness.identity.is_some()) {
                    return true;
                }
                match charge.checked_sub(*stored) {
                    Some(left) => *charge = left,
                    None => corrupt = true,
                }
                freed = freed.saturating_add(node).saturating_add(*stored);
                evicted += 1;
                false
            });
        }
    }
    if corrupt {
        // Charge accounting is corrupt: fail closed. The state then measures
        // unbounded and admits nothing.
        debug_assert!(
            std::thread::panicking(),
            "parent witness charge accounting is corrupt"
        );
        if let Some(entry) = cursor
            .parents
            .values_mut()
            .find(|entry| entry.touched == oldest)
        {
            entry.witnesses.charge = usize::MAX;
        }
        return false;
    }
    cursor.counters.parent_witness_evicted += evicted;
    // Drop the processed entry (the first at `oldest`, as `find` saw it) only
    // when it holds no witness.
    let mut first = true;
    let before = cursor.parents.len();
    cursor.parents.retain(|_, entry| {
        if !first || entry.touched != oldest {
            return true;
        }
        first = false;
        !entry.witnesses.entries.is_empty()
    });
    evicted > 0 || cursor.parents.len() < before
}

/// PR-P: the extra charge of a namespace entry: none when it exists for this
/// scope; otherwise its map node, key, scope and empty witness-map root (the
/// root `tree_nodes` charges for an empty map).
fn parent_entry_charge(exists: bool, namespace: &str, scope: &str) -> Option<usize> {
    if exists {
        return Some(0);
    }
    crate::heap_layout_bound::tree_node_bytes::<String, NamespaceParents>()?
        .checked_add(namespace.len())?
        .checked_add(scope.len())?
        .checked_add(crate::heap_layout_bound::tree_node_bytes::<
            String,
            (ParentWitness, usize),
        >()?)
}

/// PR-P (N2): whether `namespace` would be a new entry past `ROTATION_KEYS`.
/// Every caller is an optional admission and refuses it before admitting
/// anything (`parent_namespace_refused`): the retained namespaces and their
/// witnesses are never evicted for a newcomer (the count bound, not the memory
/// valve). The newcomer's parents stay owed (re-read, fail-closed). An entry
/// of another scope is not new: it is replaced in place.
fn parent_namespace_full(cursor: &CursorState, namespace: &str) -> bool {
    cursor.parents.len() >= ROTATION_KEYS && !cursor.parents.contains_key(namespace)
}

/// PR-P: the namespace's entry after admission: an entry of another scope is
/// dropped and replaced. None for a new namespace past `ROTATION_KEYS`
/// (`parent_namespace_full`, which the caller checked before admitting).
fn parent_entry<'a>(
    cursor: &'a mut CursorState,
    exists: bool,
    namespace: &str,
    scope: &str,
    page: u64,
) -> Option<&'a mut NamespaceParents> {
    if !exists {
        if parent_namespace_full(cursor, namespace) {
            return None;
        }
        cursor.parents.remove(namespace);
        cursor.parents.insert(
            exact_copy(namespace),
            NamespaceParents {
                scope: exact_copy(scope),
                touched: page,
                matched: None,
                witnesses: ParentWitnesses::default(),
            },
        );
    }
    let entry = cursor.parents.get_mut(namespace)?;
    entry.touched = page;
    Some(entry)
}

/// Whether `charge` fits in `admission_budget` (the side ledger's reservation
/// already taken) beside the least the state and the retained cache
/// can measure after every eviction `admit_locked` may make: the empty
/// retained cache's own bound (`release_until`'s floor) and, for `mandatory`,
/// the state without its join provenance and without its parent witnesses
/// (empty maps; bounds are additive per field). False: no eviction can make
/// room, so none may run. Main's admissions only: the state is
/// `state_for_main` (U1a-2a cc row 2), since a suspended proof is dropped
/// whenever the admission needs its room.
fn admission_feasible(cursor: &CursorState, charge: usize, mandatory: bool) -> bool {
    use crate::heap_layout_bound::bound;
    let state = state_for_main(cursor).and_then(|state| {
        if !mandatory {
            return Some(state);
        }
        let empty = BTreeMap::<String, JoinProvenance>::new();
        let forgettable =
            bound(&cursor.join_owners, STATE_BYTES)?.checked_sub(bound(&empty, STATE_BYTES)?)?;
        // PR-P: parent witnesses are evictable for a mandatory charge only.
        let no_parents = BTreeMap::<String, NamespaceParents>::new();
        let witnesses =
            bound(&cursor.parents, STATE_BYTES)?.checked_sub(bound(&no_parents, STATE_BYTES)?)?;
        state.checked_sub(forgettable)?.checked_sub(witnesses)
    });
    let floor = bound(&super::RetainedCache::default(), STATE_BYTES);
    state
        .zip(floor)
        .and_then(|(state, floor)| {
            admission_budget()?
                .checked_sub(state)?
                .checked_sub(charge)?
                .checked_sub(floor)
        })
        .is_some()
}

/// K6 admission of `charge` more cursor bytes, under both locks (retained,
/// then cursor): measure the cursor state (outstanding claims included),
/// then release least-recently-useful retained copies until they fit beside
/// it, all inside `admission_budget` (F4b: the side ledger's reservation is
/// never spent). If even an empty retained cache does not fit, `mandatory` (a paused
/// job: baseline progress) may then forget join provenance, which is
/// optional and only keeps its owner blocked; optional admissions never take
/// room that way. Once no provenance is left, a mandatory charge then forgets
/// parent witnesses in bounded batches sized by the checked shortfall
/// (`evict_lru_parent_witnesses`, PR-P). Nothing is evicted unless the
/// admission is first proved feasible (`admission_feasible`, R2-M1): a
/// hopeless charge (a `JoinStateBound` pause, an optional claim inside the
/// empty-retained floor) keeps every retained copy, provenance entry and
/// witness. Unsupported accounting, overflow or no room: false, nothing
/// admitted. The loop measures the state at most `JOIN_OWNERS` +
/// `ROTATION_KEYS` + 2 times: once per provenance entry, once per witness
/// batch (each either covers the shortfall or empties its namespace), and
/// once more to admit.
///
/// U1a-2a (cc row 2): `Admitter::Main` measures `state_for_main`, so every
/// choice above (which copies go, which provenance or witness is forgotten,
/// whether the charge fits) is the one main makes with no proof. Once
/// admitted, a suspended proof whose room the charge needs is dropped, still
/// under both locks. `Admitter::Proof` (never `mandatory`) admits only into
/// free room beside the whole state and the retained copies.
fn admit_locked(
    retained: &mut super::RetainedCache,
    cursor: &mut CursorState,
    charge: usize,
    mandatory: bool,
    admitter: Admitter,
) -> bool {
    let needed = !cursor.headers.is_empty() && !proof_free_room(retained, cursor, charge);
    reclaim_headers(cursor, needed, |cursor| {
        if admitter == Admitter::Proof {
            proof_free_room(retained, cursor, charge)
        } else {
            admission_feasible(cursor, charge, mandatory)
        }
    });
    if admitter == Admitter::Proof {
        debug_assert!(!mandatory, "a proof admission is never mandatory");
        return !mandatory && proof_free_room(retained, cursor, charge);
    }
    if !admission_feasible(cursor, charge, mandatory) {
        return false;
    }
    loop {
        let Some(state) = state_for_main(cursor) else {
            return false;
        };
        let room = admission_budget()
            .and_then(|budget| budget.checked_sub(state))
            .and_then(|room| room.checked_sub(charge));
        if room.is_some_and(|room| retained.release_until(room)) {
            drop_suspended_proof_over(retained, cursor, charge, admission_budget());
            return true;
        }
        // Even an empty retained cache did not fit beside the state (or the
        // state alone left no room): only a mandatory charge goes on, one
        // forgotten provenance entry at a time (at most `JOIN_OWNERS`), then
        // parent witnesses in batches covering the checked shortfall.
        if !mandatory {
            return false;
        }
        if evict_oldest_join_owner(cursor) {
            continue;
        }
        let Some(floor) =
            crate::heap_layout_bound::bound(&super::RetainedCache::default(), STATE_BYTES)
        else {
            return false;
        };
        let Some(deficit) = state
            .checked_add(charge)
            .and_then(|need| need.checked_add(floor))
            .and_then(|need| need.checked_sub(admission_budget()?))
            .filter(|deficit| *deficit > 0)
        else {
            return false;
        };
        if !evict_lru_parent_witnesses(cursor, deficit) {
            return false;
        }
    }
}

// Both locks are held (retained then cursor). Never discard optional facts
// for a hopeless claim; clearing preserves the pending eviction count.
fn reclaim_headers(
    cursor: &mut CursorState,
    needed: bool,
    feasible: impl FnOnce(&CursorState) -> bool,
) -> bool {
    if !needed || cursor.headers.is_empty() {
        return false;
    }
    let headers = std::mem::take(&mut cursor.headers);
    let fits = feasible(cursor);
    cursor.headers = headers;
    if fits {
        cursor.headers.clear();
    }
    fits
}

fn optional_bytes(cursor: &CursorState) -> Option<usize> {
    cursor
        .headers
        .optional_bytes()?
        .checked_add(cursor.proof.charge())
}

// Header facts are only scalar/string graphs. Use the shared field walker
// and budget on portable builds too; native cursor admission keeps its existing
// layout-supported gate. Opaque or over-visit resident graphs refuse caching.
fn header_room(retained: &super::RetainedCache, cursor: &CursorState, charge: usize) -> bool {
    let Some(limit) = admission_budget() else {
        return false;
    };
    let mut c = Counter::new(limit);
    c.add(std::mem::size_of_val(retained) + std::mem::size_of_val(cursor))
        .and_then(|()| retained.heap_bound(&mut c))
        .and_then(|()| cursor.heap_bound(&mut c))
        .and_then(|()| c.add(charge))
        .is_some()
}

impl SharedCache {
    pub(super) fn retained_reservation(
        &self,
        retained: &super::RetainedCache,
        key: &String,
        incoming: &crate::transcript_cache::Retained<super::CachedJsonlReduction>,
        live: usize,
        rank: (i64, i64),
    ) -> usize {
        self.with_cursor(|cursor| {
            let reservation = |cursor: &CursorState| {
                live.saturating_add(state_for_main(cursor).unwrap_or(STATE_BYTES))
                    .saturating_add(super::side_ledger::SIDE_LEDGER_BYTES)
            };
            let needed = !cursor.headers.is_empty()
                && !retained.insertion_fits(key, incoming, reservation(cursor), rank, false);
            reclaim_headers(cursor, needed, |cursor| {
                retained.insertion_fits(key, incoming, reservation(cursor), rank, true)
            });
            reservation(cursor)
        })
        .unwrap_or(STATE_BYTES)
    }
    pub(in crate::snapshots) fn refresh_header(
        &self,
        key: String,
        header: Option<codex_file_join::CachedHeader>,
    ) {
        let Ok(retained) = self.retained() else {
            self.with_cursor(|cursor| cursor.headers.refresh(key, None));
            return;
        };
        self.with_cursor(|cursor| {
            cursor.headers.refresh(key.clone(), None);
            if let Some(header) = header {
                if codex_file_join::HeaderCache::admission_charge(key.capacity(), &header)
                    .is_some_and(|charge| header_room(&retained, cursor, charge))
                {
                    cursor.headers.refresh(key, Some(header));
                }
            }
        });
    }
    /// The cursor lock, marked held (`CursorHeld`) for `run`. Also R0's
    /// blocking resident measure (`SharedCache::heap_bound`).
    pub(in crate::snapshots) fn with_cursor<T>(
        &self,
        run: impl FnOnce(&mut CursorState) -> T,
    ) -> Option<T> {
        // Checked before locking: a relock would deadlock, not panic.
        debug_assert!(
            !cursor_held(),
            "cursor lock taken while this thread holds it"
        );
        let mut cursor = self.cursor.lock().ok()?;
        let _held = CursorHeld::enter();
        Some(run(&mut cursor))
    }

    /// K6 reservation for a paused job (mandatory). In one critical section
    /// under the retained lock, then the cursor lock (never the reverse): admit
    /// `charge` (`admit_locked`) and claim it in the cursor state, where every
    /// later measurement (`cursor_resident`, another admission, a retained
    /// insert) sees it until the credit is settled. None: nothing claimed.
    fn cursor_reserve(self: &Arc<Self>, charge: usize) -> Option<CursorCredit> {
        self.cursor_claim(charge, false)
    }
    fn cursor_claim(self: &Arc<Self>, charge: usize, free_only: bool) -> Option<CursorCredit> {
        let mut retained = self.retained().ok()?;
        let mut header_occupancy_refused = false;
        let claimed = self
            .with_cursor(|cursor| {
                let admitted = if free_only {
                    charge
                        .checked_add(super::ENTRY_BYTES + super::side_ledger::SIDE_LEDGER_BYTES)
                        .is_some_and(|with_floor| {
                            // Decoders use free room only: preserve the real primary
                            // tail floor without evicting any resident state. Header
                            // reclamation belongs to feasible progress/retained admission.
                            let admitted = proof_free_room(&retained, cursor, with_floor);
                            if !admitted {
                                header_occupancy_refused =
                                    decoder_fits_without_headers(&retained, cursor, with_floor);
                            }
                            admitted
                        })
                } else {
                    admit_locked(&mut retained, cursor, charge, true, Admitter::Main)
                };
                if !admitted {
                    return None;
                }
                cursor.reserved = cursor.reserved.checked_add(charge)?;
                Some(cursor.id)
            })
            .flatten();
        drop(retained);
        // #799 logging may perform I/O: the retained and cursor guards have
        // both ended. A refusal still creates no credit and evicts nothing.
        if header_occupancy_refused {
            crate::local_resource_diagnostics::codex_zst_refused(
                crate::local_resource_diagnostics::CodexZstCause::DecoderRefusedHeaderOccupancy,
            );
        }
        let claimed = claimed?;
        Some(CursorCredit {
            cache: Arc::clone(self),
            cursor: claimed,
            bytes: charge,
            settled: false,
        })
    }

    /// Outstanding claimed bytes (`usize::MAX`: poisoned or corrupt).
    #[cfg(test)]
    pub(in crate::snapshots) fn cursor_reserved(&self) -> usize {
        self.with_cursor(|cursor| cursor.reserved)
            .unwrap_or(usize::MAX)
    }

    /// Requested-layout charge of the paused job.
    #[cfg(test)]
    pub(super) fn cursor_charge(&self) -> usize {
        self.with_cursor(|cursor| match cursor.slot {
            Slot::Paused(_) => cursor.slot_charge,
            Slot::Empty | Slot::ActiveElsewhere { .. } => 0,
        })
        .unwrap_or(0)
    }

    /// Everything the cursor state holds (paused job, memo, parked, rotation
    /// and invalidation records, a suspended proof). An unbounded state reads
    /// as the whole budget. Main's measures leave the suspended proof out:
    /// the retained insert (U1a-2a ss-6) and M1's `release_to_fit` and
    /// `release_older_to_fit` (D6(e), `release_room_for_main`) reserve
    /// `cursor_resident_for_main` and retire the proof under their lock;
    /// this whole-state measure is for tests.
    #[cfg(test)]
    pub(super) fn cursor_resident(&self) -> usize {
        self.with_cursor(|cursor| crate::heap_layout_bound::bound(&*cursor, STATE_BYTES))
            .flatten()
            .unwrap_or(STATE_BYTES)
    }

    /// U1a-2a (cc row 3, rev 11 §5.4): `cursor_resident` as main measures
    /// it, without the suspended proof (`state_for_main`). The retained
    /// insert reserves this, then `drop_suspended_proof_if_over` retires the
    /// proof if the insert took its room.
    #[cfg(test)]
    pub(super) fn cursor_resident_for_main(&self) -> usize {
        self.with_cursor(|cursor| state_for_main(cursor))
            .flatten()
            .unwrap_or(STATE_BYTES)
    }

    /// U1a-2a (cc row 3, ss-6): after a retained insert that reserved
    /// `cursor_resident_for_main()`, still under the insert's retained lock:
    /// drop the suspended proof (freeing its box) if `live_bytes_in`, the
    /// side ledger's fixed charge, the whole cursor state and the retained
    /// copies no longer fit `STATE_BYTES`, the retained cache's own limit.
    /// So the insert's choice never depended on the proof, and the proof is
    /// gone before the insert returns and anything else spends that room.
    pub(super) fn drop_suspended_proof_if_over(
        &self,
        retained: &super::RetainedCache,
        live_bytes_in: usize,
    ) {
        let budget = STATE_BYTES
            .checked_sub(live_bytes_in)
            .and_then(|room| room.checked_sub(super::side_ledger::SIDE_LEDGER_BYTES));
        self.with_cursor(|cursor| drop_suspended_proof_over(retained, cursor, 0, budget));
    }

    pub(super) fn retire_headers_over_room(&self, room: usize) {
        let Ok(_retained) = self.retained() else {
            return;
        };
        self.with_cursor(|cursor| {
            let bytes = optional_bytes(cursor);
            if bytes.map_or(true, |bytes| bytes > room) {
                cursor.headers.clear();
            }
        });
    }

    /// U1a-2a (R2-B3, r79, fix round 2 DB1): where main allocates against
    /// its copy budget (`retire_proof_beside_copy`), both shares leave
    /// `room` bytes in main's view (`bound_for_main`). A suspended proof
    /// plus optional header facts larger than that would spend bytes main
    /// is about to use. Headers yield first; any remaining excess proof is
    /// retired here (retained, then cursor; the job is freed under them,
    /// its entry `seq`s kept for the index's next hook), counted
    /// `side_proof_drops`. Otherwise nothing is
    /// locked beyond one `try_lock` read; a cursor busy elsewhere is decided
    /// under the locks, never skipped.
    pub(in crate::snapshots) fn retire_proof_over_room(&self, room: usize) {
        let over = match self.cursor.try_lock() {
            Ok(cursor) => optional_bytes(&cursor).map_or(true, |bytes| bytes > room),
            Err(std::sync::TryLockError::WouldBlock) => true,
            Err(std::sync::TryLockError::Poisoned(_)) => false,
        };
        if !over {
            return;
        }
        let Ok(_retained) = self.retained() else {
            return;
        };
        self.with_cursor(|cursor| {
            if optional_bytes(cursor).map_or(true, |bytes| bytes > room) {
                cursor.headers.clear();
            }
            if cursor.proof.charge() > room {
                retire_holder(cursor);
                record_proof_drop();
            }
        });
    }

    /// U1a-2a D6(e): M1's release room, under the caller's retained lock, in
    /// one cursor critical section (retained, then cursor; nothing relocks).
    /// The room is main's: `STATE_BYTES` less `state_for_main` (no suspended
    /// proof) and `pinned`, which carries the side ledger's fixed charge
    /// once (`context_overhead`), as `heap_bound` and `admission_budget` do.
    /// Only where `reachable(room)` holds (the caller's fit can be met) is a
    /// suspended proof retired, and only when the whole state (the proof
    /// included), the copies and `pinned` overflow `STATE_BYTES`; counted
    /// `side_proof_release_drops`, never a retained release cause. So the
    /// proof's bytes count toward the fit before any copy is evicted, and
    /// the room returned is the no-proof one. Nothing mandatory (main's
    /// state, a reservation, the side ledger) is touched. None, with nothing
    /// dropped: the cursor lock is poisoned, main's state is unbounded, the
    /// room is short, or `reachable` refuses it.
    pub(super) fn release_room_for_main(
        &self,
        retained: &super::RetainedCache,
        pinned: usize,
        reachable: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        self.with_cursor(|cursor| {
            let room = |cursor: &CursorState| STATE_BYTES.checked_sub(state_for_main(cursor)?)?
                .checked_sub(pinned);
            let needed = !room(cursor).zip(crate::heap_layout_bound::bound(retained, STATE_BYTES))
                .is_some_and(|(room, copies)| copies <= room);
            reclaim_headers(cursor, needed, |cursor| room(cursor).is_some_and(&reachable));
            let room = room(cursor).filter(|room| reachable(*room))?;
            if retire_suspended_proof_over(retained, cursor, pinned, Some(STATE_BYTES)) {
                crate::local_resource_diagnostics::codex_side_lifecycle::record(
                    crate::local_resource_diagnostics::codex_side_lifecycle::Event::ProofReleaseDrop,
                );
            }
            Some(room)
        })
        .flatten()
    }

    /// U1a-2a (cc rows 1, 5; rev 11 §5.3, rev 12): the proof hook's claim on
    /// the holder for index (`namespace`, `index_path`, `incarnation`).
    /// - This index's own job → `Mine` (out of the holder, touched now).
    /// - The same namespace and path under another incarnation (the index
    ///   was replaced or re-minted) → dropped (counted), `Free`.
    /// - Another index's job → `Busy` while it was touched within
    ///   `NAMESPACE_STALE_PAGES` cursor pages; else dropped as stale
    ///   (counted), `Free`.
    /// - Nothing suspended → `Free`. A poisoned cursor → `Busy`.
    pub(in crate::snapshots) fn proof_take(
        self: &Arc<Self>,
        namespace: &Scope,
        index_path: &Path,
        incarnation: &str,
    ) -> ProofTake {
        enum Claim {
            Mine(Box<ProofJob>),
            Free { dropped: bool },
            Busy,
        }
        let claim = self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            let ProofHolder::Suspended { job, .. } = &cursor.proof else {
                return Claim::Free { dropped: false };
            };
            let own = job.namespace == namespace.0 && job.index_path == index_path;
            let mine = own && job.incarnation == incarnation;
            let live = page.saturating_sub(job.touched_page) < NAMESPACE_STALE_PAGES;
            if mine {
                let ProofHolder::Suspended { mut job, .. } = std::mem::take(&mut cursor.proof)
                else {
                    unreachable!("checked suspended holder");
                };
                job.touched_page = page;
                return Claim::Mine(job);
            }
            if !own && live {
                return Claim::Busy;
            }
            retire_holder(cursor);
            Claim::Free { dropped: true }
        });
        match claim {
            Some(Claim::Mine(job)) => ProofTake::Mine(ProofLease::new(self, job)),
            Some(Claim::Free { dropped }) => {
                if dropped {
                    record_proof_drop();
                }
                ProofTake::Free
            }
            Some(Claim::Busy) | None => ProofTake::Busy,
        }
    }

    /// U1a-2a (owner note 3, r79): the entry `seq`s of every retired job
    /// bound to (`namespace`, `index_path`, `incarnation`), taken out (at
    /// most `RETIRED_PROOFS × RETIRED_PROOF_ENTRIES`). A retired job of
    /// another binding stays until its own hook or a later retirement
    /// replaces it.
    pub(in crate::snapshots) fn take_retired_proof_seqs(
        &self,
        namespace: &Scope,
        index_path: &Path,
        incarnation: &str,
    ) -> Vec<u64> {
        let binding = retired_binding(&namespace.0, index_path, incarnation);
        let taken = self.with_cursor(|cursor| {
            let mut taken = [0_u64; RETIRED_PROOFS * RETIRED_PROOF_ENTRIES];
            let mut len = 0;
            for slot in &mut cursor.proof_retired.slots {
                if slot.len == 0 || slot.binding != binding {
                    continue;
                }
                for seq in &slot.seqs[..slot.len] {
                    taken[len] = *seq;
                    len += 1;
                }
                *slot = RetiredProof::default();
            }
            (taken, len)
        });
        taken.map_or_else(Vec::new, |(taken, len)| taken[..len].to_vec())
    }

    /// U1a-2a (cc row 8, rev 10 §6.1): `namespace`'s proof hook ran on this
    /// page and found proof work `due` (or none). `note_page` counts a page
    /// of the same namespace with due work that never reached the hook.
    pub(in crate::snapshots) fn note_proof_hook(&self, namespace: &Scope, due: bool) {
        self.with_cursor(|cursor| {
            if due {
                cursor.proof_due = Some((namespace.0.clone(), true));
            } else if cursor
                .proof_due
                .as_ref()
                .is_some_and(|(due_namespace, _)| *due_namespace == namespace.0)
            {
                cursor.proof_due = None;
            }
        });
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn proof_suspended_for_test(&self) -> Option<(String, usize)> {
        self.with_cursor(|cursor| match &cursor.proof {
            ProofHolder::None => None,
            ProofHolder::Suspended { job, charge } => Some((job.namespace.clone(), *charge)),
        })
        .flatten()
    }

    /// Content-free cursor diagnostics for the scan's one completion log
    /// record: process-global counter deltas since `page`'s window opened
    /// (overlapping scans included; not attributed to this scan) and the
    /// retained gauges. Read-only, and never waits: `None` (logged `null`,
    /// unknown) when the window never opened or the cursor state is busy or
    /// poisoned.
    pub(in crate::snapshots) fn cursor_diagnostics(
        &self,
        page: &PageBudget,
    ) -> Option<Box<crate::local_resource_diagnostics::CodexCursorCounts>> {
        use crate::local_resource_diagnostics::{
            CodexCursorCounts, CodexCursorEvents, CodexCursorRetained,
        };
        let start = page.window_start.as_deref()?;
        let cursor = self.cursor.try_lock().ok()?;
        let fixed = |value: u64| u32::try_from(value).unwrap_or(u32::MAX);
        let now = &cursor.counters;
        let d = |pick: fn(&Counters) -> u64| fixed(pick(now).saturating_sub(pick(start)));
        Some(Box::new(CodexCursorCounts {
            during_scan_window: CodexCursorEvents {
                jobs_started: d(|c| c.jobs_started),
                jobs_paused: d(|c| c.jobs_paused),
                jobs_resumed: d(|c| c.jobs_resumed),
                jobs_certified: d(|c| c.jobs_certified),
                jobs_uncertified: d(|c| c.jobs_uncertified),
                jobs_invalidated: d(|c| c.jobs_invalidated),
                jobs_member_changed: d(|c| c.jobs_member_changed),
                jobs_state_bound: d(|c| c.jobs_state_bound),
                jobs_lost: d(|c| c.jobs_lost),
                jobs_deferred_inputs: d(|c| c.jobs_deferred_inputs),
                jobs_start_unstartable: d(|c| c.jobs_start_unstartable),
                jobs_audit_restarted: d(|c| c.jobs_audit_restarted),
                jobs_finish_failed: d(|c| c.jobs_finish_failed),
                jobs_frame_returned: d(|c| c.jobs_frame_returned),
                deferred: d(|c| c.deferred),
                deferred_rotation: d(|c| c.deferred_rotation),
                deferred_next_generation: d(|c| c.deferred_next_generation),
                namespace_busy: d(|c| c.namespace_busy),
                cursor_disabled_unsupported_layout: d(|c| c.cursor_disabled_unsupported_layout),
                audit_overdue: d(|c| c.audit_overdue),
                sealed_fragment_withheld: d(|c| c.sealed_fragment_withheld),
                eof_record_applied: d(|c| c.eof_record_applied),
                jobs_unavailable_ended: d(|c| c.jobs_unavailable_ended),
                memo_hits: d(|c| c.memo_hits),
                memo_records: d(|c| c.memo_records),
                parked_hits: d(|c| c.parked_hits),
            },
            retained: CodexCursorRetained {
                paused_job: matches!(cursor.slot, Slot::Paused(_)),
                paused_job_charged_bytes: fixed(cursor.slot_charge as u64),
                memo_entries: fixed(cursor.memo.entries.len() as u64),
                parked_entries: fixed(cursor.parked.len() as u64),
                invalidation_entries: fixed(cursor.invalidations.len() as u64),
                rotation_waiters: fixed(cursor.rotation.waiting.len() as u64),
                lifetime_audit_overdue_max_age_seconds: fixed(now.audit_overdue_max_age_seconds),
            },
        }))
    }

    pub(in crate::snapshots) fn cursor_slot_free(&self) -> bool {
        self.with_cursor(|cursor| matches!(cursor.slot, Slot::Empty))
            .unwrap_or(false)
    }

    /// Move existing negative state into the serialized write holder BEFORE
    /// funding. Refusal must own the attribution as well as the cause. Moving
    /// already resident allocations allocates nothing; replay cannot read.
    pub(in crate::snapshots) fn custody_decision_to_save(
        self: &Arc<Self>,
        namespace: &Scope,
        index: &mut ScanIndex,
        committed: &ScanIndex,
        path: &Path,
    ) -> anyhow::Result<Option<CustodySave>> {
        let mut first = false;
        let decision = self
            .with_cursor(|cursor| {
                if cursor.custody_unsaved.is_none() {
                    let Slot::Paused(job) = &mut cursor.slot else {
                        return Ok(None);
                    };
                    if !job
                        .cursor
                        .as_ref()
                        .is_some_and(|m| m.namespace == namespace.0)
                    {
                        return Ok(None);
                    }
                    for key in cursor.slot_key.iter().chain(&cursor.slot_members) {
                        let Some(cause) =
                            index.files.get(key).and_then(|e| e.codex_compressed_hold)
                        else {
                            continue;
                        };
                        let owners = index.codex_state_only_blocked_by_file.get(key);
                        if committed
                            .files
                            .get(key)
                            .is_some_and(|e| e.codex_compressed_hold == Some(cause))
                            && owners.into_iter().flatten().all(|owner| {
                                committed
                                    .codex_state_only_blocked_by_file
                                    .get(key)
                                    .is_some_and(|s| s.contains(owner))
                                    && committed
                                        .codex_state_only_blocked_session_ids
                                        .contains(owner)
                            })
                            && index
                                .codex_state_only_blocked_session_ids
                                .is_subset(&committed.codex_state_only_blocked_session_ids)
                        {
                            continue;
                        }
                        // Reuse an existing key allocation. With no attribution,
                        // escrow the entry too; it is returned unchanged, never
                        // copied into the committed index as accepted authority.
                        let (key, owners, entry) =
                            match index.codex_state_only_blocked_by_file.remove_entry(key) {
                                Some((key, owners)) => (key, owners, None),
                                None => {
                                    let (key, entry) =
                                        index.files.remove_entry(key).expect("held entry");
                                    (key, BTreeSet::new(), Some(entry))
                                }
                            };
                        cursor.custody_unsaved = Some(CustodyWrite {
                            pending: Some(CustodyDecision {
                                origin: CustodyOrigin::new(path),
                                key,
                                cause,
                                owners,
                                veto: std::mem::take(
                                    &mut index.codex_state_only_blocked_session_ids,
                                ),
                                entry,
                            }),
                        });
                        if let Some(meta) = job.cursor.as_mut() {
                            first = meta.custody_deferred.is_none();
                            meta.custody_deferred
                                .get_or_insert((super::now_seconds(), 0));
                        }
                        break;
                    }
                }
                match cursor.custody_unsaved.take() {
                    Some(CustodyWrite {
                        pending: Some(decision),
                    }) => {
                        if !decision.origin.matches(path) {
                            cursor.custody_unsaved = Some(CustodyWrite {
                                pending: Some(decision),
                            });
                            anyhow::bail!("custody transaction belongs to another index");
                        }
                        cursor.custody_unsaved = Some(CustodyWrite { pending: None });
                        Ok(Some(decision))
                    }
                    Some(CustodyWrite { pending: None }) => {
                        cursor.custody_unsaved = Some(CustodyWrite { pending: None });
                        anyhow::bail!("custody transaction already saving")
                    }
                    None => Ok(None),
                }
            })
            .unwrap_or_else(|| anyhow::bail!("custody decision holder unavailable"))?;
        if first {
            crate::local_resource_diagnostics::custody_latch_deferred(1, 0, 0);
        }
        Ok(decision.map(|decision| CustodySave {
            cache: Arc::clone(self),
            decision: Some(decision),
        }))
    }

    /// Yield BEFORE inventory/acquisition until the COMPLETE pending payload
    /// has been funded and saved. No cause-only replay or allocation here.
    pub(in crate::snapshots) fn replay_custody_decision(&self) -> bool {
        self.with_cursor(|cursor| cursor.custody_unsaved.is_some())
            .unwrap_or(true)
    }

    /// The key of the paused or active job (tests; selection uses
    /// `cursor_job_owns`).
    #[cfg(test)]
    pub(in crate::snapshots) fn cursor_job_key(&self) -> Option<String> {
        self.with_cursor(|cursor| match cursor.slot {
            Slot::Empty => None,
            Slot::Paused(_) | Slot::ActiveElsewhere { .. } => cursor.slot_key.clone(),
        })
        .flatten()
    }

    /// A paused or active job owns this path key: the singleton's own file or
    /// any member of the group job (§d.1.2 c). Selection skips it.
    pub(in crate::snapshots) fn cursor_job_owns(&self, key: &str) -> bool {
        self.with_cursor(|cursor| match cursor.slot {
            Slot::Empty => false,
            Slot::Paused(_) | Slot::ActiveElsewhere { .. } => {
                cursor.slot_key.as_deref() == Some(key) || cursor.slot_members.contains(key)
            }
        })
        .unwrap_or(false)
    }

    /// The owner of the paused or active group job, if any.
    pub(in crate::snapshots) fn cursor_group_owner(&self) -> Option<String> {
        self.with_cursor(|cursor| match &cursor.slot {
            Slot::Paused(job) => job.group.as_ref().map(|group| group.owner.clone()),
            Slot::Empty | Slot::ActiveElsewhere { .. } => None,
        })
        .flatten()
    }

    /// The paused group job's current canonical member (tests).
    #[cfg(test)]
    pub(in crate::snapshots) fn paused_group_position(&self) -> Option<usize> {
        self.with_cursor(|cursor| match &cursor.slot {
            Slot::Paused(job) => job.group.as_ref().map(|group| group.current),
            Slot::Empty | Slot::ActiveElsewhere { .. } => None,
        })
        .flatten()
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn counters_for_test(&self) -> Counters {
        self.with_cursor(|cursor| cursor.counters)
            .unwrap_or_default()
    }

    /// Count one selected entry skipped because a job owns it (L1).
    pub(in crate::snapshots) fn note_join_in_progress(&self) {
        self.with_cursor(|cursor| cursor.counters.join_in_progress_members += 1);
    }

    /// Terminal group debt by reason (§d.1.1 S11 counter).
    pub(in crate::snapshots) fn note_join_refusal(&self, reason: codex_file_join::JoinRefusal) {
        self.with_cursor(|cursor| {
            let slot = &mut cursor.counters.join_terminal_debt[reason.slot()];
            *slot = slot.saturating_add(1);
        });
    }

    pub(in crate::snapshots) fn note_group_memo_hit(&self) {
        self.with_cursor(|cursor| cursor.counters.group_memo_hits += 1);
    }

    pub(in crate::snapshots) fn note_probe_bound(&self) {
        self.with_cursor(|cursor| cursor.counters.probe_bound += 1);
    }

    /// M-5: this group's attempt ended as terminal debt in generation
    /// `fence`; a later selection in the same generation is skipped.
    pub(in crate::snapshots) fn group_attempted(
        &self,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
    ) {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| cursor.rotation.complete(&key, fence));
    }

    /// M-5 (b) at pop: the group's attempt already ended in this generation.
    /// Counted in `groups_fenced`; its members are not processed again.
    pub(in crate::snapshots) fn group_fenced(
        &self,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
    ) -> bool {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| {
            let fenced = cursor.rotation.fenced(&key, fence);
            if fenced {
                cursor.counters.groups_fenced += 1;
            }
            fenced
        })
        .unwrap_or(false)
    }

    /// PR-P: the namespace's parent state for one page, under the cursor lock.
    /// Touches the (namespace, scope) restart slot and the witness entry; an
    /// entry of another scope is dropped (its witnesses are lost and
    /// revalidated fail-closed). Never inserts into `parents`. A poisoned
    /// cursor reports the budget spent and nothing witnessed (fail closed),
    /// with the count unobserved (N1).
    pub(in crate::snapshots) fn parent_state(&self, namespace: &Scope, scope: &str) -> ParentState {
        self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            let (slot, evicted) = cursor
                .parent_restarts
                .touch(parent_restart_key(&namespace.0, scope), page);
            let restarts = slot.restarts;
            if evicted {
                cursor.counters.parent_restart_slot_evicted += 1;
            }
            if cursor
                .parents
                .get(&namespace.0)
                .is_some_and(|entry| entry.scope != scope)
            {
                cursor.parents.remove(&namespace.0);
            }
            match cursor.parents.get_mut(&namespace.0) {
                Some(entry) => {
                    entry.touched = page;
                    ParentState {
                        restarts,
                        restarts_observed: true,
                        matched: entry.matched.clone(),
                        witnesses: entry
                            .witnesses
                            .entries
                            .iter()
                            .map(|(parent, (witness, _))| (parent.clone(), witness.clone()))
                            .collect(),
                    }
                }
                None => ParentState {
                    restarts,
                    restarts_observed: true,
                    matched: None,
                    witnesses: Vec::new(),
                },
            }
        })
        .unwrap_or(ParentState {
            restarts: PARENT_RESTART_BUDGET,
            restarts_observed: false,
            matched: None,
            witnesses: Vec::new(),
        })
    }

    /// PR-P: admits one witness, optionally (it never forgets provenance or
    /// witnesses to make room and never takes a claim's room), in one
    /// critical section under the retained lock, then the cursor lock. The
    /// charge is computed from lengths before any key is copied: the witness
    /// node, the key and the moved-in strings' capacities, plus a new entry's
    /// node, key, scope and empty-map root. Construction is checked against it. Unsupported
    /// layout or no room: refused (`parent_witness_refused`), nothing kept.
    /// The count bound is separate: a witness for a new namespace past
    /// `ROTATION_KEYS` (the 65th) is refused before admission
    /// (`parent_namespace_refused`, also `parent_witness_refused`); the 64
    /// retained namespaces keep their witnesses, and the newcomer's parent
    /// stays owed.
    pub(in crate::snapshots) fn witness_parent(
        &self,
        namespace: &Scope,
        scope: &str,
        parent: &str,
        witness: ParentWitness,
    ) -> bool {
        let refuse = |cache: &Self| {
            cache.with_cursor(|cursor| cursor.counters.parent_witness_refused += 1);
            false
        };
        let stored = parent
            .len()
            .checked_add(witness.identity.as_ref().map_or(0, String::capacity))
            .and_then(|bytes| {
                bytes.checked_add(witness.waits_on.as_ref().map_or(0, String::capacity))
            });
        let Some(stored) = stored else {
            return refuse(self);
        };
        let Ok(mut retained) = self.retained() else {
            return refuse(self);
        };
        let admitted = self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            if parent_namespace_full(cursor, &namespace.0) {
                cursor.counters.parent_namespace_refused += 1;
                cursor.counters.parent_witness_refused += 1;
                return false;
            }
            let exists = cursor
                .parents
                .get(&namespace.0)
                .is_some_and(|entry| entry.scope == scope);
            let Some(charge) = parent_entry_charge(exists, &namespace.0, scope).and_then(|entry| {
                crate::heap_layout_bound::tree_node_bytes::<String, (ParentWitness, usize)>()?
                    .checked_add(stored)?
                    .checked_add(entry)
            }) else {
                cursor.counters.parent_witness_refused += 1;
                return false;
            };
            if !crate::heap_layout_bound::layout_supported()
                || !admit_locked(&mut retained, cursor, charge, false, Admitter::Main)
            {
                cursor.counters.parent_witness_refused += 1;
                return false;
            }
            let key = exact_copy(parent);
            let built = key
                .capacity()
                .checked_add(witness.identity.as_ref().map_or(0, String::capacity))
                .and_then(|bytes| {
                    bytes.checked_add(witness.waits_on.as_ref().map_or(0, String::capacity))
                });
            if built != Some(stored) {
                // Outside the accounting contract: refuse, freed here.
                cursor.counters.parent_witness_refused += 1;
                return false;
            }
            let Some(entry) = parent_entry(cursor, exists, &namespace.0, scope, page) else {
                return false;
            };
            let previous = entry.witnesses.entries.insert(key, (witness, stored));
            let charge = previous
                .map_or(Some(entry.witnesses.charge), |(_, old)| {
                    entry.witnesses.charge.checked_sub(old)
                })
                .and_then(|charge| charge.checked_add(stored));
            entry.witnesses.charge = charge.unwrap_or_else(|| {
                // Corrupt accounting: fail closed (measures unbounded).
                debug_assert!(
                    std::thread::panicking(),
                    "parent witness charge accounting is corrupt"
                );
                usize::MAX
            });
            true
        });
        drop(retained);
        admitted.unwrap_or(false)
    }

    /// PR-P: removes and uncharges witnesses, under the cursor lock only
    /// (frees). An empty list, or an absent entry, is a no-op.
    pub(in crate::snapshots) fn drop_parent_witnesses(
        &self,
        namespace: &Scope,
        scope: &str,
        parents: &[String],
    ) {
        if parents.is_empty() {
            return;
        }
        self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            let Some(entry) = cursor
                .parents
                .get_mut(&namespace.0)
                .filter(|entry| entry.scope == scope)
            else {
                return;
            };
            entry.touched = page;
            for parent in parents {
                if let Some((_, stored)) = entry.witnesses.entries.remove(parent.as_str()) {
                    entry.witnesses.charge = entry
                        .witnesses
                        .charge
                        .checked_sub(stored)
                        .unwrap_or_else(|| {
                            debug_assert!(
                                std::thread::panicking(),
                                "parent witness charge accounting is corrupt"
                            );
                            usize::MAX
                        });
                }
            }
        });
    }

    /// PR-P: marks the namespace matched for this traversal, admitted like
    /// `witness_parent` (the copied end, plus a new entry; a new namespace
    /// past `ROTATION_KEYS` is refused the same way). A refusal leaves it
    /// unmarked, so the next page re-matches (`parent_match_unmarked`).
    pub(in crate::snapshots) fn mark_parents_matched(
        &self,
        namespace: &Scope,
        scope: &str,
        end: &str,
        restarts: u64,
    ) {
        let unmarked = |cache: &Self| {
            cache.with_cursor(|cursor| cursor.counters.parent_match_unmarked += 1);
        };
        let Ok(mut retained) = self.retained() else {
            return unmarked(self);
        };
        self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            if parent_namespace_full(cursor, &namespace.0) {
                cursor.counters.parent_namespace_refused += 1;
                cursor.counters.parent_match_unmarked += 1;
                return;
            }
            let exists = cursor
                .parents
                .get(&namespace.0)
                .is_some_and(|entry| entry.scope == scope);
            let Some(charge) = parent_entry_charge(exists, &namespace.0, scope)
                .and_then(|entry| entry.checked_add(end.len()))
            else {
                cursor.counters.parent_match_unmarked += 1;
                return;
            };
            if !crate::heap_layout_bound::layout_supported()
                || !admit_locked(&mut retained, cursor, charge, false, Admitter::Main)
            {
                cursor.counters.parent_match_unmarked += 1;
                return;
            }
            let Some(entry) = parent_entry(cursor, exists, &namespace.0, scope, page) else {
                cursor.counters.parent_match_unmarked += 1;
                return;
            };
            entry.matched = Some((exact_copy(end), restarts));
        });
    }

    /// PR-P: one parent-resolution restart of (namespace, scope); returns the
    /// new count. Inline table: never refused, no heap. A poisoned cursor
    /// counts nothing and returns None (N1: an unknown count, never the
    /// budget reported as observed).
    pub(in crate::snapshots) fn note_parent_restart(
        &self,
        namespace: &Scope,
        scope: &str,
    ) -> Option<u64> {
        self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            let (slot, evicted) = cursor
                .parent_restarts
                .touch(parent_restart_key(&namespace.0, scope), page);
            slot.restarts = slot.restarts.saturating_add(1);
            let restarts = slot.restarts;
            if evicted {
                cursor.counters.parent_restart_slot_evicted += 1;
            }
            restarts
        })
    }

    /// §d.1.3: B blocked `owner` for a queued group of `members`. The exact
    /// member keys are the L-1 release's deletion authority. Admission,
    /// construction and commit run in one critical section (retained lock,
    /// then cursor lock): the entry's accounted size is admitted before any
    /// byte of it is allocated (optional: it never forgets other provenance or
    /// a paused job's room for it), so nothing built is ever uncharged and no
    /// other admission can spend the same room. Refused provenance (malformed
    /// keys, unsupported accounting, overflow, no room, a poisoned lock) is
    /// forgotten, which keeps the owner blocked; it never releases one, and
    /// nothing partial is stored.
    pub(in crate::snapshots) fn record_join_owner(&self, owner: &str, members: &[CandidateFile]) {
        // Encoding is checked before anything is reserved or allocated.
        let charge = join_keys_len(members)
            .filter(|_| !owner.is_empty())
            .and_then(|keys_len| {
                // Requested-layout accounting (the supported toolchain's
                // contract, as every cursor charge): a new map node, the owner
                // key (`with_capacity(len)`, exact) and the joined keys
                // (`with_capacity(keys_len)`, filled exactly, never regrown).
                let charge = crate::heap_layout_bound::tree_node_bytes::<String, JoinProvenance>()?
                    .checked_add(owner.len())?
                    .checked_add(keys_len)?;
                Some((charge, keys_len))
            });
        let Some((charge, keys_len)) = charge else {
            self.with_cursor(|cursor| cursor.join_owners.remove(owner));
            return;
        };
        let Ok(mut retained) = self.retained() else {
            self.with_cursor(|cursor| cursor.join_owners.remove(owner));
            return;
        };
        self.with_cursor(|cursor| {
            let used = cursor.tick();
            // Unchanged membership: refresh recency; nothing is built.
            if let Some((tick, stored)) = cursor.join_owners.get_mut(owner) {
                if same_join_members(stored, members) {
                    *tick = used;
                    return;
                }
            }
            if !admit_locked(&mut retained, cursor, charge, false, Admitter::Main) {
                cursor.join_owners.remove(owner);
                return;
            }
            // Construction, within the admitted charge. While it runs the old
            // entry (if any) stays counted beside it: the overlap is charged.
            let mut keys = String::with_capacity(keys_len);
            for (position, member) in members.iter().enumerate() {
                if position > 0 {
                    keys.push('\0');
                }
                push_join_key(&mut keys, &member.path);
            }
            let replacing = cursor.join_owners.contains_key(owner);
            let built = crate::heap_layout_bound::tree_node_bytes::<String, JoinProvenance>()
                .and_then(|node| node.checked_add(if replacing { 0 } else { owner.len() }))
                .and_then(|bytes| bytes.checked_add(keys.capacity()));
            if keys.len() != keys_len || !built.is_some_and(|built| built <= charge) {
                // Outside the accounting contract: refuse, freed here.
                cursor.join_owners.remove(owner);
                return;
            }
            // Commit. Replacing keeps the stored owner key (no copy); a new
            // owner at the cap first forgets the least recent provenance, which
            // only keeps that owner blocked. Replaced or evicted bytes are freed
            // here, under the lock that counted them.
            if let Some(entry) = cursor.join_owners.get_mut(owner) {
                *entry = (used, keys);
            } else {
                if cursor.join_owners.len() >= JOIN_OWNERS {
                    evict_oldest_join_owner(cursor);
                }
                cursor.join_owners.insert(owner.to_owned(), (used, keys));
            }
        });
    }

    /// L-1: every owner whose recorded member keys are all absent from
    /// `census` (exact `local_index_key` equality) and for which `keep` is
    /// false is removed, and `release(owner, its recorded member keys)` runs
    /// for it, all under the cursor lock; each entry is freed there, so no
    /// released bytes outlive their charge and nothing is copied out.
    /// Malformed or empty provenance is never released. Neither closure may
    /// call a `SharedCache` method (enforced in debug builds). A poisoned
    /// cursor releases nothing, which keeps every owner blocked.
    pub(in crate::snapshots) fn release_join_owners(
        &self,
        census: &BTreeSet<String>,
        keep: impl Fn(&str) -> bool,
        mut release: impl FnMut(&str, std::str::Split<'_, char>),
    ) {
        self.with_cursor(|cursor| {
            // In place: `release` reads the entry, which `retain` then drops.
            cursor.join_owners.retain(|owner, (_, members)| {
                let departed = join_members_well_formed(members)
                    && !keep(owner.as_str())
                    && members.split('\0').all(|member| !census.contains(member));
                if departed {
                    release(owner.as_str(), members.split('\0'));
                }
                !departed
            });
        });
    }

    /// The disclosure of a parked `JoinStateBound` file that is the same
    /// object, unshrunk and unedited (growth keeps it parked), with the same
    /// reduction dependencies. Anything else wakes it: the record is dropped
    /// and the file is attempted again.
    #[cfg(test)]
    pub(in crate::snapshots) fn cursor_parked(
        &self,
        key: &str,
        file: &File,
        dependencies: Option<&str>,
    ) -> Option<Disclosure> {
        self.cursor_parked_stamp(key, OpenStamp::capture(file).ok(), dependencies)
    }

    pub(in crate::snapshots) fn cursor_parked_stamp(
        &self,
        key: &str,
        now: Option<OpenStamp>,
        dependencies: Option<&str>,
    ) -> Option<Disclosure> {
        self.with_cursor(|cursor| {
            let used = cursor.tick();
            let parked = cursor.parked.get_mut(key)?;
            if let Some(now) = now.filter(|now| {
                (if parked.exact {
                    parked.stamp == *now
                } else {
                    parked.stamp.wake_compatible(now)
                }) && parked.dependencies.as_deref() == dependencies
            }) {
                parked.stamp = now;
                parked.used = used;
                let disclosure = parked.disclosure.clone();
                cursor.counters.parked_hits += 1;
                return Some(disclosure);
            }
            cursor.parked.remove(key);
            None
        })
        .flatten()
    }

    /// Park a `ProbeBudgetOrder` group under its live member's boot stamp
    /// (round 3): strict debt disclosed again at zero replay bytes until a
    /// member changes (`exact`: any live-member stamp change) or a
    /// dependency does. Bounded like every parked record.
    pub(in crate::snapshots) fn park_group(
        &self,
        key: &str,
        stamp: OpenStamp,
        dependencies: Option<String>,
        disclosure: Disclosure,
        exact: bool,
    ) {
        self.with_cursor(|cursor| {
            let used = cursor.tick();
            park(
                cursor,
                key.to_owned(),
                Parked {
                    stamp,
                    dependencies,
                    disclosure,
                    used,
                    exact,
                },
            );
        });
    }

    /// A memo entry or parked record exists for the group: its boot reaches
    /// that lookup before the cursor-slot check (round 3, R2-M1).
    pub(in crate::snapshots) fn group_recorded(&self, namespace: &Scope, key: &str) -> bool {
        let memo_key = memo_key(namespace, key);
        self.with_cursor(|cursor| {
            cursor.memo.entries.contains_key(&memo_key) || cursor.parked.contains_key(key)
        })
        .unwrap_or(false)
    }

    /// A group that read nothing for a job (unchanged, memo hit, parked)
    /// stops waiting for the slot, with no fence and no served update
    /// (round 3, R2-M1).
    pub(in crate::snapshots) fn cursor_unwait(&self, namespace: &Scope, key: &str) {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| cursor.rotation.waiting.remove(&key));
    }

    /// The group asked for a page of its own (round 3) and is not fenced in
    /// this generation (round 4: a fenced pop would waste the page).
    pub(in crate::snapshots) fn group_own_page(
        &self,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
    ) -> bool {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| {
            cursor.rotation.own_page.contains_key(&key) && !cursor.rotation.fenced(&key, fence)
        })
        .unwrap_or(false)
    }

    /// The group's boot takes its own-page request: true when it was asked.
    pub(in crate::snapshots) fn take_group_own_page(&self, namespace: &Scope, key: &str) -> bool {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| cursor.rotation.own_page.remove(&key).is_some())
            .unwrap_or(false)
    }

    /// Its probes outran the page's remaining singleton budget: next time it
    /// takes a page of its own (round 3).
    pub(in crate::snapshots) fn request_group_own_page(&self, namespace: &Scope, key: &str) {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| {
            let page = cursor.rotation.page;
            bounded_insert(&mut cursor.rotation.own_page, &key, page, |page| *page);
        });
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn rotation_waiters_for_test(&self) -> usize {
        self.with_cursor(|cursor| cursor.rotation.waiting.len())
            .unwrap_or(0)
    }

    pub(in crate::snapshots) fn cursor_note_deferred(&self) {
        self.with_cursor(|cursor| cursor.counters.deferred += 1);
    }

    /// Growth read after its path was processed in this census generation
    /// re-enters the queue as next-generation evidence, not a census
    /// member (K7 for singletons and re-reads, G1).
    pub(in crate::snapshots) fn cursor_note_next_generation(&self, count: u64) {
        if count > 0 {
            self.with_cursor(|cursor| cursor.counters.deferred_next_generation += count);
        }
    }

    /// A cursor job reached the page budget without its lease (unreachable
    /// while the frame holds one): the job is dropped, never continued
    /// in-page, and its pending path restarts it (L2).
    pub(in crate::snapshots) fn cursor_note_lost(&self) {
        self.with_cursor(|cursor| cursor.counters.jobs_lost += 1);
    }

    /// The page plan with slot rotation and the census fence (K7). Only a
    /// file larger than the singleton budget on a cursor build is affected:
    /// a file whose attempt completed in this generation is `Fenced`; a
    /// file another waiter is ahead of is deferred; every deferred large
    /// file is recorded as waiting. `census_member`: the read holds this
    /// generation's census, so it waits ahead of every re-read (G1).
    #[allow(clippy::too_many_arguments)]
    pub(in crate::snapshots) fn cursor_plan(
        &self,
        page: &mut PageBudget,
        limits: Limits,
        expected: u64,
        slot_free: bool,
        cursor_enabled: bool,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
        census_member: bool,
    ) -> StartPlan {
        self.cursor_plan_paced(
            page,
            limits,
            expected,
            slot_free,
            cursor_enabled,
            namespace,
            key,
            fence,
            census_member,
            None,
        )
    }

    /// `cursor_plan` with the Stage 1 guard (§6) for a singleton: on an
    /// ordinary page, a large start that rotation would grant (`Cursor`,
    /// `expected` above the singleton budget) is deferred while its key's
    /// last attempt's ordinary-equivalent eligibility is ahead
    /// (`PaceTable::verdict`). A paced deferral is an ordinary `Defer`: the
    /// caller requeues the file, owed. It is never recorded as a waiter (it
    /// leaves `rotation.waiting`, so it blocks no turn) and is neither a
    /// completion, a fence, a skip nor a loss; it counts `deferred_paced`.
    /// The file's stamp is read before the cursor lock (no IO under it); an
    /// unreadable stamp plans as today (the start then refuses it).
    #[allow(clippy::too_many_arguments)]
    pub(in crate::snapshots) fn cursor_plan_paced(
        &self,
        page: &mut PageBudget,
        limits: Limits,
        expected: u64,
        slot_free: bool,
        cursor_enabled: bool,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
        census_member: bool,
        pace: Option<PaceProbe<'_>>,
    ) -> StartPlan {
        let plan = page.plan(limits, expected, slot_free, cursor_enabled);
        if !matches!(plan, StartPlan::Cursor | StartPlan::Defer) || expected <= limits.singleton {
            return plan;
        }
        page.note_page(self, namespace);
        let paced = pace
            .filter(|_| plan == StartPlan::Cursor && !page.continuation())
            .and_then(|probe| {
                let rev = OpenStamp::capture(probe.file).ok()?;
                Some((pace_key(&namespace.0, &group_scope(probe.index), key), rev))
            });
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| {
            if cursor.rotation.fenced(&key, fence) {
                cursor.rotation.waiting.remove(&key);
                cursor.counters.deferred_next_generation += 1;
                return StartPlan::Fenced;
            }
            if plan == StartPlan::Cursor && !cursor.rotation.turn_as(&key, census_member) {
                cursor.counters.deferred_rotation += 1;
                cursor.rotation.wait_as(&key, census_member);
                return StartPlan::Defer;
            }
            if plan == StartPlan::Defer {
                cursor.rotation.wait_as(&key, census_member);
            }
            if let Some((pace_key, rev)) = paced.as_ref() {
                if cursor.pace.verdict(*pace_key, rev, pace_now()) == PaceVerdict::Defer {
                    cursor.rotation.waiting.remove(&key);
                    cursor.counters.deferred_paced += 1;
                    return StartPlan::Defer;
                }
            }
            plan
        })
        .unwrap_or(plan)
    }

    /// Count a committed attempt once the native finish ran (M4).
    pub(in crate::snapshots) fn cursor_published(&self, publication: Publication, finished: bool) {
        self.with_cursor(|cursor| {
            let counters = &mut cursor.counters;
            if !finished {
                counters.jobs_finish_failed += 1;
            } else if publication.certified {
                counters.jobs_certified += 1;
            } else {
                counters.jobs_uncertified += 1;
            }
            if finished && publication.eof_applied {
                counters.eof_record_applied += 1;
            }
            if let Some(age) = publication.overdue_age.filter(|_| finished) {
                counters.audit_overdue += 1;
                counters.audit_overdue_max_age_seconds =
                    counters.audit_overdue_max_age_seconds.max(age);
            }
        });
    }

    /// Start a `SingletonFull` job for `job`: claim the empty slot, freeze the
    /// extent at the acquisition's open length, enable the chunked skip and
    /// keep every turn witness exactly (K1).
    pub(in crate::snapshots) fn cursor_start(
        self: &Arc<Self>,
        job: &mut OwnedActiveFile,
        namespace: &Scope,
        dependencies: Option<String>,
        owner: Option<String>,
        census_trusted: bool,
        index: &ScanIndex,
    ) -> std::result::Result<CursorLease, StartRefusal> {
        let key = local_index_key(&job.candidate.path);
        let waiter = rotation_key(&namespace.0, &key);
        let refuse = |refusal: StartRefusal| {
            self.with_cursor(|cursor| {
                cursor.rotation.waiting.remove(&waiter);
                match refusal {
                    StartRefusal::InputsUnavailable => cursor.counters.jobs_deferred_inputs += 1,
                    StartRefusal::Unstartable => cursor.counters.jobs_start_unstartable += 1,
                    StartRefusal::Busy => {}
                }
            });
            refusal
        };
        // #625 decoder seam: a compressed input has no physical offsets,
        // samples or frozen extent, and its decoded size is not the on-disk
        // length `PageBudget::plan` compares with B. Refuse it explicitly
        // (never a cursor job); the activation names the compressed > B plan
        // and sizes it by decoded bytes.
        if refuse_compressed_codex(
            Some(&job.candidate.path),
            Some(&job.parser.reader.reader),
            CodexZstCause::PhysicalOffsetUnsupported,
        )
        .is_err()
        {
            return Err(refuse(StartRefusal::Unstartable));
        }
        if job.parser.reader.reader.is_compressed() {
            return Err(refuse(StartRefusal::Unstartable));
        }
        // The certificate needs the acquisition's open stamp and samples.
        let Some((frozen, start)) = job
            .parser
            .reader
            .acquisition
            .as_ref()
            .map(|plan| (plan.frozen_length(), plan.start_offset()))
        else {
            return Err(refuse(StartRefusal::InputsUnavailable));
        };
        // Resume revalidates every priority decision against the witnesses.
        if job
            .parser
            .accumulator
            .codex_observed_priority_turns
            .is_none()
        {
            return Err(refuse(StartRefusal::Unstartable));
        }
        let Ok(stamp_open) = OpenStamp::capture(job.parser.reader.reader.get_ref()) else {
            return Err(refuse(StartRefusal::Unstartable));
        };
        // Stage 1 guard (§6): the attempt's slot is written with the claim.
        // It is accelerated only with known coverage and a recorded slot.
        let pace_key = pace_key(&namespace.0, &group_scope(index), &key);
        let now = pace_now();
        let (token, accelerate) = self
            .with_cursor(|cursor| {
                if !matches!(cursor.slot, Slot::Empty) {
                    return None;
                }
                let token = cursor.next_token;
                cursor.next_token = cursor.next_token.wrapping_add(1).max(1);
                cursor.slot = Slot::ActiveElsewhere { token };
                cursor.slot_key = Some(key.clone());
                cursor.rotation.waiting.remove(&waiter);
                cursor.counters.jobs_started += 1;
                let known = matches!(
                    cursor.pace.verdict(pace_key, &stamp_open, now),
                    PaceVerdict::Start { accelerate: true }
                );
                let recorded = cursor.pace.begin(pace_key, &stamp_open, now);
                Some((token, known && recorded))
            })
            .flatten()
            .ok_or(StartRefusal::Busy)?;
        let limits = Limits::current();
        job.parser.accumulator.codex_priority_witnesses_uncapped = true;
        job.parser.reader.set_chunked_skip(limits.skip_chunk);
        // The reader counts from the acquisition start (`s` for a tail).
        job.parser
            .reader
            .set_extent_limit(frozen.min(stamp_open.extent).saturating_sub(start));
        job.cursor = Some(JobMeta {
            counting: counting_view(&job.candidate, index),
            fence: census_token(index),
            key,
            namespace: namespace.0.clone(),
            stamp_open,
            started: super::now_seconds(),
            dependencies,
            owner,
            census_trusted,
            pages: 1,
            unavailable_resumes: 0,
            custody_deferred: None,
            charge: None,
            eof_applied: false,
            pace: JobPace::new(pace_key, now, accelerate),
        });
        Ok(CursorLease {
            cache: Arc::clone(self),
            token,
            armed: true,
        })
    }

    /// Start a group job (P2): claim the empty slot for the group key and its
    /// members, keep every turn witness exactly, and freeze the first member
    /// at its boot extent. Each later member is armed at its open
    /// (`arm_group_member`); the live (last) member gets its acquisition and
    /// frozen extent there.
    pub(in crate::snapshots) fn cursor_start_group(
        self: &Arc<Self>,
        job: &mut OwnedActiveFile,
        namespace: &Scope,
        dependencies: Option<String>,
        census_trusted: bool,
        index: &ScanIndex,
    ) -> std::result::Result<CursorLease, StartRefusal> {
        let Some(group) = job.group.as_ref() else {
            return Err(StartRefusal::Unstartable);
        };
        let key = group.key.clone();
        let owner = group.owner.clone();
        let boot = group.stamps.first().cloned();
        let counting = group_counting_view(&group.members, index);
        let members = group
            .members
            .iter()
            .map(|member| local_index_key(&member.path))
            .collect::<BTreeSet<_>>();
        let waiter = rotation_key(&namespace.0, &key);
        let refuse = |refusal: StartRefusal| {
            self.with_cursor(|cursor| {
                cursor.rotation.waiting.remove(&waiter);
                if refusal == StartRefusal::Unstartable {
                    cursor.counters.jobs_start_unstartable += 1;
                }
            });
            refusal
        };
        // Compressed members larger than B keep refusing until P4 (named debt).
        if job.parser.reader.reader.is_compressed() {
            return Err(refuse(StartRefusal::Unstartable));
        }
        let (Ok(stamp_open), Some(boot)) =
            (OpenStamp::capture(job.parser.reader.reader.get_ref()), boot)
        else {
            return Err(refuse(StartRefusal::Unstartable));
        };
        let token = self
            .with_cursor(|cursor| {
                if !matches!(cursor.slot, Slot::Empty) {
                    return None;
                }
                let token = cursor.next_token;
                cursor.next_token = cursor.next_token.wrapping_add(1).max(1);
                cursor.slot = Slot::ActiveElsewhere { token };
                cursor.slot_key = Some(key.clone());
                cursor.slot_members = members;
                cursor.rotation.waiting.remove(&waiter);
                cursor.counters.jobs_started += 1;
                cursor.counters.groups_started += 1;
                Some(token)
            })
            .flatten()
            .ok_or(StartRefusal::Busy)?;
        let limits = Limits::current();
        let accumulator = &mut job.parser.accumulator;
        accumulator.codex_priority_witnesses_uncapped = true;
        // Resume revalidates every priority decision against the witnesses.
        accumulator
            .codex_observed_priority_turns
            .get_or_insert_with(BTreeMap::new);
        job.parser.reader.set_chunked_skip(limits.skip_chunk);
        job.parser.reader.set_extent_limit(boot.extent);
        job.cursor = Some(JobMeta {
            counting,
            fence: census_token(index),
            key,
            namespace: namespace.0.clone(),
            stamp_open,
            started: super::now_seconds(),
            dependencies,
            owner: Some(owner),
            census_trusted,
            pages: 1,
            unavailable_resumes: 0,
            custody_deferred: None,
            charge: None,
            eof_applied: false,
            // Stage 1: a group is never paced or accelerated (no slot).
            pace: JobPace::new([0; 2], pace_now(), false),
        });
        Ok(CursorLease {
            cache: Arc::clone(self),
            token,
            armed: true,
        })
    }

    /// Take the paused job for this scan namespace and claim the slot. A
    /// live job of another namespace is left alone (K10): this scan's large
    /// files wait their rotation turn. Only a stale job (not paused or
    /// resumed for `NAMESPACE_STALE_PAGES` cursor pages, so its namespace
    /// stopped scanning) is evicted; its path restarts in its namespace.
    /// A continuation page (Stage 1, E2) never evicts: it only resumes its
    /// own namespace's job.
    pub(in crate::snapshots) fn cursor_resume(
        self: &Arc<Self>,
        namespace: &Scope,
        continuation: bool,
    ) -> Option<(Box<OwnedActiveFile>, CursorLease)> {
        let mut group_held = false;
        let claimed = self.with_cursor(|cursor| {
            let Slot::Paused(job) = &cursor.slot else {
                return None;
            };
            if continuation && job.group.is_some() {
                group_held = true;
                return None;
            }
            let foreign = job
                .cursor
                .as_ref()
                .map_or(true, |meta| meta.namespace != namespace.0);
            let live = job.cursor.is_some()
                && cursor.rotation.page.saturating_sub(cursor.slot_touched) < NAMESPACE_STALE_PAGES;
            if foreign {
                if continuation {
                    return None;
                }
                if live {
                    cursor.counters.namespace_busy += 1;
                    return None;
                }
                // Stage 1 (§6): the evicted attempt keeps its equivalent.
                if let Some(pace) = job.cursor.as_ref().map(|meta| meta.pace) {
                    cursor.pace_record(&pace);
                }
                cursor.slot = Slot::Empty;
                cursor.slot_key = None;
                cursor.slot_members.clear();
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
            cursor.slot_touched = cursor.rotation.page;
            cursor.counters.jobs_resumed += 1;
            Some((job, token))
        });
        if group_held {
            crate::local_resource_diagnostics::codex_continuation(Some("group_job"));
        }
        let (job, token) = claimed??;
        Some((
            job,
            CursorLease {
                cache: Arc::clone(self),
                token,
                armed: true,
            },
        ))
    }

    /// A resumed job failed revalidation on changed evidence (§p): count it
    /// and free the slot. Its path is still pending, so a later page
    /// restarts it, unless this was the `MEMBER_CHANGED_AFTER`th consecutive
    /// invalidation: then the returned strict debt is disclosed and the path
    /// released.
    pub(in crate::snapshots) fn cursor_invalidate(
        &self,
        lease: CursorLease,
        job: &OwnedActiveFile,
    ) -> Option<Disclosure> {
        // The job key: a singleton's path key, a group's job key.
        let key = job.cursor.as_ref().map_or_else(
            || local_index_key(&job.candidate.path),
            |meta| meta.key.clone(),
        );
        let rotation = job
            .cursor
            .as_ref()
            .map(|meta| (rotation_key(&meta.namespace, &meta.key), meta.fence.clone()));
        let mut member_changed = false;
        lease.end(|cursor| {
            // Stage 1 (§6): the invalidated attempt keeps its equivalent.
            if let Some(meta) = job.cursor.as_ref() {
                cursor.pace_record(&meta.pace);
            }
            member_changed = invalidated(cursor, &key);
            if member_changed {
                if let Some((waiter, fence)) = rotation.as_ref() {
                    cursor.rotation.complete(waiter, fence.as_deref());
                }
            }
        });
        member_changed.then(|| {
            let owner = job.cursor.as_ref().and_then(|meta| meta.owner.clone());
            strict_disclosure(job, owner, DebtReason::MemberChanged)
        })
    }

    pub(in crate::snapshots) fn memo_lookup(&self, key: &str) -> Option<MemoEntry> {
        self.with_cursor(|cursor| cursor.memo.entries.get(key).cloned())
            .flatten()
    }

    /// Count a hit and move the entry's stamp to the matched (possibly
    /// grown) one, so a later same-length change is measured from here.
    pub(in crate::snapshots) fn memo_hit(&self, key: &str, stamp: OpenStamp) {
        self.with_cursor(|cursor| {
            cursor.counters.memo_hits += 1;
            cursor.memo.touch(key);
            if let Some(entry) = cursor.memo.entries.get_mut(key) {
                entry.stamp = stamp;
            }
        });
    }

    pub(in crate::snapshots) fn memo_record(&self, key: String, entry: MemoEntry) {
        self.with_cursor(|cursor| {
            if cursor.memo.insert(key, entry) {
                cursor.counters.memo_records += 1;
            }
            // `insert` changes the map either way (insert, evict, or remove).
            cursor.memo.publish_resident();
        });
    }

    pub(in crate::snapshots) fn memo_forget(&self, key: &str) {
        self.with_cursor(|cursor| {
            if cursor.memo.remove(key) {
                cursor.memo.publish_resident();
            }
        });
    }
}

/// Whether a read of `paths` holds this generation's census (G1): one of
/// them was selected on this page as a census member, or none was selected
/// at all. Only selected paths are pending, so a read whose selected paths
/// are all re-reads holds nothing.
pub(in crate::snapshots) fn census_member<'a>(
    flags: &BTreeMap<String, (bool, bool)>,
    paths: impl IntoIterator<Item = &'a Path>,
) -> bool {
    let mut selected = false;
    for path in paths {
        if let Some((member, _)) = flags.get(&local_index_key(path)) {
            if *member {
                return true;
            }
            selected = true;
        }
    }
    !selected
}

/// The census flag `path` was selected with on this page (a member when it
/// was not selected), for a path returned to the queue (G1).
pub(in crate::snapshots) fn selected_census_member(
    flags: &BTreeMap<String, (bool, bool)>,
    path: &Path,
) -> bool {
    census_member(flags, [path])
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
        order_modified: None,
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

/// `requeue` for every member of a group in one pass over the pending
/// paths (round 4, L2): O(P + n), not O(P) per member, and no pending path
/// is cloned.
pub(in crate::snapshots) fn requeue_members<'a>(
    index: &mut ScanIndex,
    flags: &BTreeMap<String, (bool, bool)>,
    members: impl IntoIterator<Item = &'a CandidateFile>,
) {
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    let members = members.into_iter().collect::<Vec<_>>();
    // The members not pending yet; a repeated member is pushed once.
    let mut absent = members
        .iter()
        .copied()
        .map(|member| member.path.as_path())
        .collect::<std::collections::HashSet<_>>();
    for pending in &traversal.pending_candidates {
        if absent.is_empty() {
            break;
        }
        absent.remove(pending.path.as_path());
    }
    for candidate in members {
        if !absent.remove(candidate.path.as_path()) {
            continue;
        }
        let (census_member, watcher_hint) = flags
            .get(&local_index_key(&candidate.path))
            .copied()
            .unwrap_or((true, false));
        traversal.pending_candidates.push_back(ScanTraversalPath {
            order_modified: None,
            scan_root: candidate.scan_root.clone(),
            path: candidate.path.clone(),
            census_member,
            watcher_hint,
        });
    }
}

/// `dequeue` for every member of a group in one pass (round 4, L2).
pub(in crate::snapshots) fn dequeue_members<'a>(
    index: &mut ScanIndex,
    members: impl IntoIterator<Item = &'a CandidateFile>,
) {
    if let Some(traversal) = index.traversal.as_mut() {
        let paths = members
            .into_iter()
            .map(|member| member.path.as_path())
            .collect::<std::collections::HashSet<_>>();
        traversal
            .pending_candidates
            .retain(|pending| !paths.contains(pending.path.as_path()));
    }
}

/// Release a finished job's path. A watcher hint for a pending path is
/// dropped (`enqueue_watcher_hints`), so writes during the job left no hint;
/// if the file grew past the frozen extent, keep the path as a watcher hint
/// instead, and the next page tails the appended bytes from `s`. A large
/// re-read of it in this generation is `Fenced` (K7), so the census waits
/// for at most that one small tail. `next_generation`: the job froze its
/// extent in this generation, after `census_window_end`, so the appended
/// bytes are next-generation evidence and the hint is not a census member
/// (G1); a withheld fragment or a job from an older generation keeps it one.
pub(in crate::snapshots) fn release_path(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    grown: bool,
    next_generation: bool,
) {
    if !grown {
        dequeue(index, candidate);
        return;
    }
    let census_member = !next_generation;
    let Some(traversal) = index.traversal.as_mut() else {
        return;
    };
    let mut kept = false;
    traversal.pending_candidates.retain_mut(|pending| {
        if pending.path != candidate.path {
            return true;
        }
        let keep = !std::mem::replace(&mut kept, true);
        if keep {
            pending.census_member = census_member;
            pending.watcher_hint = true;
        }
        keep
    });
    if !kept {
        traversal.pending_candidates.push_back(ScanTraversalPath {
            order_modified: None,
            scan_root: candidate.scan_root.clone(),
            path: candidate.path.clone(),
            census_member,
            watcher_hint: true,
        });
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
    /// `counting_view` recomputed from the resuming scan's index (K8).
    pub(in crate::snapshots) counting: String,
    /// `group_scope` recomputed from the resuming scan's index (R1-M1).
    pub(in crate::snapshots) group_scope: String,
    /// The state and sidecar census are complete now (R1-M1).
    pub(in crate::snapshots) census_complete: bool,
    pub(in crate::snapshots) custody: Option<&'a ScanIndex>,
}

/// What the resuming scan supplies to `resume_paused_job`.
pub(in crate::snapshots) struct ResumeContext<'a> {
    pub(in crate::snapshots) source: SnapshotSource,
    pub(in crate::snapshots) sampling: &'a super::Context,
    pub(in crate::snapshots) codex: &'a CodexTitleMetadata,
    pub(in crate::snapshots) claude: &'a ClaudeTitleMetadata,
    pub(in crate::snapshots) support: Option<&'a Path>,
    pub(in crate::snapshots) context_curve_enabled: bool,
    pub(in crate::snapshots) traces: Option<Arc<CodexTurnTraceMap>>,
    pub(in crate::snapshots) parents:
        Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    pub(in crate::snapshots) inventory: Option<&'a codex_file_join::HeaderInventory>,
    /// Selection flags of this page's Codex candidates (`requeue`).
    pub(in crate::snapshots) flags: &'a BTreeMap<String, (bool, bool)>,
    /// The state and sidecar census are complete this page (R1-M1).
    pub(in crate::snapshots) census_complete: bool,
    /// Stage 1 (E2): this is a continuation page; it never counts toward
    /// `UNAVAILABLE_RESUMES` and never evicts another namespace's job.
    pub(in crate::snapshots) continuation: bool,
    /// Stage 1 (§6): the ordinary interval a continuation page stands for
    /// (`PageBudget::ordinary_equivalent`); `None` is unknown coverage.
    pub(in crate::snapshots) ordinary_equivalent: Option<std::time::Duration>,
}

/// How `resume_paused_job` used the page.
pub(in crate::snapshots) enum Resumed {
    /// No paused job of this namespace.
    Idle,
    /// The revalidated job continues in this page under its lease.
    Active(Box<OwnedActiveFile>, CursorLease),
    /// Deferred, invalidated, or ended as strict debt: the page is spent.
    Spent,
}

/// Resume this namespace's paused job and revalidate it (§p, K9). Kept out
/// of `OwnedSourceScan::step` (never inlined) and boxed, so the job's moves
/// do not grow that function's debug stack frame.
#[inline(never)]
pub(in crate::snapshots) fn resume_paused_job(
    context: ResumeContext<'_>,
    index: &mut ScanIndex,
    identified_candidates: &mut VecDeque<CandidateFile>,
    targets: DisclosureTargets<'_>,
) -> Resumed {
    let sampling = context.sampling;
    let Some((mut job, lease)) = sampling
        .cache
        .cursor_resume(&sampling.namespace, context.continuation)
    else {
        return Resumed::Idle;
    };
    // E2: a path that no longer names the held object (archived, renamed,
    // deleted or replaced) can never revalidate; end the job now.
    if !path_names_held_object(&job) {
        return end_unavailable(job, lease, index, targets);
    }
    let scope = job.sampling.as_ref().and_then(|_| {
        super::reduction_dependencies(
            context.source,
            &job.candidate,
            context.codex,
            context.claude,
            context.support,
            None,
        )
        .map(|dependency| {
            sampling.file_scope(
                context.source,
                &job.candidate,
                &dependency,
                true,
                context.context_curve_enabled,
                index,
            )
        })
    });
    // A group's counting view is built over every member (R1-M2).
    let counting = job_counting_view(&job, index);
    if context.source == SnapshotSource::Codex && job_has_custody(&job, index) {
        if let Some(meta) = job.cursor.as_mut() {
            let first = meta.custody_deferred.is_none();
            let state = meta
                .custody_deferred
                .get_or_insert((super::now_seconds(), 0));
            state.1 = state.1.saturating_add(1);
            crate::local_resource_diagnostics::custody_latch_deferred(
                u64::from(first),
                state.1,
                super::now_seconds().saturating_sub(state.0),
            );
        }
    }
    let verdict = revalidate(
        &mut job,
        ResumeInputs {
            codex: context.codex,
            claude: context.claude,
            support: context.support,
            traces: context.traces,
            parents: context.parents,
            inventory: context.inventory,
            scope,
            counting,
            group_scope: group_scope(index),
            census_complete: context.census_complete,
            custody: Some(index),
        },
    );
    let debt = match verdict {
        Resume::Valid => {
            if let Some(meta) = job.cursor.as_mut() {
                meta.unavailable_resumes = 0;
                // Stage 1 (§6): this page's ordinary-equivalent time; an
                // unknown one disables the attempt's acceleration.
                let _ = accrue_equivalent(meta, context.continuation, context.ordinary_equivalent);
            }
            // This page also selected the job's paths; read them once,
            // through the job, and keep them pending so the census still
            // waits if the job pauses.
            for file in job_files(&job) {
                identified_candidates.retain(|candidate| candidate.path != file.path);
                if !context.continuation {
                    requeue(index, context.flags, file);
                }
            }
            return Resumed::Active(job, lease);
        }
        // Unavailable evidence is not a member change: the job waits in the
        // slot, its path pending (K9), for at most `UNAVAILABLE_RESUMES`
        // consecutive ordinary pages (E2). A continuation page only defers:
        // it never counts, so it cannot end the job early (Stage 1).
        Resume::Unavailable if context.continuation => match lease.defer(job) {
            PauseEnd::Paused => None,
            PauseEnd::StateBound(job, disclosure) => Some((job, disclosure)),
        },
        Resume::Unavailable => {
            let waited = job.cursor.as_mut().map_or(UNAVAILABLE_RESUMES, |meta| {
                meta.unavailable_resumes = meta.unavailable_resumes.saturating_add(1);
                meta.unavailable_resumes
            });
            if waited >= UNAVAILABLE_RESUMES {
                return end_unavailable(job, lease, index, targets);
            }
            match lease.defer(job) {
                PauseEnd::Paused => None,
                PauseEnd::StateBound(job, disclosure) => Some((job, disclosure)),
            }
        }
        Resume::Changed => sampling
            .cache
            .cursor_invalidate(lease, &job)
            .map(|disclosure| (job, disclosure)),
    };
    if let Some((job, disclosure)) = debt {
        // Strict debt (`JoinStateBound`, or `MemberChanged` after repeated
        // real invalidations).
        disclose_job_debt(&job, &disclosure, index, targets);
        for file in job_files(&job) {
            dequeue(index, file);
        }
    }
    // Otherwise its path is still pending; a later page resumes or
    // restarts it.
    Resumed::Spent
}

/// The job's path still names the object its held FD reads (dev/ino only;
/// no byte is read from the path).
fn path_names_held_object(job: &OwnedActiveFile) -> bool {
    path_names_object(job.parser.reader.reader.get_ref(), &job.candidate.path)
}

/// `path` names the object `file` reads (dev/ino; no byte read from it).
fn path_names_object(file: &File, path: &Path) -> bool {
    OpenStamp::capture(file).is_ok_and(|held| {
        fs::symlink_metadata(path)
            .is_ok_and(|path| path.dev() == held.dev && path.ino() == held.ino)
    })
}

/// E2: end a resumed job whose evidence cannot become available: free the
/// slot, count the file's attempt for this generation (K7) and process its
/// path with a retryable `Reduction` cause. Nothing publishes; the prior
/// body is kept, and the next generation restarts the read.
fn end_unavailable(
    job: Box<OwnedActiveFile>,
    lease: CursorLease,
    index: &mut ScanIndex,
    targets: DisclosureTargets<'_>,
) -> Resumed {
    let meta = job.cursor.as_ref();
    let rotation = meta.map(|meta| rotation_key(&meta.namespace, &meta.key));
    lease.end(|cursor| {
        cursor.counters.jobs_unavailable_ended += 1;
        // Stage 1 (§6): the ended attempt keeps its equivalent.
        if let Some(meta) = meta {
            cursor.pace_record(&meta.pace);
        }
        // Missing evidence is not evidence of stability: the file's count
        // of real invalidations is kept (R2-L1).
        if let (Some(meta), Some(rotation)) = (meta, rotation.as_ref()) {
            cursor.rotation.complete(rotation, meta.fence.as_deref());
        }
    });
    targets
        .census
        .record_unreadable(UnreadableCause::Reduction, 1);
    for file in job_files(&job) {
        dequeue(index, file);
    }
    Resumed::Spent
}

/// The revalidation verdict at resume (K9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum Resume {
    Valid,
    /// Evidence changed: an invalidation, counted toward `MemberChanged`.
    Changed,
    /// Evidence needed to decide is unavailable this page (incomplete header
    /// inventory, no reduction dependencies or scope, or no traces while a
    /// witnessed turn was priority): the job waits, uncounted.
    Unavailable,
}

/// Singleton subset of the revalidation checklist, run at every resume:
/// same object without shrink or in-place edit (growth is outside the frozen
/// extent), unchanged reduction dependencies and scope, still a singleton,
/// this cycle's traces and parent ledgers installed, every priority decision
/// so far still valid, and a counting view the paused accumulator may
/// continue under (`counting_reusable`, the second restore path K8 names).
pub(in crate::snapshots) fn revalidate(
    job: &mut OwnedActiveFile,
    inputs: ResumeInputs<'_>,
) -> Resume {
    if job.group.is_some() {
        return revalidate_group(job, inputs);
    }
    let Some(meta) = job.cursor.as_ref() else {
        return Resume::Changed;
    };
    let Ok(now) = OpenStamp::capture(job.parser.reader.reader.get_ref()) else {
        return Resume::Changed;
    };
    if !meta.stamp_open.append_compatible(&now)
        || !counting_reusable(&job.parser.accumulator, &meta.counting, &inputs.counting)
    {
        return Resume::Changed;
    }
    let Some(dependencies) = sampled_scan::reduction_dependencies(
        SnapshotSource::Codex,
        &job.candidate,
        inputs.codex,
        inputs.claude,
        inputs.support,
        None,
    ) else {
        return Resume::Unavailable;
    };
    // R1-M1: under an untrusted census (at start or now) the dependency
    // fingerprint follows census completeness, so a mismatch is not proof of
    // a member change: unavailable evidence.
    let changed = if meta.census_trusted && inputs.census_complete {
        Resume::Changed
    } else {
        Resume::Unavailable
    };
    if Some(&dependencies) != meta.dependencies.as_ref() {
        return changed;
    }
    let Some(scope) = inputs.scope.as_ref() else {
        return Resume::Unavailable;
    };
    if job.sampling.as_ref().map(|active| &active.scope) != Some(scope) {
        return changed;
    }
    let Some(inventory) = inputs.inventory.filter(|inventory| {
        inventory.resumable_for(meta.owner.as_ref(), meta.custody_deferred.is_some())
    }) else {
        return Resume::Unavailable;
    };
    if let Some(owner) = meta.owner.as_ref() {
        if inventory.headers.iter().any(|header| {
            &header.owner == owner
                && header.candidate.path != job.candidate.path
                && !codex_archive_path(&header.candidate.path)
        }) {
            return Resume::Changed;
        }
        match held_roster_has_extra(inputs.custody, owner, None, |key| key == meta.key) {
            Some(true) => return Resume::Changed,
            None => return Resume::Unavailable,
            Some(false) => {}
        }
    }
    revalidate_decisions(job, inputs.traces, inputs.parents)
}

/// Negative membership evidence, independent of read/selection eligibility.
/// One capped roster pass, borrowed keys/owners only; exhaustion grants no resume.
fn held_roster_has_extra(
    index: Option<&ScanIndex>,
    owner: &str,
    home: Option<&Path>,
    is_boot: impl Fn(&str) -> bool,
) -> Option<bool> {
    let Some((index, traversal)) = index.and_then(|i| i.traversal.as_ref().map(|t| (i, t))) else {
        return Some(false);
    };
    for (at, key) in traversal.codex_rollout_paths.iter().enumerate() {
        if at == codex_file_join::MAX_HEADER_FILES {
            return None;
        }
        // Archives are outside plain continuation groups, just as in groups().
        if !codex_archive_path(Path::new(key))
            && !is_boot(key)
            && index
                .files
                .get(key)
                .is_some_and(|e| e.codex_compressed_hold.is_some())
            && index
                .codex_state_only_blocked_by_file
                .get(key)
                .is_some_and(|owners| owners.contains(owner))
            && home.map_or(true, |home| {
                traversal
                    .owning_scan_root(Path::new(key))
                    .is_some_and(|root| codex_file_join::member_home_ref(root) == home)
            })
        {
            return Some(true);
        }
    }
    Some(false)
}

/// The group subset of the revalidation checklist (P2): the member being
/// read is the same object without shrink or in-place edit; every member
/// already read still names its boot object's content (`same_content`, at
/// the exact boot length; a ctime-only change is not a change); the group's reduction
/// dependencies, member set and counting view are unchanged; then the
/// singleton's priority-decision and live-input rules. A member's path
/// stamp carries no birth witness: an in-place same-length rewrite that
/// restores mtime passes here, and a replacement is seen only through a new
/// inode number, which APFS does not reuse (Linux would need a birth
/// witness). The strict sealed-member validator before publication still
/// compares ctime.
fn revalidate_group(job: &mut OwnedActiveFile, inputs: ResumeInputs<'_>) -> Resume {
    let (Some(meta), Some(group)) = (job.cursor.as_ref(), job.group.as_ref()) else {
        return Resume::Changed;
    };
    let Ok(now) = OpenStamp::capture(job.parser.reader.reader.get_ref()) else {
        return Resume::Changed;
    };
    if !meta.stamp_open.append_compatible(&now)
        || !counting_reusable(&job.parser.accumulator, &meta.counting, &inputs.counting)
        || group.scope != inputs.group_scope
    {
        return Resume::Changed;
    }
    let sealed_changed = group
        .members
        .iter()
        .zip(&group.stamps)
        .take(group.current)
        .any(|(member, stamp)| {
            !OpenStamp::of_path(&member.path).is_some_and(|now| now.same_content(stamp))
        });
    if sealed_changed {
        return Resume::Changed;
    }
    let changed = if meta.census_trusted && inputs.census_complete {
        Resume::Changed
    } else {
        Resume::Unavailable
    };
    let live = group.members.last().map(|member| member.path.as_path());
    if meta.dependencies.as_deref()
        != live
            .map(|live| {
                group_dependencies(&group.members, live, inputs.codex, |member| {
                    member.opened_object_identity.clone()
                })
            })
            .as_deref()
    {
        return changed;
    }
    let Some(inventory) = inputs.inventory.filter(|inventory| {
        inventory.resumable_for(Some(&group.owner), meta.custody_deferred.is_some())
    }) else {
        return Resume::Unavailable;
    };
    let mut current = inventory
        .headers
        .iter()
        .filter(|header| {
            header.owner == group.owner
                && header.home == group.home
                && !codex_archive_path(&header.candidate.path)
        })
        .map(|header| local_index_key(&header.candidate.path))
        .collect::<BTreeSet<_>>();
    let members = group
        .members
        .iter()
        .map(|m| local_index_key(&m.path))
        .collect::<BTreeSet<_>>();
    if current.iter().any(|key| !members.contains(key)) {
        return Resume::Changed;
    }
    match held_roster_has_extra(inputs.custody, &group.owner, Some(&group.home), |key| {
        members.contains(key)
    }) {
        Some(true) => return Resume::Changed,
        None => return Resume::Unavailable,
        Some(false) => {}
    }
    // Restore omitted boot headers only after ruling out held newcomers.
    if let Some(index) = inputs.custody {
        current.extend(group.members.iter().filter_map(|member| {
            let key = local_index_key(&member.path);
            index
                .files
                .get(&key)
                .is_some_and(|e| e.codex_compressed_hold.is_some())
                .then_some(key)
        }));
    }
    if current != members {
        // A member appeared or vanished: another job.
        return Resume::Changed;
    }
    let traces = inputs.traces;
    let parents = inputs.parents;
    if let Some(group) = job.group.as_mut() {
        group.reinstall_tee_inputs(traces.clone(), parents.clone());
    }
    revalidate_decisions(job, traces, parents)
}

/// Every priority decision so far still holds under this cycle's traces;
/// then this cycle's traces and parent ledgers are installed.
fn revalidate_decisions(
    job: &mut OwnedActiveFile,
    traces: Option<Arc<CodexTurnTraceMap>>,
    parents: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
) -> Resume {
    let Some(observed) = job
        .parser
        .accumulator
        .codex_observed_priority_turns
        .as_ref()
    else {
        return Resume::Changed;
    };
    match traces.as_ref() {
        None if observed.values().any(|priority| *priority) => return Resume::Unavailable,
        traces => {
            let decisions_hold = observed.iter().all(|(turn, priority)| {
                *priority == traces.is_some_and(|traces| traces.is_priority_turn(turn))
            });
            if !decisions_hold {
                // R2-H1: a failed or capped trace load cannot prove a
                // decision changed; the job waits for complete evidence.
                if traces.is_some_and(|traces| traces.is_incomplete()) {
                    return Resume::Unavailable;
                }
                return Resume::Changed;
            }
        }
    }
    let accumulator = &mut job.parser.accumulator;
    accumulator.codex_turn_traces = traces;
    accumulator.codex_parent_ownership_ledgers = parents;
    Resume::Valid
}

/// A hold whose cause no appended byte can remove: an ambiguous fork, a
/// broken native ordinal stream, or (#597) a parentless created thread whose
/// proof failed on a set-only stream or header conjunct. Every flag read here
/// only ever moves toward held within one read.
///
/// A parentless thread missing its sidecar projection (no `trace_id`, a
/// state row that disagrees, or a sidecar rollout extent that lags the file)
/// is cured by sidecar evidence or by the file catching up with its extent:
/// it is memoized too, on its exact stamp (`growth_may_cure`), and wakes on
/// any change of the path's full sidecar fingerprint (rollout extent, state
/// row, title and decoration included) or conflicted candidate ids, which
/// the entry records (`sidecar_fingerprint`). Zero accepted usage is
/// append-curable and never memoized.
pub(in crate::snapshots) fn held_monotone(accumulator: &SnapshotAccumulator) -> bool {
    match accumulator.codex_ownership_boundary {
        CodexOwnershipBoundary::AmbiguousFork => true,
        CodexOwnershipBoundary::NativeCreatedThread
            if accumulator.codex_parent_session_ref.is_none() =>
        {
            !accumulator.codex_ordinal_sequence_valid
                || !accumulator.codex_native_created_thread_valid
                || accumulator.codex_creator_evidence_conflicted
                || accumulator.origin.parent_session_ref.is_some()
                || accumulator.origin.source_subagent == Some(true)
                || accumulator.codex_sidecar_projected_next_ordinal.is_none()
        }
        CodexOwnershipBoundary::NativeCreatedThread | CodexOwnershipBoundary::Ordinal { .. } => {
            !accumulator.codex_ordinal_sequence_valid
        }
        _ => false,
    }
}

/// B1 (steady-state rev 2): every hold that the classifier's created-thread
/// branch, or its identity-ambiguous return, produced depends on the file
/// length and on the sidecar. The sidecar bind needs the rollout extent to
/// equal the file length (`codex_sidecar_rollout_file_matches`) and only then
/// sets the trusted parent, projection and creation time, whether the thread
/// is state- or rollout-declared. Growth or a sidecar change may therefore
/// cure the hold (an admission) or change its parent ref, so its memo entry
/// hits only on the exact recorded stamp, and any growth re-reads it.
///
/// `NativeCreatedThread` is set only inside that branch, so this covers the
/// parentless missing-projection hold (R1-H1) and #635's unbound
/// `AmbiguousFork` hold. Memo eligibility only; admission is unchanged.
pub(in crate::snapshots) fn growth_may_cure(accumulator: &SnapshotAccumulator) -> bool {
    accumulator.codex_created_thread_native_only
}

/// Memo key: namespace and path, like rotation keys (R1-M1).
pub(in crate::snapshots) fn memo_key(namespace: &Scope, key: &str) -> String {
    rotation_key(&namespace.0, key)
}

/// Every hold except an ambiguous fork (cured by peer parent evidence, which
/// the entry's parent ledger records) also wakes on sidecar change. When in
/// doubt the sidecar is kept as a wake input (K3). A created-thread or
/// identity-ambiguous hold's `AmbiguousFork` is decided by its sidecar bind,
/// so it wakes too (B1).
pub(in crate::snapshots) fn sidecar_wakes(accumulator: &SnapshotAccumulator) -> bool {
    !matches!(
        accumulator.codex_ownership_boundary,
        CodexOwnershipBoundary::AmbiguousFork
    ) || accumulator.codex_created_thread_native_only
}

/// The path's full sidecar facts (K3): the non-reduction sidecar
/// fingerprint (rollout extent `next_byte_offset`/`next_ordinal`, state row
/// `rollout_path`/`created_at`, title, decoration, family) and which of the
/// path's candidate ids are identity conflicts. Its census flags are in the
/// memo digest.
pub(in crate::snapshots) fn sidecar_fingerprint(codex: &CodexTitleMetadata, path: &Path) -> String {
    sha256_hex(&[
        "codex_memo_sidecar:v2",
        &codex.path_sidecar_fingerprint(path),
        &conflicted_identities(codex, path),
    ])
}

/// The path's candidate ids that are identity conflicts, resolved, sorted
/// and newline-joined. The set, not its size: a conflict moving from one
/// candidate to another at an equal count also wakes (R1-L1). A path with no
/// rollout id is identity-ambiguous exactly while the state census holds
/// any created thread (`seed_codex_sidecar_parent`), so that bit stands in.
fn conflicted_identities(codex: &CodexTitleMetadata, path: &Path) -> String {
    let candidates = codex_session_id_candidates_from_path(path);
    if candidates.is_empty() {
        return format!("no_candidates:{}", !codex.state_created_threads.is_empty());
    }
    candidates
        .iter()
        .map(|identity| resolve_codex_identity(identity.as_str()))
        .filter(|identity| codex.identity_conflicts.contains(identity.as_str()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
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
    pub(in crate::snapshots) fn read(path: &Path, file: &File, offset: u64) -> Option<Self> {
        refuse_compressed_codex(Some(path), None, CodexZstCause::PhysicalOffsetUnsupported).ok()?;
        let stamp = OpenStamp::capture(file).ok()?;
        if offset == 0 || stamp.extent < offset {
            return None;
        }
        let sample = |start: u64, end: u64| -> Option<String> {
            let mut bytes = vec![0_u8; usize::try_from(end - start).ok()?];
            file.read_exact_at(&mut bytes, start).ok()?;
            Some(format!("{:x}", Sha256::digest(&bytes)))
        };
        let width = SAMPLE_BYTES as u64;
        Some(Self {
            dev: stamp.dev,
            ino: stamp.ino,
            offset,
            head: sample(0, offset.min(width))?,
            boundary: sample(offset.saturating_sub(width), offset)?,
        })
    }
}

/// Which census rule a terminal Codex disclosure follows (K2, the parent's
/// H-3 ruling). The one classification for fresh refusals, memo hits,
/// parked records and any future durable memo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum DebtReason {
    /// A loss-free held ownership refusal (a named terminal reason):
    /// settleable non-progressing residue.
    HeldTerminal,
    /// The job did not fit the state budget: strict, never settleable.
    JoinStateBound,
    /// Repeated invalidations: its counted causes include in-place edits
    /// and dependency changes a later generation can cure, so it is not
    /// clearly terminal and stays strict.
    MemberChanged,
    /// A group whose chain broke in the chronological fallback order its
    /// probe limit forced (round 3): the order may be our own artifact, so
    /// it is strict; parked until a member changes.
    ProbeBudgetOrder,
}
impl HeapLayoutBound for DebtReason {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}

impl DebtReason {
    fn settleable(self) -> bool {
        matches!(self, Self::HeldTerminal)
    }
}

/// What a held singleton disclosed when it was parsed, or the strict debt of
/// a job that ended without a publishable result; a memo hit or parked
/// record discloses exactly this again through `disclose_terminal_codex_debt`.
#[derive(Clone, Debug)]
pub(in crate::snapshots) struct Disclosure {
    pub(in crate::snapshots) reason: DebtReason,
    pub(in crate::snapshots) cause: usize,
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence: bool,
    pub(in crate::snapshots) state_only_blocked_session_ids: Vec<String>,
    pub(in crate::snapshots) diagnostic_reason: FileReason,
    pub(in crate::snapshots) parsed_snapshot_count: usize,
    /// The fresh held parse's line and drop totals, replayed on a hit.
    pub(in crate::snapshots) held: HeldCounts,
    /// The parse's parent request, replayed on a hit (same 256 rule).
    pub(in crate::snapshots) parent_ref: Option<String>,
    /// PR-P: the held child's parent cause, replayed into the census on a
    /// hit (held disclosure only, never proof).
    pub(in crate::snapshots) parent_unresolvable: Option<CodexParentUnresolvable>,
}
crate::heap_layout_bound::fields!(Disclosure; reason, cause, ownership_incomplete_file_count,
    zero_snapshot_usage_evidence, state_only_blocked_session_ids, diagnostic_reason,
    parsed_snapshot_count, held, parent_ref, parent_unresolvable);

/// PR-1: the line and drop totals a fresh held parse adds to the census,
/// replayed on a hit. All inline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct HeldCounts {
    pub(in crate::snapshots) over_line_cap: usize,
    pub(in crate::snapshots) recognized_usage_drop: usize,
    pub(in crate::snapshots) dropped_usage_record: u64,
    /// `ParsedJsonlFile::terminal_line_loss_count`.
    pub(in crate::snapshots) terminal_line_loss: usize,
}
crate::heap_layout_bound::fields!(HeldCounts; over_line_cap, recognized_usage_drop,
    dropped_usage_record, terminal_line_loss);

/// PR-1: what the held classification depended on in its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct ParentDep {
    pub(in crate::snapshots) id: String,
    /// The ledger identity the classification used (`None`: none was used).
    pub(in crate::snapshots) ledger: Option<String>,
    /// The parent's opened identity at record time: the identity the
    /// after-parse fence just proved when a ledger was used, else the probe.
    pub(in crate::snapshots) current: Option<String>,
    /// PR-P: the step-map witness the classification read (`None`: none).
    pub(in crate::snapshots) witnessed: Option<CodexParentUnresolvable>,
}
crate::heap_layout_bound::fields!(ParentDep; id, ledger, current, witnessed);

/// The parent's state at lookup: the index ledger identity, the probe and
/// (PR-P) the step-map witness the classifier would read now.
pub(in crate::snapshots) struct ParentNow {
    pub(in crate::snapshots) ledger: Option<String>,
    pub(in crate::snapshots) current: Option<String>,
    pub(in crate::snapshots) witnessed: Option<CodexParentUnresolvable>,
}

/// Strict debt of a job that ended without a publishable result
/// (`JoinStateBound`, `MemberChanged`): its owner is blocked, the prior body
/// is kept, and the census stays strict. The file was not parsed to
/// completion this cycle, never a read or line loss.
fn strict_disclosure(
    job: &OwnedActiveFile,
    owner: Option<String>,
    reason: DebtReason,
) -> Disclosure {
    let owner = job.parser.accumulator.source_session_id.clone().or(owner);
    Disclosure {
        reason,
        cause: ownership::GROUP,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: owner.into_iter().collect(),
        diagnostic_reason: FileReason::NotParsedThisCycle,
        parsed_snapshot_count: 0,
        held: HeldCounts::default(),
        parent_ref: None,
        parent_unresolvable: None,
    }
}

/// A held singleton's memo entry. No entry expires on a timer (C2); it
/// wakes on cheap changed evidence only: an object change, shrink or
/// same-length stamp change (mtime/ctime) of the held file, a head or
/// boundary sample mismatch at the refused offset, any dependency in the
/// digest (parser, proof and scope versions, reduction dependencies, census
/// flags, owner members, counting view), the parent ledger, or (for every
/// hold but an ambiguous fork) the path's full sidecar facts (K3).
///
/// Premise (disclosed): an in-place interior edit outside the samples that
/// also appends is not detected until the entry is lost (restart, LRU
/// eviction) or a dependency changes. A miss is never treated as proof of
/// uniqueness; it only costs a re-read.
#[derive(Clone, Debug)]
pub(in crate::snapshots) struct MemoEntry {
    digest: String,
    /// Absent for a group refused in a sealed member: growth of the live
    /// member cannot cure it (§d.4).
    live: Option<LiveWitness>,
    /// The held file's stamp when recorded or last matched.
    stamp: OpenStamp,
    /// Parent ref, the ledger identity used, and the parent's opened
    /// identity: a new or changed parent ledger or parent object is peer
    /// evidence that can change the hold.
    parent: Option<ParentDep>,
    /// `sidecar_fingerprint` when recorded, for holds sidecar evidence can
    /// cure (`sidecar_wakes`).
    sidecar: Option<String>,
    /// The hold may be cured by the file catching up with its sidecar
    /// extent (`growth_may_cure`): only the exact recorded stamp is a hit.
    exact_stamp: bool,
    /// This parse produced a `scan_complete` ledger of its own, so a re-read
    /// as a referenced parent would insert it.
    own_ledger: bool,
    disclosure: Disclosure,
    used: u64,
    charge: usize,
}
crate::heap_layout_bound::fields!(MemoEntry; digest, live, stamp, parent, sidecar, exact_stamp,
    own_ledger, disclosure, used, charge);

impl MemoEntry {
    pub(in crate::snapshots) fn new(
        digest: String,
        live: LiveWitness,
        stamp: OpenStamp,
        parent: Option<ParentDep>,
        sidecar: Option<String>,
        disclosure: Disclosure,
    ) -> Self {
        Self::new_group(digest, Some(live), stamp, parent, sidecar, disclosure)
    }

    /// A group's entry (P2): `stamp` is the live member's, `live` its witness
    /// when the refusal was in the live member.
    pub(in crate::snapshots) fn new_group(
        digest: String,
        live: Option<LiveWitness>,
        stamp: OpenStamp,
        parent: Option<ParentDep>,
        sidecar: Option<String>,
        disclosure: Disclosure,
    ) -> Self {
        Self {
            digest,
            live,
            stamp,
            parent,
            sidecar,
            exact_stamp: false,
            own_ledger: false,
            disclosure,
            used: 0,
            charge: 0,
        }
    }

    /// R1-H1: a hold an append can cure never matches a grown file.
    pub(in crate::snapshots) fn growth_may_cure(mut self, growth_may_cure: bool) -> Self {
        self.exact_stamp = growth_may_cure;
        self
    }

    /// This parse produced a `scan_complete` ledger of its own. Always
    /// false for an ownership-incomplete parse today (its ledger is cleared);
    /// a guard should that change.
    pub(in crate::snapshots) fn own_ledger(mut self, own_ledger: bool) -> Self {
        self.own_ledger = own_ledger;
        self
    }

    /// PR-P: production bypasses every owed parent's entry (B14); tests
    /// still read the flag.
    #[cfg(test)]
    pub(in crate::snapshots) fn has_own_ledger(&self) -> bool {
        self.own_ledger
    }

    pub(in crate::snapshots) fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }

    pub(in crate::snapshots) fn parent_ref(&self) -> Option<&str> {
        self.parent.as_ref().map(|dep| dep.id.as_str())
    }

    /// Every wake dependency except the stamp holds.
    fn dependencies_hold(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        parent_now: Option<&ParentNow>,
        sidecar_now: &str,
    ) -> bool {
        self.digest == digest
            && self.parent.as_ref().map_or(true, |dep| {
                parent_now.is_some_and(|now| {
                    dep.ledger == now.ledger
                        && dep.current == now.current
                        && dep.witnessed == now.witnessed
                })
            })
            && self
                .sidecar
                .as_deref()
                .map_or(true, |sidecar| sidecar == sidecar_now)
            && self.live.as_ref().map_or(true, |live| {
                LiveWitness::read(path, file, live.offset).as_ref() == Some(live)
            })
    }

    /// Every wake dependency is unchanged, the held file is untouched since
    /// its stamp (or only grew, for a non-exact group entry), and the live
    /// witness still holds. Returns the current stamp on a hit.
    #[cfg(test)]
    pub(in crate::snapshots) fn matches(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        parent_now: Option<&ParentNow>,
        sidecar_now: &str,
    ) -> Option<OpenStamp> {
        let now = OpenStamp::capture(file).ok()?;
        self.matches_stamp(path, digest, file, parent_now, sidecar_now, now)
    }

    pub(in crate::snapshots) fn matches_stamp(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        parent_now: Option<&ParentNow>,
        sidecar_now: &str,
        now: OpenStamp,
    ) -> Option<OpenStamp> {
        let stamp_holds = if self.exact_stamp {
            self.stamp == now
        } else {
            self.stamp.wake_compatible(&now)
        };
        (stamp_holds && self.dependencies_hold(path, digest, file, parent_now, sidecar_now))
            .then_some(now)
    }

    /// L-2: an exact entry whose file only grew while every other wake input
    /// held (the re-read a counted tail would save): the current extent.
    pub(in crate::snapshots) fn grew_past_exact(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        parent_now: Option<&ParentNow>,
        sidecar_now: &str,
    ) -> Option<u64> {
        let now = OpenStamp::capture(file).ok()?;
        (self.exact_stamp
            && now.extent > self.stamp.extent
            && self.stamp.wake_compatible(&now)
            && self.dependencies_hold(path, digest, file, parent_now, sidecar_now))
        .then(|| now.extent())
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

    fn remove(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// L-2 gauge: the memo's measured bytes (the per-entry charges). O(entries
    /// <= MEMO_ENTRIES), under the cursor lock already held. The entry count
    /// is `CodexCursorRetained.memo_entries`.
    fn publish_resident(&self) {
        let bytes = self
            .entries
            .values()
            .fold(0_u64, |sum, entry| sum.saturating_add(entry.charge as u64));
        crate::local_resource_diagnostics::codex_memo_lifecycle::set_resident(bytes);
    }
}

/// The memo key for a singleton: parser, identity and proof versions, the
/// file's logical key and opened `{dev, ino}` (never its growing length),
/// the receipt scope, the counting view, and the wake dependencies
/// (path-scoped reduction facts and header witness, the path's conflicted
/// candidate ids, the global sidecar census flags, and how many inventory
/// members its owner has). The upload
/// context and the census flags cannot cure most holds but are kept as
/// conservative wake inputs (K3); their cost is one re-read per held file
/// when they change.
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
        "codex_singleton_memo:v3",
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
        // PR-1: the tier receipt configures the parse
        // (`configure_tier_replay`), contents included.
        &{
            let (receipt, required) = crate::snapshots::codex_file_join::receipt_state(
                index.files.get(&local_index_key(&candidate.path)),
            );
            let receipt = receipt.map_or_else(
                || "none".to_owned(),
                |receipt| {
                    serde_json::to_string(&receipt).unwrap_or_else(|_| "unserializable".to_owned())
                },
            );
            format!("receipt:{required}:{receipt}")
        },
        dependencies,
        // Class 7: an identity conflict on a candidate changes the blocked
        // ids of any hold, sidecar-woken or not.
        &conflicted_identities(codex, &candidate.path),
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

/// The one writer of a terminal Codex disclosure, for fresh refusals, memo
/// hits and parked records alike. A settleable `HeldTerminal` disclosure
/// records exactly what the native finish path records for the same held
/// parse: residue key, blocked owners, ownership-incomplete and zero-usage
/// counts, and an incomplete finalization entry. A strict disclosure
/// (`JoinStateBound`, `MemberChanged`) blocks its owner and keeps the prior
/// body, but is never residue: it keeps the census red as a retryable
/// unreadable file. A different census ruling changes this function only.
pub(in crate::snapshots) struct DisclosureTargets<'a> {
    pub(in crate::snapshots) census: &'a mut ScanCensus,
    pub(in crate::snapshots) residue_index_keys: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) residue_blocked_session_ids: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) codex_state_only_blocked_session_ids: &'a mut BTreeSet<String>,
    pub(in crate::snapshots) pending_finalization: &'a mut Vec<PendingIndexFinalization>,
}

impl DisclosureTargets<'_> {
    /// The same targets for one more disclosure.
    pub(in crate::snapshots) fn reborrow(&mut self) -> DisclosureTargets<'_> {
        DisclosureTargets {
            census: &mut *self.census,
            residue_index_keys: &mut *self.residue_index_keys,
            residue_blocked_session_ids: &mut *self.residue_blocked_session_ids,
            codex_state_only_blocked_session_ids: &mut *self.codex_state_only_blocked_session_ids,
            pending_finalization: &mut *self.pending_finalization,
        }
    }
}

/// Disclose a finished job's strict debt (`JoinStateBound`, `MemberChanged`)
/// through the one writer, keeping the job's prior body.
pub(in crate::snapshots) fn disclose_job_debt(
    job: &OwnedActiveFile,
    disclosure: &Disclosure,
    index: &mut ScanIndex,
    targets: DisclosureTargets<'_>,
) {
    if let Some(group) = job.group.as_ref() {
        codex_file_join::disclose_members(disclosure, &group.members, index, targets);
        return;
    }
    disclose_terminal_codex_debt(
        disclosure,
        &job.candidate,
        (
            job.previous_snapshot_fingerprint.clone(),
            job.previous_upload_body_witness.clone(),
        ),
        index,
        targets,
    );
}

pub(in crate::snapshots) fn disclose_terminal_codex_debt(
    disclosure: &Disclosure,
    candidate: &CandidateFile,
    previous: (Option<String>, Option<String>),
    index: &mut ScanIndex,
    targets: DisclosureTargets<'_>,
) {
    let settleable = disclosure.reason.settleable();
    let index_key = local_index_key(&candidate.path);
    // U1a-2a (cc row 7): this key's latest parse is debt, so its side record
    // (if any) is held, under its own lineage cause. Update only.
    index.refresh_codex_parent_side_held(
        &index_key,
        &codex_parent_path_ids(&candidate.path),
        disclosure.parent_unresolvable.is_some(),
        disclosure
            .parent_unresolvable
            .map_or(CAUSE_NO_EVIDENCE, |cause| cause.index() as u8),
    );
    if settleable {
        targets.residue_index_keys.insert(index_key.clone());
    }
    for session_id in &disclosure.state_only_blocked_session_ids {
        let session_id = resolve_codex_identity(session_id.as_str());
        if settleable {
            targets
                .residue_blocked_session_ids
                .insert(session_id.clone());
        }
        targets
            .codex_state_only_blocked_session_ids
            .insert(session_id.clone());
        index
            .codex_state_only_blocked_session_ids
            .insert(session_id);
    }
    // L-SB: a settleable disclosure is this key's whole latest parse; a
    // strict one keeps the prior body, so it keeps the prior attribution
    // plus its owner.
    let blocked = disclosure
        .state_only_blocked_session_ids
        .iter()
        .map(|session_id| resolve_codex_identity(session_id.as_str()))
        .collect::<BTreeSet<_>>();
    if settleable {
        index.attribute_codex_blocked(&index_key, blocked);
    } else {
        index.extend_codex_blocked_attribution(&index_key, blocked);
    }
    targets.pending_finalization.push(PendingIndexFinalization {
        archive_first_read: false,
        withheld_content: None,
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
    if settleable {
        targets.census.ownership_incomplete_file_count +=
            disclosure.ownership_incomplete_file_count;
        targets
            .census
            .causes
            .add(disclosure.cause, disclosure.ownership_incomplete_file_count);
        targets.census.zero_snapshot_usage_evidence_count +=
            usize::from(disclosure.zero_snapshot_usage_evidence);
        // PR-1: the fresh finish's line and drop totals.
        let held = &disclosure.held;
        targets.census.over_line_cap_count += held.over_line_cap;
        targets.census.recognized_usage_drop_count += held.recognized_usage_drop;
        targets.census.dropped_usage_record_count = targets
            .census
            .dropped_usage_record_count
            .saturating_add(held.dropped_usage_record);
        if held.terminal_line_loss > 0 {
            let loss = held.terminal_line_loss;
            targets.census.terminal_over_line_cap_count = targets
                .census
                .terminal_over_line_cap_count
                .saturating_add(loss);
            targets.census.terminal_recognized_usage_drop_count = targets
                .census
                .terminal_recognized_usage_drop_count
                .saturating_add(loss);
            targets.census.terminal_dropped_usage_record_count = targets
                .census
                .terminal_dropped_usage_record_count
                .saturating_add(loss as u64);
        }
        // PR-1: a memo hit is this child's parent request too (refs are
        // cleared on index reset).
        if let Some(parent) = disclosure.parent_ref.as_deref() {
            index.record_codex_parent_ref(parent);
        }
        // PR-P: the fresh parse's held parent cause, counted again.
        if let Some(cause) = disclosure.parent_unresolvable {
            targets.census.parent_unresolvable.record(cause.index(), 1);
        }
    } else {
        targets
            .census
            .record_unreadable(UnreadableCause::Reduction, 1);
    }
}

#[cfg(test)]
#[path = "codex_cursor_tests.rs"]
pub(in crate::snapshots) mod tests;

#[cfg(all(test, target_os = "macos"))]
mod header_admission_tests {
    use super::*;
    fn populated() -> (PathBuf, Arc<SharedCache>, String) {
        let (root, fixture) = codex_file_join::tests::fixture();
        let paths = fixture
            .headers
            .iter()
            .map(|header| local_index_key(&header.candidate.path))
            .collect::<BTreeSet<_>>();
        let mut inventory = codex_file_join::HeaderInventory::new(
            &[root.join("sessions")],
            &paths,
            Some(&fixture.directories),
        );
        let cache = Arc::new(SharedCache::default());
        while !inventory.step_cached(&CodexTitleMetadata::default(), Some(&cache)) {}
        let key = paths.first().unwrap().clone();
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(&key))
            .flatten()
            .is_some());
        (root, cache, key)
    }
    #[test]
    fn header_byte_admission_stops_below_count_cap() {
        let (root, cache, key) = populated();
        let facts = cache
            .with_cursor(|cursor| cursor.headers.get(&key))
            .flatten()
            .unwrap();
        let mut refused = false;
        for number in 0..codex_file_join::MAX_HEADER_FILES {
            let key = format!("header-{number}");
            cache.refresh_header(key.clone(), Some(facts.clone()));
            if cache
                .with_cursor(|cursor| cursor.headers.get(&key))
                .flatten()
                .is_none()
            {
                refused = true;
                break;
            }
        }
        assert!(refused, "byte-full must refuse below the roster count cap");
        assert!(cache
            .with_cursor(|cursor| state_for_main(cursor))
            .flatten()
            .is_some());
        // Real cursor reservations still succeed by dropping optional facts.
        let credit = cache
            .cursor_reserve(8 * 1024 * 1024)
            .expect("native progress wins");
        assert!(cache
            .with_cursor(|cursor| cursor.headers.is_empty())
            .unwrap());
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn over_budget_facts_yield_for_native_admission_but_hopeless_claims_keep_them() {
        let (root, cache, key) = populated();
        assert!(with_test_state_budget(0, || cache.cursor_reserve(1024)).is_none());
        assert!(cache
            .with_cursor(|cursor| cursor.headers.get(&key))
            .flatten()
            .is_some());
        cache
            .with_cursor(|cursor| {
                let facts = cursor.headers.get(&key).unwrap();
                // Model a resident graph that became full after caching headers.
                for number in 0..codex_file_join::MAX_HEADER_FILES {
                    cursor
                        .headers
                        .refresh(format!("header-{number}"), Some(facts.clone()));
                }
                assert!(state_for_main(cursor).is_none(), "starvation precondition");
            })
            .unwrap();
        let credit = cache
            .cursor_reserve(1024)
            .expect("headers cannot strand a cursor");
        assert!(cache
            .with_cursor(|cursor| cursor.headers.is_empty())
            .unwrap());
        credit.refund();
        assert_eq!(cache.cursor_reserved(), 0);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn optional_proof_can_reclaim_header_room() {
        let (root, cache, key) = populated();
        let mut retained = cache.retained().unwrap();
        cache
            .with_cursor(|cursor| {
                let facts = cursor.headers.get(&key).unwrap();
                for number in 0..codex_file_join::MAX_HEADER_FILES {
                    cursor
                        .headers
                        .refresh(format!("header-{number}"), Some(facts.clone()));
                }
                assert!(!proof_free_room(&retained, cursor, 1024));
                assert!(admit_locked(
                    &mut retained,
                    cursor,
                    1024,
                    false,
                    Admitter::Proof
                ));
                assert!(cursor.headers.is_empty());
            })
            .unwrap();
        drop(retained);
        fs::remove_dir_all(root).unwrap();
    }
}
