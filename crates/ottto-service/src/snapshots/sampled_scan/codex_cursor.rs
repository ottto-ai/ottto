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
use super::{state_bytes, SharedCache};
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
/// A live cursor job's copy-budget charge is walked again after this many
/// consumed bytes: at most 16 walks per page (B / 4 MiB), plus the
/// pause and completion walks, against one per line before.
pub(in crate::snapshots) const CHARGE_REFRESH_BYTES: u64 = 4 * 1024 * 1024;
/// Consecutive invalidated attempts of one file after which its attempt ends
/// as strict `MemberChanged` debt. Growth never invalidates: appended
/// bytes belong to the next tail; unavailable evidence never counts (K9).
const MEMBER_CHANGED_AFTER: u32 = 3;
const INVALIDATION_KEYS: usize = 64;
const PARKED_KEYS: usize = 64;
/// The paused reader buffer keeps at least this much capacity.
const PAUSED_BUFFER_BYTES: usize = 64 * 1024;
const MEMO_ENTRIES: usize = 256;
/// Bytes one memo lookup or record reads from the held file (head and
/// boundary samples). Charged to the page's singleton budget.
pub(in crate::snapshots) const SAMPLE_READ_BYTES: u64 = 2 * SAMPLE_BYTES as u64;
/// A paused job is stale, and another namespace may evict it, once this many
/// cursor pages passed without its own namespace resuming it (K10).
const NAMESPACE_STALE_PAGES: u64 = 16;
/// A paused job whose revalidation evidence stays unavailable for this
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
/// Bumped when a join or singleton proof rule changes; it is part of every
/// memo key, so a bump wakes every memoized hold without a timed retry.
pub(in crate::snapshots) const CODEX_JOIN_PROOF_VERSION: &str = "codex_join_proof:v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct Limits {
    cursor: u64,
    singleton: u64,
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
        }
    }

    /// Files above this size are read by the cursor, never as one pass.
    pub(in crate::snapshots) fn singleton(&self) -> u64 {
        self.singleton
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
    _skip_chunk: usize,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_LIMITS.with(|limits| limits.set(None));
        }
    }
    TEST_LIMITS.with(|limits| limits.set(Some(Limits { cursor, singleton })));
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
    state_bytes()
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
    /// Process counters at this scan's page tick: the start of its
    /// diagnostics window (`SharedCache::cursor_diagnostics`). Boxed so the
    /// by-value scan object stays small.
    window_start: Option<Box<Counters>>,
    /// Resume-only frame: no selection.
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
    disabled_disclosed, page_noted, resume_claimed, window_start, continuation,
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
/// (`SharedCache::cursor_plan_paced`): the file as opened now.
#[derive(Clone, Copy)]
pub(in crate::snapshots) struct PaceProbe<'a> {
    pub(in crate::snapshots) file: &'a File,
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
/// durable authority. A refusal never resets it; byte pages and continuation
/// wall-work bound admission of the next archive.
#[derive(Clone, Debug, Default)]
pub(crate) struct ArchivePass {
    pub(crate) started: bool,
    pub(crate) work: u64,
    pub(crate) power: bool,
    /// Continuation's platform gates; a pass and its pages share them.
    pub(crate) gates: crate::snapshot_sync::ArchiveGates,
    pub(crate) dirty: bool,
    pub(crate) prepared: bool,
    pub(crate) headers_prepared: bool,
    pub(crate) deferred: std::collections::BTreeSet<String>,
}
crate::heap_layout_bound::split_fields!(ArchivePass;
    inline: [started, work, power, dirty, prepared, headers_prepared];
    heap: [deferred]; shared: [gates]);

impl ArchivePass {
    /// A new ordinary pass: fresh counters and the prepare-time power gate;
    /// the cached-archive walk position and the gates carry over.
    pub(crate) fn prepare(&mut self) {
        let Self {
            started,
            work,
            power,
            gates,
            ..
        } = self;
        (*started, *work) = (false, 0);
        *power = gates.power_ready();
    }

    /// Archive work may start now: prepare-time and live power, the pass's
    /// wall work (continuation's contention threshold), and `remaining`
    /// page bytes.
    pub(crate) fn ready(&self, remaining: u64) -> bool {
        self.power && remaining > 0 && crate::snapshot_sync::archive_work_ready(self.work)
    }
}

impl PageBudget {
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

    /// Continue a paid archive without resetting the page's other claims.
    pub(in crate::snapshots) fn continue_singleton(&mut self) {
        self.singleton_decoded = 0;
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

    /// At most one resume attempt per scan object: true only the first
    /// time. A deferred job is never resumed again in the same page.
    pub(in crate::snapshots) fn claim_resume(&mut self) -> bool {
        !std::mem::replace(&mut self.resume_claimed, true)
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
    /// staleness counts ordinary pages only.
    pub(in crate::snapshots) fn note_page(&mut self, cache: &SharedCache) {
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
            self.window_start = cache.with_cursor(|cursor| {
                cursor.rotation.page = cursor.rotation.page.saturating_add(1);
                let start = Box::new(cursor.counters);
                cursor.counters.deferred_next_generation = cursor
                    .counters
                    .deferred_next_generation
                    .saturating_add(self.next_generation_hints);
                start
            });
        }
    }
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
crate::durable_tail_codec::durable_struct!(OpenStamp {
    N dev: u64,
    N ino: u64,
    N extent: u64,
    N modified: (i64, i64),
    N changed: (i64, i64),
});

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
    pub(in crate::snapshots) fn matches_acquisition(
        &self,
        stamp: &crate::transcript_acquisition::FileStamp,
    ) -> bool {
        stamp.same_listing(self.dev, self.ino, self.extent, self.modified)
    }
    pub(in crate::snapshots) fn same_content(&self, other: &Self) -> bool {
        self == other
    }
    /// Device, inode, length and modified time, for the stored head.
    pub(in crate::snapshots) fn parts(&self) -> (u64, u64, u64, (i64, i64)) {
        (self.dev, self.ino, self.extent, self.modified)
    }
    pub(in crate::snapshots) fn from_parts(
        dev: u64,
        ino: u64,
        extent: u64,
        modified: (i64, i64),
    ) -> Self {
        Self {
            dev,
            ino,
            extent,
            modified,
        }
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
    /// `append_compatible`, which never compares ctime.
    pub(in crate::snapshots) fn wake_compatible(&self, now: &Self) -> bool {
        self.same_object(now) && (now.extent > self.extent || self == now)
    }

    pub(in crate::snapshots) fn extent(&self) -> u64 {
        self.extent
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
        // stays within the existing state_bytes() admission; failure leaves
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
                if charge.is_some_and(|charge| admit_locked(&mut retained, cursor, charge, false)) {
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

/// The charge estimate from a walked `(charge, consumed, buffer)`; see `charge_estimate`.
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

/// A job charged by bytes like a cursor job: any cursor job, and a
/// group job read in one page. Its state is walked with
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

/// The charge estimate of a byte-charged job, if its last walk is recent.
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

/// The position charge of one member swap: `MEMBER_SWAP_CHARGE` plus the
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

/// The job's input position for the estimate: the reader's `consumed`, plus the bytes
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
    /// The certificate refused as `Lossy` alone, after a
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
    /// Consecutive resume pages whose evidence was unavailable.
    unavailable_resumes: u32,
    /// The last walked copy-budget charge, the reader position and the
    /// reader buffer capacity it was taken at (see `charge_estimate`).
    charge: Option<(usize, u64, usize)>,
    /// This read's withheld final record was applied at a genuine
    /// unchanged EOF on its completion step (`apply_eof_record`).
    eof_applied: bool,
    /// Stage 1 guard (§6): this attempt's pacing facts, inline.
    pace: JobPace,
}
crate::heap_layout_bound::fields!(JobMeta; key, namespace, stamp_open, started, dependencies,
    owner, counting, fence, census_trusted, pages, unavailable_resumes, charge, eof_applied,
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

// A key, two `Instant`s, a `Duration` and a flag: nothing on the heap.
crate::heap_layout_bound::no_heap!(true; JobPace);

/// A `Duration` held inline (no heap), for the page's ordinary equivalent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct InlineDuration(std::time::Duration);

crate::heap_layout_bound::no_heap!(true; InlineDuration);

/// An `Instant` held inline (no heap), for a continuation page's deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct InlineInstant(std::time::Instant);

crate::heap_layout_bound::no_heap!(true; InlineInstant);

/// The counting view of `candidate`'s index entries (K8): what a fresh
/// singleton parser would be configured with now. Recorded at job start,
/// recomputed from the current entries at every resume and at emission.
/// `"legacy"` while the counting cutover is inactive.
pub(in crate::snapshots) fn counting_view(candidate: &CandidateFile, index: &ScanIndex) -> String {
    crate::snapshots::codex_counting_version::singleton_view(candidate, index)
}

/// A group's counting view (#603): what
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

/// A group job's `scope_job`: the join-proof and identity versions.
/// Recorded at job start; a change at any resume or at emission invalidates
/// the job (a paused group never mixes proofs). Settings, capabilities and the
/// replay directive are no input: they apply after the scan.
pub(in crate::snapshots) fn group_scope() -> String {
    sha256_hex(&[
        "codex_group_scope:v2",
        CODEX_JOIN_PROOF_VERSION,
        SnapshotSource::Codex.scan_identity_version(),
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

thread_local! {
    /// Set only for the duration of one `bound_for_main` walk.
    static MAIN_VIEW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Main copy view: omit optional header facts, retaining the usual
/// lock/visit refusal. `copy_budget_step` reclaims headers beside active
/// progress; `retire_headers_beside_copy` reclaims them before copying/shape-F
/// allocation. Measuring alone grants no allocation authority.
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

/// The cursor state's bound as main's admissions measure it.
fn state_for_main(cursor: &CursorState) -> Option<usize> {
    crate::heap_layout_bound::bound(cursor, state_bytes()).filter(|state| *state <= state_bytes())
}

/// `charge` fits beside the whole cursor state and the retained copies,
/// inside `state_budget`. Nothing is released or evicted.
fn free_room(retained: &super::RetainedCache, cursor: &CursorState, charge: usize) -> bool {
    use crate::heap_layout_bound::bound;
    bound(cursor, state_bytes())
        .zip(bound(retained, state_bytes()))
        .and_then(|(state, resident)| {
            state_budget()
                .checked_sub(state)?
                .checked_sub(resident)?
                .checked_sub(charge)
        })
        .is_some()
}

/// The room left for retained copies beside the whole cursor state and
/// `charge`. `None`: even an empty retained cache would not fit.
fn decoder_room(cursor: &CursorState, charge: usize) -> Option<usize> {
    use crate::heap_layout_bound::bound;
    let state = bound(cursor, state_bytes())?;
    let floor = bound(&super::RetainedCache::default(), state_bytes())?;
    let room = state_budget().checked_sub(state)?.checked_sub(charge)?;
    (room >= floor).then_some(room)
}

/// A decoder's claim, under both locks. An owed archive decode is mandatory
/// work, so it may displace recomputable cache: header facts first, then
/// retained copies. It never drops a join owner or durable owed state. If
/// the claim cannot fit, nothing is evicted.
fn admit_decoder(
    retained: &mut super::RetainedCache,
    cursor: &mut CursorState,
    charge: usize,
) -> bool {
    if free_room(retained, cursor, charge) {
        return true;
    }
    reclaim_headers(cursor, true, |cursor| {
        decoder_room(cursor, charge).is_some()
    });
    decoder_room(cursor, charge).is_some_and(|room| retained.release_until(room))
}

/// Declares `Counters`: the logged events (`codex_cursor_events!`, in log key
/// order), then the RAM-only counters.
macro_rules! cursor_counters {
    ($($(#[$doc:meta])* $event:ident,)+) => {
        /// Content-free RAM counters. They reach the scan's one completion log
        /// record through `SharedCache::cursor_diagnostics`.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub(in crate::snapshots) struct Counters {
            $($(#[$doc])* pub(in crate::snapshots) $event: u64,)+
            /// Largest `now - due` of an `audit_overdue` completion, in seconds.
            pub(in crate::snapshots) audit_overdue_max_age_seconds: u64,

        }
        crate::heap_layout_bound::fields!(Counters; $($event,)+ audit_overdue_max_age_seconds);
    };
}
crate::local_resource_diagnostics::codex_cursor_events!(cursor_counters);

/// A `JoinStateBound` file waits here until its object or reduction
/// dependencies change. Its job ran out of a build constant
/// (`state_bytes()`) while reading a prefix that only grows, so an append
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

// Fixed slots of keys, `Instant`s, `OpenStamp`s and offsets.
crate::heap_layout_bound::no_heap!(true; PaceTable);

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

/// One owner's L-1 provenance: (LRU tick, member keys joined by '\0').
type JoinProvenance = (u64, String);

static NEXT_CURSOR_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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
    parked: BTreeMap<String, Parked>,
    rotation: Rotation,
    counters: Counters,
    /// Stage 1 guard (§6): huge keys' last attempts (inline, never walked).
    pace: PaceTable,
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
            parked: BTreeMap::new(),
            rotation: Rotation::default(),
            counters: Counters::default(),
            pace: PaceTable::default(),
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
            parked,
            rotation,
            counters,
            // Stage 1 guard: inline slots and deadline, no heap; charged once
            // through this state's `size_of_val` (`bound`).
            pace: _,
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
        parked.heap_bound(c)?;
        rotation.heap_bound(c)?;
        counters.heap_bound(c)
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

/// A committed attempt awaiting the native finish. It counts as
/// certified or uncertified only once `finish` succeeded.
#[must_use]
pub(in crate::snapshots) struct Publication {
    certified: bool,
    /// `now - due` when it certified at or after its audit deadline.
    overdue_age: Option<u64>,
    /// This read's withheld final record was applied at genuine EOF.
    eof_applied: bool,
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
    /// publishes only through the same-object identity proof
    /// (`FinishGrant::LossySameObject`), revalidated in `finish`.
    Uncertified {
        grown: bool,
        publication: Publication,
        fragment: Option<SealedFragment>,
    },
    /// Nothing from this attempt is published or committed and its path
    /// stays pending: a necessary invalidation (replacement, shrink,
    /// same-size edit, held-FD sample mismatch, unknown witness, dependency
    /// or counting change; counted), a tail past its audit deadline, or
    /// unavailable evidence (K9); the last two are uncounted.
    Restart,
    /// The attempt was invalidated `MEMBER_CHANGED_AFTER` times in a row:
    /// disclose this strict debt and release the path.
    MemberChanged(Disclosure),
}

/// The paused job's requested-layout charge (K1, N3): the whole job walked
/// with `completed_bound` (live source-wide inputs already removed), so every
/// collection element (turn-key witnesses, usage hours, capability buckets)
/// gets its own visit budget and the job is limited by bytes (`state_bytes()`)
/// alone, never by the walk's visit limit. A pause is a completion-only
/// composition: it runs once per page, never per line. None when the witness
/// map is absent (a job that could never revalidate) or the charge exceeds
/// `state_bytes()`.
pub(in crate::snapshots) fn paused_charge(job: &OwnedActiveFile) -> Option<usize> {
    job.parser
        .accumulator
        .codex_observed_priority_turns
        .as_ref()?;
    crate::heap_layout_bound::completed_bound(job, state_bytes())
}

/// The pause walk is the resumed page's starting copy-budget charge:
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
/// its salvage was already taken); the charge then walks the actual resulting capacity, which the
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

/// Stage 1: add one resumed page's ordinary-equivalent time to its
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
    /// Lock order: the pause site holds no lock here. The lease is a
    /// slot token, not a lock; `accelerated` reads the job's own flag; the one
    /// `with_cursor` below takes only the cursor lock, with neither the
    /// retained lock held, and calls no locking helper inside
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

    /// What a ready ticket's paused singleton reads from its page's join
    /// evidence: its path, its owner and whether its ownership header is
    /// decided. None for a group or a
    /// ticket that is not ready. No IO.
    pub(in crate::snapshots) fn paused_singleton(
        &self,
        ticket: &CodexCursorTicket,
    ) -> Option<(PathBuf, Option<String>, bool)> {
        self.with_cursor(|cursor| {
            let job = ready_job(cursor, ticket)
                .ok()
                .filter(|job| job.group.is_none())?;
            Some((
                job.candidate.path.clone(),
                job.cursor.as_ref()?.owner.clone(),
                job.parser.accumulator.codex_ownership_boundary
                    != CodexOwnershipBoundary::Undetermined,
            ))
        })?
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
    // The EOF record is applied on the completion step, before the protected-tier gate
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
    // A group's receipts and replay are bound to its start scope.
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
    // Under an untrusted census the scope follows census completeness,
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
    // #630 review: a hold an append may cure is memoized on the held
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
    // A lossy job's identity proof covers only a completed
    // traversal of the frozen extent, ending on a record boundary, whose loss
    // is parse/salvage loss main publishes. A read failure, an unfinished
    // read or a withheld record gets no proof, and an EOF-applied record
    // keeps strict finish identity.
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
        // An uncertified job grants it only through the same-object proof,
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
        .set_extent_limit(frozen.min(stamp_open.extent).saturating_sub(start));
    meta.stamp_open = stamp_open;
    meta.started = super::now_seconds();
    // The replay's own completion step decides the EOF record again.
    meta.eof_applied = false;
    true
}

/// On the cursor job's completion step and
/// before the protected-tier replay gate, as main applies its
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

/// The EOF-apply predicate: a withheld record not yet applied, the held FD exactly
/// the opened object (dev, ino, length, mtime, ctime) and the read at that
/// length.
///
/// ctime stays here on purpose: an applied record gives up the S12
/// grant for main's strict finish identity, whose opened-object digest
/// still hashes ctime. Comparing content only would turn a ctime-only
/// change into a finish refusal and a restart instead of a withheld record.
/// It moves with that digest.
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

/// The EOF apply for a group job's live member: `eof_record_due`, the member
/// still exactly its `boot` object (so strict finish identity holds against
/// its boot identity), and a record main's trailing-line rule applies
/// without loss (`apply_physical_line`: within the line cap, UTF-8, blank
/// or one JSON value). A group refuses any line loss, so a
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
        && reader.sealed_fragment.is_some()
        && std::str::from_utf8(bytes).is_ok_and(|line| {
            line.trim().is_empty() || serde_json::from_str::<serde_json::Value>(line).is_ok()
        })
}

/// The withheld record was applied: the job gets no S12 grant.
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

/// M-1 `scope_job` of a group, with its wake dependencies (§d.4): identity
/// and proof versions, owner, canonical member keys, every sealed
/// member's opened identity and the live member's `{dev, ino}` (never its
/// growing length), header digests, counting view, each
/// member's path reduction facts and the census flags.
pub(in crate::snapshots) fn group_memo_digest(
    owner: &str,
    members: &[&CandidateFile],
    live: &OpenStamp,
    digests: &[&str],
    index: &ScanIndex,
    codex: &CodexTitleMetadata,
    identity: impl Fn(&CandidateFile) -> String,
) -> String {
    let mut parts = vec![
        "codex_group_memo:v2".to_owned(),
        CODEX_JOIN_PROOF_VERSION.to_owned(),
        SnapshotSource::Codex.scan_identity_version().to_owned(),
        owner.to_owned(),
        group_counting_view(members.iter().copied(), index),
        format!("{}:{}", live.dev, live.ino),
        if members
            .iter()
            .any(|member| codex.created_thread_census_incomplete_for(&member.path))
        {
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
// Never account from encode/write. May reclaim headers and retained copies when
// the claim fits (`admit_decoder`): no primary floor or owed-state eviction.
static DECODER_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(in crate::snapshots) struct DecoderOwner(Option<CursorCredit>);
impl DecoderOwner {
    pub(in crate::snapshots) fn acquire(cache: &Arc<SharedCache>, bytes: usize) -> Option<Self> {
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

/// Whether `charge` fits in `state_budget` beside the least the state and
/// the retained cache can measure after every eviction `admit_locked` may
/// make: the empty retained cache's own bound (`release_until`'s floor) and,
/// for `mandatory`, the state without its join provenance (an empty map;
/// bounds are additive per field). False: no eviction can make room, so none
/// may run.
fn admission_feasible(cursor: &CursorState, charge: usize, mandatory: bool) -> bool {
    use crate::heap_layout_bound::bound;
    let state = state_for_main(cursor).and_then(|state| {
        if !mandatory {
            return Some(state);
        }
        let empty = BTreeMap::<String, JoinProvenance>::new();
        let forgettable = bound(&cursor.join_owners, state_bytes())?
            .checked_sub(bound(&empty, state_bytes())?)?;
        state.checked_sub(forgettable)
    });
    let floor = bound(&super::RetainedCache::default(), state_bytes());
    state
        .zip(floor)
        .and_then(|(state, floor)| {
            state_budget()
                .checked_sub(state)?
                .checked_sub(charge)?
                .checked_sub(floor)
        })
        .is_some()
}

/// K6 admission of `charge` more cursor bytes, under both locks (retained,
/// then cursor): measure the cursor state (outstanding claims included),
/// then release least-recently-useful retained copies until they fit beside
/// it, all inside `state_budget`. If even an empty retained cache does not
/// fit, `mandatory` (a paused job: baseline progress) may then forget join
/// provenance, which is optional and only keeps its owner blocked; optional
/// admissions never take room that way. Nothing is evicted unless the
/// admission is first proved feasible (`admission_feasible`): a hopeless
/// charge (a `JoinStateBound` pause, an optional claim inside the
/// empty-retained floor) keeps every retained copy and provenance entry.
/// Unsupported accounting, overflow or no room: false, nothing admitted. The
/// loop measures the state at most `JOIN_OWNERS` + 1 times: once per
/// provenance entry, and once more to admit.
fn admit_locked(
    retained: &mut super::RetainedCache,
    cursor: &mut CursorState,
    charge: usize,
    mandatory: bool,
) -> bool {
    let needed = !cursor.headers.is_empty() && !free_room(retained, cursor, charge);
    reclaim_headers(cursor, needed, |cursor| {
        admission_feasible(cursor, charge, mandatory)
    });
    if !admission_feasible(cursor, charge, mandatory) {
        return false;
    }
    loop {
        let Some(state) = state_for_main(cursor) else {
            return false;
        };
        let room = state_budget()
            .checked_sub(state)
            .and_then(|room| room.checked_sub(charge));
        if room.is_some_and(|room| retained.release_until(room)) {
            return true;
        }
        // Even an empty retained cache did not fit beside the state (or the
        // state alone left no room): only a mandatory charge goes on, one
        // forgotten provenance entry at a time (at most `JOIN_OWNERS`).
        if !mandatory || !evict_oldest_join_owner(cursor) {
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
    cursor.headers.optional_bytes()
}

// Header facts are only scalar/string graphs. Use the shared field walker
// and budget on portable builds too; native cursor admission keeps its existing
// layout-supported gate. Opaque or over-visit resident graphs refuse caching.
fn header_room(retained: &super::RetainedCache, cursor: &CursorState, charge: usize) -> bool {
    let mut c = Counter::new(state_budget());
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
        incoming: &crate::transcript_cache::Taken<super::CachedJsonlReduction>,
        live: usize,
        rank: (i64, i64),
    ) -> usize {
        self.with_cursor(|cursor| {
            let reservation = |cursor: &CursorState| {
                live.saturating_add(state_for_main(cursor).unwrap_or(state_bytes()))
            };
            let needed = !cursor.headers.is_empty()
                && !retained.insertion_fits(
                    key,
                    &incoming.retained,
                    reservation(cursor),
                    rank,
                    false,
                );
            reclaim_headers(cursor, needed, |cursor| {
                retained.insertion_fits(key, &incoming.retained, reservation(cursor), rank, true)
            });
            reservation(cursor)
        })
        .unwrap_or(state_bytes())
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
    fn cursor_claim(self: &Arc<Self>, charge: usize, decoder: bool) -> Option<CursorCredit> {
        let mut retained = self.retained().ok()?;
        let claimed = self
            .with_cursor(|cursor| {
                let admitted = if decoder {
                    // The real primary tail floor stays free beside the decoder.
                    charge
                        .checked_add(super::ENTRY_BYTES)
                        .is_some_and(|with_floor| admit_decoder(&mut retained, cursor, with_floor))
                } else {
                    admit_locked(&mut retained, cursor, charge, true)
                };
                if !admitted {
                    return None;
                }
                cursor.reserved = cursor.reserved.checked_add(charge)?;
                Some(cursor.id)
            })
            .flatten();
        drop(retained);
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
    /// and invalidation records). An unbounded state reads as the whole
    /// budget.
    #[cfg(test)]
    pub(super) fn cursor_resident(&self) -> usize {
        self.with_cursor(|cursor| crate::heap_layout_bound::bound(&*cursor, state_bytes()))
            .flatten()
            .unwrap_or(state_bytes())
    }

    /// Clear the optional header facts when they exceed `room` (retained,
    /// then cursor): at each copy-budget step, and before main allocates
    /// against its copy budget (`retire_headers_beside_copy`).
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

    /// The release room, under the caller's retained lock, in
    /// one cursor critical section (retained, then cursor; nothing relocks).
    /// The room is main's: `state_bytes()` less `state_for_main` and
    /// `pinned`. Header facts are reclaimed first, only where
    /// `reachable(room)` can then be met. Nothing mandatory (main's state, a
    /// reservation) is touched. None, with nothing dropped: the cursor lock
    /// is poisoned, main's state is unbounded, the room is short, or
    /// `reachable` refuses it.
    pub(super) fn release_room_for_main(
        &self,
        retained: &super::RetainedCache,
        pinned: usize,
        reachable: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        self.with_cursor(|cursor| {
            let room = |cursor: &CursorState| {
                state_bytes()
                    .checked_sub(state_for_main(cursor)?)?
                    .checked_sub(pinned)
            };
            let needed = !room(cursor)
                .zip(crate::heap_layout_bound::bound(retained, state_bytes()))
                .is_some_and(|(room, copies)| copies <= room);
            reclaim_headers(cursor, needed, |cursor| {
                room(cursor).is_some_and(&reachable)
            });
            room(cursor).filter(|room| reachable(*room))
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
        macro_rules! window_deltas {
            ($($(#[$doc:meta])* $event:ident,)+) => {
                CodexCursorEvents { $($event: d(|c| c.$event)),+ }
            };
        }
        Some(Box::new(CodexCursorCounts {
            during_scan_window: crate::local_resource_diagnostics::codex_cursor_events!(
                window_deltas
            ),
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
    /// Its members are not processed again.
    pub(in crate::snapshots) fn group_fenced(
        &self,
        namespace: &Scope,
        key: &str,
        fence: Option<&str>,
    ) -> bool {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| cursor.rotation.fenced(&key, fence))
            .unwrap_or(false)
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
            if !admit_locked(&mut retained, cursor, charge, false) {
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
    /// that lookup before the cursor-slot check.
    pub(in crate::snapshots) fn group_recorded(&self, namespace: &Scope, key: &str) -> bool {
        let memo_key = memo_key(namespace, key);
        self.with_cursor(|cursor| {
            cursor.memo.entries.contains_key(&memo_key) || cursor.parked.contains_key(key)
        })
        .unwrap_or(false)
    }

    /// A group that read nothing for a job (unchanged, memo hit, parked)
    /// stops waiting for the slot, with no fence and no served update.
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
    #[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
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
    /// completion, a fence, a skip nor a loss.
    /// The file's stamp is read before the cursor lock (no IO under it); an
    /// unreadable stamp plans as today (the start then refuses it).
    #[expect(clippy::too_many_arguments, reason = "11 args; no options struct yet")]
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
        page.note_page(self);
        let paced = pace
            .filter(|_| plan == StartPlan::Cursor && !page.continuation())
            .and_then(|probe| {
                let rev = OpenStamp::capture(probe.file).ok()?;
                Some((pace_key(&namespace.0, &group_scope(), key), rev))
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

                    return StartPlan::Defer;
                }
            }
            plan
        })
        .unwrap_or(plan)
    }

    /// Count a committed attempt once the native finish ran.
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
        let pace_key = pace_key(&namespace.0, &group_scope(), &key);
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
        job.parser.accumulator.codex_priority_witnesses_uncapped = true;
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

                Some(token)
            })
            .flatten()
            .ok_or(StartRefusal::Busy)?;
        let accumulator = &mut job.parser.accumulator;
        accumulator.codex_priority_witnesses_uncapped = true;
        // Resume revalidates every priority decision against the witnesses.
        accumulator
            .codex_observed_priority_turns
            .get_or_insert_with(BTreeMap::new);
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
    /// A continuation page never evicts: it only resumes its
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
    requeue_members(index, flags, [candidate]);
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
    pub(in crate::snapshots) inventory: Option<&'a codex_file_join::HeaderInventory>,
    /// The acquisition scope recomputed under the resuming scan's index.
    pub(in crate::snapshots) scope: Option<Scope>,
    /// `counting_view` recomputed from the resuming scan's index (K8).
    pub(in crate::snapshots) counting: String,
    /// `group_scope` recomputed from the resuming scan's index.
    pub(in crate::snapshots) group_scope: String,
    /// The state and sidecar census are complete now.
    pub(in crate::snapshots) census_complete: bool,
}

/// What the resuming scan supplies to `resume_paused_job`.
pub(in crate::snapshots) struct ResumeContext<'a> {
    pub(in crate::snapshots) source: SnapshotSource,
    pub(in crate::snapshots) sampling: &'a super::Context,
    pub(in crate::snapshots) codex: &'a CodexTitleMetadata,
    pub(in crate::snapshots) claude: &'a ClaudeTitleMetadata,
    pub(in crate::snapshots) support: Option<&'a Path>,
    pub(in crate::snapshots) traces: Option<Arc<CodexTurnTraceMap>>,
    pub(in crate::snapshots) inventory: Option<&'a codex_file_join::HeaderInventory>,
    /// Selection flags of this page's Codex candidates (`requeue`).
    pub(in crate::snapshots) flags: &'a BTreeMap<String, (bool, bool)>,
    /// The state and sidecar census are complete this page.
    pub(in crate::snapshots) census_complete: bool,
    /// Stage 1: this is a continuation page; it never counts toward
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
    // A path that no longer names the held object (archived, renamed,
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
        )
        .map(|dependency| sampling.file_scope(context.source, &job.candidate, &dependency))
    });
    // A group's counting view is built over every member.
    let counting = job_counting_view(&job, index);
    let verdict = revalidate(
        &mut job,
        ResumeInputs {
            codex: context.codex,
            claude: context.claude,
            support: context.support,
            traces: context.traces,
            inventory: context.inventory,
            scope,
            counting,
            group_scope: group_scope(),
            census_complete: context.census_complete,
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
        // consecutive ordinary pages. A continuation page only defers:
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

/// End a resumed job whose evidence cannot become available: free the
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
/// this cycle's traces installed, every priority decision
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
    ) else {
        return Resume::Unavailable;
    };
    // Under an untrusted census (at start or now) the dependency
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
    let Some(inventory) = inputs.inventory.filter(|inventory| inventory.complete) else {
        return Resume::Unavailable;
    };
    let members = inventory
        .headers
        .iter()
        .filter(|header| Some(&header.owner) == meta.owner.as_ref())
        .count();
    if meta.owner.is_some() && members > 1 {
        // A continuation appeared: the owner is now a group, never a singleton.
        return Resume::Changed;
    }
    revalidate_decisions(job, inputs.traces)
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
    let Some(inventory) = inputs.inventory.filter(|inventory| inventory.complete) else {
        return Resume::Unavailable;
    };
    let current = inventory
        .headers
        .iter()
        .filter(|header| header.owner == group.owner && header.home == group.home)
        .map(|header| local_index_key(&header.candidate.path))
        .collect::<BTreeSet<_>>();
    let members = group
        .members
        .iter()
        .map(|member| local_index_key(&member.path))
        .collect::<BTreeSet<_>>();
    if current != members {
        // A member appeared or vanished: another job.
        return Resume::Changed;
    }
    let traces = inputs.traces;
    if let Some(group) = job.group.as_mut() {
        group.reinstall_tee_inputs(traces.clone());
    }
    revalidate_decisions(job, traces)
}

/// What this cycle's traces say about a read's earlier priority decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum PriorityDecisions {
    Hold,
    /// Absent or incomplete traces cannot prove a decision changed.
    Unavailable,
    Changed,
}

/// The one comparison of earlier priority decisions with current traces,
/// shared by a paused job's resume and a Tail load's LIVE install.
pub(in crate::snapshots) fn priority_decisions(
    observed: &BTreeMap<String, bool>,
    traces: Option<&Arc<CodexTurnTraceMap>>,
) -> PriorityDecisions {
    if traces.is_none() && observed.values().any(|priority| *priority) {
        return PriorityDecisions::Unavailable;
    }
    let decisions_hold = observed.iter().all(|(turn, priority)| {
        *priority == traces.is_some_and(|traces| traces.is_priority_turn(turn))
    });
    if decisions_hold {
        PriorityDecisions::Hold
    } else if traces.is_some_and(|traces| traces.is_incomplete()) {
        // R2-H1: a failed or capped trace load cannot prove a decision
        // changed; the read waits for complete evidence.
        PriorityDecisions::Unavailable
    } else {
        PriorityDecisions::Changed
    }
}

/// Every priority decision so far still holds under this cycle's traces;
/// then this cycle's traces are installed.
fn revalidate_decisions(
    job: &mut OwnedActiveFile,
    traces: Option<Arc<CodexTurnTraceMap>>,
) -> Resume {
    let Some(observed) = job
        .parser
        .accumulator
        .codex_observed_priority_turns
        .as_ref()
    else {
        return Resume::Changed;
    };
    match priority_decisions(observed, traces.as_ref()) {
        PriorityDecisions::Hold => {}
        PriorityDecisions::Unavailable => return Resume::Unavailable,
        PriorityDecisions::Changed => return Resume::Changed,
    }
    job.parser.accumulator.codex_turn_traces = traces;
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
/// parentless missing-projection hold and #635's unbound
/// `AmbiguousFork` hold. Memo eligibility only; admission is unchanged.
pub(in crate::snapshots) fn growth_may_cure(accumulator: &SnapshotAccumulator) -> bool {
    accumulator.codex_created_thread_native_only
}

/// Memo key: namespace and path, like rotation keys.
pub(in crate::snapshots) fn memo_key(namespace: &Scope, key: &str) -> String {
    rotation_key(&namespace.0, key)
}

/// Every hold except an ambiguous fork (whose sidecar does not decide it)
/// also wakes on sidecar change. When in
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
/// candidate to another at an equal count also wakes. A path with no
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

/// Which census rule a terminal Codex disclosure follows (K2). The one
/// classification for fresh refusals, memo hits,
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
crate::heap_layout_bound::no_heap!(true; DebtReason);

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
}
crate::heap_layout_bound::fields!(Disclosure; reason, cause, ownership_incomplete_file_count,
    zero_snapshot_usage_evidence, state_only_blocked_session_ids, diagnostic_reason,
    parsed_snapshot_count, held);

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
    }
}

/// A held singleton's memo entry. No entry expires on a timer (C2); it
/// wakes on cheap changed evidence only: an object change, shrink or
/// same-length stamp change (mtime/ctime) of the held file, a head or
/// boundary sample mismatch at the refused offset, any dependency in the
/// digest (parser, proof and scope versions, reduction dependencies, census
/// flags, owner members, counting view), or (for every hold but an
/// ambiguous fork) the path's full sidecar facts (K3).
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
    /// `sidecar_fingerprint` when recorded, for holds sidecar evidence can
    /// cure (`sidecar_wakes`).
    sidecar: Option<String>,
    /// The hold may be cured by the file catching up with its sidecar
    /// extent (`growth_may_cure`): only the exact recorded stamp is a hit.
    exact_stamp: bool,
    disclosure: Disclosure,
    used: u64,
    charge: usize,
}
crate::heap_layout_bound::fields!(MemoEntry; digest, live, stamp, sidecar, exact_stamp,
    disclosure, used, charge);

impl MemoEntry {
    pub(in crate::snapshots) fn new(
        digest: String,
        live: LiveWitness,
        stamp: OpenStamp,
        sidecar: Option<String>,
        disclosure: Disclosure,
    ) -> Self {
        Self::new_group(digest, Some(live), stamp, sidecar, disclosure)
    }

    /// A group's entry (P2): `stamp` is the live member's, `live` its witness
    /// when the refusal was in the live member.
    pub(in crate::snapshots) fn new_group(
        digest: String,
        live: Option<LiveWitness>,
        stamp: OpenStamp,
        sidecar: Option<String>,
        disclosure: Disclosure,
    ) -> Self {
        Self {
            digest,
            live,
            stamp,
            sidecar,
            exact_stamp: false,
            disclosure,
            used: 0,
            charge: 0,
        }
    }

    /// A hold an append can cure never matches a grown file.
    pub(in crate::snapshots) fn growth_may_cure(mut self, growth_may_cure: bool) -> Self {
        self.exact_stamp = growth_may_cure;
        self
    }

    pub(in crate::snapshots) fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }

    /// Every wake dependency except the stamp holds.
    fn dependencies_hold(&self, path: &Path, digest: &str, file: &File, sidecar_now: &str) -> bool {
        self.digest == digest
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
        sidecar_now: &str,
    ) -> Option<OpenStamp> {
        let now = OpenStamp::capture(file).ok()?;
        self.matches_stamp(path, digest, file, sidecar_now, now)
    }

    pub(in crate::snapshots) fn matches_stamp(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        sidecar_now: &str,
        now: OpenStamp,
    ) -> Option<OpenStamp> {
        let stamp_holds = if self.exact_stamp {
            self.stamp == now
        } else {
            self.stamp.wake_compatible(&now)
        };
        (stamp_holds && self.dependencies_hold(path, digest, file, sidecar_now)).then_some(now)
    }

    /// L-2: an exact entry whose file only grew while every other wake input
    /// held (the re-read a counted tail would save): the current extent.
    pub(in crate::snapshots) fn grew_past_exact(
        &self,
        path: &Path,
        digest: &str,
        file: &File,
        sidecar_now: &str,
    ) -> Option<u64> {
        let now = OpenStamp::capture(file).ok()?;
        (self.exact_stamp
            && now.extent > self.stamp.extent
            && self.stamp.wake_compatible(&now)
            && self.dependencies_hold(path, digest, file, sidecar_now))
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
            crate::heap_layout_bound::bound(&(key.clone(), entry.clone()), state_bytes())
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

/// The memo key for a singleton: identity and proof versions, the
/// file's logical key and opened `{dev, ino}` (never its growing length),
/// the counting view, and the wake dependencies (path-scoped reduction facts
/// and header witness, the path's conflicted candidate ids, the global sidecar
/// census flags, and how many inventory members its owner has). The census
/// flags cannot cure most holds but are kept as conservative wake inputs
/// (K3); their cost is one re-read per held file when they change. No setting
/// or capability wakes a held file.
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
        "codex_singleton_memo:v4",
        CODEX_JOIN_PROOF_VERSION,
        SnapshotSource::Codex.scan_identity_version(),
        &local_index_key(&candidate.path),
        &stamp.dev.to_string(),
        &stamp.ino.to_string(),
        counting,
        // PR-1: the tier receipt configures the parse
        // (`configure_tier_replay`), contents included.
        &{
            let (receipt, required) = crate::snapshots::codex_file_join::receipt_state(
                index.files.get(&local_index_key(&candidate.path)),
            );
            let receipt =
                receipt.map_or_else(|| "none".to_owned(), |receipt| receipt.parse_input());
            format!("receipt:{required}:{receipt}")
        },
        dependencies,
        // Class 7: an identity conflict on a candidate changes the blocked
        // ids of any hold, sidecar-woken or not.
        &conflicted_identities(codex, &candidate.path),
        if codex.created_thread_census_incomplete_for(&candidate.path) {
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
/// unreadable file. A different census rule changes this function only.
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
    } else {
        targets
            .census
            .record_unreadable(UnreadableCause::Reduction, 1);
    }
}

#[cfg(test)]
#[path = "codex_cursor_tests.rs"]
pub(in crate::snapshots) mod tests;

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
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
    fn optional_admission_can_reclaim_header_room() {
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
                assert!(!free_room(&retained, cursor, 1024));
                assert!(admit_locked(&mut retained, cursor, 1024, false));
                assert!(cursor.headers.is_empty());
            })
            .unwrap();
        drop(retained);
        fs::remove_dir_all(root).unwrap();
    }
}
