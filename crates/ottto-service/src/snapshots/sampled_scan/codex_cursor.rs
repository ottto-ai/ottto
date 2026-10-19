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
const CHARGE_REFRESH_BYTES: u64 = 4 * 1024 * 1024;
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
/// Bumped when a join or singleton proof rule changes; it is part of every
/// memo key, so a bump wakes every memoized hold without a timed retry.
const CODEX_JOIN_PROOF_VERSION: &str = "codex_join_proof:v2";

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
}
crate::heap_layout_bound::fields!(PageBudget; cursor_decoded, singleton_decoded,
    disabled_disclosed, page_noted, resume_claimed, window_start);

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

    /// Advance the cursor page clock once per scan object (K7, K10). The
    /// diagnostics window opens under this same lock (no extra lock).
    pub(in crate::snapshots) fn note_page(&mut self, cache: &SharedCache) {
        if !std::mem::replace(&mut self.page_noted, true) {
            self.window_start = cache.with_cursor(|cursor| {
                cursor.rotation.page = cursor.rotation.page.saturating_add(1);
                Box::new(cursor.counters)
            });
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
        Ok(Self::of(&file.metadata()?))
    }

    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            extent: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    /// The object `path` names now, without following a final symlink.
    fn of_path(path: &Path) -> Option<Self> {
        fs::symlink_metadata(path)
            .ok()
            .map(|metadata| Self::of(&metadata))
    }

    /// Same object, no shrink, and no equal-length in-place change. Growth
    /// is compatible: appended bytes are outside the frozen extent.
    pub(in crate::snapshots) fn append_compatible(&self, now: &Self) -> bool {
        self.same_object(now) && (now.extent > self.extent || now == self)
    }

    fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    pub(in crate::snapshots) fn extent(&self) -> u64 {
        self.extent
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

    /// The live job's copy-budget charge without a walk (E3): the last
    /// `completed_bound` plus every byte the reader consumed since plus the
    /// reader buffer's capacity growth since (`buffer` is its capacity now).
    /// Not a strict upper bound: an accumulator collection that regrows can
    /// add more than the bytes that caused it. That slack lasts at most
    /// `CHARGE_REFRESH_BYTES` of input and is corrected by the next walk;
    /// the pause and completion walks are exact. None when no charge is
    /// recorded, the reader restarted, or `CHARGE_REFRESH_BYTES` were
    /// consumed since (the caller walks again: at most one walk per that
    /// many bytes, never one per line). The scanner reads it through
    /// `job_charge_estimate`, which also covers group jobs.
    #[cfg(test)]
    pub(in crate::snapshots) fn charge_estimate(
        &self,
        consumed: u64,
        buffer: usize,
    ) -> Option<usize> {
        estimate_charge(self.charge, consumed, buffer, 1)
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
/// R2-L3): a member swap needs no walk.
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

/// The job's input position for E3: the reader's `consumed`, plus the bytes
/// a group's completed member readers consumed (R2-N4, R2-L3).
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

/// The identity `finish` may accept for a cursor job's grown object. Only
/// `finish_job` sets it (in the reader's `sealed_prefix` slot).
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
    /// The last walked copy-budget charge, the reader position and the
    /// reader buffer capacity it was taken at (E3; see `charge_estimate`).
    charge: Option<(usize, u64, usize)>,
    /// E1: this read's withheld final record was applied at a genuine
    /// unchanged EOF on its completion step (`apply_eof_record`).
    eof_applied: bool,
}
crate::heap_layout_bound::fields!(JobMeta; key, namespace, stamp_open, started, dependencies,
    owner, counting, fence, census_trusted, pages, unavailable_resumes, charge, eof_applied);

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
    crate::snapshots::codex_counting_version::group_view(
        members
            .into_iter()
            .filter_map(|member| index.files.get(&local_index_key(&member.path))),
    )
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
}
crate::heap_layout_bound::fields!(Counters; jobs_started, jobs_paused, jobs_resumed,
    jobs_certified, jobs_uncertified, jobs_invalidated, jobs_member_changed, jobs_state_bound,
    jobs_lost, jobs_deferred_inputs, jobs_start_unstartable, jobs_audit_restarted,
    jobs_finish_failed, jobs_frame_returned, deferred, deferred_rotation,
    deferred_next_generation, namespace_busy, cursor_disabled_unsupported_layout, audit_overdue,
    audit_overdue_max_age_seconds, sealed_fragment_withheld, eof_record_applied,
    jobs_unavailable_ended, memo_hits, memo_records, parked_hits, groups_started,
    group_memo_hits, join_in_progress_members, groups_fenced, probe_bound, join_terminal_debt);

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
    /// Large files waiting for the slot: (first page waited, last page seen).
    waiting: BTreeMap<String, (u64, u64)>,
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

    /// True when no active waiter is ahead of `key`. Order: rank (last
    /// completed attempt, zero if never served), then first page waited
    /// (this page if `key` is not waiting).
    fn turn(&self, key: &str) -> bool {
        let mine = (
            self.rank(key),
            self.waiting.get(key).map_or(self.page, |(first, _)| *first),
        );
        !self.waiting.iter().any(|(other, (first, seen))| {
            other != key
                && self.page.saturating_sub(*seen) < WAITER_ACTIVE_PAGES
                && (self.rank(other), *first) < mine
        })
    }

    fn wait(&mut self, key: &str) {
        let page = self.page;
        self.waiting
            .retain(|_, (_, seen)| page.saturating_sub(*seen) < WAITER_FORGET_PAGES);
        if let Some((_, seen)) = self.waiting.get_mut(key) {
            *seen = page;
            return;
        }
        if self.waiting.len() >= ROTATION_KEYS {
            if let Some(victim) = self
                .waiting
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(key, _)| key.clone())
            {
                self.waiting.remove(&victim);
            }
        }
        self.waiting.insert(key.to_owned(), (page, page));
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

pub(in crate::snapshots) struct CursorState {
    slot: Slot,
    slot_key: Option<String>,
    /// Member keys of the slot's group job (empty for a singleton): selection
    /// skips them while the job exists (§d.1.2 c).
    slot_members: BTreeSet<String>,
    /// Owners B blocked for queued groups, with their compact member keys
    /// (§d.1.3 provenance, L-1). RAM only; bounded.
    join_owners: BTreeMap<String, (u64, Vec<u64>)>,
    /// Requested-layout charge of the paused job, measured when it paused.
    slot_charge: usize,
    /// Cursor page when the paused job last paused or resumed (K10).
    slot_touched: u64,
    next_token: u64,
    /// LRU clock shared by the invalidation and parked records (L1).
    clock: u64,
    memo: SingletonMemo,
    invalidations: BTreeMap<String, (u32, u64)>,
    parked: BTreeMap<String, Parked>,
    rotation: Rotation,
    counters: Counters,
}

impl Default for CursorState {
    fn default() -> Self {
        Self {
            slot: Slot::Empty,
            slot_key: None,
            slot_members: BTreeSet::new(),
            join_owners: BTreeMap::new(),
            slot_charge: 0,
            slot_touched: 0,
            next_token: 1,
            clock: 0,
            memo: SingletonMemo::default(),
            invalidations: BTreeMap::new(),
            parked: BTreeMap::new(),
            rotation: Rotation::default(),
            counters: Counters::default(),
        }
    }
}

impl HeapLayoutBound for CursorState {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        let Self {
            slot,
            slot_key,
            slot_members,
            join_owners,
            slot_charge,
            slot_touched,
            next_token,
            clock,
            memo,
            invalidations,
            parked,
            rotation,
            counters,
        } = self;
        // The paused job was walked once when it paused; its charge stays
        // fixed while it sits here because nothing mutates a paused parser.
        match slot {
            Slot::Empty | Slot::ActiveElsewhere { .. } => c.add(0)?,
            Slot::Paused(_) => c.add(*slot_charge)?,
        }
        slot_key.heap_bound(c)?;
        slot_members.heap_bound(c)?;
        // Owner strings are visited; member keys are inline u64s.
        join_owners.heap_bound(c)?;
        slot_touched.heap_bound(c)?;
        next_token.heap_bound(c)?;
        clock.heap_bound(c)?;
        memo.heap_bound(c)?;
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
    let consumed = job.parser.reader.consumed_bytes();
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
        let admitted = paused_charge(&job).filter(|charge| self.cache.cursor_make_room(*charge));
        let Some(charge) = admitted else {
            job.parser.restore_live_reduction_inputs(inputs);
            if let Some(group) = job.group.as_mut() {
                group.restore_tee_inputs(tee_inputs);
            }
            let owner = job.cursor.as_ref().and_then(|meta| meta.owner.clone());
            let disclosure = strict_disclosure(&job, owner, DebtReason::JoinStateBound);
            self.end(|cursor| {
                cursor.counters.jobs_state_bound += 1;
                if let Some(meta) = job.cursor.as_ref() {
                    cursor.invalidations.remove(&meta.key);
                    let used = cursor.tick();
                    // A group parks under its live member's boot stamp, the
                    // file its lookup opens (R2-H1); sealed members wake it
                    // through the identities in its dependencies.
                    let stamp = job
                        .group
                        .as_ref()
                        .and_then(|group| group.stamps.last())
                        .unwrap_or(&meta.stamp_open)
                        .clone();
                    park(
                        cursor,
                        meta.key.clone(),
                        Parked {
                            stamp,
                            dependencies: meta.dependencies.clone(),
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
        record_paused_charge(&mut job, charge);
        self.store(job, charge, count);
        PauseEnd::Paused
    }

    /// Frame drop (K12): an intact job returns to the slot. A job that no
    /// longer fits is lost; its path is still pending, so it restarts.
    fn return_job(self, mut job: Box<OwnedActiveFile>) {
        shrink_paused_buffer(&mut job.parser.reader.buf);
        drop(job.parser.take_live_reduction_inputs());
        drop(job.group.as_mut().and_then(|group| group.take_tee_inputs()));
        match paused_charge(&job).filter(|charge| self.cache.cursor_make_room(*charge)) {
            Some(charge) => {
                record_paused_charge(&mut job, charge);
                self.store(job, charge, |counters| counters.jobs_frame_returned += 1);
            }
            None => self.end(|cursor| cursor.counters.jobs_lost += 1),
        }
    }

    /// Move the job into the slot this lease holds, then disarm.
    fn store(self, job: Box<OwnedActiveFile>, charge: usize, count: fn(&mut Counters)) {
        let token = self.token;
        let cache = Arc::clone(&self.cache);
        let mut job = Some(job);
        self.end(|cursor| {
            if matches!(cursor.slot, Slot::ActiveElsewhere { token: held } if held == token) {
                cursor.slot = Slot::Paused(job.take().expect("job moved once"));
                cursor.slot_charge = charge;
                cursor.slot_touched = cursor.rotation.page;
                count(&mut cursor.counters);
            }
        });
        if job.is_some() {
            // The slot no longer named this lease (impossible while armed).
            // The path is still pending, so the next page restarts the job.
            cache.with_cursor(|cursor| cursor.counters.jobs_lost += 1);
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
    let update = |cursor: &mut CursorState| match &result {
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
        job.parser.reader.sealed_prefix = frozen_end.map(|extent| {
            FinishGrant::Certified(SealedPrefix {
                dev: meta.stamp_open.dev,
                ino: meta.stamp_open.ino,
                extent,
            })
        });
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
        mark_eof_applied(job);
    }
}

/// E1's predicate: a withheld record not yet applied, the held FD exactly
/// the opened object (dev, ino, length, mtime, ctime) and the read at that
/// length.
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

/// First eight bytes of SHA-256 of a path key: L-1 provenance is matched
/// against the walk's rollout paths through the same digest.
pub(in crate::snapshots) fn compact_key(key: &str) -> u64 {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
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
    FinishGrant::Certified(SealedPrefix {
        dev: meta.stamp_open.dev,
        ino: meta.stamp_open.ino,
        extent,
    })
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
            parts.push(member.opened_object_identity.clone());
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
                    member.opened_object_identity.clone()
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

impl SharedCache {
    fn with_cursor<T>(&self, run: impl FnOnce(&mut CursorState) -> T) -> Option<T> {
        self.cursor.lock().ok().map(|mut cursor| run(&mut cursor))
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
    /// and invalidation records), reserved at insert admission (K6). An
    /// unbounded state reserves the whole budget.
    pub(super) fn cursor_resident(&self) -> usize {
        self.with_cursor(|cursor| crate::heap_layout_bound::bound(&*cursor, STATE_BYTES))
            .flatten()
            .unwrap_or(STATE_BYTES)
    }

    /// Release least-recently-useful retained copies until the cursor state
    /// plus `charge` fits the state budget beside them (K6). False when it
    /// cannot fit even beside an empty retained cache.
    fn cursor_make_room(&self, charge: usize) -> bool {
        let Some(state) = self
            .with_cursor(|cursor| crate::heap_layout_bound::bound(&*cursor, STATE_BYTES))
            .flatten()
        else {
            return false;
        };
        let Some(room) = state_budget()
            .checked_sub(state)
            .and_then(|room| room.checked_sub(charge))
        else {
            return false;
        };
        self.inner
            .lock()
            .is_ok_and(|mut retained| retained.release_until(room))
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

    /// §d.1.3: B blocked `owner` for a queued group of `members`.
    pub(in crate::snapshots) fn record_join_owner(&self, owner: &str, members: &[CandidateFile]) {
        let keys = members
            .iter()
            .map(|member| compact_key(&local_index_key(&member.path)))
            .collect::<Vec<_>>();
        self.with_cursor(|cursor| {
            let used = cursor.tick();
            if !cursor.join_owners.contains_key(owner) && cursor.join_owners.len() >= JOIN_OWNERS {
                // Forgetting the least recent provenance only keeps that owner
                // blocked (today's behavior); it never releases one.
                if let Some(oldest) = cursor
                    .join_owners
                    .iter()
                    .min_by_key(|(_, (used, _))| *used)
                    .map(|(owner, _)| owner.clone())
                {
                    cursor.join_owners.remove(&oldest);
                }
            }
            cursor.join_owners.insert(owner.to_owned(), (used, keys));
        });
    }

    /// L-1: owners whose every recorded member is absent from `present`
    /// (compact keys of the completed walk's rollout paths) and for which
    /// `keep` is false. Their provenance is dropped with the release.
    pub(in crate::snapshots) fn release_join_owners(
        &self,
        present: &BTreeSet<u64>,
        keep: impl Fn(&str) -> bool,
    ) -> Vec<String> {
        self.with_cursor(|cursor| {
            let released = cursor
                .join_owners
                .iter()
                .filter(|(owner, (_, members))| {
                    !keep(owner) && members.iter().all(|member| !present.contains(member))
                })
                .map(|(owner, _)| owner.clone())
                .collect::<Vec<_>>();
            for owner in &released {
                cursor.join_owners.remove(owner);
            }
            released
        })
        .unwrap_or_default()
    }

    /// The disclosure of a parked `JoinStateBound` file that is the same
    /// object, unshrunk and unedited (growth keeps it parked), with the same
    /// reduction dependencies. Anything else wakes it: the record is dropped
    /// and the file is attempted again.
    pub(in crate::snapshots) fn cursor_parked(
        &self,
        key: &str,
        file: &File,
        dependencies: Option<&str>,
    ) -> Option<Disclosure> {
        let now = OpenStamp::capture(file).ok();
        self.with_cursor(|cursor| {
            let used = cursor.tick();
            let parked = cursor.parked.get_mut(key)?;
            if let Some(now) = now.filter(|now| {
                (if parked.exact {
                    parked.stamp == *now
                } else {
                    parked.stamp.append_compatible(now)
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

    /// The group asked for a page of its own (round 3).
    pub(in crate::snapshots) fn group_own_page(&self, namespace: &Scope, key: &str) -> bool {
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| cursor.rotation.own_page.contains_key(&key))
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
    /// file is recorded as waiting.
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
    ) -> StartPlan {
        let plan = page.plan(limits, expected, slot_free, cursor_enabled);
        if !matches!(plan, StartPlan::Cursor | StartPlan::Defer) || expected <= limits.singleton {
            return plan;
        }
        page.note_page(self);
        let key = rotation_key(&namespace.0, key);
        self.with_cursor(|cursor| {
            if cursor.rotation.fenced(&key, fence) {
                cursor.rotation.waiting.remove(&key);
                cursor.counters.deferred_next_generation += 1;
                return StartPlan::Fenced;
            }
            if plan == StartPlan::Cursor && !cursor.rotation.turn(&key) {
                cursor.counters.deferred_rotation += 1;
                cursor.rotation.wait(&key);
                return StartPlan::Defer;
            }
            if plan == StartPlan::Defer {
                cursor.rotation.wait(&key);
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
        let token = self
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
                Some(token)
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
            charge: None,
            eof_applied: false,
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
            charge: None,
            eof_applied: false,
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
    pub(in crate::snapshots) fn cursor_resume(
        self: &Arc<Self>,
        namespace: &Scope,
    ) -> Option<(Box<OwnedActiveFile>, CursorLease)> {
        let (job, token) = self.with_cursor(|cursor| {
            let Slot::Paused(job) = &cursor.slot else {
                return None;
            };
            let foreign = job
                .cursor
                .as_ref()
                .map_or(true, |meta| meta.namespace != namespace.0);
            let live = job.cursor.is_some()
                && cursor.rotation.page.saturating_sub(cursor.slot_touched) < NAMESPACE_STALE_PAGES;
            if foreign {
                if live {
                    cursor.counters.namespace_busy += 1;
                    return None;
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
        })??;
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

/// Release a finished job's path. A watcher hint for a pending path is
/// dropped (`enqueue_watcher_hints`), so writes during the job left no hint;
/// if the file grew past the frozen extent, keep the path as a watcher hint
/// instead, and the next page tails the appended bytes from `s`. A large
/// re-read of it in this generation is `Fenced` (K7), so the census waits
/// for at most that one small tail.
pub(in crate::snapshots) fn release_path(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    grown: bool,
) {
    if !grown {
        dequeue(index, candidate);
        return;
    }
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
            pending.census_member = true;
            pending.watcher_hint = true;
        }
        keep
    });
    if !kept {
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root: candidate.scan_root.clone(),
            path: candidate.path.clone(),
            census_member: true,
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
    let Some((mut job, lease)) = sampling.cache.cursor_resume(&sampling.namespace) else {
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
        },
    );
    let debt = match verdict {
        Resume::Valid => {
            if let Some(meta) = job.cursor.as_mut() {
                meta.unavailable_resumes = 0;
            }
            // This page also selected the job's paths; read them once,
            // through the job, and keep them pending so the census still
            // waits if the job pauses.
            for file in job_files(&job) {
                identified_candidates.retain(|candidate| candidate.path != file.path);
                requeue(index, context.flags, file);
            }
            return Resumed::Active(job, lease);
        }
        // Unavailable evidence is not a member change: the job waits in the
        // slot, its path pending (K9), for at most `UNAVAILABLE_RESUMES`
        // consecutive pages (E2).
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
    revalidate_decisions(job, inputs.traces, inputs.parents)
}

/// The group subset of the revalidation checklist (P2): the member being
/// read is the same object without shrink or in-place edit; every member
/// already read still names exactly its boot object; the group's reduction
/// dependencies, member set and counting view are unchanged; then the
/// singleton's priority-decision and live-input rules.
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
        .any(|(member, stamp)| OpenStamp::of_path(&member.path).as_ref() != Some(stamp));
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
            .map(|live| group_dependencies(&group.members, live, inputs.codex))
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
/// is cured by sidecar evidence, never by an append: it is memoized too, and
/// wakes on any change of the path's full sidecar fingerprint (rollout
/// extent, state row, title and decoration included) or identity conflicts,
/// which the entry records (`sidecar_fingerprint`). Zero accepted usage is
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

/// R1-H1: a parentless created thread held for a missing sidecar projection
/// may be cured by an append, when the sidecar's rollout extent is ahead of
/// the flushed file and the file catches up. Its memo entry hits only on the
/// exact recorded stamp, so any growth re-reads it.
pub(in crate::snapshots) fn growth_may_cure(accumulator: &SnapshotAccumulator) -> bool {
    matches!(
        accumulator.codex_ownership_boundary,
        CodexOwnershipBoundary::NativeCreatedThread
    ) && accumulator.codex_parent_session_ref.is_none()
        && accumulator.codex_sidecar_projected_next_ordinal.is_none()
}

/// Memo key: namespace and path, like rotation keys (R1-M1).
pub(in crate::snapshots) fn memo_key(namespace: &Scope, key: &str) -> String {
    rotation_key(&namespace.0, key)
}

/// Every hold except an ambiguous fork (cured by peer parent evidence, which
/// the entry's parent ledger records) also wakes on sidecar change. When in
/// doubt the sidecar is kept as a wake input (K3).
pub(in crate::snapshots) fn sidecar_wakes(accumulator: &SnapshotAccumulator) -> bool {
    !matches!(
        accumulator.codex_ownership_boundary,
        CodexOwnershipBoundary::AmbiguousFork
    )
}

/// The path's full sidecar facts (K3): the non-reduction sidecar
/// fingerprint (rollout extent `next_byte_offset`/`next_ordinal`, state row
/// `rollout_path`/`created_at`, title, decoration, family) and how many of
/// the path's candidate ids are identity conflicts. Its census flags are in
/// the memo digest.
pub(in crate::snapshots) fn sidecar_fingerprint(codex: &CodexTitleMetadata, path: &Path) -> String {
    let conflicts = codex_session_id_candidates_from_path(path)
        .iter()
        .filter(|identity| {
            codex
                .identity_conflicts
                .contains(resolve_codex_identity(identity.as_str()).as_str())
        })
        .count();
    sha256_hex(&[
        "codex_memo_sidecar:v1",
        &codex.path_sidecar_fingerprint(path),
        &conflicts.to_string(),
    ])
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
    pub(in crate::snapshots) ownership_incomplete_file_count: usize,
    pub(in crate::snapshots) zero_snapshot_usage_evidence: bool,
    pub(in crate::snapshots) state_only_blocked_session_ids: Vec<String>,
    pub(in crate::snapshots) diagnostic_reason: FileReason,
    pub(in crate::snapshots) parsed_snapshot_count: usize,
}
crate::heap_layout_bound::fields!(Disclosure; reason, ownership_incomplete_file_count,
    zero_snapshot_usage_evidence, state_only_blocked_session_ids, diagnostic_reason,
    parsed_snapshot_count);

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
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        state_only_blocked_session_ids: owner.into_iter().collect(),
        diagnostic_reason: FileReason::NotParsedThisCycle,
        parsed_snapshot_count: 0,
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
    /// Parent ref and its ledger identity: a new or changed parent ledger
    /// is peer evidence that can cure an ambiguous-fork hold.
    parent: Option<(String, Option<String>)>,
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
crate::heap_layout_bound::fields!(MemoEntry; digest, live, stamp, parent, sidecar, exact_stamp,
    disclosure, used, charge);

impl MemoEntry {
    pub(in crate::snapshots) fn new(
        digest: String,
        live: LiveWitness,
        stamp: OpenStamp,
        parent: Option<(String, Option<String>)>,
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
        parent: Option<(String, Option<String>)>,
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

    pub(in crate::snapshots) fn disclosure(&self) -> &Disclosure {
        &self.disclosure
    }

    pub(in crate::snapshots) fn parent_ref(&self) -> Option<&str> {
        self.parent.as_ref().map(|(parent, _)| parent.as_str())
    }

    /// Every wake dependency is unchanged, the held file only grew or is
    /// untouched since its stamp, and the live witness still holds at the
    /// refused offset. Growth past that offset is a hit. Returns the current
    /// stamp on a hit.
    pub(in crate::snapshots) fn matches(
        &self,
        digest: &str,
        file: &File,
        parent_ledger: Option<String>,
        sidecar_now: &str,
    ) -> Option<OpenStamp> {
        let now = OpenStamp::capture(file).ok()?;
        let stamp_holds = if self.exact_stamp {
            self.stamp == now
        } else {
            self.stamp.append_compatible(&now)
        };
        (self.digest == digest
            && stamp_holds
            && self
                .parent
                .as_ref()
                .map_or(true, |(_, ledger)| *ledger == parent_ledger)
            && self
                .sidecar
                .as_deref()
                .map_or(true, |sidecar| sidecar == sidecar_now)
            && self.live.as_ref().map_or(true, |live| {
                LiveWitness::read(file, live.offset).as_ref() == Some(live)
            }))
        .then_some(now)
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
/// the receipt scope, the counting view, and the wake dependencies
/// (path-scoped reduction facts and header witness, the global sidecar
/// census flags, and how many inventory members its owner has). The upload
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
    if settleable {
        targets.census.ownership_incomplete_file_count +=
            disclosure.ownership_incomplete_file_count;
        targets.census.zero_snapshot_usage_evidence_count +=
            usize::from(disclosure.zero_snapshot_usage_evidence);
    } else {
        targets
            .census
            .record_unreadable(UnreadableCause::Reduction, 1);
    }
}

#[cfg(test)]
#[path = "codex_cursor_tests.rs"]
mod tests;
