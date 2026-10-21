//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{Release, TranscriptCache, CACHE_BYTES, CACHE_ENTRIES, ENTRY_BYTES};
use sampled_jsonl::CachedJsonlReduction;

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
const STATE_BYTES: usize =
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES;

pub(super) mod codex_cursor;

#[cfg(test)]
thread_local! {
    static TEST_STATE_BYTES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// `STATE_BYTES`, or this thread's scaled override (tests only).
pub(super) fn state_bytes() -> usize {
    #[cfg(test)]
    if let Some(bytes) = TEST_STATE_BYTES.with(std::cell::Cell::get) {
        return bytes;
    }
    STATE_BYTES
}

/// Scale the state budget (here and in the cursor) and the per-entry limit on
/// this thread for `run` (tests only). Build the `SharedCache` inside `run`.
#[cfg(test)]
pub(super) fn with_test_budgets<T>(state: usize, entry: usize, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_STATE_BYTES.with(|bytes| bytes.set(self.0));
        }
    }
    let _reset = Reset(TEST_STATE_BYTES.with(|bytes| bytes.replace(Some(state))));
    codex_cursor::with_test_state_budget(state, || {
        crate::transcript_cache::with_test_entry_bytes(entry, run)
    })
}

/// The retained-copy cache behind `SharedCache::retained`.
pub(super) type RetainedCache = TranscriptCache<CachedJsonlReduction>;

thread_local! {
    /// This thread holds the retained lock (a `RetainedGuard` is alive).
    /// Lock-order checks read it in debug builds only.
    static RETAINED_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this thread holds the retained lock.
pub(super) fn retained_held() -> bool {
    RETAINED_HELD.with(std::cell::Cell::get)
}

/// The retained-copy lock, marked held for its scope, so a relock on the same
/// thread panics in debug builds instead of hanging. Reset on drop, unwinds
/// included.
pub(super) struct RetainedGuard<'a> {
    guard: std::sync::MutexGuard<'a, RetainedCache>,
}
impl<'a> RetainedGuard<'a> {
    fn new(guard: std::sync::MutexGuard<'a, RetainedCache>) -> Self {
        RETAINED_HELD.with(|held| held.set(true));
        Self { guard }
    }
}
impl Drop for RetainedGuard<'_> {
    fn drop(&mut self) {
        RETAINED_HELD.with(|held| held.set(false));
    }
}
impl std::ops::Deref for RetainedGuard<'_> {
    type Target = RetainedCache;
    fn deref(&self) -> &RetainedCache {
        &self.guard
    }
}
impl std::ops::DerefMut for RetainedGuard<'_> {
    fn deref_mut(&mut self) -> &mut RetainedCache {
        &mut self.guard
    }
}

thread_local! {
    static BLOCKING_RESIDENT_MEASURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// P1-RETAIN R0: while held, this thread's resident walk waits on the
/// retained and cursor locks, one at a time, instead of reading contention as
/// an unbounded resident. Used for a shape-F completion measure only; every
/// other walk keeps `try_lock`. Restored on drop.
pub(super) struct BlockingResidentMeasure(bool);
impl BlockingResidentMeasure {
    pub(super) fn enter() -> Self {
        Self(BLOCKING_RESIDENT_MEASURE.with(|blocking| blocking.replace(true)))
    }
}
impl Drop for BlockingResidentMeasure {
    fn drop(&mut self) {
        BLOCKING_RESIDENT_MEASURE.with(|blocking| blocking.set(self.0));
    }
}

pub(crate) struct SharedCache {
    inner: Mutex<RetainedCache>,
    /// The resumable Codex job slot and held-singleton memo. Charged once,
    /// here; copy budgets and insert admission see it through this cache.
    cursor: Mutex<codex_cursor::CursorState>,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(TranscriptCache::with_byte_limit(state_bytes())),
            cursor: Mutex::new(codex_cursor::CursorState::default()),
        }
    }
}
impl std::fmt::Debug for SharedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedTranscriptCache")
    }
}
impl HeapLayoutBound for SharedCache {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.inner.heap_bound(c)?;
        self.cursor.heap_bound(c)
    }
}
impl SharedCache {
    /// The retained-copy lock. Lock order: retained, then cursor, never the
    /// reverse; never twice on one thread (both checked in debug builds).
    pub(super) fn retained(&self) -> std::sync::LockResult<RetainedGuard<'_>> {
        debug_assert!(
            !codex_cursor::cursor_held(),
            "retained lock taken under the cursor lock"
        );
        debug_assert!(
            !retained_held(),
            "retained lock taken while this thread holds it"
        );
        match self.inner.lock() {
            Ok(guard) => Ok(RetainedGuard::new(guard)),
            Err(poisoned) => Err(std::sync::PoisonError::new(RetainedGuard::new(
                poisoned.into_inner(),
            ))),
        }
    }
    /// Copy-refusal release: evicts retained copies only. The paused cursor
    /// job, the held-singleton memo, parked records and rotation state are
    /// charged and bounded in `heap_bound`, and survive (K6).
    pub(super) fn clear(&self) {
        if let Ok(mut cache) = self.retained() {
            cache.clear();
        } else {
            record(Event::ClearPoisonedLock);
        }
    }
    /// M1: evict retained copies in victim order until they fit the state
    /// budget beside the cursor state and `pinned` bytes, measured under
    /// blocking locks in the one order (retained, then cursor). Usually it
    /// evicts nothing. False, with nothing evicted: the retained lock is
    /// poisoned, the cursor state is unbounded or poisoned, or even an empty
    /// cache would not fit. Evicted copies drop under the retained lock, as
    /// `clear` drops them; no guard or credit drops there, so nothing relocks.
    pub(super) fn release_to_fit(&self, pinned: usize) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let floor = crate::heap_layout_bound::bound(&RetainedCache::default(), state_bytes());
        state_bytes()
            .checked_sub(self.cursor_resident())
            .and_then(|room| room.checked_sub(pinned))
            .filter(|limit| floor.is_some_and(|floor| floor <= *limit))
            .is_some_and(|limit| retained.release_until_for(limit, Release::CopyRefusal))
    }
    /// M1 Path A: `release_to_fit`, evicting only retained copies ranked
    /// strictly below `rank`, and only where evicting them makes room;
    /// otherwise nothing (`TranscriptCache::release_older_until`).
    pub(super) fn release_older_to_fit(&self, pinned: usize, rank: (i64, i64)) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        state_bytes()
            .checked_sub(self.cursor_resident())
            .and_then(|room| room.checked_sub(pinned))
            .is_some_and(|limit| retained.release_older_until(limit, rank))
    }
    pub(super) fn take(
        &self,
        key: &str,
    ) -> Option<crate::transcript_cache::Taken<CachedJsonlReduction>> {
        match self.retained() {
            Ok(mut cache) => cache.take(key),
            Err(_) => {
                record(Event::TakePoisonedLock);
                None
            }
        }
    }
    pub(super) fn retained_sealed_offset(&self, key: &str) -> Option<u64> {
        self.retained().ok()?.sealed_offset(key)
    }
    /// Poison the retained lock from another thread (tests only).
    #[cfg(test)]
    pub(super) fn poison_retained(&self) {
        std::thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _guard = self.inner.lock();
                panic!("poisoning the retained lock (test)");
            });
            assert!(poisoner.join().is_err());
        });
    }
    #[cfg(test)]
    pub(super) fn retained_checkpoint(
        &self,
        key: &str,
    ) -> Option<crate::transcript_acquisition::Checkpoint> {
        self.retained().ok()?.checkpoint(key)
    }
    pub(super) fn insert(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) {
        if let Some(state) = completed.reduction {
            if let Ok(mut cache) = self.retained() {
                // The whole cursor state (paused job, memo, parked and rotation
                // records, outstanding claims) keeps its charge: admission may
                // not fill the state budget underneath it. Measured under the
                // retained lock, so every claim made before this insert is seen.
                // A copy whose R0 release ran is admitted at exactly the rank
                // that release ranked residents against.
                let live_bytes = live_bytes.saturating_add(self.cursor_resident());
                cache.insert_reserving_at_rank(
                    key,
                    crate::transcript_cache::Retained {
                        checkpoint: completed.checkpoint,
                        state,
                    },
                    live_bytes,
                    completed.released,
                );
            } else {
                record(Event::InsertPoisonedLock);
            }
        }
    }
}

pub(super) struct Context {
    pub(super) cache: Arc<SharedCache>,
    pub(super) namespace: Scope,
    pub(super) audit_metadata_supported: bool,
    pub(super) audit_slots: usize,
    pub(super) full_files: usize,
    pub(super) tail_files: usize,
    pub(super) unchanged_files: usize,
    pub(super) native_bytes: u64,
    pub(super) sample_bytes: u64,
    pub(super) full_reasons: [usize; 11],
    pub(super) priority_replays: usize,
    pub(super) audits_started: usize,
    pub(super) audits_completed: usize,
    pub(super) start_overdue_seconds: u64,
    pub(super) completion_overdue_seconds: u64,
    pub(super) admission: crate::local_resource_diagnostics::AcquisitionAdmission,
}
crate::heap_layout_bound::fields!(Context; cache, namespace, audit_metadata_supported, audit_slots,
    full_files, tail_files, unchanged_files, native_bytes, sample_bytes, full_reasons,
    priority_replays, audits_started, audits_completed, start_overdue_seconds,
    completion_overdue_seconds, admission);

pub(super) struct Active {
    pub(super) key: String,
    pub(super) scope: Scope,
    pub(super) mode: ReadMode,
    pub(super) audit_due: Option<u64>,
    /// The taken copy's admitted victim-order hint while this read continues
    /// it (Tail or Unchanged); `None` otherwise. Only a continued copy may
    /// release residents for its own copy (P1-RETAIN R0), and it ranks them
    /// by its re-admission rank (`tail_completion_budget`), not by this hint.
    pub(super) retained_hint: Option<(i64, i64)>,
    /// The finalization charge reserved beside the continued copy at its last
    /// admission (Q-PR13(iii) β); 0 without one.
    pub(super) retained_finalization_charge: usize,
    /// The continued copy's usage witness at its take
    /// (`SnapshotAccumulator::usage_witness`); `None` without one. Q-PR15's
    /// guard compares it at completion.
    pub(super) retained_usage: Option<u64>,
}
crate::heap_layout_bound::fields!(Active; key, scope, mode, audit_due, retained_hint,
    retained_finalization_charge, retained_usage);

impl Context {
    pub(super) fn file_scope(
        &self,
        source: SnapshotSource,
        candidate: &CandidateFile,
        sidecar: &str,
        artifacts: bool,
        context_curve: bool,
        index: &ScanIndex,
    ) -> Scope {
        Scope(sha256_hex(&[
            "sampled_native_reduction:v1",
            &self.namespace.0,
            source.api_slug(),
            source.parser_version(),
            source.scan_identity_version(),
            &local_index_key(&candidate.scan_root),
            &local_index_key(&candidate.path),
            sidecar,
            if artifacts {
                "artifacts"
            } else {
                "no_artifacts"
            },
            if context_curve { "curve" } else { "no_curve" },
            index
                .active_upload_context_fingerprint
                .as_deref()
                .unwrap_or("none"),
            index
                .historical_replay_generation
                .as_deref()
                .unwrap_or("none"),
        ]))
    }
    pub(super) fn record_mode(&mut self, mode: ReadMode, audit_due: Option<u64>) {
        match mode {
            ReadMode::Full(reason) => {
                self.full_files += 1;
                self.full_reasons[reason.slot()] += 1;
                if let Some(due) = audit_due {
                    self.audits_started += 1;
                    self.start_overdue_seconds = self
                        .start_overdue_seconds
                        .max(now_seconds().saturating_sub(due));
                }
            }
            ReadMode::Tail => self.tail_files += 1,
            ReadMode::Unchanged => self.unchanged_files += 1,
        }
    }
    pub(super) fn record_input(&mut self, metrics: crate::transcript_acquisition::ReadMetrics) {
        self.native_bytes = self.native_bytes.saturating_add(metrics.native_bytes);
        self.sample_bytes = self
            .sample_bytes
            .saturating_add(metrics.sample_bytes as u64);
    }
    pub(super) fn complete_audit(&mut self, due: u64) {
        self.audits_completed += 1;
        self.completion_overdue_seconds = self
            .completion_overdue_seconds
            .max(now_seconds().saturating_sub(due));
    }
}

impl OwnedSourceScan {
    pub(crate) fn with_sampled_acquisition(
        mut self,
        cache: Arc<SharedCache>,
        namespace: Scope,
    ) -> Self {
        if matches!(
            self.source,
            SnapshotSource::ClaudeCode | SnapshotSource::Codex
        ) {
            sampled_audit::normalize_marker_storage(&mut self.index);
            let pending = self
                .index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .take(CACHE_ENTRIES + 1)
                .count();
            self.sampling = Some(Context {
                cache,
                namespace,
                audit_metadata_supported: pending <= CACHE_ENTRIES,
                audit_slots: CACHE_ENTRIES.saturating_sub(pending),
                full_files: 0,
                tail_files: 0,
                unchanged_files: 0,
                native_bytes: 0,
                sample_bytes: 0,
                full_reasons: [0; 11],
                priority_replays: 0,
                audits_started: 0,
                audits_completed: 0,
                start_overdue_seconds: 0,
                completion_overdue_seconds: 0,
                admission: Default::default(),
            });
        }
        self
    }
    /// The conservative release: no measurement is supplied, so every shape
    /// but a measured full native baseline still clears (L-A1).
    #[cfg(test)]
    pub(crate) fn release_sampled_cache_for_copy_refusal(&self) {
        release_cache_for_copy_refusal(self.sampling.as_ref(), self.active_file.as_deref(), None);
    }
    /// Charge only optimization-owned native state, samples/keys and copies.
    /// The unchanged serial index/metadata is baseline; parked/proof/send
    /// frames still use their existing aggregate 32MiB allocation/lifetime gate.
    #[cfg(test)]
    pub(super) fn sampled_copy_budget(&mut self) -> usize {
        self.sampled_copy_step().0
    }
    /// The copy budget and the resident bound measured by the same walk.
    #[cfg(test)]
    pub(super) fn sampled_copy_parts(&mut self) -> (usize, Option<usize>) {
        let (budget, step) = self.sampled_copy_step();
        (budget, step.resident)
    }
    /// The copy budget and what the same walk measured (`StepMeasure`).
    pub(super) fn sampled_copy_step(&mut self) -> (usize, StepMeasure) {
        copy_budget_step(
            self.sampling.as_ref(),
            self.active_file.as_deref_mut(),
            false,
        )
    }
}

/// L-A1: an unsampled synchronous native read. Its retained entry, if any,
/// was dropped before the active was built; it owns no acquisition, cursor
/// job, group proof or tee, alias or receipt. Each conjunct is checked even
/// where another implies it today.
fn owns_no_optimization_state(active: &OwnedActiveFile) -> bool {
    active.sampling.is_none()
        && active.cursor.is_none()
        && active.group.is_none()
        && active.aliases.is_empty()
        && active.applied_receipts.is_empty()
        && active.parser.reader.acquisition.is_none()
        && active
            .parser
            .accumulator
            .codex_tier_replay
            .as_ref()
            .map_or(true, |replay| replay.join.is_none())
}

/// P1-RETAIN R0, shape F: a sampled Tail/Unchanged singleton that borrows
/// only its own retained reduction (moved into the parser at prepare) and its
/// plan. Each conjunct is checked even where another implies it today.
pub(super) fn borrows_only_retained_reduction(active: &OwnedActiveFile) -> bool {
    active
        .sampling
        .as_ref()
        .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Tail | ReadMode::Unchanged))
        && !active.comparison_target
        && active.cursor.is_none()
        && active.group.is_none()
        && active.aliases.is_empty()
        && active.applied_receipts.is_empty()
        && active.parser.reader.acquisition.is_some()
        && active
            .parser
            .accumulator
            .codex_tier_replay
            .as_ref()
            .map_or(true, |replay| replay.join.is_none())
}

/// Whether a refusal beside `active` fits the residents to the active's
/// optional charge: not a full native read and not an unsampled one, whose
/// refusal treats their native state as baseline and never uses the charge.
fn refusal_charges_active(active: &OwnedActiveFile) -> bool {
    !active
        .sampling
        .as_ref()
        .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
        && !owns_no_optimization_state(active)
}

/// What one step's budget walk measured, for that step's refusal decision
/// only; never carried to another step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StepMeasure {
    /// The resident bound (`None`: not measured, e.g. a contended
    /// `try_lock`, the visit cap, or over the state budget).
    pub(super) resident: Option<usize>,
    /// The active file's optional charge (`None`: unknown, e.g. it exceeds
    /// the state budget). The walk less the reader's line buffer: a full read
    /// of the same line holds that buffer too, so it is native baseline
    /// (#641, #654), not optional memory. Where the per-step walk hit the
    /// visit cap, the byte walk's (`completed_bound`) charge instead.
    pub(super) active: Option<usize>,
    /// The active's charge in this step's copy budget: its whole walk, line
    /// buffer included (`None`: none, so the budget is zero).
    pub(super) used: Option<usize>,
}
impl StepMeasure {
    /// The active's per-step walk hit the visit cap, so its optional charge
    /// came from the byte walk and the copy budget stays zero (M1 F1).
    fn visit_limited(&self) -> bool {
        self.active.is_some() && self.used.is_none()
    }
}

/// The conservative copy-refusal release, given at most a resident bound and
/// no active charge (L-A1): any active other than a measured native baseline
/// read still clears. `None` supplies no measurement: nothing is re-measured.
/// Production never reaches either branch this way: its step start always
/// supplies a `StepMeasure` with the active's charge (`release_cache_to_fit`).
/// Rows that pass `None`, or a non-exempt active, pin a non-production branch.
#[cfg(test)]
pub(super) fn release_cache_for_copy_refusal(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    measured_resident: Option<usize>,
) {
    release_for_copy_refusal(
        sampling,
        active,
        measured_resident.map(|resident| StepMeasure {
            resident: Some(resident),
            active: None,
            used: None,
        }),
    );
}

/// M1: the copy-refusal release for `sampling` beside `active`, decided on
/// this step's own walk (`step`).
pub(super) fn release_cache_to_fit(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    step: StepMeasure,
) {
    release_for_copy_refusal(sampling, active, Some(step));
}

/// A zero copy budget forbids an optional copy beside the active. It does
/// not by itself mean the residents overflow: the budget is half of what is
/// left, so it is zero whenever the cache is merely full. M1 releases
/// retained copies only where optional memory (residents, cursor state and
/// the active's optional charge) really exceeds the state budget, and then
/// only as many as the overflow needs, in victim order. The whole cache is
/// cleared only where the charge to fit is unknown or cannot fit beside an
/// empty cache; each such clear is counted by its cause. A sampled tail then
/// makes room for its own copy from older entries only (`admit_tail_copy`),
/// except a shape-F singleton (`borrows_only_retained_reduction`), which is
/// released for only at its completion (P1-RETAIN R0, Q-PR14). `step` `None`
/// is a caller with no step measurement: the conservative release.
fn release_for_copy_refusal(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    step: Option<StepMeasure>,
) {
    let Some(context) = sampling else {
        return;
    };
    // A full parser's native accumulator is the unchanged synchronous
    // baseline. Its local layout refusal forbids optional copies, but
    // does not invalidate other already bounded resident reductions.
    // Acquisition/path scratch still uses the separate 1MiB reserve.
    // Borrowed tail state and unsupported audit metadata keep a release.
    let native_full_baseline = active.is_some_and(|active| {
        active
            .sampling
            .as_ref()
            .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
    });
    // The optional charge the residents must fit beside, and the clear's
    // cause where it cannot be fitted (no charge: clear).
    let (charge, cause) = if !context.audit_metadata_supported {
        (None, Event::ClearMetadataUnsupported)
    } else if native_full_baseline {
        if crate::heap_layout_bound::bound(context, state_bytes()).is_some() {
            return;
        }
        (step.map(|_| 0), Event::ClearFullResidentBoundUnknown)
    } else if active.is_none() {
        (step.map(|_| 0), Event::ClearNoActive)
    } else if active.is_some_and(owns_no_optimization_state) {
        // Like a full parser, an unsampled native read is the unchanged
        // synchronous baseline and retains nothing, so its refusal does
        // not invalidate residents this step measured as bounded. This
        // is not a combined native-plus-cache bound.
        if step
            .and_then(|step| step.resident)
            .is_some_and(|resident| resident <= state_bytes())
        {
            return;
        }
        (step.map(|_| 0), Event::ClearFullResidentBoundUnknown)
    } else {
        if step.is_some_and(|step| step.visit_limited()) {
            record(Event::CopyRefusalWalkVisitLimit);
        }
        if active.is_some_and(borrows_only_retained_reduction) {
            // P1-RETAIN R0 (Q-PR14): a sampled Tail/Unchanged singleton
            // (shape F) gets neither `fit_residents` nor Path A here. Its
            // retained reduction was moved into the parser by the destructive
            // take; its copy's only release is at completion, sized exactly,
            // of residents ranked strictly below its copy's re-admission
            // rank, after every non-budget, entry and stamp gate
            // (`tail_completion_budget`). Until then its
            // optional-copy allowance stays zero, and an unknown or
            // unsupported measure there refuses its copy. Nothing is evicted
            // or cleared here, whether or not the residents and its charge
            // already overflow the state budget (disclosed residual (i)).
            return;
        }
        (step.and_then(|step| step.active), Event::ClearOtherActive)
    };
    if let Some(charge) = charge {
        if fit_residents(context, step.and_then(|step| step.resident), charge) {
            if let (Some(active), Some(step), Event::ClearOtherActive) = (active, step, cause) {
                admit_tail_copy(context, active, step, charge);
            }
            return;
        }
    }
    record(cause);
    context.cache.clear();
}

/// Fit the residents beside `charge` within the state budget, evicting only
/// what a real overflow needs. False where they cannot fit even emptied.
fn fit_residents(context: &Context, resident: Option<usize>, charge: usize) -> bool {
    // This step's walk already shows the residents fit beside the charge: a
    // merely full cache. Nothing is released.
    if resident
        .and_then(|resident| resident.checked_add(charge))
        .is_some_and(|total| total <= state_bytes())
    {
        record(Event::CopyRefusalKept);
        return true;
    }
    // An unknown resident (contention, the visit cap, a real overflow) is
    // measured again under blocking locks before anything is evicted.
    if resident.is_none() {
        record(Event::CopyRefusalRemeasured);
    }
    context_overhead(context)
        .and_then(|overhead| overhead.checked_add(charge))
        .is_some_and(|pinned| context.cache.release_to_fit(pinned))
}

/// M1 Path A (review §3c, owner-accepted): at a zero-budget step of a
/// sampled tail, make room for its own copy by evicting, in victim order,
/// only entries ranked strictly older than the tailed file, and only where
/// that makes the copy fit; otherwise nothing. Main's wipe evicted every such
/// entry; a newer entry never yields to an older tail (G3). The room is the
/// next step's copy budget: the active's whole walk plus twice its optional
/// charge, which over-approximates the copy (`retain_reduction` takes half
/// the remainder). The tail's growth after this step is not foreseen, and a
/// zero-budget completion step has already fixed its own budget.
fn admit_tail_copy(context: &Context, active: &OwnedActiveFile, step: StepMeasure, charge: usize) {
    let tail = active
        .sampling
        .as_ref()
        .is_some_and(|sampling| sampling.mode == ReadMode::Tail);
    if !tail || codex_cursor::byte_charged(active) || charge > ENTRY_BYTES {
        return;
    }
    let pinned = step
        .used
        .zip(context_overhead(context))
        .and_then(|(used, overhead)| {
            overhead
                .checked_add(used)?
                .checked_add(charge.checked_mul(2)?)
        });
    if let Some(pinned) = pinned {
        context
            .cache
            .release_older_to_fit(pinned, tail_rank(&active.candidate));
    }
}

/// The tailed file's eviction rank as its re-admission records it: its
/// modification time, clipped to now (`TranscriptCache` clips at admission).
fn tail_rank(candidate: &CandidateFile) -> (i64, i64) {
    let nanos = candidate.modified_unix_nanos;
    let modified = (
        i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX),
        i64::try_from(nanos % 1_000_000_000).unwrap_or_default(),
    );
    crate::transcript_cache::admission_rank(modified, crate::transcript_cache::admission_now())
}

/// `context`'s charge outside its shared cache's two locked states, as
/// `bound(context)` counts it, plus those states' inline layouts, which their
/// own bounds count again: a few hundred bytes over, never under.
fn context_overhead(context: &Context) -> Option<usize> {
    use crate::heap_layout_bound::bound;
    use std::mem::{align_of, size_of};
    // Exhaustive destructuring: a new owned field must be charged here too.
    let Context {
        cache: _,
        namespace,
        audit_metadata_supported: _,
        audit_slots: _,
        full_files: _,
        tail_files: _,
        unchanged_files: _,
        native_bytes: _,
        sample_bytes: _,
        full_reasons: _,
        priority_replays: _,
        audits_started: _,
        audits_completed: _,
        start_overdue_seconds: _,
        completion_overdue_seconds: _,
        admission,
    } = context;
    // The shared cache's `Arc` payload charge.
    let shared = size_of::<SharedCache>()
        .checked_add(align_of::<SharedCache>())?
        .checked_add(2 * size_of::<usize>())?;
    size_of::<Context>()
        .checked_add(shared)?
        .checked_add(bound(namespace, state_bytes())?)?
        .checked_add(bound(admission, state_bytes())?)
}

/// Whether `context_overhead` plus the two locked states covers
/// `bound(context)` (tests only).
#[cfg(test)]
pub(super) fn context_overhead_covers(context: &Context) -> bool {
    use crate::heap_layout_bound::bound;
    let Some(whole) = bound(context, state_bytes()) else {
        return false;
    };
    let Ok(retained) = context.cache.retained() else {
        return false;
    };
    bound(&*retained, state_bytes())
        .zip(context_overhead(context))
        .and_then(|(retained, overhead)| {
            retained
                .checked_add(overhead)?
                .checked_add(context.cache.cursor_resident())
        })
        .is_some_and(|parts| parts >= whole)
}

/// A completing cursor job's exact copy budget (E3), with the same
/// refusal release the step start applies to an ordinary file.
pub(super) fn completion_copy_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> usize {
    let (budget, step) = copy_budget_step(sampling, Some(&mut *active), true);
    if budget == 0 {
        release_cache_to_fit(sampling, Some(&*active), step);
    }
    budget
}

/// The copy budget left beside the active file. A cursor job's state grows
/// past the ordinary walk's visit limit (usage hours, witnesses), so it is
/// charged by bytes like its pause (N3), but never walked per line (E3):
/// mid-job it uses the last walk plus the bytes consumed and the reader
/// buffer growth since (`JobMeta::charge_estimate`, bounded slack corrected
/// at the next walk, at most every `CHARGE_REFRESH_BYTES`); `completing`
/// walks exactly, once, on the step that consumes the budget.
/// This accounting is amortized across the job, not completion-only.
/// Also returns what this walk measured (`StepMeasure`), for the same
/// step's refusal decision only.
pub(super) fn copy_budget_step(
    sampling: Option<&Context>,
    active: Option<&mut OwnedActiveFile>,
    completing: bool,
) -> (usize, StepMeasure) {
    let Some(context) = sampling.filter(|context| context.audit_metadata_supported) else {
        return (0, StepMeasure::default());
    };
    let resident = crate::heap_layout_bound::bound(context, state_bytes());
    let remaining = resident.and_then(|resident| state_bytes().checked_sub(resident));
    let Some(active) = active else {
        let budget = remaining.map_or(0, |remaining| remaining / 2);
        return (
            budget,
            StepMeasure {
                resident,
                active: None,
                used: None,
            },
        );
    };
    let consumed = active.parser.reader.consumed_bytes();
    let buffer = active.parser.reader.buf.capacity();
    let estimate = (!completing)
        .then(|| codex_cursor::job_charge_estimate(active, consumed, buffer))
        .flatten();
    let byte_charged = codex_cursor::byte_charged(active);
    // Every active is walked to the whole state budget, a non-byte-charged
    // one past its line buffer, so a refusal knows its real optional charge
    // (M1; F2 for a byte-charged job). The budget below is unchanged: it
    // still charges the walk against the measured remainder.
    let limit = if byte_charged {
        state_bytes()
    } else {
        state_bytes().saturating_add(buffer)
    };
    // (the budget's charge, the refusal's optional charge)
    let (used, optional) = if let Some(estimate) = estimate {
        // The E3 estimate is charged whole, its buffer growth included.
        (Some(estimate), Some(estimate))
    } else {
        // These native source-wide inputs predate the optimization, are
        // refreshed on reuse, and are absent from every retained copy.
        // All active owned parser/acquisition/path/receipt state stays charged.
        let inputs = active.parser.take_live_reduction_inputs();
        // A group's legacy tee holds the same inputs (P2).
        let tee_inputs = active
            .group
            .as_mut()
            .and_then(|group| group.take_tee_inputs());
        // The walk charges the file itself, as before it was boxed.
        let file: &OwnedActiveFile = active;
        let bound = if byte_charged {
            crate::heap_layout_bound::completed_bound(file, limit)
        } else {
            crate::heap_layout_bound::bound(file, limit)
        };
        // F1: a per-step walk over the visit cap (a long Codex tail's usage
        // hours, keep R2 §2.2) takes the visit-robust byte walk for the
        // refusal's charge only; the copy budget stays zero. It runs only on
        // the steps of such an active, never for a shape whose refusal does
        // not use the charge.
        let visit_limited = if !byte_charged && bound.is_none() && refusal_charges_active(file) {
            crate::heap_layout_bound::completed_bound(file, limit)
        } else {
            None
        };
        active.parser.restore_live_reduction_inputs(inputs);
        if let Some(group) = active.group.as_mut() {
            group.restore_tee_inputs(tee_inputs);
        }
        if byte_charged {
            // The real walk, so the E3 estimate stays usable for the next
            // refusal (F2); `usize::MAX` only where the job alone exceeds
            // the state budget.
            codex_cursor::record_job_charge(active, bound.unwrap_or(usize::MAX), consumed, buffer);
            (bound, bound)
        } else {
            (
                bound,
                bound
                    .or(visit_limited)
                    .map(|bound| bound.saturating_sub(buffer)),
            )
        }
    };
    let budget = remaining
        .zip(used)
        .and_then(|(remaining, used)| remaining.checked_sub(used))
        .map(|remaining| remaining / 2)
        .unwrap_or(0);
    (
        budget,
        StepMeasure {
            resident,
            active: optional,
            used,
        },
    )
}

/// The copy budget a completion hands to retention (P1-RETAIN R0 and its
/// diagnostic packet). No production counter reads the variant.
pub(super) enum RetainBudget {
    /// Admit against `budget` now. The flags say whether the walk behind it
    /// measured the residents and the active file; only refusal
    /// classification reads them.
    Granted {
        budget: usize,
        resident_measured: bool,
        active_measured: bool,
    },
    /// Aliases or an applied receipt: never retained, and not a budget
    /// refusal. `raw` is this completion's pre-release budget.
    TierOrJoinExcluded { raw: usize },
    /// A cursor job with applied bytes outside its certified prefix.
    Unsealed { raw: usize },
    /// Shape F: admit against `budget_after`, and only after `release` has
    /// run, which happens after every non-budget gate (`retain_reduction`).
    Deferred {
        raw: usize,
        budget_after: usize,
        release: DeferredRelease,
    },
}
impl RetainBudget {
    /// A budget whose refusals are outside the packet's buckets (cursor,
    /// group and unsampled completions).
    pub(super) fn granted_unclassified(budget: usize) -> Self {
        Self::Granted {
            budget,
            resident_measured: true,
            active_measured: true,
        }
    }
    /// This completion's pre-release budget.
    pub(super) fn raw(&self) -> usize {
        match self {
            Self::Granted { budget, .. } => *budget,
            Self::TierOrJoinExcluded { raw }
            | Self::Unsealed { raw }
            | Self::Deferred { raw, .. } => *raw,
        }
    }
    /// The finalization copy's limits, taken before this budget moves into a
    /// retention call. Which one applies depends on what retention did
    /// (`FinalizationBudget::after`).
    pub(super) fn finalization(&self) -> FinalizationBudget {
        FinalizationBudget {
            raw: self.raw(),
            released: match self {
                Self::Deferred { budget_after, .. } => Some(*budget_after),
                _ => None,
            },
        }
    }
    /// What a retained copy is admitted against without a deferred release:
    /// excluded and unsealed passes get none.
    pub(super) fn admission_budget(&self) -> usize {
        match self {
            Self::Granted { budget, .. } => *budget,
            Self::TierOrJoinExcluded { .. } | Self::Unsealed { .. } => 0,
            Self::Deferred { budget_after, .. } => *budget_after,
        }
    }
    /// The same budget with any deferred release dropped unrun: `Deferred`
    /// becomes `Granted` at its pre-release budget, so no path that cannot
    /// run the release (a cursor job's sealed prefix) admits against
    /// `budget_after`.
    pub(super) fn without_release(self) -> Self {
        match self {
            Self::Deferred { raw, .. } => Self::granted_unclassified(raw),
            other => other,
        }
    }
    /// The same pre-release budget, excluded from retention.
    pub(super) fn excluded(self) -> Self {
        Self::TierOrJoinExcluded { raw: self.raw() }
    }
    /// The same pre-release budget, unsealed.
    pub(super) fn unsealed(self) -> Self {
        Self::Unsealed { raw: self.raw() }
    }
}
impl From<(usize, StepMeasure)> for RetainBudget {
    fn from((budget, step): (usize, StepMeasure)) -> Self {
        Self::Granted {
            budget,
            resident_measured: step.resident.is_some(),
            active_measured: step.used.is_some(),
        }
    }
}

/// The finalization copy's limit for one completion: its pre-release budget,
/// or `budget_after` once its deferred release has actually run
/// (`CompletedNativeAcquisition::released`). A release that was refused,
/// raced, or never reached leaves the pre-release budget.
#[derive(Clone, Copy, Debug)]
pub(super) struct FinalizationBudget {
    raw: usize,
    released: Option<usize>,
}
impl FinalizationBudget {
    pub(super) fn after(self, released: bool) -> usize {
        match self.released {
            Some(budget_after) if released => budget_after,
            _ => self.raw,
        }
    }
}

/// How a deferred release ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseOutcome {
    /// The prefix was released (or the residents already fit): admit.
    Released,
    /// The residents changed so the lower-ranked prefix no longer covers the
    /// need: nothing evicted, no copy.
    Race,
    /// The retained lock was poisoned or the residents could not be measured:
    /// nothing evicted, no copy.
    Unmeasurable,
}

/// A shape-F completion's release of residents ranked strictly below its
/// copy's re-admission rank, sized at completion for both its clone and its
/// insert (`tail_completion_budget`). It runs at most once, inside
/// `retain_reduction`, after every non-budget gate; anything less than the
/// exact prefix evicts nothing.
pub(super) struct DeferredRelease {
    cache: Arc<SharedCache>,
    /// `R − need`, in the retained cache's bound units.
    target: usize,
    /// The copy's re-admission rank, computed once
    /// (`transcript_cache::admission_rank` of `modified`): only residents
    /// ranked strictly below it leave, and the copy is admitted at exactly it.
    pub(super) rank: (i64, i64),
    /// The source mtime `rank` was computed from (the read plan's stamp). A
    /// checkpoint carrying any other releases nothing.
    pub(super) modified: (i64, i64),
    /// `entry_bytes() − entry_overhead − bound(key)`: the copy's admission
    /// limit, so the insert's entry and key bounds cannot refuse it (e).
    pub(super) entry_limit: usize,
}
impl DeferredRelease {
    /// Re-measure and re-check under the retained lock, then release exactly
    /// the lower-ranked prefix through the cache's one eviction path
    /// (`TranscriptCache::release_older_prefix`, `Release::CopyAdmission`).
    /// A race, a poisoned lock or an unmeasurable cache evicts nothing.
    pub(super) fn execute(self) -> ReleaseOutcome {
        let Ok(mut retained) = self.cache.retained() else {
            return ReleaseOutcome::Unmeasurable;
        };
        let Some(resident) = crate::heap_layout_bound::bound(&*retained, usize::MAX) else {
            return ReleaseOutcome::Unmeasurable;
        };
        let Some(need) = resident.checked_sub(self.target).filter(|need| *need > 0) else {
            return ReleaseOutcome::Released;
        };
        match retained.release_older_prefix(self.rank, need) {
            Some(_) => ReleaseOutcome::Released,
            None => ReleaseOutcome::Race,
        }
    }
}

/// P1-RETAIN R0 at a shape-F completion (a sampled Tail/Unchanged singleton,
/// `borrows_only_retained_reduction`): one exact measure, then whether this
/// copy fits, and whether releasing residents ranked strictly below its
/// re-admission rank would make both its clone and its insert fit.
///
/// The rank (Q-PR14 amendment) is the one this copy is admitted at: its read
/// plan's source mtime (the checkpoint the commit carries), clipped to now
/// as every admission clips (`transcript_cache::admission_rank`). It is
/// computed once, here, and carried unchanged to `execute` and the insert, so
/// no later clock read or mtime change widens which residents may leave;
/// equal or newer ranks never leave. Nothing is mutated here: a feasible
/// release is `Deferred` and runs only after every non-budget gate. This is
/// the shape's only release: the step start releases nothing for it
/// (Q-PR14, `release_for_copy_refusal`).
///
/// The measure is the step walk's (`copy_budget_step`, completing), taken
/// under blocking locks: `A` is the active's whole walk (`StepMeasure::used`)
/// and the room is the state budget less the residents. An unmeasured part
/// (residents, a visit-limited or over-budget active) grants nothing and
/// releases nothing.
///
/// `K = max(C, F_prev)` (Q-PR13(iii) β): the clone charge, or the
/// finalization charge reserved beside the copy at its last admission. The
/// insert's own slot (`ins_extra`) and the active charge `A` are never held at
/// once (`finish` consumes the parser first), so they combine by `max`.
///
/// Q-PR15 (b), a conservative optional-admission refusal: where `K` is the
/// previous finalization charge (`F_prev > C`) and this read added usage
/// (`SnapshotAccumulator::usage_witness` grew since the take), the new
/// finalization copy is predicted not to fit `K`, so no release is deferred
/// and the copy is admitted against `b_ins` only. Both facts are owned before
/// `finish`; no IO, allocation or walk is added. An unchanged or usage-free
/// tail still releases.
pub(super) fn tail_completion_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> RetainBudget {
    // 1. Measure, waiting on the locks.
    let (budget, step) = {
        let _blocking = BlockingResidentMeasure::enter();
        copy_budget_step(sampling, Some(&mut *active), true)
    };
    let measured = RetainBudget::from((budget, step));
    let (Some(context), Some(resident), Some(a)) = (sampling, step.resident, step.used) else {
        return measured;
    };
    let Some(remaining) = state_bytes().checked_sub(resident) else {
        return measured;
    };
    let Some(file) = active.sampling.as_ref() else {
        return measured;
    };
    let continued = file.retained_hint.is_some();
    let finalization_prev = file.retained_finalization_charge;
    let taken_usage = file.retained_usage;
    let key_len = file.key.len();
    let key_bound = crate::heap_layout_bound::bound(&file.key, usize::MAX);
    // 2. The insert-aware budget, computed before the clone charge.
    let Some(slot) = crate::transcript_cache::entry_slot_bytes::<CachedJsonlReduction>(key_len)
    else {
        return RetainBudget::Granted {
            budget: 0,
            resident_measured: true,
            active_measured: true,
        };
    };
    let ins_extra = slot.saturating_sub(
        std::mem::size_of::<CachedJsonlReduction>()
            + std::mem::size_of::<crate::transcript_acquisition::ReadPlan>(),
    );
    // Tests only: `ins_extra > A` does not occur on a supported layout, so
    // the rows that need it set this term (`test_hooks::set_ins_extra`).
    #[cfg(test)]
    let ins_extra = test_hooks::ins_extra().unwrap_or(ins_extra);
    let floor = a.max(ins_extra);
    let b_ins = remaining.checked_sub(floor).map_or(0, |room| room / 2);
    let granted = RetainBudget::Granted {
        budget: b_ins,
        resident_measured: true,
        active_measured: true,
    };
    #[cfg(test)]
    test_hooks::probe(|probe| {
        *probe = test_hooks::Probe {
            a,
            remaining,
            ins_extra,
            b_ins,
            ..test_hooks::Probe::default()
        }
    });
    let Some(clone) = active
        .parser
        .retention_bound(crate::transcript_cache::entry_bytes())
    else {
        return granted;
    };
    let k = clone.max(finalization_prev);
    #[cfg(test)]
    test_hooks::probe(|probe| {
        probe.clone = Some(clone);
        probe.finalization_prev = finalization_prev;
        probe.k = Some(k);
    });
    // Overflow-safe; `None` or 0 means `b_ins >= K` (or an unreachable
    // overflow, admitted only against `b_ins` anyway).
    let Some(need) = k
        .checked_mul(2)
        .and_then(|twice| twice.checked_add(floor))
        .and_then(|total| total.checked_sub(remaining))
        .filter(|need| *need > 0)
    else {
        return granted;
    };
    #[cfg(test)]
    test_hooks::probe(|probe| probe.need = Some(need));
    let Some(entry_limit) = crate::transcript_cache::entry_bytes()
        .checked_sub(crate::transcript_cache::entry_overhead::<
            CachedJsonlReduction,
        >())
        .zip(key_bound)
        .and_then(|(limit, key)| limit.checked_sub(key))
    else {
        return granted;
    };
    // In the entry/key band the insert would refuse it: never release for it.
    if clone > entry_limit {
        return granted;
    }
    // Q-PR15 (b): the conservative finalization guard (see above).
    if finalization_prev > clone
        && taken_usage.is_some_and(|taken| active.parser.accumulator.usage_witness() > taken)
    {
        #[cfg(test)]
        test_hooks::probe(|probe| probe.finalization_guard = true);
        return granted;
    }
    // 3. The re-admission rank, once; only a continued copy with a plan.
    if !continued {
        return granted;
    }
    let Some(modified) = active.parser.planned_modified_hint() else {
        return granted;
    };
    let rank =
        crate::transcript_cache::admission_rank(modified, crate::transcript_cache::admission_now());
    #[cfg(test)]
    test_hooks::probe(|probe| probe.rank = Some(rank));
    // 4. Exact feasibility under the retained lock, without mutating.
    let Ok(retained) = context.cache.retained() else {
        return granted;
    };
    let Some(resident) = crate::heap_layout_bound::bound(&*retained, usize::MAX) else {
        return granted;
    };
    if resident < need || retained.release_prefix(rank, need).is_none() {
        return granted;
    }
    drop(retained);
    RetainBudget::Deferred {
        raw: b_ins,
        budget_after: k,
        release: DeferredRelease {
            cache: Arc::clone(&context.cache),
            target: resident - need,
            rank,
            modified,
            entry_limit,
        },
    }
}

/// Completion hooks and recorders (tests only). Nothing here runs in a
/// production build.
#[cfg(test)]
pub(super) mod test_hooks {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::snapshots) enum Point {
        /// After revalidation, before `retain_reduction`.
        BeforeRetain,
        /// `retain_reduction`'s deferred path, before the stamp gate.
        BeforeStampGate,
        /// After `retain_reduction` returns, before `finish`.
        AfterRetain,
    }

    /// What `tail_completion_budget` measured on its last call.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(in crate::snapshots) struct Probe {
        pub(in crate::snapshots) a: usize,
        pub(in crate::snapshots) remaining: usize,
        pub(in crate::snapshots) ins_extra: usize,
        pub(in crate::snapshots) b_ins: usize,
        pub(in crate::snapshots) clone: Option<usize>,
        pub(in crate::snapshots) finalization_prev: usize,
        pub(in crate::snapshots) k: Option<usize>,
        pub(in crate::snapshots) need: Option<usize>,
        /// Q-PR15's conservative finalization guard refused the release.
        pub(in crate::snapshots) finalization_guard: bool,
        /// The copy's re-admission rank, once computed (step 3).
        pub(in crate::snapshots) rank: Option<(i64, i64)>,
    }

    /// A retention budget as a retention call received it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::snapshots) enum Decision {
        Granted {
            budget: usize,
            resident_measured: bool,
            active_measured: bool,
        },
        TierOrJoinExcluded,
        Unsealed,
        Deferred {
            raw: usize,
            budget_after: usize,
        },
    }

    type Hook = Box<dyn FnMut()>;
    thread_local! {
        static HOOKS: RefCell<Vec<(Point, Hook)>> = RefCell::new(Vec::new());
        static PROBE: RefCell<Probe> = RefCell::new(Probe::default());
        static DECISIONS: RefCell<Vec<Decision>> = const { RefCell::new(Vec::new()) };
        static BUCKETS: RefCell<Vec<super::sampled_jsonl::Bucket>> = const { RefCell::new(Vec::new()) };
        static UNREADABLE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static FINISH_ERRORS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static INS_EXTRA: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    /// Run `hook` each time this thread reaches `point`, until `clear`.
    pub(in crate::snapshots) fn set(point: Point, hook: impl FnMut() + 'static) {
        HOOKS.with(|hooks| hooks.borrow_mut().push((point, Box::new(hook))));
    }

    /// Drop every hook and recorded value on this thread.
    pub(in crate::snapshots) fn clear() {
        HOOKS.with(|hooks| hooks.borrow_mut().clear());
        PROBE.with(|probe| *probe.borrow_mut() = Probe::default());
        DECISIONS.with(|decisions| decisions.borrow_mut().clear());
        BUCKETS.with(|buckets| buckets.borrow_mut().clear());
        UNREADABLE.with(|causes| causes.borrow_mut().clear());
        FINISH_ERRORS.with(|errors| errors.borrow_mut().clear());
        INS_EXTRA.with(|term| term.set(None));
    }

    pub(in crate::snapshots) fn fire(point: Point) {
        // Out of the table while it runs, so a hook may use the cache.
        let mut fired = HOOKS.with(|hooks| {
            let mut hooks = hooks.borrow_mut();
            let (fired, kept) = std::mem::take(&mut *hooks)
                .into_iter()
                .partition::<Vec<_>, _>(|(at, _)| *at == point);
            *hooks = kept;
            fired
        });
        for (_, hook) in &mut fired {
            hook();
        }
        HOOKS.with(|hooks| hooks.borrow_mut().extend(fired));
    }

    pub(in crate::snapshots) fn probe(update: impl FnOnce(&mut Probe)) {
        PROBE.with(|probe| update(&mut probe.borrow_mut()));
    }

    pub(in crate::snapshots) fn last_probe() -> Probe {
        PROBE.with(|probe| *probe.borrow())
    }

    pub(in crate::snapshots) fn record_budget(budget: &super::RetainBudget) {
        let decision = match budget {
            super::RetainBudget::Granted {
                budget,
                resident_measured,
                active_measured,
            } => Decision::Granted {
                budget: *budget,
                resident_measured: *resident_measured,
                active_measured: *active_measured,
            },
            super::RetainBudget::TierOrJoinExcluded { .. } => Decision::TierOrJoinExcluded,
            super::RetainBudget::Unsealed { .. } => Decision::Unsealed,
            super::RetainBudget::Deferred {
                raw, budget_after, ..
            } => Decision::Deferred {
                raw: *raw,
                budget_after: *budget_after,
            },
        };
        DECISIONS.with(|decisions| decisions.borrow_mut().push(decision));
    }

    pub(in crate::snapshots) fn decisions() -> Vec<Decision> {
        DECISIONS.with(|decisions| decisions.borrow().clone())
    }

    pub(in crate::snapshots) fn record_bucket(bucket: super::sampled_jsonl::Bucket) {
        BUCKETS.with(|buckets| buckets.borrow_mut().push(bucket));
    }

    pub(in crate::snapshots) fn buckets() -> Vec<super::sampled_jsonl::Bucket> {
        BUCKETS.with(|buckets| buckets.borrow().clone())
    }

    /// A census unreadable cause, by its `UnreadableCause` ordinal.
    pub(in crate::snapshots) fn record_unreadable(cause: usize) {
        UNREADABLE.with(|causes| causes.borrow_mut().push(cause));
    }

    pub(in crate::snapshots) fn unreadable() -> Vec<usize> {
        UNREADABLE.with(|causes| causes.borrow().clone())
    }

    /// The error chain of a sampled completion's failed `finish`.
    pub(in crate::snapshots) fn record_finish_error(error: &anyhow::Error) {
        FINISH_ERRORS.with(|errors| errors.borrow_mut().push(format!("{error:#}")));
    }

    pub(in crate::snapshots) fn finish_errors() -> Vec<String> {
        FINISH_ERRORS.with(|errors| errors.borrow().clone())
    }

    /// Sets R0's insert term in place of the measured one, until `clear`.
    pub(in crate::snapshots) fn set_ins_extra(term: Option<usize>) {
        INS_EXTRA.with(|ins_extra| ins_extra.set(term));
    }

    pub(in crate::snapshots) fn ins_extra() -> Option<usize> {
        INS_EXTRA.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Pin this thread's scan clock (tests only); `None` restores real time.
#[cfg(test)]
pub(super) fn set_test_now(now: Option<u64>) {
    TEST_NOW.with(|clock| clock.set(now));
}

pub(super) fn now_seconds() -> u64 {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(std::cell::Cell::get) {
        return now;
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub(super) fn compatible_reduction(accumulator: &SnapshotAccumulator) -> bool {
    accumulator.source != SnapshotSource::Codex
        || (accumulator.codex_observed_priority_turns.is_some()
            && accumulator.codex_usage_accounting_complete()
            && lineage_retainable(accumulator))
}

/// Which ownership lineages a retained copy may continue (P1-RETAIN-3).
fn lineage_retainable(accumulator: &SnapshotAccumulator) -> bool {
    // (1) Today's class, unchanged: no fork, no header parent, no sidecar parent.
    let today = !accumulator.codex_is_fork
        && accumulator.codex_parent_session_ref.is_none()
        && accumulator.codex_sidecar_parent.is_none();
    // (2) A fork whose boundary was decided from in-file header fields only:
    // exact_start → Ordinal, history_base → AllLocal, subagent legacy trigger
    // → AllLocal. Not a created thread or sidecar-ambiguous file (native_only),
    // and no parent ledger was read.
    let in_file_fork = accumulator.codex_is_fork
        && !accumulator.codex_created_thread_native_only
        && !accumulator.codex_parent_ledger_consulted
        && matches!(
            accumulator.codex_ownership_boundary,
            CodexOwnershipBoundary::Ordinal { .. } | CodexOwnershipBoundary::AllLocal
        );
    // NativeCreatedThread: false until step 2 (G-CT). Ledger-resolved
    // AwaitingParentPrefix → AllLocal: false until U1a-2.
    today || in_file_fork
}

#[allow(clippy::too_many_arguments)]
pub(super) fn new_source_parser(
    file: File,
    candidate: &CandidateFile,
    source: SnapshotSource,
    metadata: &CodexTitleMetadata,
    traces: Option<Arc<CodexTurnTraceMap>>,
    parents: Option<Arc<Mutex<BTreeMap<String, CodexParentOwnershipLedger>>>>,
    artifacts: bool,
    curve: bool,
    identity_capture: bool,
    index: &ScanIndex,
) -> Result<OwnedJsonlParser> {
    let mut parser = OwnedJsonlParser::new(
        file,
        &candidate.path,
        source,
        match source {
            SnapshotSource::Codex => apply_codex_line,
            SnapshotSource::ClaudeCode => apply_claude_code_line,
            SnapshotSource::Pi => apply_pi_line,
        },
        (source == SnapshotSource::Codex).then_some(metadata),
        traces,
        parents,
        artifacts,
        curve,
    )?;
    parser.accumulator.claude_request_identity_capture = identity_capture;
    if source == SnapshotSource::Codex {
        configure_tier_replay(&mut parser, candidate, index);
        codex_counting_version::configure_singleton(&mut parser, candidate, index);
    }
    Ok(parser)
}
pub(super) fn configure_tier_replay(
    parser: &mut OwnedJsonlParser,
    candidate: &CandidateFile,
    index: &ScanIndex,
) {
    let previous =
        codex_file_join::receipt_state(index.files.get(&local_index_key(&candidate.path)));
    parser.accumulator.codex_tier_replay = Some(codex_file_join::TierReplay::new(
        previous.0,
        previous.1,
        index
            .active_upload_context_fingerprint
            .clone()
            .unwrap_or_default(),
    ));
}

/// Actual path-scoped interpretation dependencies. Decode no provider row here;
/// reuse existing sidecar inventory and bounded owning-header authority.
pub(super) fn reduction_dependencies(
    source: SnapshotSource,
    candidate: &CandidateFile,
    codex: &CodexTitleMetadata,
    claude: &ClaudeTitleMetadata,
    support: Option<&Path>,
) -> Option<String> {
    if source == SnapshotSource::Codex {
        Some(sha256_hex(&[
            "codex_reduction_dependencies:v1",
            &codex.path_reduction_fingerprint(&candidate.path),
            &codex_file_join::header_reduction_witness(candidate).ok()?,
        ]))
    } else {
        let mut scoped = candidate.clone();
        // Claude API/trace evidence is joined freshly after native finish, not
        // retained in the pre-finish transcript accumulator. Keep Desktop and
        // child naming dependencies here; keep usage sidecars in selection.
        let reduction_support = if source == SnapshotSource::ClaudeCode {
            None
        } else {
            support
        };
        prepare_owned_scan_candidate(source, &mut scoped, codex, claude, reduction_support);
        if source == SnapshotSource::ClaudeCode {
            Some(sha256_hex(&[
                "claude_reduction_dependencies:v1",
                &scoped.source_file_fingerprint,
            ]))
        } else {
            Some(scoped.source_file_fingerprint)
        }
    }
}

#[cfg(test)]
#[path = "claude_sidecar_reduction_tests.rs"]
mod claude_sidecar_reduction_tests;

#[cfg(test)]
mod cache_lifecycle_tests {
    use super::*;

    #[test]
    fn cache_lifecycle_poisoned_lock_is_not_reported_as_absent() {
        let cache = SharedCache::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.inner.lock().unwrap();
            panic!("synthetic cache lock poison");
        }));
        assert!(result.is_err());
        let (_, counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
            assert!(cache.take("synthetic").is_none());
            cache.clear();
        });
        assert_eq!(counts.take_poisoned_lock, 1);
        assert_eq!(counts.take_absent, 0);
        assert_eq!(counts.take_hit, 0);
        assert_eq!(counts.clear_poisoned_lock, 1);
        assert_eq!(counts.clear_entries_released, 0);
    }
}
