//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{Release, TranscriptCache, CACHE_BYTES, CACHE_ENTRIES, ENTRY_BYTES};

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
const STATE_BYTES: usize =
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES;

pub(super) mod codex_cursor;
pub(super) mod side_ledger;

/// The retained-copy cache behind `SharedCache::retained`.
pub(super) type RetainedCache = TranscriptCache<sampled_jsonl::CachedJsonlReduction>;

pub(crate) struct SharedCache {
    inner: Mutex<RetainedCache>,
    /// The resumable Codex job slot and held-singleton memo. Charged once,
    /// here; copy budgets and insert admission see it through this cache.
    cursor: Mutex<codex_cursor::CursorState>,
    /// Codex parent side-request pacing (U1a-2a), process lifetime. A leaf
    /// lock (retained, then cursor, then side; nothing is locked under it).
    /// Charged as the fixed `side_ledger::SIDE_LEDGER_BYTES`, never walked.
    side: Mutex<side_ledger::SideLedger>,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(TranscriptCache::with_byte_limit(STATE_BYTES)),
            cursor: Mutex::new(codex_cursor::CursorState::default()),
            side: Mutex::new(side_ledger::SideLedger::default()),
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
        self.cursor.heap_bound(c)?;
        // Never `side`'s lock: a busy lock would read as unbounded and zero
        // every copy budget. The ledger's whole heap is this proved constant;
        // its inline tables are inside `size_of::<SharedCache>()`, which the
        // caller's `bound` (or `Arc`) charges once (D5′ size test).
        c.add(side_ledger::SIDE_LEDGER_BYTES)
    }
}
impl SharedCache {
    /// The retained-copy lock. Lock order: retained, then cursor, never the
    /// reverse (checked in debug builds).
    pub(super) fn retained(
        &self,
    ) -> std::sync::LockResult<std::sync::MutexGuard<'_, RetainedCache>> {
        debug_assert!(
            !codex_cursor::cursor_held(),
            "retained lock taken under the cursor lock"
        );
        self.inner.lock()
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
    /// U1a-2a D6(e): the cursor state is main's, without a suspended proof;
    /// where the fit is reachable, that proof is retired first, under these
    /// same locks, if the copies overflow beside it, so its bytes count
    /// toward the fit before any copy is evicted (`release_room_for_main`).
    pub(super) fn release_to_fit(&self, pinned: usize) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let floor = crate::heap_layout_bound::bound(&RetainedCache::default(), STATE_BYTES);
        let Some(limit) = self.release_room_for_main(&retained, pinned, |limit| {
            floor.is_some_and(|floor| floor <= limit)
        }) else {
            return false;
        };
        retained.release_until_for(limit, Release::CopyRefusal)
    }
    /// M1 Path A: `release_to_fit`, evicting only retained copies ranked
    /// strictly below `rank`, and only where evicting them makes room;
    /// otherwise nothing, the suspended proof included
    /// (`TranscriptCache::release_older_until`, `older_release_fits`).
    pub(super) fn release_older_to_fit(&self, pinned: usize, rank: (i64, i64)) -> bool {
        let Ok(mut retained) = self.retained() else {
            return false;
        };
        let Some(limit) = self.release_room_for_main(&retained, pinned, |limit| {
            retained.older_release_fits(limit, rank)
        }) else {
            return false;
        };
        retained.release_older_until(limit, rank)
    }
    pub(super) fn take(
        &self,
        key: &str,
    ) -> Option<crate::transcript_cache::Retained<sampled_jsonl::CachedJsonlReduction>> {
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
                // records, outstanding claims) and the side ledger's fixed charge
                // keep their charge: admission may not fill the state budget
                // underneath them. Measured under the retained lock, so every
                // claim made before this insert is seen. The side term is the
                // same constant `heap_bound` adds and cursor admission keeps
                // (`codex_cursor::admission_budget`, F4b). Slice M order: PR-R,
                // then M2, extend this reservation; they keep this term.
                // U1a-2a ss-6: the cursor term is main's (`cursor_resident_for_main`,
                // no suspended proof), so the insert decides as with no proof;
                // the proof is then retired under this same lock if the insert
                // took its room.
                let live_bytes_in = live_bytes;
                let live_bytes = live_bytes
                    .saturating_add(self.cursor_resident_for_main())
                    .saturating_add(side_ledger::SIDE_LEDGER_BYTES);
                cache.insert_reserving(
                    key,
                    crate::transcript_cache::Retained {
                        checkpoint: completed.checkpoint,
                        state,
                    },
                    live_bytes,
                );
                self.drop_suspended_proof_if_over(&cache, live_bytes_in);
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
}
crate::heap_layout_bound::fields!(Active; key, scope, mode, audit_due);

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

    /// U1a-2a (fix round 2, DB1): the room this walk left in main's view
    /// (`bound_for_main`) for the copy budget's two equal shares, a retained
    /// copy and finish/output: `STATE_BYTES - resident - used`, or
    /// `STATE_BYTES - resident` with no active. The same arithmetic
    /// `copy_budget_step` halves, on this walk's own fields (no second
    /// walk; a field would edit M1's unedited test literals). `None`:
    /// unknown. Read only beside this walk's own non-zero budget, which
    /// implies a known room, where that budget is allocated against
    /// (`retire_proof_beside_copy`).
    pub(super) fn room(&self) -> Option<usize> {
        let remaining = STATE_BYTES.checked_sub(self.resident?)?;
        match (self.active, self.used) {
            (_, Some(used)) => remaining.checked_sub(used),
            (None, None) => Some(remaining),
            (Some(_), None) => None,
        }
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
/// makes room for its own copy from older entries only (`admit_tail_copy`).
/// `step` `None` is a caller with no step measurement: the conservative
/// release.
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
        if crate::heap_layout_bound::bound(context, STATE_BYTES).is_some() {
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
            .is_some_and(|resident| resident <= STATE_BYTES)
        {
            return;
        }
        (step.map(|_| 0), Event::ClearFullResidentBoundUnknown)
    } else {
        if step.is_some_and(|step| step.visit_limited()) {
            record(Event::CopyRefusalWalkVisitLimit);
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
        .is_some_and(|total| total <= STATE_BYTES)
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    modified.min((
        i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        i64::from(now.subsec_nanos()),
    ))
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
    // The shared cache's `Arc` payload charge, and the side ledger's fixed
    // charge, which `heap_bound` adds lock-free outside the two locked states
    // (U1a-2a ss-4, F4b).
    let shared = size_of::<SharedCache>()
        .checked_add(align_of::<SharedCache>())?
        .checked_add(2 * size_of::<usize>())?
        .checked_add(side_ledger::SIDE_LEDGER_BYTES)?;
    size_of::<Context>()
        .checked_add(shared)?
        .checked_add(bound(namespace, STATE_BYTES)?)?
        .checked_add(bound(admission, STATE_BYTES)?)
}

/// Whether `context_overhead` plus the two locked states covers
/// `bound(context)` (tests only).
#[cfg(test)]
pub(super) fn context_overhead_covers(context: &Context) -> bool {
    use crate::heap_layout_bound::bound;
    let Some(whole) = bound(context, STATE_BYTES) else {
        return false;
    };
    let Ok(retained) = context.cache.retained() else {
        return false;
    };
    bound(&*retained, STATE_BYTES)
        .zip(context_overhead(context))
        .and_then(|(retained, overhead)| {
            retained
                .checked_add(overhead)?
                .checked_add(context.cache.cursor_resident())
        })
        .is_some_and(|parts| parts >= whole)
}

/// A completing cursor job's exact copy budget (E3), with the same
/// refusal release the step start applies to an ordinary file, and the
/// walk it came from (for `retire_proof_beside_copy`).
pub(super) fn completion_copy_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> (usize, StepMeasure) {
    let (budget, step) = copy_budget_step(sampling, Some(&mut *active), true);
    if budget == 0 {
        release_cache_to_fit(sampling, Some(&*active), step);
    }
    (budget, step)
}

/// U1a-2a (R2-B3, fix round 2 DB1, c22 ruling (b); fix round 3 DM3): main's
/// copy budget funds two shares at once, a retained copy and finish/output
/// (`ClaudeResponses::finish_copy_budget`), so before main allocates
/// against `budget` (its completion's clone and finish), a suspended proof
/// larger than what both shares leave of `step`'s room is retired:
/// `proof + copy + finish/output <= room`, the room main's view
/// (`bound_for_main`) measured without the proof. Both clones admit a copy
/// only within `min(budget, ENTRY_BYTES)` before they allocate it
/// (`retain_reduction`'s `retention_bound`, `retain_sealed_prefix`'s
/// `admitted`), so the copy's share is `min(budget, ENTRY_BYTES)`. The
/// caller passes 0 where its completion cannot retain a copy. Where no copy
/// can be allocated (`budget == 0`, which an unknown room always gives)
/// nothing is retired: no proof drops on unavailable inputs. Non-allocating
/// steps never call this, and M1 Path A (`admit_tail_copy`) clones nothing
/// at its zero-budget step.
pub(super) fn retire_proof_beside_copy(
    sampling: Option<&Context>,
    budget: usize,
    step: StepMeasure,
) {
    if budget == 0 {
        return;
    }
    let Some((context, room)) = sampling.zip(step.room()) else {
        return;
    };
    context
        .cache
        .retire_proof_over_room(room.saturating_sub(copy_shares(budget)));
    #[cfg(test)]
    COPY_RETIRE_PROBE.with(|probe| {
        let whole = crate::heap_layout_bound::bound(context, STATE_BYTES);
        let main = codex_cursor::bound_for_main(context, STATE_BYTES);
        probe.set(Some(CopyRetireProbe {
            proof: whole
                .zip(main)
                .and_then(|(whole, main)| whole.checked_sub(main)),
            resident: step.resident,
            used: step.used.unwrap_or(0),
            budget,
        }))
    });
}

/// U1a-2a (fix round 3, DM3): the finish/output share plus the copy's share,
/// which both clones cap at `ENTRY_BYTES` before they allocate.
fn copy_shares(budget: usize) -> usize {
    budget.saturating_add(budget.min(ENTRY_BYTES))
}

/// Tests only: what `retire_proof_beside_copy` saw right after its retire.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct CopyRetireProbe {
    /// The suspended proof's charge left beside the copy (`bound(context)`
    /// less main's view, measured together, so main's own growth since the
    /// walk cancels).
    pub(super) proof: Option<usize>,
    /// The walk's main-view resident, its active charge and the budget.
    pub(super) resident: Option<usize>,
    pub(super) used: usize,
    pub(super) budget: usize,
}
#[cfg(test)]
impl CopyRetireProbe {
    /// At the clone: the walk's resident + the proof + the active + both
    /// shares (`copy_shares`) fit `STATE_BYTES`.
    pub(super) fn fits(&self) -> bool {
        self.resident
            .zip(self.proof)
            .and_then(|(resident, proof)| {
                resident
                    .checked_add(proof)?
                    .checked_add(self.used)?
                    .checked_add(copy_shares(self.budget))
            })
            .is_some_and(|total| total <= STATE_BYTES)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests only: the last `retire_proof_beside_copy` on this thread.
    static COPY_RETIRE_PROBE: std::cell::Cell<Option<CopyRetireProbe>> =
        const { std::cell::Cell::new(None) };
}

/// Tests only: the last `COPY_RETIRE_PROBE` on this thread, taken.
#[cfg(test)]
pub(super) fn copy_retire_probe() -> Option<CopyRetireProbe> {
    COPY_RETIRE_PROBE.with(std::cell::Cell::take)
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
    // U1a-2a (R2-B3): main's view, any suspended proof charged as none, so
    // optional proof work never shrinks a copy budget. It is no allocation
    // authority either: the walk's `room` goes with the budget, and where
    // main allocates against it the proof is retired first
    // (`retire_proof_beside_copy`, fix round 2 DB1).
    let resident = codex_cursor::bound_for_main(context, STATE_BYTES);
    let remaining = resident.and_then(|resident| STATE_BYTES.checked_sub(resident));
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
        STATE_BYTES
    } else {
        STATE_BYTES.saturating_add(buffer)
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
    let room = remaining
        .zip(used)
        .and_then(|(remaining, used)| remaining.checked_sub(used));
    let budget = room.map_or(0, |room| room / 2);
    (
        budget,
        StepMeasure {
            resident,
            active: optional,
            used,
        },
    )
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
