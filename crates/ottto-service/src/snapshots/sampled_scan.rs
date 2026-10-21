//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{TranscriptCache, CACHE_BYTES, CACHE_ENTRIES};

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
const STATE_BYTES: usize =
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES;

pub(super) mod codex_cursor;

/// The retained-copy cache behind `SharedCache::retained`.
pub(super) type RetainedCache = TranscriptCache<sampled_jsonl::CachedJsonlReduction>;

pub(crate) struct SharedCache {
    inner: Mutex<RetainedCache>,
    /// The resumable Codex job slot and held-singleton memo. Charged once,
    /// here; copy budgets and insert admission see it through this cache.
    cursor: Mutex<codex_cursor::CursorState>,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(TranscriptCache::with_byte_limit(STATE_BYTES)),
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
                // records, outstanding claims) keeps its charge: admission may
                // not fill the state budget underneath it. Measured under the
                // retained lock, so every claim made before this insert is seen.
                let live_bytes = live_bytes.saturating_add(self.cursor_resident());
                cache.insert_reserving(
                    key,
                    crate::transcript_cache::Retained {
                        checkpoint: completed.checkpoint,
                        state,
                    },
                    live_bytes,
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
    /// The conservative release: no resident measurement is supplied, so an
    /// unsampled native active still clears (L-A1).
    #[cfg(test)]
    pub(crate) fn release_sampled_cache_for_copy_refusal(&self) {
        release_cache_for_copy_refusal(self.sampling.as_ref(), self.active_file.as_deref(), None);
    }
    /// Charge only optimization-owned native state, samples/keys and copies.
    /// The unchanged serial index/metadata is baseline; parked/proof/send
    /// frames still use their existing aggregate 32MiB allocation/lifetime gate.
    #[cfg(test)]
    pub(super) fn sampled_copy_budget(&mut self) -> usize {
        self.sampled_copy_parts().0
    }
    /// The copy budget and the resident bound measured by the same walk.
    pub(super) fn sampled_copy_parts(&mut self) -> (usize, Option<usize>) {
        copy_budget_parts(
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

/// The copy-refusal release for `sampling` beside `active`.
/// `measured_resident` is the resident bound from this same step's budget
/// walk, used only for this decision; `None` keeps the conservative release.
pub(super) fn release_cache_for_copy_refusal(
    sampling: Option<&Context>,
    active: Option<&OwnedActiveFile>,
    measured_resident: Option<usize>,
) {
    if let Some(context) = sampling {
        // A full parser's native accumulator is the unchanged synchronous
        // baseline. Its local layout refusal forbids optional copies, but
        // does not invalidate other already bounded resident reductions.
        // Acquisition/path scratch still uses the separate 1MiB reserve.
        // Borrowed tail state, unsupported audit metadata and an unbounded
        // resident graph retain the existing conservative release behavior.
        let native_full_baseline = active.is_some_and(|active| {
            active
                .sampling
                .as_ref()
                .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
        });
        if native_full_baseline && context.audit_metadata_supported {
            if crate::heap_layout_bound::bound(context, STATE_BYTES).is_some() {
                return;
            }
            record(Event::ClearFullResidentBoundUnknown);
        } else if !context.audit_metadata_supported {
            record(Event::ClearMetadataUnsupported);
        } else if active.is_none() {
            record(Event::ClearNoActive);
        } else if active.is_some_and(owns_no_optimization_state) {
            // Like a full parser, an unsampled native read is the unchanged
            // synchronous baseline and retains nothing, so its refusal does
            // not invalidate residents this step measured as bounded. This
            // is not a combined native-plus-cache bound.
            if measured_resident.is_some_and(|resident| resident <= STATE_BYTES) {
                return;
            }
            record(Event::ClearFullResidentBoundUnknown);
        } else {
            record(Event::ClearOtherActive);
        }
        context.cache.clear();
    }
}

/// A completing cursor job's exact copy budget (E3), with the same
/// refusal release the step start applies to an ordinary file.
pub(super) fn completion_copy_budget(
    sampling: Option<&Context>,
    active: &mut OwnedActiveFile,
) -> usize {
    let budget = copy_budget_parts(sampling, Some(&mut *active), true).0;
    if budget == 0 {
        release_cache_for_copy_refusal(sampling, Some(&*active), None);
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
/// Also returns the resident bound this walk measured (`None` on the early
/// returns), for the same step's refusal decision only.
pub(super) fn copy_budget_parts(
    sampling: Option<&Context>,
    active: Option<&mut OwnedActiveFile>,
    completing: bool,
) -> (usize, Option<usize>) {
    let Some(context) = sampling.filter(|context| context.audit_metadata_supported) else {
        return (0, None);
    };
    let Some(resident) = crate::heap_layout_bound::bound(context, STATE_BYTES) else {
        return (0, None);
    };
    let Some(remaining) = STATE_BYTES.checked_sub(resident) else {
        return (0, None);
    };
    let active = active.map_or(Some(0), |active| {
        let consumed = active.parser.reader.consumed_bytes();
        let buffer = active.parser.reader.buf.capacity();
        let estimate = (!completing)
            .then(|| codex_cursor::job_charge_estimate(active, consumed, buffer))
            .flatten();
        if let Some(estimate) = estimate {
            return Some(estimate);
        }
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
        let byte_charged = codex_cursor::byte_charged(file);
        let bound = if byte_charged {
            crate::heap_layout_bound::completed_bound(file, remaining)
        } else {
            crate::heap_layout_bound::bound(file, remaining)
        };
        active.parser.restore_live_reduction_inputs(inputs);
        if let Some(group) = active.group.as_mut() {
            group.restore_tee_inputs(tee_inputs);
        }
        if byte_charged {
            codex_cursor::record_job_charge(active, bound.unwrap_or(usize::MAX), consumed, buffer);
        }
        bound
    });
    let budget = active
        .and_then(|used| remaining.checked_sub(used))
        .map(|remaining| remaining / 2)
        .unwrap_or(0);
    (budget, Some(resident))
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
