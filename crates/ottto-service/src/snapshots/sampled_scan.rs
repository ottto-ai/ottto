//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{CACHE_BYTES, CACHE_ENTRIES};

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
/// The optional-state budget.
fn state_bytes() -> usize {
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES
}

pub(super) mod codex_cursor;
#[cfg(unix)]
mod retired_records;
#[cfg(all(test, unix))]
pub(crate) mod transition_fixture;

// RAM-only per-key cap pacing; unify with P2's shared paced_full at integration.
// Fixed slots charge their full inline size through SharedCache, with no path heap.
pub(super) const CAP_PACE_SECONDS: u64 = 6 * 60 * 60;
const CAP_CLOCK_SANITY_SECONDS: u64 = 30 * 24 * 60 * 60;
#[derive(Clone, Copy)]
struct CapStamp {
    key: [u8; 32],
    at: SystemTime,
}
struct CapPace {
    entries: [Option<CapStamp>; CACHE_ENTRIES],
}
impl Default for CapPace {
    fn default() -> Self {
        Self {
            entries: [None; CACHE_ENTRIES],
        }
    }
}
impl CapPace {
    /// (may read Full, evicted). Backwards/implausible clocks expire, never hold.
    fn admit(&mut self, key: &str, now: SystemTime) -> (bool, bool) {
        let key: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|old| old.key == key))
        {
            let old = slot.expect("matched pace");
            if now.duration_since(old.at).is_ok_and(|elapsed| {
                elapsed.as_secs() <= CAP_CLOCK_SANITY_SECONDS
                    && elapsed.as_secs() < CAP_PACE_SECONDS
            }) {
                return (false, false);
            }
            *slot = Some(CapStamp { key, at: now });
            return (true, false);
        }
        let empty = self.entries.iter().position(Option::is_none);
        let slot = empty.unwrap_or_else(|| {
            self.entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.expect("full pace").at)
                .expect("nonempty pace")
                .0
        });
        self.entries[slot] = Some(CapStamp { key, at: now });
        (true, empty.is_none())
    }
}

pub(crate) struct SharedCache {
    pub(crate) withheld_memo: withheld_account::Memo,
    cap_pace: Mutex<CapPace>,
    /// The resumable Codex job slot and held-singleton memo. Charged once,
    /// here.
    cursor: Mutex<codex_cursor::CursorState>,
    /// Quiet retirements of the current passes, and the retired record
    /// directory's failed-removal ages. A leaf lock, never held while taking
    /// another. Outside the state budget: pass-scoped, never walked.
    #[cfg(unix)]
    pub(in crate::snapshots) quiet: Mutex<sampled_audit::quiet_retirement::QuietRetirements>,
    /// The state database this owner's fixture scans continue from: Claude's
    /// continuation lives there, not in RAM.
    #[cfg(test)]
    pub(crate) test_route: Mutex<Option<e2_pipeline_scan_fixture::FixtureRoute>>,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            withheld_memo: Default::default(),
            cap_pace: Mutex::new(CapPace::default()),
            cursor: Mutex::new(codex_cursor::CursorState::default()),
            #[cfg(unix)]
            quiet: Mutex::default(),
            #[cfg(test)]
            test_route: Default::default(),
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
        // The shared cache owns the memo allocation header even when empty.
        // Its optional entries are priced separately by the rotation owner.
        self.withheld_memo.heap_bound(c)?;
        self.cursor.heap_bound(c)?;
        c.add(self.root_reservation())
    }
}
#[cfg(test)]
impl SharedCache {
    pub(super) fn cap_pace_for_test(&self, key: &str, now: SystemTime) -> (bool, bool, usize) {
        let mut pace = self.cap_pace.lock().unwrap();
        let (admitted, evicted) = pace.admit(key, now);
        (admitted, evicted, pace.entries.iter().flatten().count())
    }
    /// Stage 1 K8, tests only: panic while holding the cursor lock.
    pub(crate) fn panic_under_cursor_lock_for_test(&self) {
        self.with_cursor(|_| panic!("W9: panic under the cursor lock (test)"));
    }
    /// Stage 1 K8, tests only: whether the cursor lock is poisoned now.
    pub(crate) fn cursor_poisoned_for_test(&self) -> bool {
        self.cursor.is_poisoned()
    }
}

// The qualified 64-bit root reservation. The budgets it feeds stay as they were.
const OFF_MAIN_SHARED_BYTES: usize = 40_784;
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<SharedCache>() <= OFF_MAIN_SHARED_BYTES);
impl SharedCache {
    fn root_reservation(&self) -> usize {
        OFF_MAIN_SHARED_BYTES.saturating_sub(size_of::<SharedCache>())
    }
}
impl SharedCache {
    /// Bind before constructor-time discovery/selection, which consults CONTENT.
    pub(crate) fn bind_withheld(&self, index: &mut ScanIndex) {
        index.withheld_memo = self.withheld_memo.clone();
        index
            .withheld_memo
            .retain_held(&index.claude_account_deferred_holds);
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
    /// Of `native_bytes`, a Full read's; the rest is Tail.
    pub(super) full_native_bytes: u64,
    pub(super) sample_bytes: u64,
    pub(super) full_reasons: [usize; 11],
    pub(super) priority_replays: usize,
    pub(super) audits_started: usize,
    pub(super) audits_completed: usize,
    pub(super) audit_quiet_retired: usize,
    pub(super) audit_cap_full: usize,
    pub(super) audit_cap_delay: usize,
    pub(super) pace_evicted: usize,
    pub(super) start_overdue_seconds: u64,
    pub(super) completion_overdue_seconds: u64,
    pub(super) admission: crate::local_resource_diagnostics::AcquisitionAdmission,
}
crate::heap_layout_bound::fields!(Context; cache, namespace, audit_metadata_supported, audit_slots,
    full_files, tail_files, unchanged_files, native_bytes, full_native_bytes, sample_bytes, full_reasons,
    priority_replays, audits_started, audits_completed, audit_quiet_retired, audit_cap_full, audit_cap_delay, pace_evicted, start_overdue_seconds,
    completion_overdue_seconds, admission);

pub(super) struct Active {
    pub(super) key: String,
    pub(super) scope: Scope,
    pub(super) mode: ReadMode,
    pub(super) audit_due: Option<u64>,
    /// This read is a protected-tier replay: a non-Full read found protected
    /// tiers and re-reads the file from its start (D168 `tier_prefix_replay`).
    pub(super) tier_prefix_replay: bool,
}
crate::heap_layout_bound::fields!(Active; key, scope, mode, audit_due, tier_prefix_replay);

impl Context {
    #[inline(never)]
    pub(super) fn cap_candidate(&mut self, key: &str) -> bool {
        let now = cap_wall_time();
        let (admit, evicted) = self
            .cache
            .cap_pace
            .lock()
            .map(|mut pace| pace.admit(key, now))
            .unwrap_or((true, false));
        self.pace_evicted += usize::from(evicted);
        if admit {
            self.audit_cap_full += 1;
        } else {
            self.audit_cap_delay += 1;
        }
        admit
    }
}
fn cap_wall_time() -> SystemTime {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(std::cell::Cell::get) {
        return UNIX_EPOCH + std::time::Duration::from_secs(now);
    }
    SystemTime::now()
}

impl Context {
    pub(super) fn file_scope(
        &self,
        source: SnapshotSource,
        candidate: &CandidateFile,
        sidecar: &str,
    ) -> Scope {
        // Only what changes the reader's output. Settings, capabilities and
        // the replay directive apply after the scan; the parser is compiled,
        // so it changes only across a restart, which drops RAM checkpoints.
        Scope(sha256_hex(&[
            "sampled_native_reduction:v2",
            &self.namespace.0,
            source.api_slug(),
            source.scan_identity_version(),
            &local_index_key(&candidate.scan_root),
            &local_index_key(&candidate.path),
            sidecar,
            // Retired full context-curve upload: keeps the scope bytes.
            "no_curve",
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
    pub(super) fn record_input(
        &mut self,
        metrics: crate::transcript_acquisition::ReadMetrics,
        full: bool,
    ) {
        self.native_bytes = self.native_bytes.saturating_add(metrics.native_bytes);
        if full {
            self.full_native_bytes = self.full_native_bytes.saturating_add(metrics.native_bytes);
        }
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
        if self.source == SnapshotSource::ClaudeCode {
            cache.bind_withheld(&mut self.index);
            self.resource_probe
                .set_withheld_memo(self.index.withheld_memo.clone());
        }
        // Every source is admitted on unix.
        let admitted = cfg!(unix) || self.source != SnapshotSource::Pi;
        if admitted {
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
                // Legacy prefix/audit scheduling and diagnostic observations
                // keep these values; ordinary restore never gates on them.
                audit_metadata_supported: pending <= CACHE_ENTRIES,
                audit_slots: CACHE_ENTRIES.saturating_sub(pending),
                full_files: 0,
                tail_files: 0,
                unchanged_files: 0,
                native_bytes: 0,
                full_native_bytes: 0,
                sample_bytes: 0,
                full_reasons: [0; 11],
                priority_replays: 0,
                audits_started: 0,
                audits_completed: 0,
                audit_quiet_retired: 0,
                audit_cap_full: 0,
                audit_cap_delay: 0,
                pace_evicted: 0,
                start_overdue_seconds: 0,
                completion_overdue_seconds: 0,
                admission: Default::default(),
            });
        }
        self
    }
}

/// Completion hooks and recorders (tests only). Nothing here runs in a
/// production build.
#[cfg(test)]
pub(super) mod test_hooks {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::snapshots) enum Point {
        /// The first opened-object identity sample has actually been read.
        AfterIdentityHead,
        /// After revalidation, before `retain_reduction`.
        BeforeRetain,
        /// After `retain_reduction` returns, before `finish`.
        AfterRetain,
        /// The completion is settled (receipt, owed hold or degraded
        /// disposition), before cursor publication, birth or any effect.
        BeforeNativeEffects,
    }

    type Hook = Box<dyn FnMut()>;
    type SelectionHook =
        Box<dyn FnOnce(&mut super::super::ScanIndex, Option<super::super::CandidateParseReason>)>;
    thread_local! {
        static HOOKS: RefCell<Vec<(Point, Hook)>> = RefCell::new(Vec::new());
        static AFTER_SELECTION: RefCell<Option<SelectionHook>> = const { RefCell::new(None) };
        static UNREADABLE: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static FINISH_ERRORS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static ACTIVE_KEY: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Run `hook` each time this thread reaches `point`, until `clear`.
    pub(in crate::snapshots) fn set(point: Point, hook: impl FnMut() + 'static) {
        HOOKS.with(|hooks| hooks.borrow_mut().push((point, Box::new(hook))));
    }

    pub(in crate::snapshots) fn after_selection(
        index: &mut super::super::ScanIndex,
        reason: Option<super::super::CandidateParseReason>,
    ) {
        let hook = AFTER_SELECTION.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook(index, reason);
        }
    }

    /// Drop every hook and recorded value on this thread.
    pub(in crate::snapshots) fn clear() {
        HOOKS.with(|hooks| hooks.borrow_mut().clear());
        AFTER_SELECTION.with(|slot| slot.borrow_mut().take());
        UNREADABLE.with(|causes| causes.borrow_mut().clear());
        FINISH_ERRORS.with(|errors| errors.borrow_mut().clear());
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

    /// `fire`, with the candidate's index key readable through
    /// `active_key` while the hooks run.
    pub(in crate::snapshots) fn fire_for_key(point: Point, key: &str) {
        ACTIVE_KEY.with(|active| *active.borrow_mut() = Some(key.to_owned()));
        fire(point);
        ACTIVE_KEY.with(|active| active.borrow_mut().take());
    }

    /// The key `fire_for_key` is firing for, if any.
    pub(in crate::snapshots) fn active_key() -> Option<String> {
        ACTIVE_KEY.with(|active| active.borrow().clone())
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

pub(super) struct ParserOptions<'a> {
    pub(super) source: SnapshotSource,
    pub(super) metadata: &'a CodexTitleMetadata,
    pub(super) traces: Option<Arc<CodexTurnTraceMap>>,
    pub(super) identity_capture: bool,
    pub(super) cache: Option<&'a Arc<SharedCache>>,
}

pub(super) fn new_source_parser(
    file: File,
    candidate: &CandidateFile,
    index: &ScanIndex,
    options: ParserOptions<'_>,
) -> Result<Box<OwnedJsonlParser>> {
    let ParserOptions {
        source,
        metadata,
        traces,
        identity_capture,
        cache,
    } = options;
    let input = if source == SnapshotSource::Codex {
        OpenedInput::encoded(file, &candidate.path, cache)?
    } else {
        OpenedInput::plain(file)
    };
    let mut parser = OwnedJsonlParser::new_opened(
        input,
        &candidate.path,
        source,
        match source {
            SnapshotSource::Codex => apply_codex_line,
            SnapshotSource::ClaudeCode => apply_claude_code_line,
            SnapshotSource::Pi => apply_pi_line,
        },
        (source == SnapshotSource::Codex).then_some(metadata),
        traces,
    )?;
    parser.accumulator.claude_request_identity_capture = identity_capture;
    if source == SnapshotSource::Codex {
        configure_tier_replay(&mut parser, candidate, index);
        codex_counting_version::configure_singleton(&mut parser, candidate, index);
    }
    Ok(Box::new(parser))
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

#[cfg(test)]
thread_local! { static TEST_REFUSE_REDUCTION_DEPENDENCIES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

/// Actual path-scoped interpretation dependencies. Decode no provider row here;
/// reuse existing sidecar inventory and bounded owning-header authority.
pub(super) fn reduction_dependencies(
    source: SnapshotSource,
    candidate: &CandidateFile,
    codex: &CodexTitleMetadata,
    claude: &ClaudeTitleMetadata,
    support: Option<&Path>,
) -> Option<String> {
    #[cfg(test)]
    if TEST_REFUSE_REDUCTION_DEPENDENCIES.with(std::cell::Cell::get) {
        return None;
    }
    match source {
        SnapshotSource::Codex => Some(sha256_hex(&[
            "codex_reduction_dependencies:v1",
            &codex.path_reduction_fingerprint(&candidate.path),
            &codex_file_join::header_reduction_witness(candidate).ok()?,
        ])),
        // Claude's sidecar evidence and its Desktop and child naming are live
        // inputs joined at finish, never in the pre-finish reduction: a
        // rename re-selects the file (its sidecar fingerprint) and never voids
        // its reduction (L05).
        SnapshotSource::ClaudeCode => Some("claude_reduction_dependencies:v2".to_owned()),
        SnapshotSource::Pi => {
            let mut scoped = candidate.clone();
            prepare_owned_scan_candidate(source, &mut scoped, codex, claude, support);
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

    /// [behaviour] Cache root and the measured cursor state are charged once.
    /// The ordinary heap walk refuses busy state instead of blocking.
    #[test]
    fn shared_cache_root_formula_and_nonblocking_measure() {
        use crate::heap_layout_bound::bound;
        use std::mem::{align_of, size_of};
        let cache = Arc::new(SharedCache::default());
        assert_eq!(
            bound(&cache, usize::MAX).is_some(),
            crate::heap_layout_bound::layout_supported()
        );
        if !crate::heap_layout_bound::layout_supported() {
            return;
        }
        let mut whole = Counter::new(usize::MAX);
        cache.heap_bound(&mut whole).unwrap();
        let mut parts = Counter::new(usize::MAX);
        cache.cursor.heap_bound(&mut parts).unwrap();
        cache.withheld_memo.heap_bound(&mut parts).unwrap();
        assert_eq!(
            whole.bytes,
            OFF_MAIN_SHARED_BYTES
                + align_of::<SharedCache>()
                + 2 * size_of::<usize>()
                + parts.bytes
        );
        {
            let _held = cache.cursor.lock().unwrap();
            assert!(bound(&cache, usize::MAX).is_none());
        }
        assert!(bound(&cache, usize::MAX).is_some());
    }
}

/// Why a read found no stored continuation.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissClass {
    NoEntry,
    HistoryOwed,
    Missing,
    Unavailable,
}
#[cfg(unix)]
impl MissClass {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NoEntry => "no_entry",
            Self::HistoryOwed => "ineligible.history_owed",
            Self::Missing => "missing",
            Self::Unavailable => "unavailable",
        }
    }
}

/// A RAM miss classified solely from committed index state and pass
/// registration. A cleared fingerprint is owed evidence, not a class: the file
/// misses for the same reason as one whose fingerprint survived.
#[cfg(unix)]
pub(in crate::snapshots) fn ram_miss_class(
    index: &ScanIndex,
    key: &str,
    has_slot: bool,
) -> MissClass {
    let entry = index.files.get(key);
    if entry.is_none() && !has_slot {
        MissClass::NoEntry
    } else if index.effective_upload_body_witness_revision_requires_adoption(key) {
        MissClass::HistoryOwed
    } else if entry.is_none() {
        MissClass::NoEntry
    } else if has_slot {
        MissClass::Missing
    } else {
        MissClass::Unavailable
    }
}
