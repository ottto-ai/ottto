//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::claude_copy_containment::membership::MembershipIndex;
#[cfg(test)]
use super::claude_copy_containment::membership::{Allowance, Refused, ScopedSession};
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{TranscriptCache, CACHE_BYTES, CACHE_ENTRIES};
use std::sync::atomic::{AtomicBool, Ordering};

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
const STATE_BYTES: usize =
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES;

pub(crate) struct SharedCache {
    inner: Mutex<SharedState>,
    // Policy only, never evidence/coverage or a read grant. Production stays
    // disabled until the complete containment integration is validated.
    copy_containment_required: AtomicBool,
}
/// One lock and one retained budget for both optional graphs. The membership
/// pool is negative-only; owning it establishes no read/upload permission.
struct SharedState {
    reductions: TranscriptCache<sampled_jsonl::CachedJsonlReduction>,
    copy_membership: MembershipIndex,
    // Required negative attempt memory is not an optional parser cache. Never
    // evict it on clear/pressure and then grant the same event another read.
    copy_attempts: BTreeSet<CopyAttempt>,
    copy_attempt_charge: usize,
    // Outstanding required-decode/index leases are not optional cache entries.
    // Clearing reductions must never refund a still-live index or decoder.
    copy_reserved: usize,
    copy_reservation_invalid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CopyAttempt {
    scope: [u8; 32],
    location: [u8; 32],
    revision: [u8; 32],
    event: [u8; 32],
}
impl CopyAttempt {
    pub(super) fn new(scope: &str, candidate: &CandidateFile, event: &str) -> Option<Self> {
        let hash = |domain: &str, parts: &[&str]| -> [u8; 32] {
            let mut digest = Sha256::new();
            update_length_prefixed(&mut digest, domain.as_bytes());
            for part in parts {
                update_length_prefixed(&mut digest, part.as_bytes());
            }
            digest.finalize().into()
        };
        Some(Self {
            scope: hash("copy_attempt_scope:v1", &[scope]),
            location: hash(
                "copy_attempt_location:v1",
                &[candidate.scan_root.to_str()?, candidate.path.to_str()?],
            ),
            revision: hash(
                "copy_attempt_revision:v1",
                &[&candidate.source_file_fingerprint],
            ),
            event: hash("copy_attempt_event:v1", &[event]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyAttemptResult {
    Claimed,
    Repeated,
    Unavailable,
}
impl SharedState {
    fn with_byte_limit(bytes: usize) -> Self {
        Self {
            reductions: TranscriptCache::with_byte_limit(bytes),
            copy_membership: MembershipIndex::default(),
            copy_attempts: BTreeSet::new(),
            copy_attempt_charge: 0,
            copy_reserved: 0,
            copy_reservation_invalid: false,
        }
    }
    fn attempt_charge(&self) -> Option<usize> {
        if self.copy_attempt_charge != 0 {
            return Some(self.copy_attempt_charge);
        }
        // No mutator removes markers: empty + never charged is precisely the
        // never-allocated state. Keep the disabled ordinary cache unchanged.
        self.copy_attempts.is_empty().then_some(0)
    }
}
impl HeapLayoutBound for SharedState {
    fn heap_bound(&self, counter: &mut Counter) -> Option<()> {
        let Self {
            reductions,
            copy_membership,
            copy_attempts: _,
            copy_attempt_charge: _,
            copy_reserved,
            copy_reservation_invalid,
        } = self;
        if *copy_reservation_invalid {
            return None;
        }
        reductions.heap_bound(counter)?;
        // Includes conservative inline/root overhead twice if necessary. Never
        // replace this with a complete ID graph walk on every parser check.
        counter.add(copy_membership.current_charge(STATE_BYTES)?)?;
        counter.add(self.attempt_charge()?)?;
        counter.add(*copy_reserved)
    }
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SharedState::with_byte_limit(STATE_BYTES)),
            copy_containment_required: AtomicBool::new(false),
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
        let Self {
            inner,
            copy_containment_required: _, // Inline atomic, no owned allocation.
        } = self;
        inner.heap_bound(c)
    }
}
impl SharedCache {
    pub(in crate::snapshots) fn reserve_copy_bytes(
        self: &Arc<Self>,
        bytes: usize,
    ) -> Option<CopyReservation> {
        if !self.copy_containment_required()
            || !super::claude_copy_containment::required_decode::profile_supported()
        {
            return None;
        }
        let mut reservation = CopyReservation {
            owner: Arc::clone(self),
            bytes: 0,
        };
        reservation.resize(bytes)?;
        Some(reservation)
    }

    #[cfg(test)]
    pub(crate) fn reserved_copy_bytes_for_test(&self) -> Option<usize> {
        Some(self.inner.try_lock().ok()?.copy_reserved)
    }

    #[cfg(test)]
    pub(crate) fn with_copy_credit_pressure_for_test<R>(
        self: &Arc<Self>,
        run: impl FnOnce() -> R,
    ) -> R {
        let mut pressure = Vec::new();
        while let Some(credit) = self.reserve_copy_bytes(1024) {
            pressure.push(credit);
        }
        let result = run();
        drop(pressure);
        result
    }

    pub(crate) fn copy_containment_required(&self) -> bool {
        self.copy_containment_required.load(Ordering::Relaxed)
    }
    // No CLI, environment or production switch. Exercise the real process
    // owner and preparation path without enabling an incomplete release.
    #[cfg(test)]
    pub(crate) fn require_copy_containment_for_test(&self) {
        self.copy_containment_required
            .store(true, Ordering::Relaxed);
    }

    pub(crate) fn clear(&self) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.reductions.clear();
            cache.copy_membership = MembershipIndex::default();
            // Attempt markers deliberately survive optional-cache eviction.
        }
    }
    /// Atomic claim BEFORE native parser construction, never an upload permit.
    /// The current parser owner supplies its existing remaining copy budget.
    /// Keeping a bounded exact event history is conservative: once the shared
    /// existing hold allowance is spent, new events park rather than evicting
    /// a marker and rereading an old event. No clock/reset/restart allowance.
    pub(super) fn claim_copy_attempt(
        &self,
        attempt: CopyAttempt,
        remaining: usize,
    ) -> CopyAttemptResult {
        if !self.copy_containment_required() {
            return CopyAttemptResult::Unavailable;
        }
        let Ok(mut cache) = self.inner.try_lock() else {
            return CopyAttemptResult::Unavailable;
        };
        if cache.copy_attempts.contains(&attempt) {
            return CopyAttemptResult::Repeated;
        }
        if !crate::heap_layout_bound::layout_supported()
            || cache
                .copy_attempts
                .len()
                .saturating_add(cache.copy_membership.held_slots_used())
                >= MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
            || cache
                .copy_attempts
                .len()
                .saturating_add(cache.copy_membership.owner_slots_used())
                >= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
        {
            return CopyAttemptResult::Unavailable;
        }
        let Some(resident) = crate::heap_layout_bound::bound(&*cache, STATE_BYTES) else {
            return CopyAttemptResult::Unavailable;
        };
        let Some(room) = STATE_BYTES
            .checked_sub(resident)
            .and_then(|room| room.checked_sub(std::mem::size_of::<Self>()))
        else {
            return CopyAttemptResult::Unavailable;
        };
        let mut extra = Counter::new(remaining.min(room));
        // Charge a full prospective tree beside all old resident nodes and
        // the fixed incoming key. No insertion/clone precedes this check.
        if extra.add(std::mem::size_of::<CopyAttempt>()).is_none()
            || crate::heap_layout_bound::tree_nodes::<CopyAttempt, ()>(
                cache.copy_attempts.len() + 1,
                &mut extra,
            )
            .is_none()
        {
            return CopyAttemptResult::Unavailable;
        }
        let mut retained = Counter::new(STATE_BYTES);
        if retained
            .add(std::mem::size_of_val(&cache.copy_attempts))
            .is_none()
            || crate::heap_layout_bound::tree_nodes::<CopyAttempt, ()>(
                cache.copy_attempts.len() + 1,
                &mut retained,
            )
            .is_none()
        {
            return CopyAttemptResult::Unavailable;
        }
        cache.copy_attempts.insert(attempt);
        cache.copy_attempt_charge = retained.bytes;
        CopyAttemptResult::Claimed
    }
    /// Exercise custody on the actual process cache before native completion
    /// supplies the production admission call. The caller must move an already
    /// owned input, not infer a permission to clone an unbounded native graph.
    #[cfg(test)]
    fn retain_copy_membership(
        &self,
        held: ScopedSession,
        ids: BTreeSet<String>,
        remaining: Allowance,
        live_bytes: usize,
    ) -> Result<usize, Refused> {
        if !self.copy_containment_required() {
            return Err(Refused::OwnerUnavailable);
        }
        let mut cache = self
            .inner
            .try_lock()
            .map_err(|_| Refused::OwnerUnavailable)?;
        let resident = crate::heap_layout_bound::bound(&cache.reductions, STATE_BYTES)
            .ok_or(Refused::UnavailableLayout)?;
        if cache.copy_reservation_invalid {
            return Err(Refused::OwnerUnavailable);
        }
        let heap_bytes = remaining
            .heap_bytes
            .min(STATE_BYTES)
            .checked_sub(std::mem::size_of::<Self>())
            .and_then(|bytes| bytes.checked_sub(resident))
            .and_then(|bytes| bytes.checked_sub(live_bytes))
            .and_then(|bytes| bytes.checked_sub(cache.attempt_charge()?))
            .and_then(|bytes| bytes.checked_sub(cache.copy_reserved))
            .ok_or(Refused::HeapBudget)?;
        let held_slots = remaining
            .held_slots
            .saturating_sub(cache.copy_attempts.len());
        let owner_slots = remaining
            .owner_slots
            .saturating_sub(cache.copy_attempts.len());
        cache.copy_membership.insert(
            held,
            ids,
            &Allowance {
                owner_slots,
                held_slots,
                heap_bytes,
            },
        )
    }
    pub(super) fn take(
        &self,
        key: &str,
    ) -> Option<crate::transcript_cache::Retained<sampled_jsonl::CachedJsonlReduction>> {
        self.inner.lock().ok()?.reductions.take(key)
    }
    pub(super) fn insert(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) {
        if let Some(state) = completed.reduction {
            if let Ok(mut cache) = self.inner.lock() {
                let Some(live_bytes) = cache
                    .copy_membership
                    .current_charge(STATE_BYTES)
                    .and_then(|membership| membership.checked_add(live_bytes))
                    .and_then(|live| live.checked_add(cache.attempt_charge()?))
                    .and_then(|live| live.checked_add(cache.copy_reserved))
                    .and_then(|live| live.checked_add(std::mem::size_of::<Self>()))
                    .filter(|all_live| !cache.copy_reservation_invalid && *all_live <= STATE_BYTES)
                else {
                    return;
                };
                let retained = crate::transcript_cache::Retained {
                    checkpoint: completed.checkpoint,
                    state,
                };
                if cache.copy_membership.is_empty() && cache.copy_attempts.is_empty() {
                    cache.reductions.insert_reserving(key, retained, live_bytes);
                } else {
                    cache
                        .reductions
                        .insert_reserving_peak(key, retained, live_bytes);
                }
            }
        }
    }
}

/// A move-only credit. No reservation is stored inside SharedState or an
/// optional cache value, so its destructor never runs under that owner's lock.
/// The value being paid for must be destroyed before this credit is returned.
pub(in crate::snapshots) struct CopyReservation {
    owner: Arc<SharedCache>,
    bytes: usize,
}
impl std::fmt::Debug for CopyReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequiredCopyReservation")
    }
}
impl CopyReservation {
    pub(in crate::snapshots) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(in crate::snapshots) fn owner(&self) -> &Arc<SharedCache> {
        &self.owner
    }
    pub(in crate::snapshots) fn resize(&mut self, bytes: usize) -> Option<()> {
        self.grow_or_resize(bytes, bytes)
    }
    /// A reader checks its prepaid scalar on every byte, but only grows credit
    /// geometrically. Near the ceiling claim the available remainder once,
    /// rather than retrying a failed doubling and taking the mutex per byte.
    pub(in crate::snapshots) fn grow_to_fit(
        &mut self,
        minimum: usize,
        preferred: usize,
    ) -> Option<()> {
        self.grow_or_resize(minimum, preferred.max(minimum))
    }
    fn grow_or_resize(&mut self, minimum: usize, preferred: usize) -> Option<()> {
        let mut state = self.owner.inner.try_lock().ok()?;
        let resident = crate::heap_layout_bound::bound(&*state, STATE_BYTES)?;
        let room = STATE_BYTES
            .checked_sub(resident.checked_sub(self.bytes)?)?
            .checked_sub(std::mem::size_of::<SharedCache>())?;
        let bytes = preferred.min(room);
        if bytes < minimum {
            return None;
        }
        let next = state
            .copy_reserved
            .checked_sub(self.bytes)?
            .checked_add(bytes)?;
        state.copy_reserved = next;
        self.bytes = bytes;
        Some(())
    }
    /// Transfer ownership without a refund/readmission race or an allocation.
    pub(in crate::snapshots) fn split(&mut self, bytes: usize) -> Option<Self> {
        let remaining = self.bytes.checked_sub(bytes)?;
        let result = Self {
            owner: Arc::clone(&self.owner),
            bytes,
        };
        self.bytes = remaining;
        Some(result)
    }
}
impl Drop for CopyReservation {
    fn drop(&mut self) {
        // Poison is never cleared/admitted by this path. Retiring an already
        // paid value still needs to return its exact credit after its data died.
        let mut state = self
            .owner
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match state.copy_reserved.checked_sub(self.bytes) {
            Some(next) => state.copy_reserved = next,
            None => state.copy_reservation_invalid = true,
        }
    }
}

pub(super) struct Context {
    pub(super) cache: Arc<SharedCache>,
    namespace: Scope,
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
}
crate::heap_layout_bound::fields!(Context; cache, namespace, audit_metadata_supported, audit_slots,
    full_files, tail_files, unchanged_files, native_bytes, sample_bytes, full_reasons,
    priority_replays, audits_started, audits_completed, start_overdue_seconds,
    completion_overdue_seconds);

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
            });
        }
        self
    }
    pub(crate) fn release_sampled_cache_for_copy_refusal(&self) {
        if let Some(context) = self.sampling.as_ref() {
            // A full parser's native accumulator is the unchanged synchronous
            // baseline. Its local layout refusal forbids optional copies, but
            // does not invalidate other already bounded resident reductions.
            // Acquisition/path scratch still uses the separate 1MiB reserve.
            // Borrowed tail state, unsupported audit metadata and an unbounded
            // resident graph retain the existing conservative release behavior.
            let native_full_baseline = self.active_file.as_ref().is_some_and(|active| {
                active
                    .sampling
                    .as_ref()
                    .is_some_and(|sampling| matches!(sampling.mode, ReadMode::Full(_)))
            });
            if native_full_baseline
                && context.audit_metadata_supported
                && crate::heap_layout_bound::bound(context, STATE_BYTES).is_some()
            {
                return;
            }
            context.cache.clear();
        }
    }
    /// Charge only optimization-owned native state, samples/keys and copies.
    /// The unchanged serial index/metadata is baseline; parked/proof/send
    /// frames still use their existing aggregate 32MiB allocation/lifetime gate.
    pub(super) fn sampled_copy_budget(&mut self) -> usize {
        let Some(context) = self
            .sampling
            .as_ref()
            .filter(|context| context.audit_metadata_supported)
        else {
            return 0;
        };
        let Some(resident) = crate::heap_layout_bound::bound(context, STATE_BYTES) else {
            return 0;
        };
        let Some(remaining) = STATE_BYTES.checked_sub(resident) else {
            return 0;
        };
        let active = self.active_file.as_mut().map_or(Some(0), |active| {
            // These native source-wide inputs predate the optimization, are
            // refreshed on reuse, and are absent from every retained copy.
            // All active owned parser/acquisition/path/receipt state stays charged.
            let inputs = active.parser.take_live_reduction_inputs();
            let bound = crate::heap_layout_bound::bound(active, remaining);
            active.parser.restore_live_reduction_inputs(inputs);
            bound
        });
        active
            .and_then(|used| remaining.checked_sub(used))
            .map(|remaining| remaining / 2)
            .unwrap_or(0)
    }
}

pub(super) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub(super) fn compatible_reduction(accumulator: &SnapshotAccumulator) -> bool {
    accumulator.source != SnapshotSource::Codex
        || (accumulator.codex_observed_priority_turns.is_some()
            && !accumulator.codex_is_fork
            && accumulator.codex_parent_session_ref.is_none()
            && accumulator.codex_sidecar_parent.is_none()
            && accumulator.codex_usage_accounting_complete())
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
