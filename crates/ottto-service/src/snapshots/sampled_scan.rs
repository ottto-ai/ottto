//! Production glue. One process-owned cache is shared by background and manual
//! cycles; provider parsing, durable index/CAS and delivery remain native.
use super::*;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{TranscriptCache, CACHE_BYTES, CACHE_ENTRIES};

// The existing owner enforces aggregate parked/optional-send overlap. The
// separate 1MiB reserve covers bounded marker strings in existing index copies
// and fixed acquisition/path scratch; it is not a daemon RSS allowance.
const AUDIT_AND_SCRATCH_BYTES: usize = 1024 * 1024;
const STATE_BYTES: usize =
    CACHE_BYTES - crate::source_rotation::OVERLAP_BUDGET - AUDIT_AND_SCRATCH_BYTES;

pub(crate) struct SharedCache {
    inner: Mutex<TranscriptCache<sampled_jsonl::CachedJsonlReduction>>,
}
impl Default for SharedCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(TranscriptCache::with_byte_limit(STATE_BYTES)),
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
        self.inner.heap_bound(c)
    }
}
impl SharedCache {
    pub(super) fn clear(&self) {
        if let Ok(mut cache) = self.inner.lock() {
            cache.clear();
        }
    }
    pub(super) fn take(
        &self,
        key: &str,
    ) -> Option<crate::transcript_cache::Retained<sampled_jsonl::CachedJsonlReduction>> {
        self.inner.lock().ok()?.take(key)
    }
    pub(super) fn insert(
        &self,
        key: String,
        completed: sampled_jsonl::CompletedNativeAcquisition,
        live_bytes: usize,
    ) {
        if let Some(state) = completed.reduction {
            if let Ok(mut cache) = self.inner.lock() {
                cache.insert_reserving(
                    key,
                    crate::transcript_cache::Retained {
                        checkpoint: completed.checkpoint,
                        state,
                    },
                    live_bytes,
                );
            }
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
        prepare_owned_scan_candidate(source, &mut scoped, codex, claude, support);
        Some(scoped.source_file_fingerprint)
    }
}
