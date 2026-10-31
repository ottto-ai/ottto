//! Local-only bounded evidence. This never enters a status/upload DTO.
use crate::snapshots::SnapshotQuarantineDisposition;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MAX_LOCAL_DIAGNOSTIC_BYTES: usize = 32 * 1024;
pub(crate) const LINEAGE_SAMPLES: usize = 4;
pub(crate) const MAX_FENCED_CENSUS_BYTES: usize = 8 * 1024;
pub(crate) const MAX_FENCED_CENSUS_ENTRIES: usize = 32_768;
const FENCED_CENSUS_FILE: &str = "codex-fenced-census-v1.json";
const FENCE_OUTCOME_FILE: &str = "codex-fenced-census-outcome-v1.json";
const MAX_FENCE_OUTCOME_BYTES: usize = 1024;
const MAX_CENSUS_VERSION_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessStart {
    sec: u64,
    usec: u64,
}

#[cfg(any(target_os = "macos", test))]
fn checked_process_start(
    complete: bool,
    expected_pid: u32,
    returned_pid: u32,
    sec: u64,
    usec: u64,
) -> Option<ProcessStart> {
    (complete && expected_pid > 0 && returned_pid == expected_pid && sec > 0 && usec < 1_000_000)
        .then_some(ProcessStart { sec, usec })
}

#[cfg(target_os = "macos")]
fn acquire_process_start() -> Option<ProcessStart> {
    let pid = std::process::id();
    let kernel_pid = libc::pid_t::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    // The native libc type owns the ABI; accept only a complete result for self.
    let returned = unsafe {
        libc::proc_pidinfo(
            kernel_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if returned != size {
        return None;
    }
    // SAFETY: the kernel returned the complete size of the initialized buffer.
    let info = unsafe { info.assume_init() };
    checked_process_start(
        true,
        pid,
        info.pbi_pid,
        info.pbi_start_tvsec,
        info.pbi_start_tvusec,
    )
}

#[cfg(not(target_os = "macos"))]
fn acquire_process_start() -> Option<ProcessStart> {
    None
}

fn process_start() -> Option<ProcessStart> {
    #[cfg(test)]
    if let Some(injected) = TEST_PROCESS_START.with(std::cell::Cell::get) {
        return injected;
    }
    static START: std::sync::OnceLock<Option<ProcessStart>> = std::sync::OnceLock::new();
    // Cache unavailability too; there is no per-attempt retry or subprocess.
    *START.get_or_init(acquire_process_start)
}

#[cfg(not(test))]
static CENSUS_ATTEMPT: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
thread_local! {
    // Parallel fixtures never share production attempt ordering or injected identity.
    static TEST_CENSUS_ATTEMPT: AtomicU64 = const { AtomicU64::new(0) };
    static TEST_PROCESS_START: std::cell::Cell<Option<Option<ProcessStart>>> = const { std::cell::Cell::new(None) };
    static TEST_OUTCOME_WRITES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn with_attempt_counter<T>(operation: impl FnOnce(&AtomicU64) -> T) -> T {
    #[cfg(test)]
    {
        TEST_CENSUS_ATTEMPT.with(operation)
    }
    #[cfg(not(test))]
    {
        operation(&CENSUS_ATTEMPT)
    }
}

fn begin_census_attempt() {
    with_attempt_counter(|counter| {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        });
    });
}

fn census_attempt() -> Option<u64> {
    let value = with_attempt_counter(|counter| counter.load(Ordering::Relaxed));
    // Zero means no outer boundary; saturation is unavailable, never wrap/reuse.
    (value > 0 && value < u64::MAX).then_some(value)
}

/// Fixed projection of already-owned index metadata. None means unavailable,
/// not zero/healthy. Never serialize the index or its keys/owner proofs here.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CensusIndexAggregates {
    pub schema_version: u16,
    pub generation: u64,
    pub file_count: u64,
    pub traversal_present: bool,
    pub pending_directories: Option<u64>,
    pub pending_candidates: Option<u64>,
    pub directory_census_present: bool,
    pub directory_census_stable: Option<bool>,
    pub directory_count: Option<u64>,
    pub reconciliation_started: Option<bool>,
    pub watcher_hint_seen: Option<bool>,
    pub retry_attempt: Option<u8>,
    pub retry_not_before_unix_seconds: Option<u64>,
    pub protected_aggregation_complete: bool,
    pub protected_history: Option<u64>,
    pub protected_absent_from_observed_rollouts: Option<u64>,
    pub protected_absent_valid_owner: Option<u64>,
}

/// Closed branch attribution, not an OS diagnosis or distinct-file count.
/// Ordinals belong to fenced census v3; never reorder without a schema change.
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub(crate) enum UnreadableCause {
    Metadata,
    Directory,
    OpenRead,
    ScopeObject,
    Reduction,
    AliasParser,
    ProtectedAbsence,
    LegacyHold,
}

/// Additive persisted metadata. Old traversals default to zero known causes;
/// their nonzero public count remains an explicit unattributed remainder.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct UnreadableCauses {
    counts: [u64; 8],
    /// E2 B2: which sites and files the counts came from. Additive; omitted
    /// while empty, so a traversal without unreadable paths keeps its bytes.
    #[serde(skip_serializing_if = "UnreadableSamples::is_empty")]
    samples: UnreadableSamples,
}
impl UnreadableCauses {
    pub(crate) fn record(&mut self, cause: UnreadableCause, count: u64) {
        let slot = &mut self.counts[cause as usize];
        *slot = slot.saturating_add(count);
    }
    /// `record`, plus the caller's site and `file` (path, index key) in the
    /// bounded per-cause sample.
    #[track_caller]
    pub(crate) fn record_sampled(
        &mut self,
        cause: UnreadableCause,
        count: u64,
        file: Option<(&std::path::Path, &str)>,
    ) {
        self.record(cause, count);
        if count > 0 {
            let site_line = std::panic::Location::caller().line();
            self.samples
                .insert(cause as usize, UnreadableSample::new(site_line, file));
        }
    }
    pub(crate) fn merge(&mut self, other: Self) {
        for (slot, incoming) in self.counts.iter_mut().zip(other.counts) {
            *slot = slot.saturating_add(incoming);
        }
        for (cause, incoming) in other.samples.0.into_iter().enumerate() {
            for sample in incoming.into_iter().flatten() {
                self.samples.insert(cause, sample);
            }
        }
    }
    /// The walk lost namespace: an unlistable path or directory, or an
    /// unreadable remainder no cause attributes (which may be either).
    pub(crate) fn walk_loss(&self, total: u64) -> bool {
        self.counts[UnreadableCause::Metadata as usize] > 0
            || self.counts[UnreadableCause::Directory as usize] > 0
            || !matches!(self.projection(total).unattributed, Some(0))
    }
    pub(crate) fn projection(self, total: u64) -> UnreadableBreakdown {
        let known = self
            .counts
            .iter()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value));
        let unattributed = known.and_then(|known| total.checked_sub(known));
        UnreadableBreakdown {
            counts: self.counts,
            unattributed,
            consistent: unattributed.is_some(),
        }
    }
}
#[derive(Debug, Serialize)]
pub(crate) struct UnreadableBreakdown {
    // metadata, directory, open_read, scope_object, reduction, alias_parser,
    // protected_absence, legacy_hold; fixed order, fixed length.
    counts: [u64; 8],
    unattributed: Option<u64>,
    consistent: bool,
}
crate::heap_layout_bound::fields!(UnreadableCauses; counts, samples);

/// Per-cause sample size: the first distinct events of each cause win.
const UNREADABLE_SAMPLES: usize = 4;

/// The first `UNREADABLE_SAMPLES` distinct events per `UnreadableCause`
/// ordinal. Fixed size and heap free, like `counts`.
#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(transparent)]
struct UnreadableSamples([[Option<UnreadableSample>; UNREADABLE_SAMPLES]; 8]);
/// Diagnostic only: a sample this build cannot read (another build's shape)
/// loads as empty and never fails the index load.
impl<'de> Deserialize<'de> for UnreadableSamples {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(serde_json::from_value(value).map(Self).unwrap_or_default())
    }
}
impl UnreadableSamples {
    fn insert(&mut self, cause: usize, sample: UnreadableSample) {
        let Some(slots) = self.0.get_mut(cause) else {
            return;
        };
        if slots.contains(&Some(sample)) {
            return;
        }
        if let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(sample);
        }
    }
    fn is_empty(&self) -> bool {
        self.0.iter().flatten().all(Option::is_none)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for UnreadableSamples {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// One unreadable event: the recording call's line in the producing build
/// (with the cause it names one call site) and, when the site names a file,
/// that file's root class, kind and the first 8 bytes of `digest(index key)`
/// (lineage's `file_key_digest`). Never path text. Written as one short
/// string, `line` or `line:root:kind:key_hex`, so 32 samples stay well inside
/// `MAX_LOCAL_DIAGNOSTIC_BYTES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
struct UnreadableSample {
    site_line: u32,
    file: Option<UnreadableFile>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnreadableFile {
    root: UnreadableRoot,
    kind: UnreadableFileKind,
    key_digest: [u8; 8],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadableRoot {
    DotCodex,
    /// A Codex slot home, or another source's root.
    OtherHome,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadableFileKind {
    Jsonl,
    JsonlZst,
    /// A sidecar or any other file.
    Other,
}
impl UnreadableRoot {
    const ALL: [Self; 2] = [Self::DotCodex, Self::OtherHome];
    fn name(self) -> &'static str {
        match self {
            Self::DotCodex => "dot_codex",
            Self::OtherHome => "other_home",
        }
    }
}
impl UnreadableFileKind {
    const ALL: [Self; 3] = [Self::Jsonl, Self::JsonlZst, Self::Other];
    fn name(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::JsonlZst => "jsonl_zst",
            Self::Other => "other",
        }
    }
}
impl UnreadableSample {
    fn new(site_line: u32, file: Option<(&std::path::Path, &str)>) -> Self {
        let file = file.map(|(path, index_key)| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let key_digest = digest(index_key);
            UnreadableFile {
                root: if path.components().any(|part| part.as_os_str() == ".codex") {
                    UnreadableRoot::DotCodex
                } else {
                    UnreadableRoot::OtherHome
                },
                kind: if name.ends_with(".jsonl") {
                    UnreadableFileKind::Jsonl
                } else if name.ends_with(".jsonl.zst") {
                    UnreadableFileKind::JsonlZst
                } else {
                    UnreadableFileKind::Other
                },
                key_digest: std::array::from_fn(|byte| key_digest[byte]),
            }
        });
        Self { site_line, file }
    }
}
impl From<UnreadableSample> for String {
    fn from(sample: UnreadableSample) -> Self {
        match sample.file {
            None => sample.site_line.to_string(),
            Some(file) => format!(
                "{}:{}:{}:{:016x}",
                sample.site_line,
                file.root.name(),
                file.kind.name(),
                u64::from_be_bytes(file.key_digest)
            ),
        }
    }
}
impl TryFrom<String> for UnreadableSample {
    type Error = &'static str;
    fn try_from(text: String) -> Result<Self, Self::Error> {
        let mut parts = text.split(':');
        let site_line = parts
            .next()
            .and_then(|line| line.parse().ok())
            .ok_or("unreadable sample site")?;
        let file = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (None, ..) => None,
            (Some(root), Some(kind), Some(key), None) => Some(UnreadableFile {
                root: UnreadableRoot::ALL
                    .into_iter()
                    .find(|known| known.name() == root)
                    .ok_or("unreadable sample root")?,
                kind: UnreadableFileKind::ALL
                    .into_iter()
                    .find(|known| known.name() == kind)
                    .ok_or("unreadable sample kind")?,
                key_digest: u64::from_str_radix(key, 16)
                    .map_err(|_| "unreadable sample key")?
                    .to_be_bytes(),
            }),
            _ => return Err("unreadable sample shape"),
        };
        Ok(Self { site_line, file })
    }
}

/// PR-P: number of `CodexParentUnresolvable` causes (asserted in `snapshots`).
pub(crate) const PARENT_UNRESOLVABLE_CAUSES: usize = 12;
/// Held fork children per parent cause; counts only. Persisted inside
/// `ScanTraversalCounts`, so old traversals default to zero, and an older
/// binary ignores the unknown field (as `UnreadableCauses`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ParentUnresolvableCauses {
    counts: [u64; PARENT_UNRESOLVABLE_CAUSES],
}
impl ParentUnresolvableCauses {
    /// `cause` is `CodexParentUnresolvable::index()` (this module cannot name
    /// the enum); saturating, like `UnreadableCauses::record`.
    pub(crate) fn record(&mut self, cause: usize, count: u64) {
        if let Some(slot) = self.counts.get_mut(cause) {
            *slot = slot.saturating_add(count);
        }
    }
    pub(crate) fn merge(&mut self, other: Self) {
        for (slot, incoming) in self.counts.iter_mut().zip(other.counts) {
            *slot = slot.saturating_add(incoming);
        }
    }
    #[cfg(test)]
    pub(crate) fn counts(&self) -> [u64; PARENT_UNRESOLVABLE_CAUSES] {
        self.counts
    }
    #[cfg(test)]
    pub(crate) fn saturated() -> Self {
        Self {
            counts: [u64::MAX; PARENT_UNRESOLVABLE_CAUSES],
        }
    }
}
crate::heap_layout_bound::fields!(ParentUnresolvableCauses; counts);

#[derive(Default, Serialize)]
struct CensusLossCounts {
    discovered: u64,
    ownership_incomplete: u64,
    unreadable: u64,
    disappeared: u64,
    recognized_usage_dropped: u64,
    dropped_usage: u64,
    over_line_cap: u64,
    zero_snapshot_usage_evidence: u64,
    terminal_over_line_cap: u64,
    terminal_ownership_incomplete: u64,
    terminal_zero_snapshot_usage_evidence: u64,
    terminal_recognized_usage_dropped: u64,
    terminal_dropped_usage: u64,
}

#[derive(Serialize)]
struct FencedCensusRecord<'a> {
    schema: &'static str,
    source: &'static str,
    producer_pid: u32,
    producer_start_sec: Option<u64>,
    producer_start_usec: Option<u64>,
    attempt_sequence: Option<u64>,
    producer_version: &'a str,
    observed_at: &'a str,
    scope: &'static str,
    index_view: &'static str,
    scan_input_generation: u64,
    gates: CensusGates,
    losses: CensusLossCounts,
    unreadable_causes: UnreadableBreakdown,
    index: CensusIndexAggregates,
}

fn fenced_census_path(support_dir: &std::path::Path) -> std::path::PathBuf {
    support_dir.join("snapshots").join(FENCED_CENSUS_FILE)
}

#[derive(Serialize)]
struct FenceOutcomeRecord<'a> {
    schema: &'static str,
    producer_pid: u32,
    producer_start_sec: Option<u64>,
    producer_start_usec: Option<u64>,
    producer_version: &'a str,
    attempt_sequence: Option<u64>,
    observed_at: Option<&'a str>,
    phase: CensusFencePhase,
    outcome: CensusFenceOutcome,
    invalidation: CensusInvalidation,
}

fn fence_outcome_path(support_dir: &std::path::Path) -> std::path::PathBuf {
    support_dir.join("snapshots").join(FENCE_OUTCOME_FILE)
}

fn encode_fence_outcome(
    record: &FenceOutcomeRecord<'_>,
    buffer: &mut [u8; MAX_FENCE_OUTCOME_BYTES],
) -> std::result::Result<usize, CensusPublishFailure> {
    if record.producer_version.len() > MAX_CENSUS_VERSION_BYTES {
        return Err(CensusPublishFailure::EncodingFailed);
    }
    let mut writer = std::io::Cursor::new(buffer.as_mut_slice());
    serde_json::to_writer(&mut writer, record).map_err(|_| CensusPublishFailure::EncodingFailed)?;
    Ok(writer.position() as usize)
}

fn persist_non_success(
    support_dir: &std::path::Path,
    phase: CensusFencePhase,
    outcome: CensusFenceOutcome,
    invalidation: CensusInvalidation,
) {
    let start = process_start();
    let version = crate::snapshots::collector_version();
    let clock = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .ok();
    let record = FenceOutcomeRecord {
        schema: "local_fenced_codex_census_outcome:v1",
        producer_pid: std::process::id(),
        producer_start_sec: start.map(|value| value.sec),
        producer_start_usec: start.map(|value| value.usec),
        producer_version: &version,
        attempt_sequence: census_attempt(),
        observed_at: clock.as_deref(),
        phase,
        outcome,
        invalidation,
    };
    let mut buffer = [0; MAX_FENCE_OUTCOME_BYTES];
    if let Ok(len) = encode_fence_outcome(&record, &mut buffer) {
        #[cfg(test)]
        TEST_OUTCOME_WRITES.with(|writes| writes.set(writes.get() + 1));
        // One best-effort non-durable write only. Failure cannot invalidate the
        // census, alter the fence result, or recursively persist another failure.
        let _ = ottto_core::write_owner_only_cache_file_atomic(
            &fence_outcome_path(support_dir),
            &buffer[..len],
        );
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CensusFencePhase {
    Outer,
    Inner,
}

/// Closed local outcomes only; never preserve an authority or OS error string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CensusFenceOutcome {
    Passed,
    Rejected,
    Published,
    ProjectionUnavailable,
    ClockUnavailable,
    EncodingFailed,
    PrivateWriteFailed,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CensusInvalidation {
    NotAttempted,
    Removed,
    AlreadyMissing,
    Failed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CensusPublishFailure {
    ProjectionUnavailable,
    ClockUnavailable,
    EncodingFailed,
    PrivateWriteFailed,
}
impl CensusPublishFailure {
    fn outcome(self) -> CensusFenceOutcome {
        match self {
            Self::ProjectionUnavailable => CensusFenceOutcome::ProjectionUnavailable,
            Self::ClockUnavailable => CensusFenceOutcome::ClockUnavailable,
            Self::EncodingFailed => CensusFenceOutcome::EncodingFailed,
            Self::PrivateWriteFailed => CensusFenceOutcome::PrivateWriteFailed,
        }
    }
}

fn invalidate_fenced_census(support_dir: &std::path::Path) -> CensusInvalidation {
    // Preserve the same best-effort removal. Failed removal never proves fresh
    // authority; consumers still need process-start/freshness-floor checks.
    match std::fs::remove_file(fenced_census_path(support_dir)) {
        Ok(()) => CensusInvalidation::Removed,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            CensusInvalidation::AlreadyMissing
        }
        Err(_) => CensusInvalidation::Failed,
    }
}

/// Observe the existing outer validation pair, without moving/adding its reads.
/// Outer rejection still does not invalidate the previously completed record.
pub(crate) fn observe_existing_outer_census_fence(
    source: crate::snapshots::SnapshotSource,
    support_dir: &std::path::Path,
    fence: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // SNAPSHOT_SYNC_LOCK serializes all production outer/inner flows in-process.
    // Cross-process replacement/removal remains unqualified diagnostic evidence.
    if source == crate::snapshots::SnapshotSource::Codex {
        begin_census_attempt();
    }
    let result = fence();
    if source == crate::snapshots::SnapshotSource::Codex {
        if result.is_err() {
            persist_non_success(
                support_dir,
                CensusFencePhase::Outer,
                CensusFenceOutcome::Rejected,
                CensusInvalidation::NotAttempted,
            );
        }
        crate::local_resource_diagnostics::codex_census_fence(
            CensusFencePhase::Outer,
            if result.is_ok() {
                CensusFenceOutcome::Passed
            } else {
                CensusFenceOutcome::Rejected
            },
            CensusInvalidation::NotAttempted,
        );
    }
    result
}

/// Replace an existing fence site, not add another authority/credential read.
/// Original rejection and nonfatal diagnostic/write/invalidation behavior stay
/// unchanged. Only fixed outcome scalars reach the existing local log carrier.
pub(crate) fn after_existing_census_fence(
    source: crate::snapshots::SnapshotSource,
    support_dir: &std::path::Path,
    fence: impl FnOnce() -> Result<()>,
    publish: impl FnOnce() -> std::result::Result<(), CensusPublishFailure>,
) -> Result<()> {
    let result = fence();
    if source == crate::snapshots::SnapshotSource::Codex {
        let (outcome, invalidation) = if result.is_err() {
            (
                CensusFenceOutcome::Rejected,
                invalidate_fenced_census(support_dir),
            )
        } else {
            match publish() {
                Ok(()) => (
                    CensusFenceOutcome::Published,
                    CensusInvalidation::NotAttempted,
                ),
                Err(error) => (error.outcome(), invalidate_fenced_census(support_dir)),
            }
        };
        if outcome != CensusFenceOutcome::Published {
            persist_non_success(support_dir, CensusFencePhase::Inner, outcome, invalidation);
        }
        crate::local_resource_diagnostics::codex_census_fence(
            CensusFencePhase::Inner,
            outcome,
            invalidation,
        );
    }
    result
}

fn write_fenced_census_record(
    support_dir: &std::path::Path,
    record: &FencedCensusRecord<'_>,
) -> std::result::Result<(), CensusPublishFailure> {
    if record.producer_version.len() > MAX_CENSUS_VERSION_BYTES {
        return Err(CensusPublishFailure::EncodingFailed);
    }
    // Hard serialization/allocation ceiling, independent of any future fields.
    let mut buffer = [0_u8; MAX_FENCED_CENSUS_BYTES];
    let mut writer = std::io::Cursor::new(buffer.as_mut_slice());
    serde_json::to_writer(&mut writer, record).map_err(|_| CensusPublishFailure::EncodingFailed)?;
    let len = writer.position() as usize;
    ottto_core::write_owner_only_cache_file_atomic(&fenced_census_path(support_dir), &buffer[..len])
        .map_err(|_| CensusPublishFailure::PrivateWriteFailed)
}

/// Called only by the successful existing-fence callback. Captures the working
/// view before delivery, never certifies a later checkpoint, account or ACK.
pub(crate) fn write_fenced_census(
    support_dir: &std::path::Path,
    scan: &crate::snapshots::SourceScanResult,
    index: &crate::snapshots::ScanIndex,
) -> std::result::Result<(), CensusPublishFailure> {
    let diagnostic = scan
        .local_codex_diagnostics
        .as_ref()
        .ok_or(CensusPublishFailure::ProjectionUnavailable)?;
    let version = crate::snapshots::collector_version();
    let observed_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| CensusPublishFailure::ClockUnavailable)?;
    let start = process_start();
    let record = FencedCensusRecord {
        schema: "local_fenced_codex_census:v3",
        source: "codex",
        producer_pid: std::process::id(),
        producer_start_sec: start.map(|value| value.sec),
        producer_start_usec: start.map(|value| value.usec),
        attempt_sequence: census_attempt(),
        producer_version: &version,
        observed_at: &observed_at,
        scope: "last_completed_scan_at_destination_fence",
        index_view: "working_before_delivery",
        scan_input_generation: diagnostic.generation,
        gates: diagnostic.gates,
        losses: CensusLossCounts {
            discovered: scan.discovered_file_count as u64,
            ownership_incomplete: scan.ownership_incomplete_file_count as u64,
            unreadable: scan.unreadable_path_count as u64,
            disappeared: scan.disappeared_file_count as u64,
            recognized_usage_dropped: scan.recognized_usage_drop_count as u64,
            dropped_usage: scan.dropped_usage_record_count,
            over_line_cap: scan.over_line_cap_count as u64,
            zero_snapshot_usage_evidence: scan.zero_snapshot_usage_evidence_count as u64,
            terminal_over_line_cap: scan.terminal_over_line_cap_count as u64,
            terminal_ownership_incomplete: scan.terminal_ownership_incomplete_file_count as u64,
            terminal_zero_snapshot_usage_evidence: scan.terminal_zero_snapshot_usage_evidence_count
                as u64,
            terminal_recognized_usage_dropped: scan.terminal_recognized_usage_drop_count as u64,
            terminal_dropped_usage: scan.terminal_dropped_usage_record_count,
        },
        unreadable_causes: diagnostic
            .unreadable_causes
            .projection(scan.unreadable_path_count as u64),
        index: index.local_codex_census_aggregates(),
    };
    write_fenced_census_record(support_dir, &record)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoaderReason {
    #[default]
    Complete,
    Io,
    SqliteBusy,
    SqliteOpenOrQuery,
    SqliteRowDecode,
    IncompleteShape,
    OtherFailure,
}

// Typed context tags identify the operation without inspecting error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LoaderStage {
    Open,
    Prepare,
    Query,
    Row,
}
impl std::fmt::Display for LoaderStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Prepare => "prepare",
            Self::Query => "query",
            Self::Row => "row",
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct LoaderEvidence {
    pub completed_roots: u32,
    pub failed_roots: u32,
    pub reason: LoaderReason,
    pub mixed_failure_reasons: bool,
    pub identity_conflict: bool,
    pub first_failure_root_digest: Option<[u8; 32]>,
    pub first_failure_stage: Option<LoaderStage>,
    // Same first failure as the root and stage; later failures only aggregate.
    pub sqlite_extended_code: Option<i32>,
    /// Transient SQLite open retries (CANTOPEN or BUSY) over all roots, and
    /// the roots that completed only after one.
    pub transient_retries: u32,
    pub completed_after_retry: u32,
}
impl LoaderEvidence {
    /// `retries`: the root's transient open retries before `result`.
    pub fn observe_root(
        &mut self,
        result: &Result<()>,
        retries: u32,
        conflict: bool,
        root_key: &str,
    ) {
        if self.failed_roots == 0 && result.is_err() {
            self.first_failure_root_digest = Some(digest(root_key));
        }
        self.transient_retries = self.transient_retries.saturating_add(retries);
        if retries > 0 && result.is_ok() {
            self.completed_after_retry = self.completed_after_retry.saturating_add(1);
        }
        self.observe(result, conflict);
    }

    pub fn observe(&mut self, result: &Result<()>, conflict: bool) {
        self.identity_conflict |= conflict;
        let Err(error) = result else {
            self.completed_roots = self.completed_roots.saturating_add(1);
            return;
        };
        let reason = if error.downcast_ref::<std::io::Error>().is_some() {
            LoaderReason::Io
        } else if let Some(error) = error.downcast_ref::<rusqlite::Error>() {
            match error {
                rusqlite::Error::SqliteFailure(code, _)
                    if matches!(
                        code.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    LoaderReason::SqliteBusy
                }
                rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::IntegralValueOutOfRange(..) => LoaderReason::SqliteRowDecode,
                _ => LoaderReason::SqliteOpenOrQuery,
            }
        } else if error.downcast_ref::<IncompleteShape>().is_some() {
            LoaderReason::IncompleteShape
        } else {
            LoaderReason::OtherFailure
        };
        self.mixed_failure_reasons |= self.failed_roots > 0 && self.reason != reason;
        // Keep the first bounded reason and disclose aggregation, never error text.
        if self.failed_roots == 0 {
            self.reason = reason;
            self.first_failure_stage = error.downcast_ref::<LoaderStage>().copied();
            self.sqlite_extended_code = error.downcast_ref::<rusqlite::Error>().and_then(|error| {
                if let rusqlite::Error::SqliteFailure(code, _) = error {
                    Some(code.extended_code)
                } else {
                    None
                }
            });
        }
        self.failed_roots = self.failed_roots.saturating_add(1);
    }
}

/// Content-free counts of Codex sidecar identity-conflict keys, taken from the
/// loaders' existing comparisons. New `state_threads` conflict keys split
/// exactly into alias, intra-root row and cross-root row keys. A cross-root
/// key is progress-only when `created_at`, `model` and `rollout_path` agree;
/// that classifies fields only and does not prove the copies harmless.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct IdentityConflictTaxonomy {
    pub state_alias_keys: u32,
    pub state_intra_root_row_keys: u32,
    pub state_cross_root_keys: u32,
    pub state_cross_root_progress_only_keys: u32,
    pub state_cross_root_identity_field_keys: u32,
    pub state_cross_root_field_differs: StateRowFieldDiffs,
    /// All loaders' conflict keys after every home, and the subsets the merged
    /// created classification and the prior scan's durable state-only
    /// entities still name. Spawn edges whose parent is a conflict key count
    /// once per child.
    pub conflict_keys_total: u32,
    pub conflict_keys_state_created: u32,
    pub conflict_keys_prior_state_only: u32,
    pub conflict_parent_child_edges: u32,
}
impl IdentityConflictTaxonomy {
    pub fn observe_state_cross_root(&mut self, differs: StateRowFieldDiffs) {
        self.state_cross_root_keys = self.state_cross_root_keys.saturating_add(1);
        let identity_field_differs =
            differs.created_at != 0 || differs.model != 0 || differs.rollout_path != 0;
        let class = if identity_field_differs {
            &mut self.state_cross_root_identity_field_keys
        } else {
            &mut self.state_cross_root_progress_only_keys
        };
        *class = class.saturating_add(1);
        let total = &mut self.state_cross_root_field_differs;
        for (slot, add) in [
            (&mut total.title, differs.title),
            (&mut total.tokens_used, differs.tokens_used),
            (&mut total.archived, differs.archived),
            (&mut total.created_at, differs.created_at),
            (&mut total.updated_at, differs.updated_at),
            (&mut total.model, differs.model),
            (&mut total.rollout_path, differs.rollout_path),
        ] {
            *slot = slot.saturating_add(add);
        }
    }
}

/// Per-field counts of differing `state_threads` rows; one key counts once in
/// every field it differs on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct StateRowFieldDiffs {
    pub title: u32,
    pub tokens_used: u32,
    pub archived: u32,
    pub created_at: u32,
    pub updated_at: u32,
    pub model: u32,
    pub rollout_path: u32,
}

#[derive(Debug)]
pub(crate) struct IncompleteShape;
impl std::fmt::Display for IncompleteShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Codex sidecar census shape was incomplete")
    }
}
impl std::error::Error for IncompleteShape {}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CensusGates {
    pub discovery_done: bool,
    pub traversal_healthy: bool,
    pub frozen_generation: bool,
    pub state_complete: bool,
    pub sidecar_complete: bool,
    pub reconciliation_complete: bool,
    pub parent_restart: bool,
    pub clean_followup: bool,
    pub census_complete: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FileReason {
    #[default]
    NotParsedThisCycle,
    Complete,
    ParentPending,
    OwnershipIncomplete,
    RecognizedUsageDropped,
    ReadOrLineLoss,
}

// Fixed-width digests are domain separated. No raw keys, source ids, paths,
// arbitrary strings or credentials can be placed in this diagnostic schema.
pub(crate) fn digest(value: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ottto_local_codex_recovery:v1\0");
    hash.update(value.as_bytes());
    hash.finalize().into()
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct RecoveryLineage {
    pub fingerprint_digest: [u8; 32],
    pub file_key_digest: Option<[u8; 32]>,
    pub associated_file_count: u64,
    pub legacy_file_association: bool,
    pub file_reason: FileReason,
    pub parsed_count: u64,
    pub finalized: bool,
    pub finalized_entity_count: u64,
    pub successor_digests: [[u8; 32]; LINEAGE_SAMPLES],
    pub previous_body_digest: Option<[u8; 32]>,
    pub final_body_digest: Option<[u8; 32]>,
    pub final_body_revision: u64,
    pub before_current: bool,
    pub after_current: bool,
    pub before_disposition: SnapshotQuarantineDisposition,
    pub after_disposition: SnapshotQuarantineDisposition,
}
impl RecoveryLineage {
    pub fn new(fingerprint: &str, disposition: SnapshotQuarantineDisposition) -> Self {
        Self {
            fingerprint_digest: digest(fingerprint),
            file_key_digest: None,
            associated_file_count: 0,
            legacy_file_association: false,
            file_reason: FileReason::NotParsedThisCycle,
            parsed_count: 0,
            finalized: false,
            finalized_entity_count: 0,
            successor_digests: [[0; 32]; LINEAGE_SAMPLES],
            previous_body_digest: None,
            final_body_digest: None,
            final_body_revision: 0,
            before_current: false,
            after_current: false,
            before_disposition: disposition,
            after_disposition: disposition,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CodexScanDiagnostics {
    pub version: u8,
    pub generation: u64,
    pub state_titles: LoaderEvidence,
    pub state_threads: LoaderEvidence,
    pub spawn_edges: LoaderEvidence,
    pub rollout_extents: LoaderEvidence,
    pub session_index: LoaderEvidence,
    /// E2 B3b: rollouts kept out of a failing home's created-thread hold
    /// because their proof comes from exactly one other, complete home.
    pub created_thread_scoped_rollouts: u32,
    pub identity_conflict_taxonomy: IdentityConflictTaxonomy,
    pub gates: CensusGates,
    pub unreadable_causes: UnreadableCauses,
    /// PR-P: held fork children per parent cause. Traversal-cumulative, as
    /// `unreadable_causes`: every page reports the running traversal total.
    pub parent_unresolvable: ParentUnresolvableCauses,
    /// PR-P: the scope's parent-resolution restart budget consumed, only when
    /// this page established it (its step-start pass or a restart ran).
    /// Omitted, never a fabricated 0, on discovery pages or without a shared
    /// cache, and omitted when the cursor is poisoned (N1: the scan still
    /// treats the budget as spent, but the count is unknown). A budget
    /// counter, not a count of actual restarts: an evicted slot re-enters
    /// spent, so it may read 2 (or exceed it after re-entry) with fewer
    /// restarts run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_restarts_in_scope: Option<u64>,
    pub quarantine_count: u64,
    pub sample_offset: u64,
    pub lineage: [Option<RecoveryLineage>; LINEAGE_SAMPLES],
}

/// Content-free, fixed-size Codex usage-counting V2 receipts of one scan's
/// finished parses (a singleton, or a joined group's single replay parse,
/// each folded once), summed with saturation. Owned by the scan result and
/// borrowed into the local terminal journal as `local_codex_counting_v2`;
/// also present for active-cutover scans or tombstone bookkeeping. Usage vectors are
/// `input, cached_input, cache_write_input, output, reasoning_output, total`.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub(crate) struct CountingV2Receipts {
    pub v2_sessions: u64,
    /// Cap evictions this scan, by the deterministic safety class.
    pub tombstone_evictions_v2_only: u64,
    pub tombstone_evictions_pre_cutover_legacy: u64,
    pub tombstone_evictions_not_provably_pre_cutover_legacy: u64,
    /// Finished V2 parses correlated with a retained evicted last Legacy
    /// carrier. Observations can repeat before a committed ACK absorbs it;
    /// the bounded diagnostic history can age out, so this is not exhaustive.
    pub legacy_to_v2_after_tombstone_eviction: u64,
    pub tombstone_count: u64,
    pub tombstone_cap: u64,
    pub native_counted: u64,
    pub native_not_authority: u64,
    pub native_restated: u64,
    pub native_inside_holed_coverage: u64,
    pub native_inside_holed_coverage_usage: [u64; 6],
    pub native_chain_gap: u64,
    pub native_chain_overlap: u64,
    pub native_chain_overlap_covered: [u64; 6],
    pub native_epoch_reset: u64,
    pub native_conflict: u64,
    pub native_outside_open_turn: u64,
    pub native_outside_open_turn_usage: [u64; 6],
    pub native_after_turn_closed: u64,
    pub native_after_turn_closed_usage: [u64; 6],
    pub native_after_ui_flush: u64,
    pub native_after_ui_flush_usage: [u64; 6],
    pub ui_equal_total_repeat: u64,
    pub ui_equal_total_repeat_usage: [u64; 6],
    pub ui_in_native_turn_not_counted: u64,
    pub ui_in_native_turn_not_counted_usage: [u64; 6],
    pub ui_in_unbound_span: u64,
    pub v2_cumulative_base_uncounted: u64,
    pub v2_cumulative_base_uncounted_usage: [u64; 6],
    pub turn_closure_mismatch: u64,
    pub turn_reopened: u64,
    /// Closed-turn filter hits outside the exact recent ring: an older
    /// closure or a false positive. Natives there count 0 (usage below).
    pub closed_filter_hit_unconfirmed: u64,
    pub closed_filter_hit_unconfirmed_native_usage: [u64; 6],
    pub pending_overflow_flushes: u64,
    /// Visible local debt, only for the scan that parsed it: sessions ending
    /// this parse inside a still-open UI-only turn, their staged UI events and
    /// staged usage. Not carried to later scans.
    pub open_turn_ui_pending_sessions_this_scan: u64,
    pub open_turn_ui_pending_events_this_scan: u64,
    pub open_turn_ui_pending_usage_this_scan: [u64; 6],
    /// Open turns whose staged usage sum overflowed; never folded as zero.
    pub open_turn_ui_pending_unsummable_this_scan: u64,
}

// Exhaustive inventory preserves optional scan overlap admission on #493's
// existing layout contract. Fixed arrays add no separately owned heap bytes.
crate::heap_layout_bound::fields!(CodexScanDiagnostics; version, generation, state_titles, state_threads, spawn_edges, rollout_extents, session_index, created_thread_scoped_rollouts, identity_conflict_taxonomy, gates, unreadable_causes, parent_unresolvable, parent_restarts_in_scope, quarantine_count, sample_offset, lineage);
crate::heap_layout_bound::fields!(CountingV2Receipts; v2_sessions, tombstone_evictions_v2_only, tombstone_evictions_pre_cutover_legacy, tombstone_evictions_not_provably_pre_cutover_legacy, legacy_to_v2_after_tombstone_eviction, tombstone_count, tombstone_cap, native_counted, native_not_authority, native_restated, native_inside_holed_coverage, native_inside_holed_coverage_usage, native_chain_gap, native_chain_overlap, native_chain_overlap_covered, native_epoch_reset, native_conflict, native_outside_open_turn, native_outside_open_turn_usage, native_after_turn_closed, native_after_turn_closed_usage, native_after_ui_flush, native_after_ui_flush_usage, ui_equal_total_repeat, ui_equal_total_repeat_usage, ui_in_native_turn_not_counted, ui_in_native_turn_not_counted_usage, ui_in_unbound_span, v2_cumulative_base_uncounted, v2_cumulative_base_uncounted_usage, turn_closure_mismatch, turn_reopened, closed_filter_hit_unconfirmed, closed_filter_hit_unconfirmed_native_usage, pending_overflow_flushes, open_turn_ui_pending_sessions_this_scan, open_turn_ui_pending_events_this_scan, open_turn_ui_pending_usage_this_scan, open_turn_ui_pending_unsummable_this_scan);
crate::heap_layout_bound::fields!(LoaderEvidence; completed_roots, failed_roots, reason, mixed_failure_reasons, identity_conflict, first_failure_root_digest, first_failure_stage, sqlite_extended_code, transient_retries, completed_after_retry);
crate::heap_layout_bound::fields!(CensusGates; discovery_done, traversal_healthy, frozen_generation, state_complete, sidecar_complete, reconciliation_complete, parent_restart, clean_followup, census_complete);
crate::heap_layout_bound::fields!(RecoveryLineage; fingerprint_digest, file_key_digest, associated_file_count, legacy_file_association, file_reason, parsed_count, finalized, finalized_entity_count, successor_digests, previous_body_digest, final_body_digest, final_body_revision, before_current, after_current, before_disposition, after_disposition);
crate::heap_layout_bound::fields!(IdentityConflictTaxonomy; state_alias_keys, state_intra_root_row_keys, state_cross_root_keys, state_cross_root_progress_only_keys, state_cross_root_identity_field_keys, state_cross_root_field_differs, conflict_keys_total, conflict_keys_state_created, conflict_keys_prior_state_only, conflict_parent_child_edges);
crate::heap_layout_bound::fields!(StateRowFieldDiffs; title, tokens_used, archived, created_at, updated_at, model, rollout_path);
crate::heap_layout_bound::unit_enum!(false;
    LoaderReason: Complete | Io | SqliteBusy | SqliteOpenOrQuery | SqliteRowDecode
        | IncompleteShape | OtherFailure;
    LoaderStage: Open | Prepare | Query | Row;
    FileReason: NotParsedThisCycle | Complete | ParentPending | OwnershipIncomplete
        | RecognizedUsageDropped | ReadOrLineLoss;
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_root_stage_and_native_code_survive_later_failures_without_error_text() {
        let fault = |code, stage| {
            Err(anyhow::Error::new(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("private credential error text".to_owned()),
            ))
            .context(stage)
            .context("private provider path"))
        };
        let mut evidence = LoaderEvidence::default();
        evidence.observe_root(&Ok(()), 0, false, "successful root");
        evidence.observe_root(
            &fault(26, LoaderStage::Prepare),
            0,
            false,
            "failed root one",
        );
        evidence.observe_root(&fault(10, LoaderStage::Row), 0, false, "failed root two");
        assert_eq!(evidence.completed_roots, 1);
        assert_eq!(evidence.failed_roots, 2);
        assert_eq!(
            evidence.first_failure_root_digest,
            Some(digest("failed root one"))
        );
        assert_eq!(evidence.first_failure_stage, Some(LoaderStage::Prepare));
        assert_eq!(evidence.sqlite_extended_code, Some(26));
        let text = serde_json::to_string(&evidence).unwrap();
        for forbidden in ["private", "credential", "successful root", "failed root"] {
            assert!(!text.contains(forbidden));
        }
    }
    /// [format] E2 B2: the unreadable sample keeps at most
    /// `UNREADABLE_SAMPLES` distinct events per cause, holds digests and
    /// enums only, survives the persisted round trip and merge, and an empty
    /// sample keeps the pre-sample bytes.
    #[test]
    fn unreadable_sample_is_bounded_digest_only_and_additive() {
        let empty = serde_json::to_value(UnreadableCauses::default()).unwrap();
        assert!(empty.get("samples").is_none());
        let old: UnreadableCauses =
            serde_json::from_str(r#"{"counts":[0,0,2,0,1,0,0,0]}"#).unwrap();
        assert!(old.samples.is_empty());
        let other_build: UnreadableCauses =
            serde_json::from_str(r#"{"counts":[0,0,2,0,1,0,0,0],"samples":[["7:moon"]]}"#).unwrap();
        assert!(other_build.samples.is_empty());
        assert_eq!(other_build.counts, old.counts);

        let private = std::path::Path::new("/Users/private credential/.codex/sessions");
        let mut causes = UnreadableCauses::default();
        for file in [
            "a.jsonl",
            "b.jsonl.zst",
            "c.jsonl",
            "a.jsonl",
            "d.json",
            "e.jsonl",
        ] {
            let path = private.join(file);
            let key = path.to_string_lossy().into_owned();
            causes.record_sampled(UnreadableCause::OpenRead, 1, Some((&path, &key)));
        }
        causes.record_sampled(UnreadableCause::Reduction, 1, None);
        causes.record_sampled(UnreadableCause::Directory, 0, None);
        assert_eq!(causes.counts[UnreadableCause::OpenRead as usize], 6);
        let kept = causes.samples.0[UnreadableCause::OpenRead as usize];
        // a, b.zst, c, d: the repeated a.jsonl is kept once and e is past the bound.
        assert!(kept.iter().all(Option::is_some));
        let first = kept[0].unwrap().file.unwrap();
        assert_eq!(first.root, UnreadableRoot::DotCodex);
        assert_eq!(first.kind, UnreadableFileKind::Jsonl);
        assert_eq!(
            first.key_digest[..],
            digest(&private.join("a.jsonl").to_string_lossy())[..8]
        );
        assert_eq!(
            kept[1].unwrap().file.unwrap().kind,
            UnreadableFileKind::JsonlZst
        );
        assert_eq!(
            kept[3].unwrap().file.unwrap().kind,
            UnreadableFileKind::Other
        );
        let site_only = causes.samples.0[UnreadableCause::Reduction as usize][0].unwrap();
        assert!(site_only.file.is_none() && site_only.site_line > 0);
        assert!(causes.samples.0[UnreadableCause::Directory as usize]
            .iter()
            .all(Option::is_none));

        let text = serde_json::to_string(&causes).unwrap();
        for forbidden in ["/Users", "private", "credential", ".codex", "sessions"] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
        let a_key = u64::from_be_bytes(first.key_digest);
        assert!(text.contains(&format!(":dot_codex:jsonl:{a_key:016x}\"")));
        let back: UnreadableCauses = serde_json::from_str(&text).unwrap();
        assert_eq!(back.samples.0, causes.samples.0);
        let mut merged = back;
        merged.merge(causes);
        assert_eq!(merged.samples.0, causes.samples.0, "merge stays bounded");
        assert_eq!(merged.counts[UnreadableCause::OpenRead as usize], 12);
    }
    #[test]
    fn reason_classification_never_uses_error_text() {
        let mut evidence = LoaderEvidence::default();
        evidence.observe(
            &Err(anyhow::Error::new(IncompleteShape).context("secret path")),
            true,
        );
        assert_eq!(evidence.reason, LoaderReason::IncompleteShape);
        evidence.observe(
            &Err(anyhow::anyhow!("credential and arbitrary provider error")),
            false,
        );
        evidence.observe(&Ok(()), false);
        assert!(evidence.mixed_failure_reasons);
        assert!(evidence.identity_conflict);
        assert_eq!(evidence.failed_roots, 2);
        assert_eq!(evidence.completed_roots, 1);
        assert!(!serde_json::to_string(&evidence).unwrap().contains("secret"));
    }
    /// PR-P: both parent fields are additive. `parent_restarts_in_scope` is
    /// omitted when unknown (never a fabricated 0) and present when
    /// established, 0 included; cause counts saturate, ignore an
    /// out-of-range cause, and a pre-PR-P value loads as zero.
    #[test]
    fn parent_fields_are_additive_and_unknown_restarts_are_omitted() {
        let mut diagnostics = CodexScanDiagnostics::default();
        let value = serde_json::to_value(diagnostics).unwrap();
        assert!(value.get("parent_restarts_in_scope").is_none());
        assert_eq!(
            value["parent_unresolvable"]["counts"],
            serde_json::to_value([0_u64; PARENT_UNRESOLVABLE_CAUSES]).unwrap()
        );
        diagnostics.parent_restarts_in_scope = Some(0);
        diagnostics.parent_unresolvable.record(3, 2);
        diagnostics
            .parent_unresolvable
            .record(PARENT_UNRESOLVABLE_CAUSES, 1);
        let value = serde_json::to_value(diagnostics).unwrap();
        assert_eq!(value["parent_restarts_in_scope"], 0);
        let mut expected = [0_u64; PARENT_UNRESOLVABLE_CAUSES];
        expected[3] = 2;
        assert_eq!(diagnostics.parent_unresolvable.counts(), expected);
        let old: ParentUnresolvableCauses = serde_json::from_str("{}").unwrap();
        assert_eq!(old, ParentUnresolvableCauses::default());
        let back: ParentUnresolvableCauses =
            serde_json::from_value(serde_json::to_value(diagnostics.parent_unresolvable).unwrap())
                .unwrap();
        assert_eq!(back, diagnostics.parent_unresolvable);
        let mut merged = ParentUnresolvableCauses::saturated();
        merged.merge(diagnostics.parent_unresolvable);
        assert_eq!(merged, ParentUnresolvableCauses::saturated());
    }
    #[test]
    fn fully_populated_schema_stays_bounded_and_content_free() {
        let mut diagnostics = CodexScanDiagnostics {
            version: 1,
            generation: u64::MAX,
            quarantine_count: u64::MAX,
            sample_offset: u64::MAX,
            ..Default::default()
        };
        let evidence = LoaderEvidence {
            completed_roots: u32::MAX,
            failed_roots: u32::MAX,
            first_failure_root_digest: Some([255; 32]),
            first_failure_stage: Some(LoaderStage::Prepare),
            sqlite_extended_code: Some(i32::MAX),
            transient_retries: u32::MAX,
            completed_after_retry: u32::MAX,
            ..Default::default()
        };
        // PR-P: the two parent fields at their maxima.
        diagnostics.parent_unresolvable = ParentUnresolvableCauses::saturated();
        diagnostics.parent_restarts_in_scope = Some(u64::MAX);
        diagnostics.state_titles = evidence;
        diagnostics.state_threads = evidence;
        diagnostics.spawn_edges = evidence;
        diagnostics.rollout_extents = evidence;
        diagnostics.session_index = evidence;
        diagnostics.created_thread_scoped_rollouts = u32::MAX;
        let field_differs = StateRowFieldDiffs {
            title: u32::MAX,
            tokens_used: u32::MAX,
            archived: u32::MAX,
            created_at: u32::MAX,
            updated_at: u32::MAX,
            model: u32::MAX,
            rollout_path: u32::MAX,
        };
        diagnostics.identity_conflict_taxonomy = IdentityConflictTaxonomy {
            state_alias_keys: u32::MAX,
            state_intra_root_row_keys: u32::MAX,
            state_cross_root_keys: u32::MAX,
            state_cross_root_progress_only_keys: u32::MAX,
            state_cross_root_identity_field_keys: u32::MAX,
            state_cross_root_field_differs: field_differs,
            conflict_keys_total: u32::MAX,
            conflict_keys_state_created: u32::MAX,
            conflict_keys_prior_state_only: u32::MAX,
            conflict_parent_child_edges: u32::MAX,
        };
        // Counters saturate instead of wrapping.
        diagnostics
            .identity_conflict_taxonomy
            .observe_state_cross_root(field_differs);
        assert_eq!(
            diagnostics
                .identity_conflict_taxonomy
                .state_cross_root_field_differs,
            field_differs
        );
        let mut lineage = RecoveryLineage::new(
            "raw session id /Users/private credential",
            SnapshotQuarantineDisposition::RetryPending,
        );
        lineage.file_key_digest = Some([255; 32]);
        lineage.successor_digests = [[255; 32]; LINEAGE_SAMPLES];
        lineage.previous_body_digest = Some([255; 32]);
        lineage.final_body_digest = Some([255; 32]);
        lineage.parsed_count = u64::MAX;
        lineage.finalized_entity_count = u64::MAX;
        lineage.associated_file_count = u64::MAX;
        lineage.final_body_revision = u64::MAX;
        diagnostics.lineage = [Some(lineage); LINEAGE_SAMPLES];
        diagnostics.unreadable_causes.samples = UnreadableSamples(
            [[Some(UnreadableSample {
                site_line: u32::MAX,
                file: Some(UnreadableFile {
                    root: UnreadableRoot::OtherHome,
                    kind: UnreadableFileKind::JsonlZst,
                    key_digest: [255; 8],
                }),
            }); UNREADABLE_SAMPLES]; 8],
        );
        let max = [u64::MAX; 6];
        let receipts = CountingV2Receipts {
            v2_sessions: u64::MAX,
            tombstone_evictions_v2_only: u64::MAX,
            tombstone_evictions_pre_cutover_legacy: u64::MAX,
            tombstone_evictions_not_provably_pre_cutover_legacy: u64::MAX,
            legacy_to_v2_after_tombstone_eviction: u64::MAX,
            tombstone_count: u64::MAX,
            tombstone_cap: u64::MAX,
            native_counted: u64::MAX,
            native_not_authority: u64::MAX,
            native_restated: u64::MAX,
            native_inside_holed_coverage: u64::MAX,
            native_inside_holed_coverage_usage: max,
            native_chain_gap: u64::MAX,
            native_chain_overlap: u64::MAX,
            native_chain_overlap_covered: max,
            native_epoch_reset: u64::MAX,
            native_conflict: u64::MAX,
            native_outside_open_turn: u64::MAX,
            native_outside_open_turn_usage: max,
            native_after_turn_closed: u64::MAX,
            native_after_turn_closed_usage: max,
            native_after_ui_flush: u64::MAX,
            native_after_ui_flush_usage: max,
            ui_equal_total_repeat: u64::MAX,
            ui_equal_total_repeat_usage: max,
            ui_in_native_turn_not_counted: u64::MAX,
            ui_in_native_turn_not_counted_usage: max,
            ui_in_unbound_span: u64::MAX,
            v2_cumulative_base_uncounted: u64::MAX,
            v2_cumulative_base_uncounted_usage: max,
            turn_closure_mismatch: u64::MAX,
            turn_reopened: u64::MAX,
            closed_filter_hit_unconfirmed: u64::MAX,
            closed_filter_hit_unconfirmed_native_usage: max,
            pending_overflow_flushes: u64::MAX,
            open_turn_ui_pending_sessions_this_scan: u64::MAX,
            open_turn_ui_pending_events_this_scan: u64::MAX,
            open_turn_ui_pending_usage_this_scan: max,
            open_turn_ui_pending_unsummable_this_scan: u64::MAX,
        };
        // The journal carries both blocks; together they keep the old cap.
        let mut bytes = serde_json::to_vec_pretty(&diagnostics).unwrap();
        bytes.extend(serde_json::to_vec_pretty(&receipts).unwrap());
        assert!(bytes.len() < MAX_LOCAL_DIAGNOSTIC_BYTES);
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in ["/Users", "credential", "raw session id"] {
            assert!(!text.contains(forbidden));
        }
    }
}

#[cfg(test)]
mod fenced_census_tests {
    use super::*;
    use crate::snapshots::SnapshotSource;
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            with_attempt_counter(|counter| counter.store(0, Ordering::Relaxed));
            TEST_OUTCOME_WRITES.with(|writes| writes.set(0));
            let root = std::env::temp_dir().join(format!(
                "ottto-fenced-census-{}",
                ottto_core::generate_control_token().unwrap()
            ));
            std::fs::create_dir_all(&root).unwrap();
            Self(root)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record() -> FencedCensusRecord<'static> {
        FencedCensusRecord {
            schema: "local_fenced_codex_census:v3",
            source: "codex",
            producer_pid: std::process::id(),
            producer_start_sec: process_start().map(|value| value.sec),
            producer_start_usec: process_start().map(|value| value.usec),
            attempt_sequence: census_attempt(),
            producer_version: "0.1.test",
            observed_at: "2026-10-09T10:00:00Z",
            scope: "last_completed_scan_at_destination_fence",
            index_view: "working_before_delivery",
            scan_input_generation: 7,
            gates: CensusGates::default(),
            losses: CensusLossCounts::default(),
            unreadable_causes: UnreadableCauses::default().projection(0),
            index: CensusIndexAggregates {
                generation: 8,
                ..Default::default()
            },
        }
    }

    #[test]
    fn fenced_census_unreadable_saturation_inconsistency_and_fixed_resource_bound() {
        assert_eq!(std::mem::size_of::<UnreadableCauses>(), 576);
        let mut causes = UnreadableCauses::default();
        causes.record(UnreadableCause::Metadata, u64::MAX);
        causes.record(UnreadableCause::Metadata, 1);
        assert_eq!(causes.counts[0], u64::MAX);
        assert!(causes.projection(u64::MAX).consistent);
        causes.record(UnreadableCause::Directory, 1);
        let inconsistent = causes.projection(u64::MAX);
        assert!(!inconsistent.consistent);
        assert!(inconsistent.unattributed.is_none());
        let mut observed = record();
        causes.counts = [u64::MAX; 8];
        observed.unreadable_causes = causes.projection(u64::MAX);
        observed.losses = CensusLossCounts {
            discovered: u64::MAX,
            ownership_incomplete: u64::MAX,
            unreadable: u64::MAX,
            disappeared: u64::MAX,
            recognized_usage_dropped: u64::MAX,
            dropped_usage: u64::MAX,
            over_line_cap: u64::MAX,
            zero_snapshot_usage_evidence: u64::MAX,
            terminal_over_line_cap: u64::MAX,
            terminal_ownership_incomplete: u64::MAX,
            terminal_zero_snapshot_usage_evidence: u64::MAX,
            terminal_recognized_usage_dropped: u64::MAX,
            terminal_dropped_usage: u64::MAX,
        };
        let mut buffer = [0_u8; MAX_FENCED_CENSUS_BYTES];
        let (len, stats) = crate::retry_allocation_probe::measure(|| {
            let mut writer = std::io::Cursor::new(buffer.as_mut_slice());
            serde_json::to_writer(&mut writer, &observed).unwrap();
            writer.position() as usize
        });
        assert_eq!(stats.allocations, 0);
        assert!(len < MAX_FENCED_CENSUS_BYTES);
        let json: serde_json::Value = serde_json::from_slice(&buffer[..len]).unwrap();
        assert_eq!(json["schema"], "local_fenced_codex_census:v3");
        assert_eq!(json["losses"]["terminal_over_line_cap"], u64::MAX);
        assert_eq!(json["losses"]["terminal_ownership_incomplete"], u64::MAX);
        println!("CENSUS_CAUSES inline_bytes=576 histogram_heap_bytes=0 worst_test_record_bytes={len} encoding_allocations=0");
    }

    fn sidecar(fixture: &Fixture) -> serde_json::Value {
        let bytes = std::fs::read(fence_outcome_path(fixture.path())).unwrap();
        assert!(bytes.len() <= MAX_FENCE_OUTCOME_BYTES);
        let text = std::str::from_utf8(&bytes).unwrap();
        for forbidden in [
            "PRIVATE",
            "path",
            "account",
            "credential",
            "digest",
            "error",
        ] {
            assert!(!text.contains(forbidden), "forbidden field {forbidden}");
        }
        serde_json::from_slice(&bytes).unwrap()
    }

    struct IdentityOverride(Option<Option<ProcessStart>>);
    impl IdentityOverride {
        fn new(value: Option<ProcessStart>) -> Self {
            Self(TEST_PROCESS_START.with(|injected| injected.replace(Some(value))))
        }
    }
    impl Drop for IdentityOverride {
        fn drop(&mut self) {
            TEST_PROCESS_START.with(|injected| injected.set(self.0));
        }
    }

    #[test]
    fn fenced_census_healthy_attempts_never_write_or_remove_sidecar() {
        let fixture = Fixture::new();
        let _identity = IdentityOverride::new(Some(ProcessStart {
            sec: 100,
            usec: 123456,
        }));
        for preexisting in [false, true] {
            if preexisting {
                std::fs::write(
                    fence_outcome_path(fixture.path()),
                    b"PREVIOUS_FAILURE_BYTES",
                )
                .unwrap();
            }
            for expected in if preexisting { 4..=6 } else { 1..=3 } {
                observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || {
                    Ok(())
                })
                .unwrap();
                after_existing_census_fence(
                    SnapshotSource::Codex,
                    fixture.path(),
                    || Ok(()),
                    || write_fenced_census_record(fixture.path(), &record()),
                )
                .unwrap();
                let census: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(fenced_census_path(fixture.path())).unwrap(),
                )
                .unwrap();
                assert_eq!(census["schema"], "local_fenced_codex_census:v3");
                assert_eq!(census["attempt_sequence"], expected);
                assert_eq!(census["producer_start_sec"], 100);
                assert_eq!(census["producer_start_usec"], 123456);
                assert_eq!(TEST_OUTCOME_WRITES.with(std::cell::Cell::get), 0);
                if preexisting {
                    assert_eq!(
                        std::fs::read(fence_outcome_path(fixture.path())).unwrap(),
                        b"PREVIOUS_FAILURE_BYTES"
                    );
                } else {
                    assert!(!fence_outcome_path(fixture.path()).exists());
                }
            }
        }
    }

    #[test]
    fn fenced_census_non_success_sidecar_is_private_and_reports_each_invalidation() {
        let fixture = Fixture::new();
        let path = fenced_census_path(fixture.path());
        for invalidation in ["removed", "already_missing", "failed"] {
            if invalidation == "removed" {
                write_fenced_census_record(fixture.path(), &record()).unwrap();
            } else if invalidation == "failed" {
                std::fs::create_dir_all(&path).unwrap();
            }
            observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || Ok(()))
                .unwrap();
            let original = census_attempt();
            let result = after_existing_census_fence(
                SnapshotSource::Codex,
                fixture.path(),
                || {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "PRIVATE_REJECTION",
                    )
                    .into())
                },
                || panic!("rejected fence must not publish"),
            );
            assert_eq!(
                result
                    .unwrap_err()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let value = sidecar(&fixture);
            assert_eq!(value["schema"], "local_fenced_codex_census_outcome:v1");
            assert_eq!(value["phase"], "inner");
            assert_eq!(value["outcome"], "rejected");
            assert_eq!(value["invalidation"], invalidation);
            assert_eq!(value["attempt_sequence"].as_u64(), original);
        }
        assert_eq!(TEST_OUTCOME_WRITES.with(std::cell::Cell::get), 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = fence_outcome_path(fixture.path());
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(
                path.parent()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn fenced_census_sidecar_write_failure_does_not_change_fence_or_invalidation() {
        let fixture = Fixture::new();
        write_fenced_census_record(fixture.path(), &record()).unwrap();
        let original = std::fs::read(fenced_census_path(fixture.path())).unwrap();
        // Rename over this directory fails. Sidecar failure never recurses.
        std::fs::create_dir_all(fence_outcome_path(fixture.path())).unwrap();
        let result =
            observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || {
                Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "PRIVATE_OUTER").into())
            });
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(
            std::fs::read(fenced_census_path(fixture.path())).unwrap(),
            original
        );
        assert_eq!(TEST_OUTCOME_WRITES.with(std::cell::Cell::get), 1);
        observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || Ok(()))
            .unwrap();
        let result = after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || {
                Err(
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "PRIVATE_INNER")
                        .into(),
                )
            },
            || panic!("rejected fence must not publish"),
        );
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(!fenced_census_path(fixture.path()).exists());
        observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || Ok(()))
            .unwrap();
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || Ok(()),
            || Err(CensusPublishFailure::ProjectionUnavailable),
        )
        .unwrap();
        assert_eq!(TEST_OUTCOME_WRITES.with(std::cell::Cell::get), 3);
        assert!(fence_outcome_path(fixture.path()).is_dir());
        assert_eq!(std::fs::read_dir(fence_outcome_path(fixture.path()).parent().unwrap()).unwrap().count(), 1,
            "failed writes clean temporary files, with no second census invalidation or recursive outcome");
    }

    #[test]
    fn fenced_census_start_unavailable_and_attempt_exhaustion_remain_unqualified() {
        let fixture = Fixture::new();
        let _identity = IdentityOverride::new(None);
        observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || Ok(()))
            .unwrap();
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || Ok(()),
            || write_fenced_census_record(fixture.path(), &record()),
        )
        .unwrap();
        let census: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fenced_census_path(fixture.path())).unwrap())
                .unwrap();
        assert!(census["producer_start_sec"].is_null());
        assert!(census["producer_start_usec"].is_null());
        let _ = observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || {
            Err(anyhow::anyhow!("PRIVATE"))
        });
        let failed = sidecar(&fixture);
        assert!(failed["producer_start_sec"].is_null());
        assert!(failed["producer_start_usec"].is_null());
        assert_eq!(failed["attempt_sequence"], 2);
        with_attempt_counter(|counter| counter.store(u64::MAX - 1, Ordering::Relaxed));
        begin_census_attempt();
        assert_eq!(census_attempt(), None);
        begin_census_attempt();
        assert_eq!(census_attempt(), None);
        assert_eq!(
            with_attempt_counter(|counter| counter.load(Ordering::Relaxed)),
            u64::MAX
        );
    }

    #[test]
    fn fenced_census_kernel_identity_guards_and_unavailable_cache() {
        assert_eq!(
            checked_process_start(true, 42, 42, 100, 999999),
            Some(ProcessStart {
                sec: 100,
                usec: 999999
            })
        );
        for (complete, expected, returned, sec, usec) in [
            (false, 42, 42, 100, 1),
            (true, 42, 43, 100, 1),
            (true, 0, 0, 100, 1),
            (true, 42, 42, 0, 1),
            (true, 42, 42, 100, 1000000),
        ] {
            assert!(checked_process_start(complete, expected, returned, sec, usec).is_none());
        }
        let cache = std::sync::OnceLock::new();
        let reads = std::cell::Cell::new(0);
        for _ in 0..2 {
            assert_eq!(
                *cache.get_or_init(|| {
                    reads.set(reads.get() + 1);
                    checked_process_start(false, 42, 42, 100, 0)
                }),
                None
            );
        }
        assert_eq!(reads.get(), 1);
        #[cfg(target_os = "macos")]
        {
            let first = acquire_process_start()
                .expect("own kernel identity must be available in this native fixture");
            assert_eq!(Some(first), process_start());
            assert_eq!(Some(first), acquire_process_start());
        }
    }

    #[test]
    fn fenced_census_fence_order_once_and_original_errors_invalidate_stale_record() {
        let fixture = Fixture::new();
        let calls = std::cell::RefCell::new(Vec::new());
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || {
                calls.borrow_mut().push("fence");
                Ok(())
            },
            || {
                calls.borrow_mut().push("write");
                write_fenced_census_record(fixture.path(), &record())
            },
        )
        .unwrap();
        assert_eq!(*calls.borrow(), vec!["fence", "write"]);
        assert!(fenced_census_path(fixture.path()).is_file());
        calls.borrow_mut().clear();
        let result = after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || {
                calls.borrow_mut().push("rejected");
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic authority change",
                )
                .into())
            },
            || panic!("rejected fence must not invoke projection or writer"),
        );
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(*calls.borrow(), vec!["rejected"]);
        assert!(!fenced_census_path(fixture.path()).exists());
    }

    #[test]
    fn fenced_census_private_bounded_latest_record_and_distinct_generations() {
        let fixture = Fixture::new();
        for generation in [8, 9] {
            let mut observed = record();
            observed.index.generation = generation;
            write_fenced_census_record(fixture.path(), &observed).unwrap();
        }
        let path = fenced_census_path(fixture.path());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() <= MAX_FENCED_CENSUS_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["scan_input_generation"], 7);
        assert_eq!(value["index"]["generation"], 9);
        assert_eq!(value["index_view"], "working_before_delivery");
        assert!(value["index"]["protected_history"].is_null());
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        let text = String::from_utf8(bytes).unwrap();
        for excluded in [
            "namespace",
            "fingerprint",
            "digest",
            "session_id",
            "device_id",
            "account_id",
            "lineage",
            "path",
            "committed",
            "ack",
        ] {
            assert!(
                !text.contains(excluded),
                "private/unproven field {excluded}"
            );
        }
        let enormous = "x".repeat(MAX_FENCED_CENSUS_BYTES + 1);
        let mut oversized = record();
        oversized.producer_version = &enormous;
        after_existing_census_fence(
            SnapshotSource::Codex,
            fixture.path(),
            || Ok(()),
            || write_fenced_census_record(fixture.path(), &oversized),
        )
        .unwrap();
        assert!(
            !path.exists(),
            "oversize observation must not leave stale record offered"
        );
    }

    #[test]
    fn fenced_census_inner_outcome_is_bound_and_distinguishes_failed_invalidation() {
        let fixture = Fixture::new();
        // A directory at the known target makes both atomic rename and remove_file fail.
        std::fs::create_dir_all(fenced_census_path(fixture.path())).unwrap();
        let (result, records) = crate::local_resource_diagnostics::capture(|| {
            after_existing_census_fence(
                SnapshotSource::Codex,
                fixture.path(),
                || Ok(()),
                || write_fenced_census_record(fixture.path(), &record()),
            )
        });
        result.unwrap();
        assert_eq!(
            records.len(),
            1,
            "must expose the suppressed writer outcome"
        );
        assert_eq!(records[0]["stage"], "codex_census_fence");
        assert_eq!(records[0]["counts"]["phase"], "inner");
        assert_eq!(records[0]["counts"]["outcome"], "private_write_failed");
        assert_eq!(records[0]["counts"]["invalidation"], "failed");
        let persisted = sidecar(&fixture);
        assert_eq!(persisted["phase"], "inner");
        assert_eq!(persisted["outcome"], "private_write_failed");
        assert_eq!(persisted["invalidation"], "failed");
    }

    #[test]
    fn fenced_census_outer_and_inner_checks_preserve_order_and_original_error() {
        let fixture = Fixture::new();
        let calls = std::cell::RefCell::new(Vec::new());
        let (result, records) = crate::local_resource_diagnostics::capture(|| {
            observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || {
                calls.borrow_mut().push("outer account/source");
                calls.borrow_mut().push("outer destination");
                Ok(())
            })?;
            after_existing_census_fence(
                SnapshotSource::Codex,
                fixture.path(),
                || {
                    calls.borrow_mut().push("inner account/source");
                    calls.borrow_mut().push("inner destination");
                    Ok(())
                },
                || {
                    calls.borrow_mut().push("publish");
                    write_fenced_census_record(fixture.path(), &record())
                },
            )
        });
        result.unwrap();
        assert_eq!(
            *calls.borrow(),
            vec![
                "outer account/source",
                "outer destination",
                "inner account/source",
                "inner destination",
                "publish"
            ]
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["counts"]["phase"], "outer");
        assert_eq!(records[0]["counts"]["outcome"], "passed");
        assert_eq!(records[1]["counts"]["phase"], "inner");
        assert_eq!(records[1]["counts"]["outcome"], "published");
        for row in &records {
            assert_eq!(row["schema_version"], 2);
            assert_eq!(row["source"], "codex");
            assert_eq!(row["process_id"], std::process::id());
            assert!(row["observation"]["observed_unix_ms"].as_u64().is_some());
            assert_eq!(row["counts"]["invalidation"], "not_attempted");
        }

        #[derive(Debug)]
        struct Original(std::sync::Arc<()>);
        impl std::fmt::Display for Original {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("PRIVATE_AUTHORITY_PATH_AND_ACCOUNT_CANARY")
            }
        }
        impl std::error::Error for Original {}
        let identity = std::sync::Arc::new(());
        calls.borrow_mut().clear();
        let (result, rows) = crate::local_resource_diagnostics::capture(|| -> Result<()> {
            observe_existing_outer_census_fence(SnapshotSource::Codex, fixture.path(), || {
                calls.borrow_mut().push("outer rejected");
                Err(anyhow::Error::new(Original(identity.clone())).context("PRIVATE_CONTEXT"))
            })?;
            panic!("outer rejection must prevent later checks and writes");
        });
        let error = result.unwrap_err();
        assert!(std::sync::Arc::ptr_eq(
            &error.downcast_ref::<Original>().unwrap().0,
            &identity
        ));
        assert_eq!(error.to_string(), "PRIVATE_CONTEXT");
        assert_eq!(*calls.borrow(), vec!["outer rejected"]);
        assert!(
            fenced_census_path(fixture.path()).is_file(),
            "outer rejection preserves existing no-invalidation semantics"
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["counts"]["outcome"], "rejected");
        assert_eq!(rows[0]["counts"]["invalidation"], "not_attempted");
        let failed = sidecar(&fixture);
        assert_eq!(failed["phase"], "outer");
        assert_eq!(failed["outcome"], "rejected");
        assert_eq!(failed["invalidation"], "not_attempted");
        assert!(!serde_json::to_string(&rows).unwrap().contains("PRIVATE"));
    }

    #[test]
    fn fenced_census_inner_rejection_and_publish_failures_are_nonfatal_and_closed() {
        let fixture = Fixture::new();
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            after_existing_census_fence(
                SnapshotSource::Codex,
                fixture.path(),
                || {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "PRIVATE_FENCE_ERROR",
                    )
                    .into())
                },
                || panic!("rejected fence must not publish"),
            )
        });
        assert_eq!(
            result
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(rows[0]["counts"]["outcome"], "rejected");
        assert_eq!(rows[0]["counts"]["invalidation"], "already_missing");
        for (failure, expected) in [
            (
                CensusPublishFailure::ProjectionUnavailable,
                "projection_unavailable",
            ),
            (CensusPublishFailure::ClockUnavailable, "clock_unavailable"),
            (CensusPublishFailure::EncodingFailed, "encoding_failed"),
            (
                CensusPublishFailure::PrivateWriteFailed,
                "private_write_failed",
            ),
        ] {
            write_fenced_census_record(fixture.path(), &record()).unwrap();
            let (result, rows) = crate::local_resource_diagnostics::capture(|| {
                after_existing_census_fence(
                    SnapshotSource::Codex,
                    fixture.path(),
                    || Ok(()),
                    || Err(failure),
                )
            });
            result.unwrap();
            assert!(!fenced_census_path(fixture.path()).exists());
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["counts"]["outcome"], expected);
            assert_eq!(rows[0]["counts"]["invalidation"], "removed");
        }
        // The real fixed-buffer overflow is an encoding failure, not an OS failure.
        let large = "PRIVATE".repeat(MAX_FENCED_CENSUS_BYTES);
        let mut oversized = record();
        oversized.producer_version = &large;
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            after_existing_census_fence(
                SnapshotSource::Codex,
                fixture.path(),
                || Ok(()),
                || write_fenced_census_record(fixture.path(), &oversized),
            )
        });
        result.unwrap();
        assert_eq!(rows[0]["counts"]["outcome"], "encoding_failed");
        assert!(!serde_json::to_string(&rows).unwrap().contains("PRIVATE"));
    }

    #[test]
    fn fenced_census_suppressed_for_other_sources_without_changing_checks_or_cache() {
        let fixture = Fixture::new();
        write_fenced_census_record(fixture.path(), &record()).unwrap();
        let original = std::fs::read(fenced_census_path(fixture.path())).unwrap();
        for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
            let before = census_attempt();
            let calls = std::cell::Cell::new(0);
            let (result, rows) = crate::local_resource_diagnostics::capture(|| {
                observe_existing_outer_census_fence(source, fixture.path(), || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })?;
                after_existing_census_fence(
                    source,
                    fixture.path(),
                    || {
                        calls.set(calls.get() + 1);
                        Err(anyhow::anyhow!("PRIVATE_OTHER_SOURCE"))
                    },
                    || panic!("suppressed source must not publish"),
                )
            });
            assert!(result.is_err());
            assert_eq!(calls.get(), 2);
            assert!(rows.is_empty());
            assert_eq!(census_attempt(), before);
            assert_eq!(TEST_OUTCOME_WRITES.with(std::cell::Cell::get), 0);
            assert!(!fence_outcome_path(fixture.path()).exists());
            assert_eq!(
                std::fs::read(fenced_census_path(fixture.path())).unwrap(),
                original
            );
        }
    }

    #[test]
    fn fenced_census_consumer_freshness_contract_rejects_old_process_or_change() {
        // Synthetic consumer contract using the actual emitted record; no local
        // runtime reader or current-account claim is added by this diagnostic.
        let fixture = Fixture::new();
        write_fenced_census_record(fixture.path(), &record()).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fenced_census_path(fixture.path())).unwrap())
                .unwrap();
        let acceptable = |pid: u32, floor: &str| {
            let clock = time::OffsetDateTime::parse(
                value["observed_at"].as_str().unwrap(),
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap();
            let floor =
                time::OffsetDateTime::parse(floor, &time::format_description::well_known::Rfc3339)
                    .unwrap();
            value["producer_pid"] == pid && clock >= floor
        };
        assert!(acceptable(std::process::id(), "2026-10-09T09:00:00Z"));
        assert!(!acceptable(
            std::process::id().wrapping_add(1),
            "2026-10-09T09:00:00Z"
        ));
        assert!(!acceptable(std::process::id(), "2026-10-09T11:00:00Z"));
    }
}
