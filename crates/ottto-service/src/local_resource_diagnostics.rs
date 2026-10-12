//! Content-free observations in the existing local service log, never wire data.
//! CPU includes concurrent process work; maximum RSS is a lifetime high-water mark.
use serde::{ser::SerializeMap, Serialize};
use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    ClaudeCode,
    Codex,
    Pi,
    Unknown,
}
impl Source {
    fn from_slug(slug: &str) -> Self {
        match slug {
            "claude_code" => Self::ClaudeCode,
            "codex" => Self::Codex,
            "pi" => Self::Pi,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProcessSample {
    cpu_us: u64,
    lifetime_max_rss_bytes: u64,
}

fn process_sample() -> Option<ProcessSample> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the complete struct on success.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return None;
        }
        let usage = unsafe { usage.assume_init() };
        let micros = |time: libc::timeval| {
            u64::try_from(time.tv_sec)
                .ok()?
                .checked_mul(1_000_000)?
                .checked_add(u64::try_from(time.tv_usec).ok()?)
        };
        let raw_rss = u64::try_from(usage.ru_maxrss).ok()?;
        Some(ProcessSample {
            cpu_us: micros(usage.ru_utime)?.checked_add(micros(usage.ru_stime)?)?,
            lifetime_max_rss_bytes: if cfg!(target_os = "macos") {
                raw_rss
            } else {
                raw_rss.checked_mul(1024)?
            },
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

#[derive(Debug)]
pub(crate) struct Probe {
    started: Instant,
    process: Option<ProcessSample>,
}
impl Probe {
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
            process: process_sample(),
        }
    }
    fn observation(&self) -> Observation {
        Observation::between(
            self.started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            self.process,
            process_sample(),
        )
    }
    pub(crate) fn collection(&self, source: &str, counts: CollectionCounts) {
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "native_collection_page",
            source: Source::from_slug(source),
            observation: self.observation(),
            counts,
        });
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for Probe {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Serialize)]
struct Observation {
    observed_unix_ms: Option<u64>,
    wall_elapsed_us: u64,
    shared_process_cpu_delta_us: Option<u64>,
    process_lifetime_max_rss_bytes: Option<u64>,
    process_lifetime_max_rss_before_bytes: Option<u64>,
}
impl Observation {
    fn between(wall: u64, before: Option<ProcessSample>, after: Option<ProcessSample>) -> Self {
        Self {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: wall,
            shared_process_cpu_delta_us: before
                .zip(after)
                .and_then(|(before, after)| after.cpu_us.checked_sub(before.cpu_us)),
            process_lifetime_max_rss_bytes: after.map(|sample| sample.lifetime_max_rss_bytes),
            process_lifetime_max_rss_before_bytes: before.zip(after).and_then(|(before, after)| {
                (before.lifetime_max_rss_bytes <= after.lifetime_max_rss_bytes)
                    .then_some(before.lifetime_max_rss_bytes)
            }),
        }
    }
}

/// Observe only a normally returned finish; move its value/error through unchanged.
/// A panic drops the probe silently. Outcome reporting remains with the caller.
pub(crate) fn source_finish<T>(
    source: &str,
    inner: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let probe = Probe::start();
    let result = inner();
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "source_finish",
        source: Source::from_slug(source),
        observation: probe.observation(),
        counts: EmptyCounts {},
    });
    result
}
/// Point outcome at an existing Codex authority boundary. Two fixed records at
/// most per completed page, using the existing best-effort stderr carrier.
/// This is not a completion heartbeat, resource window or ingestion verdict.
pub(crate) fn codex_census_fence(
    phase: crate::codex_scan_diagnostics::CensusFencePhase,
    outcome: crate::codex_scan_diagnostics::CensusFenceOutcome,
    invalidation: crate::codex_scan_diagnostics::CensusInvalidation,
) {
    #[derive(Serialize)]
    struct Counts {
        phase: crate::codex_scan_diagnostics::CensusFencePhase,
        outcome: crate::codex_scan_diagnostics::CensusFenceOutcome,
        invalidation: crate::codex_scan_diagnostics::CensusInvalidation,
    }
    emit(&Record {
        schema_version: SCHEMA_VERSION,
        process_id: std::process::id(),
        stage: "codex_census_fence",
        source: Source::Codex,
        // A point observation has no measured resource window. Do not take
        // extra CPU/RSS samples or invent numeric measurements for this event.
        observation: Observation {
            observed_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()),
            wall_elapsed_us: 0,
            shared_process_cpu_delta_us: None,
            process_lifetime_max_rss_bytes: None,
            process_lifetime_max_rss_before_bytes: None,
        },
        counts: Counts {
            phase,
            outcome,
            invalidation,
        },
    });
}

#[derive(Serialize)]
struct EmptyCounts {}

// Process-lifetime gaps are never drained by an individual page. Drop only
// updates atomics; there is no drop-time log, lock, allocation or syscall.
struct AbandonedPages {
    count: std::sync::atomic::AtomicU64,
    overflow: std::sync::atomic::AtomicBool,
}
impl AbandonedPages {
    const fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicU64::new(0),
            overflow: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn note(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if self
            .count
            .fetch_update(Relaxed, Relaxed, |n| n.checked_add(1))
            .is_err()
        {
            self.overflow.store(true, Relaxed);
        }
    }
    fn value(&self) -> Option<u64> {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.count.load(Relaxed);
        (!self.overflow.load(Relaxed)).then_some(n)
    }
}
static ABANDONED: [AbandonedPages; 4] = [const { AbandonedPages::new() }; 4];

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct EfficiencyMode {
    operations: u64,
    full_equivalent_bytes: u64,
    native_bytes: u64,
    guard_bytes: u64,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct AcquisitionEfficiency {
    version: u8,
    paired_totals_valid: bool,
    page_coverage_complete: bool,
    full: EfficiencyMode,
    tail: EfficiencyMode,
    unchanged: EfficiencyMode,
    attempts: u64,
    superseded_attempts: u64,
    unpaired_operations: u64,
    unpaired_observed_native_bytes: u64,
    unpaired_observed_guard_bytes: u64,
    unknown_progress_operations: u64,
    unsampled_operations: u64,
    audit_full_operations: u64,
    abandoned_pages_at_start: Option<u64>,
    abandoned_pages_at_emit: Option<u64>,
}
impl Default for AcquisitionEfficiency {
    fn default() -> Self {
        Self {
            version: 1,
            paired_totals_valid: true,
            page_coverage_complete: true,
            full: EfficiencyMode::default(),
            tail: EfficiencyMode::default(),
            unchanged: EfficiencyMode::default(),
            attempts: 0,
            superseded_attempts: 0,
            unpaired_operations: 0,
            unpaired_observed_native_bytes: 0,
            unpaired_observed_guard_bytes: 0,
            unknown_progress_operations: 0,
            unsampled_operations: 0,
            audit_full_operations: 0,
            abandoned_pages_at_start: None,
            abandoned_pages_at_emit: None,
        }
    }
}
fn checked_add(total: &mut u64, n: u64, valid: &mut bool) {
    if let Some(sum) = total.checked_add(n) {
        *total = sum;
    } else {
        *valid = false;
    }
}

#[derive(Default)]
struct ReadOperation {
    current: Option<crate::transcript_acquisition::ReadMetrics>,
    native: u64,
    guards: u64,
    known: bool,
}
impl ReadOperation {
    fn charge_current(&mut self) {
        if let Some(m) = self.current.take() {
            checked_add(&mut self.native, m.native_bytes, &mut self.known);
            checked_add(&mut self.guards, m.sample_bytes as u64, &mut self.known);
        }
    }
}

// One operation slot follows the page's one active native file across moves
// and protected-tier replay. This owner cannot be cloned.
pub(crate) struct EfficiencyPage {
    source_slot: usize,
    totals: AcquisitionEfficiency,
    active: Option<ReadOperation>,
    armed: bool,
}
impl EfficiencyPage {
    pub(crate) fn new(source: &str) -> Self {
        let source_slot = match Source::from_slug(source) {
            Source::ClaudeCode => 0,
            Source::Codex => 1,
            Source::Pi => 2,
            Source::Unknown => 3,
        };
        Self {
            source_slot,
            totals: AcquisitionEfficiency {
                abandoned_pages_at_start: ABANDONED[source_slot].value(),
                ..AcquisitionEfficiency::default()
            },
            active: None,
            armed: true,
        }
    }
    pub(crate) fn begin(&mut self) {
        self.finish(false);
        self.active = Some(ReadOperation {
            known: true,
            ..ReadOperation::default()
        });
    }
    pub(crate) fn prepared(&mut self, metrics: crate::transcript_acquisition::ReadMetrics) {
        checked_add(
            &mut self.totals.attempts,
            1,
            &mut self.totals.paired_totals_valid,
        );
        if let Some(op) = &mut self.active {
            if op.current.is_some() {
                op.known = false;
                op.charge_current();
            }
            op.current = Some(metrics);
        } else {
            self.totals.page_coverage_complete = false;
        }
    }
    pub(crate) fn progress(&mut self, metrics: Option<crate::transcript_acquisition::ReadMetrics>) {
        if let Some(op) = &mut self.active {
            match (op.current.as_ref(), metrics) {
                (Some(old), Some(next))
                    if old.mode == next.mode
                        && old.source_bytes == next.source_bytes
                        && old.start_offset == next.start_offset
                        && next.native_bytes >= old.native_bytes =>
                {
                    op.current = Some(next)
                }
                _ => op.known = false,
            }
        }
    }
    pub(crate) fn replay(&mut self) {
        if let Some(op) = &mut self.active {
            op.charge_current();
        }
        checked_add(
            &mut self.totals.superseded_attempts,
            1,
            &mut self.totals.paired_totals_valid,
        );
    }
    pub(crate) fn preparation_failed(&mut self, guards: usize) {
        checked_add(
            &mut self.totals.attempts,
            1,
            &mut self.totals.paired_totals_valid,
        );
        if let Some(op) = &mut self.active {
            checked_add(&mut op.guards, guards as u64, &mut op.known);
        }
        self.finish(false);
    }
    pub(crate) fn unsampled(&mut self) {
        self.finish(false);
        checked_add(
            &mut self.totals.unsampled_operations,
            1,
            &mut self.totals.paired_totals_valid,
        );
        self.totals.page_coverage_complete = false;
    }
    pub(crate) fn finish(&mut self, qualified: bool) {
        use crate::transcript_acquisition::ReadMode;
        let Some(mut op) = self.active.take() else {
            return;
        };
        let last = op.current;
        op.charge_current();
        if !op.known {
            self.totals.paired_totals_valid = false;
        }
        let eligible = last.filter(|m| {
            qualified
                && op.known
                && match m.mode {
                    ReadMode::Unchanged => m.native_bytes == 0,
                    ReadMode::Full(_) => m.start_offset == 0 && m.native_bytes == m.source_bytes,
                    ReadMode::Tail => {
                        m.source_bytes.checked_sub(m.start_offset) == Some(m.native_bytes)
                    }
                }
        });
        if let Some(m) = eligible {
            let bucket = match m.mode {
                ReadMode::Full(_) => &mut self.totals.full,
                ReadMode::Tail => &mut self.totals.tail,
                ReadMode::Unchanged => &mut self.totals.unchanged,
            };
            let baseline = if m.mode == ReadMode::Unchanged {
                0
            } else {
                m.source_bytes
            };
            checked_add(
                &mut bucket.operations,
                1,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut bucket.full_equivalent_bytes,
                baseline,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut bucket.native_bytes,
                op.native,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut bucket.guard_bytes,
                op.guards,
                &mut self.totals.paired_totals_valid,
            );
            if matches!(m.mode, ReadMode::Full(_)) && m.audit_due.is_some() {
                checked_add(
                    &mut self.totals.audit_full_operations,
                    1,
                    &mut self.totals.paired_totals_valid,
                );
            }
        } else {
            self.totals.page_coverage_complete = false;
            checked_add(
                &mut self.totals.unpaired_operations,
                1,
                &mut self.totals.paired_totals_valid,
            );
            if !op.known {
                checked_add(
                    &mut self.totals.unknown_progress_operations,
                    1,
                    &mut self.totals.paired_totals_valid,
                );
            }
            checked_add(
                &mut self.totals.unpaired_observed_native_bytes,
                op.native,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut self.totals.unpaired_observed_guard_bytes,
                op.guards,
                &mut self.totals.paired_totals_valid,
            );
        }
    }
    pub(crate) fn complete(&mut self) -> AcquisitionEfficiency {
        self.finish(false);
        self.armed = false;
        self.totals.abandoned_pages_at_emit = ABANDONED[self.source_slot].value();
        if self.totals.abandoned_pages_at_start != self.totals.abandoned_pages_at_emit {
            self.totals.page_coverage_complete = false;
        }
        let mut native = self.totals.unpaired_observed_native_bytes;
        let mut guards = self.totals.unpaired_observed_guard_bytes;
        let mut baseline = 0;
        for mode in [&self.totals.full, &self.totals.tail, &self.totals.unchanged] {
            checked_add(
                &mut baseline,
                mode.full_equivalent_bytes,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut native,
                mode.native_bytes,
                &mut self.totals.paired_totals_valid,
            );
            checked_add(
                &mut guards,
                mode.guard_bytes,
                &mut self.totals.paired_totals_valid,
            );
        }
        if native.checked_add(guards).is_none() {
            self.totals.paired_totals_valid = false;
        }
        if self.totals.abandoned_pages_at_start.is_none()
            || self.totals.abandoned_pages_at_emit.is_none()
        {
            self.totals.paired_totals_valid = false;
        }
        self.totals
    }
}
impl Drop for EfficiencyPage {
    fn drop(&mut self) {
        if self.armed {
            if let Some(counter) = ABANDONED.get(self.source_slot) {
                counter.note();
            }
        }
    }
}
// All fields are inline diagnostics; the static atomics own no heap. Exhaustive
// field coverage keeps these counters inside existing requested-layout budgets.
crate::heap_layout_bound::fields!(EfficiencyMode; operations, full_equivalent_bytes, native_bytes, guard_bytes);
crate::heap_layout_bound::fields!(AcquisitionEfficiency; version, paired_totals_valid, page_coverage_complete, full, tail, unchanged, attempts, superseded_attempts, unpaired_operations, unpaired_observed_native_bytes, unpaired_observed_guard_bytes, unknown_progress_operations, unsampled_operations, audit_full_operations, abandoned_pages_at_start, abandoned_pages_at_emit);
crate::heap_layout_bound::fields!(ReadOperation; current, native, guards, known);
crate::heap_layout_bound::fields!(EfficiencyPage; source_slot, totals, active, armed);

#[derive(Debug, Serialize)]
pub(crate) struct CollectionCounts {
    pub(crate) scanned_files: usize,
    pub(crate) semantic_noops: usize,
    /// Absent without sampled acquisition. Even when present, these are not
    /// total filesystem reads: byte counts exclude failed plans, joins,
    /// discovery and sidecars. Selection counts can include failed/repeated plans.
    pub(crate) sampled_acquisition: Option<ReadCounts>,
}
#[derive(Debug, Serialize)]
pub(crate) struct ReadCounts {
    pub(crate) acquisition_efficiency: AcquisitionEfficiency,
    pub(crate) full_selections: usize,
    pub(crate) tail_selections: usize,
    pub(crate) unchanged_selections: usize,
    pub(crate) completed_native_bytes: u64,
    pub(crate) completed_guard_bytes: u64,
    pub(crate) page_events: PageEvents,
    pub(crate) index_state_at_page_end: IndexState,
}
#[derive(Debug, Serialize)]
pub(crate) struct PageEvents {
    pub(crate) full_reasons: FullReasons,
    pub(crate) priority_full_replays: usize,
    pub(crate) audits_started: usize,
    pub(crate) audits_completed: usize,
    pub(crate) max_start_overdue_seconds: u64,
    pub(crate) max_completion_overdue_seconds: u64,
}
#[derive(Debug, Serialize)]
pub(crate) struct IndexState {
    pub(crate) pending_audits: usize,
    pub(crate) overdue_audits: usize,
    pub(crate) oldest_due_age_seconds: u64,
}
/// Reuse the existing counters; serialize only nonzero closed reason keys.
#[derive(Debug)]
pub(crate) struct FullReasons(pub(crate) [usize; 11]);
impl Serialize for FullReasons {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::transcript_acquisition::FullReason::*;
        let mut map = serializer.serialize_map(None)?;
        for (reason, key) in [
            (StateMissing, "state_missing"),
            (AuditDue, "audit_due"),
            (ClockChanged, "clock_changed"),
            (ScopeChanged, "scope_changed"),
            (InvalidCheckpoint, "invalid_checkpoint"),
            (Replaced, "replaced"),
            (Shrunk, "shrunk"),
            (SameSizeEdit, "same_size_edit"),
            (HeadChanged, "head_changed"),
            (BoundaryChanged, "boundary_changed"),
            (UnsupportedIdentity, "unsupported_identity"),
        ] {
            let count = self.0[reason.slot()];
            if count != 0 {
                map.serialize_entry(key, &count)?;
            }
        }
        map.end()
    }
}

#[derive(Debug, Default, Serialize)]
struct UploadCounts {
    serialized_body_bytes: Option<u64>,
    gzip_attempts: u64,
    identity_attempts: u64,
    attempted_encoded_body_bytes: u64,
    attempted_decoded_body_bytes: u64,
}
pub(crate) struct UploadCall {
    probe: Probe,
    source: Source,
    counts: UploadCounts,
}
impl UploadCall {
    pub(crate) fn start(source: &str) -> Self {
        Self {
            probe: Probe::start(),
            source: Source::from_slug(source),
            counts: UploadCounts::default(),
        }
    }
    pub(crate) fn serialized(&mut self, bytes: usize) {
        self.counts.serialized_body_bytes = Some(bytes as u64);
    }
    /// Call after request construction/validation, immediately before send_bytes.
    /// Counts attempted body buffers, not successfully delivered network bytes.
    pub(crate) fn attempt(&mut self, encoded_bytes: usize, gzip: bool) {
        let count = if gzip {
            &mut self.counts.gzip_attempts
        } else {
            &mut self.counts.identity_attempts
        };
        *count = count.saturating_add(1);
        self.counts.attempted_encoded_body_bytes = self
            .counts
            .attempted_encoded_body_bytes
            .saturating_add(encoded_bytes as u64);
        self.counts.attempted_decoded_body_bytes = self
            .counts
            .attempted_decoded_body_bytes
            .saturating_add(self.counts.serialized_body_bytes.unwrap_or(0));
    }
}
impl Drop for UploadCall {
    fn drop(&mut self) {
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "snapshot_batch_call",
            source: self.source,
            observation: self.probe.observation(),
            counts: &self.counts,
        });
    }
}

#[derive(Serialize)]
struct Record<T: Serialize> {
    schema_version: u8,
    process_id: u32,
    stage: &'static str,
    source: Source,
    observation: Observation,
    counts: T,
}
fn emit(record: &impl Serialize) {
    if let Ok(json) = serde_json::to_string(record) {
        #[cfg(test)]
        if TEST_OUTPUT.with(|output| {
            if let Some(output) = output.borrow_mut().as_mut() {
                output.push(json.clone());
                true
            } else {
                false
            }
        }) {
            return;
        }
        // Diagnostic sink failure must not change collection or ACK/recovery.
        write_line(&json, &mut std::io::stderr().lock());
    }
}

fn write_line(json: &str, writer: &mut impl Write) {
    let _ = writeln!(writer, "ottto-service: local_resources {json}");
}

#[cfg(test)]
thread_local! {
    static TEST_OUTPUT: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<serde_json::Value>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_OUTPUT.with(|output| *output.borrow_mut() = None);
        }
    }
    TEST_OUTPUT.with(|output| {
        assert!(output.borrow().is_none());
        *output.borrow_mut() = Some(Vec::new());
    });
    let _reset = Reset;
    let result = f();
    let output = TEST_OUTPUT.with(|output| output.borrow_mut().take().unwrap());
    (
        result,
        output
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(
        mode: crate::transcript_acquisition::ReadMode,
        length: u64,
        start: u64,
        native: u64,
        guards: usize,
    ) -> crate::transcript_acquisition::ReadMetrics {
        crate::transcript_acquisition::ReadMetrics {
            mode,
            source_bytes: length,
            start_offset: start,
            native_bytes: native,
            sample_bytes: guards,
            audit_due: None,
        }
    }
    fn measured(
        mode: crate::transcript_acquisition::ReadMode,
        length: u64,
        start: u64,
        native: u64,
        guards: usize,
    ) -> AcquisitionEfficiency {
        let mut p = EfficiencyPage::new("test");
        p.begin();
        p.prepared(input(mode, length, start, 0, guards));
        p.progress(Some(input(mode, length, start, native, guards)));
        p.finish(true);
        p.finish(true);
        p.complete()
    }
    #[test]
    fn efficiency_completed_modes_and_negative_guard_overhead() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let full = measured(ReadMode::Full(FullReason::StateMissing), 10000, 0, 10000, 0);
        assert_eq!(full.full.operations, 1);
        assert_eq!(full.full.full_equivalent_bytes, 10000);
        assert_eq!(full.full.native_bytes, 10000);
        assert!(full.paired_totals_valid);
        let tail = measured(ReadMode::Tail, 4096, 4086, 10, 8172);
        assert_eq!(tail.tail.operations, 1);
        assert_eq!(tail.tail.full_equivalent_bytes, 4096);
        assert_eq!(
            i128::from(tail.tail.full_equivalent_bytes)
                - i128::from(tail.tail.native_bytes)
                - i128::from(tail.tail.guard_bytes),
            -4086
        );
        let unchanged = measured(ReadMode::Unchanged, 10000, 10000, 0, 0);
        assert_eq!(unchanged.unchanged.operations, 1);
        assert_eq!(unchanged.unchanged.full_equivalent_bytes, 0);
    }
    #[test]
    fn efficiency_replay_has_one_denominator_and_all_attempt_work() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let mut p = EfficiencyPage::new("test");
        p.begin();
        p.prepared(input(ReadMode::Tail, 10000, 9900, 0, 8192));
        p.progress(Some(input(ReadMode::Tail, 10000, 9900, 100, 8192)));
        p.replay();
        p.prepared(input(
            ReadMode::Full(FullReason::StateMissing),
            10000,
            0,
            0,
            0,
        ));
        p.progress(Some(input(
            ReadMode::Full(FullReason::StateMissing),
            10000,
            0,
            10000,
            0,
        )));
        p.finish(true);
        let t = p.complete();
        assert_eq!(t.attempts, 2);
        assert_eq!(t.superseded_attempts, 1);
        assert_eq!(t.tail.operations, 0);
        assert_eq!(t.full.operations, 1);
        assert_eq!(t.full.full_equivalent_bytes, 10000);
        assert_eq!(t.full.native_bytes, 10100);
        assert_eq!(t.full.guard_bytes, 8192);
    }
    #[test]
    fn efficiency_failed_preparation_and_unfinished_operations_are_not_pairs() {
        use crate::transcript_acquisition::ReadMode;
        let mut p = EfficiencyPage::new("test");
        p.begin();
        p.preparation_failed(4096);
        p.begin();
        p.prepared(input(ReadMode::Tail, 10000, 9000, 0, 8192));
        p.progress(Some(input(ReadMode::Tail, 10000, 9000, 200, 8192)));
        // A new file closes the previous failed/early-return operation exactly once.
        p.begin();
        p.preparation_failed(0);
        let t = p.complete();
        assert_eq!(t.unpaired_operations, 3);
        assert_eq!(t.unpaired_observed_native_bytes, 200);
        assert_eq!(t.unpaired_observed_guard_bytes, 12288);
        assert!(!t.page_coverage_complete);
        assert_eq!(t.tail.operations, 0);
    }
    #[test]
    fn efficiency_unknown_or_changed_progress_is_unavailable() {
        use crate::transcript_acquisition::ReadMode;
        for next in [
            None,
            Some(input(ReadMode::Tail, 10001, 9000, 1001, 8192)),
            Some(input(ReadMode::Tail, 10000, 9000, 9, 8192)),
        ] {
            let mut p = EfficiencyPage::new("test");
            p.begin();
            p.prepared(input(ReadMode::Tail, 10000, 9000, 10, 8192));
            p.progress(next);
            p.finish(true);
            let t = p.complete();
            assert!(!t.paired_totals_valid);
            assert!(!t.page_coverage_complete);
            assert_eq!(t.unknown_progress_operations, 1);
            assert_eq!(t.tail.operations, 0);
        }
    }
    #[test]
    fn efficiency_overflow_refuses_totals_and_abandonment_counter_saturates() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let mut p = EfficiencyPage::new("test");
        p.begin();
        p.prepared(input(
            ReadMode::Full(FullReason::StateMissing),
            u64::MAX,
            0,
            u64::MAX,
            1,
        ));
        p.finish(true);
        assert!(!p.complete().paired_totals_valid);
        let counter = AbandonedPages::new();
        counter
            .count
            .store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(counter.value(), Some(u64::MAX));
        counter.note();
        assert_eq!(counter.value(), None);
        assert_eq!(
            counter.count.load(std::sync::atomic::Ordering::Relaxed),
            u64::MAX
        );
    }
    #[test]
    #[serial_test::serial(efficiency_drop)]
    fn efficiency_drop_is_silent_and_delayed_marker_is_process_lifetime() {
        let before = ABANDONED[3].value().unwrap();
        let (_, rows) = capture(|| {
            let page = EfficiencyPage::new("test");
            let moved = page;
            drop(moved);
            let second = EfficiencyPage::new("test");
            drop(second);
        });
        assert!(rows.is_empty());
        assert!(ABANDONED[3].value().unwrap() >= before + 2);
        let mut later = EfficiencyPage::new("test");
        let t = later.complete();
        assert!(t.abandoned_pages_at_start.unwrap() >= before + 2);
        assert_eq!(t.abandoned_pages_at_start, t.abandoned_pages_at_emit);
        assert!(ABANDONED[3].value().unwrap() >= before + 2); // never drained
    }
    #[test]
    #[serial_test::serial(efficiency_drop)]
    fn efficiency_completed_move_disarms_drop_without_emission() {
        let before = ABANDONED[3].value().unwrap();
        let (_, rows) = capture(|| {
            let page = EfficiencyPage::new("test");
            let mut moved = page;
            moved.complete();
            drop(moved);
        });
        assert!(rows.is_empty());
        assert_eq!(ABANDONED[3].value(), Some(before));
    }
    #[test]
    #[serial_test::serial(efficiency_drop)]
    fn efficiency_unwind_preserves_panic_and_only_marks_gap() {
        let before = ABANDONED[3].value().unwrap();
        let (result, rows) = capture(|| {
            std::panic::catch_unwind(|| {
                let mut page = EfficiencyPage::new("test");
                page.begin();
                std::panic::panic_any("synthetic original panic");
            })
        });
        assert_eq!(
            result.unwrap_err().downcast_ref::<&str>(),
            Some(&"synthetic original panic")
        );
        assert!(rows.is_empty());
        assert!(ABANDONED[3].value().unwrap() >= before + 1);
    }
    #[test]
    fn efficiency_unsampled_and_repeated_snapshot_are_explicit() {
        use crate::transcript_acquisition::ReadMode;
        let mut p = EfficiencyPage::new("test");
        p.begin();
        p.prepared(input(ReadMode::Tail, 10000, 9000, 50, 8192));
        p.progress(Some(input(ReadMode::Tail, 10000, 9000, 50, 8192)));
        p.progress(Some(input(ReadMode::Tail, 10000, 9000, 50, 8192)));
        p.finish(false);
        p.unsampled();
        let t = p.complete();
        assert_eq!(t.unpaired_observed_native_bytes, 50);
        assert_eq!(t.unpaired_observed_guard_bytes, 8192);
        assert_eq!(t.unsampled_operations, 1);
        assert!(!t.page_coverage_complete);
    }

    #[test]
    fn efficiency_inline_state_and_constant_progress_cost() {
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        use crate::transcript_acquisition::ReadMode;
        let mut page = EfficiencyPage::new("test");
        page.begin();
        page.prepared(input(ReadMode::Tail, 10000, 9000, 0, 8192));
        let mut c = Counter::new(1024);
        page.heap_bound(&mut c).unwrap();
        assert_eq!(c.bytes, 0);
        assert!(std::mem::size_of::<EfficiencyPage>() <= 512);
        let start = Instant::now();
        for _ in 0..100000 {
            std::hint::black_box(&mut page).progress(Some(input(
                ReadMode::Tail,
                10000,
                9000,
                100,
                8192,
            )));
        }
        eprintln!("EFFICIENCY_OVERHEAD retained_page_bytes={} stack_metrics_bytes={} progress_iterations=100000 elapsed_us={}", std::mem::size_of::<EfficiencyPage>(), std::mem::size_of::<crate::transcript_acquisition::ReadMetrics>(), start.elapsed().as_micros());
        page.finish(false);
        page.complete();
    }

    #[test]
    fn efficiency_worst_case_namespace_and_record_remain_bounded() {
        let mode = EfficiencyMode {
            operations: u64::MAX,
            full_equivalent_bytes: u64::MAX,
            native_bytes: u64::MAX,
            guard_bytes: u64::MAX,
        };
        let efficiency = AcquisitionEfficiency {
            version: 1,
            paired_totals_valid: false,
            page_coverage_complete: false,
            full: mode,
            tail: mode,
            unchanged: mode,
            attempts: u64::MAX,
            superseded_attempts: u64::MAX,
            unpaired_operations: u64::MAX,
            unpaired_observed_native_bytes: u64::MAX,
            unpaired_observed_guard_bytes: u64::MAX,
            unknown_progress_operations: u64::MAX,
            unsampled_operations: u64::MAX,
            audit_full_operations: u64::MAX,
            abandoned_pages_at_start: Some(u64::MAX),
            abandoned_pages_at_emit: Some(u64::MAX),
        };
        let mut reads = max_read_counts();
        reads.acquisition_efficiency = efficiency;
        let record = Record {
            schema_version: SCHEMA_VERSION,
            process_id: u32::MAX,
            stage: "native_collection_page",
            source: Source::ClaudeCode,
            observation: Observation {
                observed_unix_ms: Some(u64::MAX),
                wall_elapsed_us: u64::MAX,
                shared_process_cpu_delta_us: Some(u64::MAX),
                process_lifetime_max_rss_bytes: Some(u64::MAX),
                process_lifetime_max_rss_before_bytes: Some(u64::MAX),
            },
            counts: CollectionCounts {
                scanned_files: usize::MAX,
                semantic_noops: usize::MAX,
                sampled_acquisition: Some(reads),
            },
        };
        let text = serde_json::to_string(&record).unwrap();
        let namespace = serde_json::to_string(&efficiency).unwrap();
        assert!(text.len() < 4096);
        assert!(namespace.len() < 2048);
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy["counts"]["sampled_acquisition"]
            .as_object_mut()
            .unwrap()
            .remove("acquisition_efficiency");
        assert!(serde_json::to_string(&legacy).unwrap().len() < 2048);
        eprintln!(
            "EFFICIENCY_EVENT_SIZE worst_record_bytes={} namespace_bytes={}",
            text.len(),
            namespace.len()
        );
    }

    fn max_read_counts() -> ReadCounts {
        ReadCounts {
            acquisition_efficiency: AcquisitionEfficiency::default(),
            full_selections: (usize::MAX / 11) * 11,
            tail_selections: usize::MAX,
            unchanged_selections: usize::MAX,
            completed_native_bytes: u64::MAX,
            completed_guard_bytes: u64::MAX,
            page_events: PageEvents {
                full_reasons: FullReasons([usize::MAX / 11; 11]),
                priority_full_replays: usize::MAX,
                audits_started: usize::MAX,
                audits_completed: usize::MAX,
                max_start_overdue_seconds: u64::MAX,
                max_completion_overdue_seconds: u64::MAX,
            },
            index_state_at_page_end: IndexState {
                pending_audits: usize::MAX,
                overdue_audits: usize::MAX,
                oldest_due_age_seconds: u64::MAX,
            },
        }
    }

    fn assert_finish_record(record: &serde_json::Value, source: &str) {
        assert_eq!(record["schema_version"], SCHEMA_VERSION);
        assert_eq!(record["stage"], "source_finish");
        assert_eq!(record["source"], source);
        assert_eq!(record["counts"], serde_json::json!({}));
        assert!(record.get("result").is_none());
        println!("RESOURCE_V2_FINISH_FIXTURE {record}");
    }

    #[test]
    fn census_fence_events_have_closed_fields_and_bounded_encoding() {
        use crate::codex_scan_diagnostics::{
            CensusFenceOutcome as O, CensusFencePhase as P, CensusInvalidation as I,
        };
        let (_, rows) = capture(|| {
            for phase in [P::Outer, P::Inner] {
                for outcome in [
                    O::Passed,
                    O::Rejected,
                    O::Published,
                    O::ProjectionUnavailable,
                    O::ClockUnavailable,
                    O::EncodingFailed,
                    O::PrivateWriteFailed,
                ] {
                    for invalidation in [I::NotAttempted, I::Removed, I::AlreadyMissing, I::Failed]
                    {
                        codex_census_fence(phase, outcome, invalidation);
                    }
                }
            }
        });
        assert_eq!(rows.len(), 56);
        for row in rows {
            assert_eq!(row["stage"], "codex_census_fence");
            assert_eq!(row["source"], "codex");
            assert_eq!(row["observation"]["wall_elapsed_us"], 0);
            assert!(row["observation"]["shared_process_cpu_delta_us"].is_null());
            assert!(row["observation"]["process_lifetime_max_rss_bytes"].is_null());
            assert_eq!(row["counts"].as_object().unwrap().len(), 3);
            let text = serde_json::to_string(&row).unwrap();
            assert!(text.len() < 1024);
            for forbidden in [
                "namespace",
                "account",
                "path",
                "digest",
                "credential",
                "error",
            ] {
                assert!(!text.contains(forbidden));
            }
        }
    }

    #[test]
    #[ignore = "bounded native outcome carrier measurement"]
    fn census_fence_event_native_measurement() {
        use crate::codex_scan_diagnostics::{
            CensusFenceOutcome as O, CensusFencePhase as P, CensusInvalidation as I,
        };
        const ITERATIONS: usize = 256;
        // Warm the existing stderr handle before measuring the event path.
        codex_census_fence(P::Inner, O::Published, I::NotAttempted);
        let started = Instant::now();
        let (_, stats) = crate::retry_allocation_probe::measure(|| {
            for _ in 0..ITERATIONS {
                codex_census_fence(P::Inner, O::PrivateWriteFailed, I::Failed);
            }
        });
        assert_eq!(stats.requested_live, 0);
        assert!(stats.requested_peak_with_overlap < 2048);
        println!("CENSUS_FENCE_OVERHEAD iterations={ITERATIONS} elapsed_us={} peak_bytes={} allocations={} live_bytes={} includes_encoding_and_existing_stderr=true",
            started.elapsed().as_micros(), stats.requested_peak_with_overlap,
            stats.allocations, stats.requested_live);
    }

    #[test]
    fn resource_finish_success_preserves_value_and_contains_batch_window() {
        let value = Box::new(17);
        let original = std::ptr::from_ref(value.as_ref());
        let (result, records) = capture(|| {
            source_finish("claude_code", || {
                let mut upload = UploadCall::start("claude_code");
                upload.serialized(20);
                upload.attempt(20, false);
                Ok(value)
            })
        });
        assert_eq!(std::ptr::from_ref(result.unwrap().as_ref()), original);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["stage"], "snapshot_batch_call");
        assert_finish_record(&records[1], "claude_code");
        let batch = &records[0]["observation"];
        let finish = &records[1]["observation"];
        assert!(
            batch["wall_elapsed_us"].as_u64().unwrap()
                <= finish["wall_elapsed_us"].as_u64().unwrap()
        );
        // Unix timestamps are millisecond-granular; the monotonic span comparison
        // above remains valid independently of wall-clock resolution.
        assert!(
            batch["observed_unix_ms"].as_u64().unwrap()
                <= finish["observed_unix_ms"].as_u64().unwrap()
        );
    }

    #[test]
    fn resource_finish_error_preserves_typed_error_and_chain() {
        #[derive(Debug)]
        struct OriginalError(std::sync::Arc<()>);
        impl std::fmt::Display for OriginalError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("synthetic inner failure")
            }
        }
        impl std::error::Error for OriginalError {}
        let identity = std::sync::Arc::new(());
        let error =
            anyhow::Error::new(OriginalError(identity.clone())).context("synthetic context");
        let original_chain: Vec<_> = error.chain().map(ToString::to_string).collect();
        let (result, records) = capture(|| source_finish::<()>("codex", || Err(error)));
        let returned = result.unwrap_err();
        assert_eq!(
            returned
                .chain()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            original_chain
        );
        assert!(std::sync::Arc::ptr_eq(
            &returned.downcast_ref::<OriginalError>().unwrap().0,
            &identity
        ));
        assert_eq!(records.len(), 1);
        assert_finish_record(&records[0], "codex");
    }

    #[test]
    fn resource_finish_panic_preserves_payload_without_record() {
        let payload = std::sync::Arc::new("synthetic panic");
        let original = payload.clone();
        let (result, records) = capture(|| {
            std::panic::catch_unwind(|| {
                source_finish::<()>("pi", || std::panic::panic_any(payload))
            })
        });
        let panic = result.unwrap_err();
        assert!(std::sync::Arc::ptr_eq(
            panic.downcast_ref::<std::sync::Arc<&str>>().unwrap(),
            &original
        ));
        assert!(records.is_empty());
    }

    #[test]
    fn resource_reason_map_is_sparse_and_matches_existing_slots() {
        use crate::transcript_acquisition::FullReason::*;
        let mut counts = [0; 11];
        counts[StateMissing.slot()] = 2;
        counts[BoundaryChanged.slot()] = 3;
        assert_eq!(
            serde_json::to_value(FullReasons(counts)).unwrap(),
            serde_json::json!({"state_missing": 2, "boundary_changed": 3})
        );
        let all = serde_json::to_value(FullReasons([1; 11])).unwrap();
        let keys: Vec<_> = all
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "audit_due",
                "boundary_changed",
                "clock_changed",
                "head_changed",
                "invalid_checkpoint",
                "replaced",
                "same_size_edit",
                "scope_changed",
                "shrunk",
                "state_missing",
                "unsupported_identity"
            ]
        );
    }

    #[test]
    fn resource_log_sink_failure_does_not_escape() {
        struct FailedSink;
        impl Write for FailedSink {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "synthetic",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        write_line("{}", &mut FailedSink);
    }

    #[test]
    #[ignore = "bounded native measurement; process allocation scope needs serial isolation"]
    fn measure_local_resource_probe_overhead() {
        const ITERATIONS: u64 = 1000;
        for stage in ["native_collection_page", "source_finish"] {
            let process_before = process_sample();
            let wall = Instant::now();
            let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
                for _ in 0..ITERATIONS {
                    if stage == "source_finish" {
                        source_finish("claude_code", || Ok(())).unwrap();
                    } else {
                        Probe::start().collection(
                            "claude_code",
                            CollectionCounts {
                                scanned_files: usize::MAX,
                                semantic_noops: usize::MAX,
                                sampled_acquisition: Some(max_read_counts()),
                            },
                        );
                    }
                }
            });
            let wall_us = wall.elapsed().as_micros();
            let cpu_us = Observation::between(0, process_before, process_sample())
                .shared_process_cpu_delta_us;
            println!(
                "RESOURCE_PROBE_OVERHEAD {}",
                serde_json::json!({
                    "stage": stage, "iterations": ITERATIONS, "wall_us": wall_us,
                    "wall_us_per_record": wall_us as f64 / ITERATIONS as f64,
                    "shared_process_cpu_us": cpu_us,
                    "shared_process_cpu_us_per_record": cpu_us.map(|cpu| cpu as f64 / ITERATIONS as f64),
                    "probe_inline_bytes": std::mem::size_of::<Probe>(),
                    "upload_call_inline_bytes": std::mem::size_of::<UploadCall>(),
                    "scope_requested_allocation_peak_bytes": allocation.requested_peak,
                    "scope_requested_allocation_live_bytes": allocation.requested_live,
                    "includes_two_os_samples_json_encoding_and_existing_stderr_write": true,
                })
            );
        }
    }

    #[test]
    fn resource_unavailable_or_regressing_cpu_is_unknown_not_zero() {
        let sample = |cpu_us| {
            Some(ProcessSample {
                cpu_us,
                lifetime_max_rss_bytes: 4096,
            })
        };
        for (before, after) in [
            (None, sample(9)),
            (sample(10), None),
            (sample(10), sample(9)),
        ] {
            assert_eq!(
                Observation::between(12, before, after).shared_process_cpu_delta_us,
                None
            );
        }
        let result = Observation::between(12, sample(10), sample(17));
        assert_eq!(result.shared_process_cpu_delta_us, Some(7));
        assert_eq!(result.process_lifetime_max_rss_bytes, Some(4096));
        assert_eq!(result.process_lifetime_max_rss_before_bytes, Some(4096));
        for (before, after) in [
            (None, sample(9)),
            (sample(10), None),
            (
                sample(10),
                Some(ProcessSample {
                    cpu_us: 17,
                    lifetime_max_rss_bytes: 2048,
                }),
            ),
        ] {
            let record = serde_json::to_value(Observation::between(12, before, after)).unwrap();
            assert!(record["process_lifetime_max_rss_before_bytes"].is_null());
        }
        let rising = Observation::between(
            12,
            sample(10),
            Some(ProcessSample {
                cpu_us: 17,
                lifetime_max_rss_bytes: 8192,
            }),
        );
        assert_eq!(rising.process_lifetime_max_rss_before_bytes, Some(4096));
        assert_eq!(rising.process_lifetime_max_rss_bytes, Some(8192));
    }
    #[test]
    fn resource_attempts_count_fallback_and_presend_refusal_without_content() {
        let (_, records) = capture(|| {
            Probe::start().collection(
                "secret/path/provider",
                CollectionCounts {
                    scanned_files: usize::MAX,
                    semantic_noops: usize::MAX,
                    sampled_acquisition: Some(max_read_counts()),
                },
            );
            source_finish("secret/path/provider", || Ok(())).unwrap();
            let mut upload = UploadCall::start("secret/path/provider");
            upload.serialized(1000);
            upload.attempt(100, true);
            upload.attempt(1000, false);
            let mut refused = UploadCall::start("codex");
            refused.serialized(500);
        });
        assert_eq!(records[2]["counts"]["identity_attempts"], 0);
        assert_eq!(records[2]["counts"]["attempted_encoded_body_bytes"], 0);
        assert_eq!(records[3]["counts"]["gzip_attempts"], 1);
        assert_eq!(records[3]["counts"]["identity_attempts"], 1);
        assert_eq!(records[3]["counts"]["attempted_encoded_body_bytes"], 1100);
        assert_eq!(records[3]["counts"]["attempted_decoded_body_bytes"], 2000);
        assert_eq!(records[3]["source"], "unknown");
        for record in records {
            let text = serde_json::to_string(&record).unwrap();
            assert!(text.len() < 4096);
            let mut legacy = record.clone();
            if let Some(reads) = legacy["counts"]["sampled_acquisition"].as_object_mut() {
                reads.remove("acquisition_efficiency");
            }
            assert!(serde_json::to_string(&legacy).unwrap().len() < 2048);
            assert!(!text.contains("secret/path"));
            assert!(!text.contains("cycle_peak"));
            assert_eq!(record["schema_version"], SCHEMA_VERSION);
        }
    }
}
