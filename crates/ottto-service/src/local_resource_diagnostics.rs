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
#[derive(Serialize)]
struct EmptyCounts {}

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
    fn max_read_counts() -> ReadCounts {
        ReadCounts {
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
        assert!(
            rising.process_lifetime_max_rss_before_bytes <= rising.process_lifetime_max_rss_bytes
        );
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
            assert!(text.len() < 2048);
            assert!(!text.contains("secret/path"));
            assert!(!text.contains("cycle_peak"));
            assert_eq!(record["schema_version"], SCHEMA_VERSION);
        }
    }
}
