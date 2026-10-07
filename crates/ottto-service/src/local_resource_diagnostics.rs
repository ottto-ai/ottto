//! Content-free observations in the existing local service log, never wire data.
//! CPU includes concurrent process work; maximum RSS is a lifetime high-water mark.
use serde::Serialize;
use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
            schema_version: 1,
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
        }
    }
}

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
            schema_version: 1,
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
        let process_before = process_sample();
        let wall = Instant::now();
        let (_, allocation) = crate::retry_allocation_probe::measure_process(|| {
            for _ in 0..ITERATIONS {
                Probe::start().collection(
                    "claude_code",
                    CollectionCounts {
                        scanned_files: usize::MAX,
                        semantic_noops: usize::MAX,
                        sampled_acquisition: Some(ReadCounts {
                            full_selections: usize::MAX,
                            tail_selections: usize::MAX,
                            unchanged_selections: usize::MAX,
                            completed_native_bytes: u64::MAX,
                            completed_guard_bytes: u64::MAX,
                        }),
                    },
                );
            }
        });
        let wall_us = wall.elapsed().as_micros();
        let cpu_us =
            Observation::between(0, process_before, process_sample()).shared_process_cpu_delta_us;
        println!(
            "RESOURCE_PROBE_OVERHEAD {}",
            serde_json::json!({
                "iterations": ITERATIONS, "wall_us": wall_us,
                "shared_process_cpu_us": cpu_us, "probe_inline_bytes": std::mem::size_of::<Probe>(),
                "upload_call_inline_bytes": std::mem::size_of::<UploadCall>(),
                "scope_requested_allocation_peak_bytes": allocation.requested_peak,
                "scope_requested_allocation_live_bytes": allocation.requested_live,
                "includes_two_os_samples_json_encoding_and_existing_stderr_write": true,
            })
        );
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
    }
    #[test]
    fn resource_attempts_count_fallback_and_presend_refusal_without_content() {
        let (_, records) = capture(|| {
            let mut upload = UploadCall::start("secret/path/provider");
            upload.serialized(1000);
            upload.attempt(100, true);
            upload.attempt(1000, false);
            let mut refused = UploadCall::start("codex");
            refused.serialized(500);
        });
        assert_eq!(records[0]["counts"]["identity_attempts"], 0);
        assert_eq!(records[0]["counts"]["attempted_encoded_body_bytes"], 0);
        assert_eq!(records[1]["counts"]["gzip_attempts"], 1);
        assert_eq!(records[1]["counts"]["identity_attempts"], 1);
        assert_eq!(records[1]["counts"]["attempted_encoded_body_bytes"], 1100);
        assert_eq!(records[1]["counts"]["attempted_decoded_body_bytes"], 2000);
        assert_eq!(records[1]["source"], "unknown");
        for record in records {
            let text = serde_json::to_string(&record).unwrap();
            assert!(text.len() < 2048);
            assert!(!text.contains("secret/path"));
            assert!(!text.contains("cycle_peak"));
        }
    }
}
