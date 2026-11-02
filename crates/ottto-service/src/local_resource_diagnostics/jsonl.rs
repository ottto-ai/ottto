//! Per-page, counts-only observations. Never admission authority or wire state.
use super::*;
use serde_json::Value;
use std::cell::Cell;
use std::sync::Mutex;

#[derive(Clone, Copy, Default, Serialize)]
struct Counts {
    max_line_bytes: u64,
    lines_over_16_mib: u64,
    lines_over_64_mib: u64,
    lines_over_256_mib: u64,
    failure_tracking_evictions: u64,
    max_line_buffer_bytes: u64,
    parse_peak_estimated_bytes: u64,
}

#[derive(Clone, Copy)]
struct Failure {
    file: [u8; 32],
    offset: u64,
    attempts: u64,
}
thread_local! {
    static PAGES: Cell<[Counts; 3]> = const { Cell::new([Counts { max_line_bytes: 0, lines_over_16_mib: 0, lines_over_64_mib: 0, lines_over_256_mib: 0, failure_tracking_evictions: 0, max_line_buffer_bytes: 0, parse_peak_estimated_bytes: 0 }; 3]) };
    static SOURCE: Cell<&'static str> = const { Cell::new("unknown") };
}

// Fixed process-wide telemetry storage survives continuation workers.
static FAILURES: Mutex<FailureTracker> = Mutex::new(FailureTracker::new());

fn slot(source: &str) -> Option<usize> {
    match source {
        "codex" => Some(0),
        "claude_code" => Some(1),
        "pi" => Some(2),
        _ => None,
    }
}

pub(crate) fn begin_page(source: &str) {
    if let Some(at) = slot(source) {
        PAGES.with(|pages| {
            let mut counts = pages.get();
            counts[at] = Counts::default();
            pages.set(counts);
        });
    }
}

pub(crate) fn emit_page(source: &str, probe: &Probe) {
    let counts = slot(source).map(|at| PAGES.with(|pages| pages.get()[at]));
    if let Some(counts) =
        counts.filter(|counts| counts.max_line_bytes > 0 || counts.max_line_buffer_bytes > 0)
    {
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "jsonl_page",
            source: Source::from_slug(source),
            observation: probe.observation(),
            counts,
        });
    }
    begin_page(source);
}

pub(crate) struct Scope(&'static str);
impl Scope {
    pub(crate) fn begin(source: &str) -> Self {
        let source = match source {
            "codex" => "codex",
            "claude_code" => "claude_code",
            "pi" => "pi",
            _ => "unknown",
        };
        Self(SOURCE.with(|current| current.replace(source)))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        SOURCE.with(|source| source.set(self.0));
    }
}

/// Source rotation may interleave steps; each source keeps separate page totals.
pub(crate) fn page<T>(source: &str, inner: impl FnOnce() -> T) -> T {
    let _scope = Scope::begin(source);
    inner()
}

/// One synchronous reader page; the collection scheduler uses its existing probe instead.
pub(crate) struct Page {
    source: &'static str,
    probe: Probe,
    _scope: Scope,
}
impl Page {
    pub(crate) fn begin(source: &'static str) -> Self {
        begin_page(source);
        Self {
            source,
            probe: Probe::start(),
            _scope: Scope::begin(source),
        }
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            emit_page(self.source, &self.probe);
        }
    }
}

fn update(change: impl FnOnce(&mut Counts)) {
    if let Some(at) = SOURCE.with(|source| slot(source.get())) {
        PAGES.with(|pages| {
            let mut counts = pages.get();
            change(&mut counts[at]);
            pages.set(counts);
        });
    }
}

/// Record raw size before parsing, including lines that fail JSON decoding.
pub(crate) fn line(bytes: usize) {
    update(|counts| {
        counts.max_line_bytes = counts.max_line_bytes.max(bytes as u64);
        counts.lines_over_16_mib += u64::from(bytes > 16 * 1024 * 1024);
        counts.lines_over_64_mib += u64::from(bytes > 64 * 1024 * 1024);
        counts.lines_over_256_mib += u64::from(bytes > 256 * 1024 * 1024);
    });
}

/// Requested buffer capacity plus estimated DOM storage, not RSS or an upper bound.
pub(crate) fn parse_peak(buffer: usize, value: Option<&Value>) {
    update(|counts| {
        counts.max_line_buffer_bytes = counts.max_line_buffer_bytes.max(buffer as u64);
        let bytes = buffer.saturating_add(value.map_or(0, estimated_value_bytes));
        counts.parse_peak_estimated_bytes = counts.parse_peak_estimated_bytes.max(bytes as u64);
    });
}

fn estimated_value_bytes(value: &Value) -> usize {
    use std::mem::size_of;
    let heap = match value {
        Value::String(text) => text.capacity(),
        Value::Array(values) => values
            .capacity()
            .saturating_sub(values.len())
            .saturating_mul(size_of::<Value>())
            .saturating_add(values.iter().fold(0usize, |sum, value| {
                sum.saturating_add(estimated_value_bytes(value))
            })),
        // BTree node occupancy and allocator overhead vary: this remains explicitly an estimate.
        Value::Object(values) => values.iter().fold(0usize, |sum, (key, value)| {
            sum.saturating_add(size_of::<String>() + 3 * size_of::<usize>())
                .saturating_add(key.capacity())
                .saturating_add(estimated_value_bytes(value))
        }),
        _ => 0,
    };
    size_of::<Value>().saturating_add(heap)
}

/// Alarm once on the third consecutive failure of the same file/offset.
/// No retries, skips, holds or collection decisions originate here.
pub(crate) fn parse_result(file: [u8; 32], offset: u64, failed: bool) {
    let source = SOURCE.with(Cell::get);
    let Some(slot) = slot(source) else {
        return;
    };
    let (alarm, evicted) = FAILURES
        .lock()
        .map(|mut failures| failures.observe(slot, file, offset, failed))
        .unwrap_or((false, false));
    update(|counts| {
        counts.failure_tracking_evictions = counts
            .failure_tracking_evictions
            .saturating_add(u64::from(evicted));
    });
    if alarm {
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "jsonl_repeat_parse_failure_alarm",
            source: Source::from_slug(source),
            observation: Probe::start().stage_observation(None),
            counts: BTreeMap::from([("consecutive_failures", 3u64)]),
        });
    }
}

struct FailureTracker {
    entries: [[Option<Failure>; 64]; 3],
    next: [usize; 3],
}
impl FailureTracker {
    const fn new() -> Self {
        Self {
            entries: [[None; 64]; 3],
            next: [0; 3],
        }
    }
    fn observe(
        &mut self,
        source: usize,
        file: [u8; 32],
        offset: u64,
        failed: bool,
    ) -> (bool, bool) {
        let entries = &mut self.entries[source];
        let at = entries.iter().position(|entry| {
            entry.is_some_and(|entry| entry.file == file && entry.offset == offset)
        });
        if !failed {
            if let Some(at) = at {
                entries[at] = None;
            }
            return (false, false);
        }
        let at = at
            .or_else(|| entries.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                let at = self.next[source];
                self.next[source] = (at + 1) % entries.len();
                at
            });
        let previous = entries[at];
        let matching = previous.filter(|entry| entry.file == file && entry.offset == offset);
        let attempts = matching.map_or(1, |entry| entry.attempts.saturating_add(1));
        entries[at] = Some(Failure {
            file,
            offset,
            attempts,
        });
        (attempts == 3, previous.is_some() && matching.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [behaviour] Repeated failures alarm once, survive interleaved records and reset on success.
    #[test]
    fn repeated_parse_failure_alarm_is_observation_only() {
        let mut tracker = FailureTracker::new();
        for attempt in 1..=5 {
            assert_eq!(tracker.observe(0, [1; 32], 8, true), (attempt == 3, false));
            assert_eq!(tracker.observe(0, [2; 32], 16, true), (attempt == 3, false));
        }
        assert_eq!(tracker.observe(0, [1; 32], 8, false), (false, false));
        assert_eq!(tracker.observe(0, [1; 32], 8, true), (false, false));
        assert_eq!(tracker.observe(1, [2; 32], 16, true), (false, false));
    }
}
