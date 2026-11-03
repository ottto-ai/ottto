//! Per-source scalars for existing page records. Never admission authority or wire state.
use super::*;
use std::cell::Cell;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, Default, Serialize)]
pub(crate) struct Counts {
    #[serde(skip_serializing_if = "is_zero")]
    max_line_bytes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    lines_over_16_mib: u64,
    #[serde(skip_serializing_if = "is_zero")]
    max_line_buffer_bytes: u64,
    #[serde(skip)]
    parse_failures: u64,
}

impl Counts {
    /// The page's line sizes as their own record after `native_collection_page`,
    /// which keeps that line under its size bound. Nothing when every size is zero.
    pub(super) fn emit_page_lines(&self, source: &str) {
        if self.max_line_bytes == 0
            && self.lines_over_16_mib == 0
            && self.max_line_buffer_bytes == 0
        {
            return;
        }
        emit(&Record {
            schema_version: SCHEMA_VERSION,
            process_id: std::process::id(),
            stage: "native_collection_jsonl_lines",
            source: Source::from_slug(source),
            observation: Observation::point(),
            counts: self,
        });
    }
    /// One line when the malformed/UTF-8 counters rise on consecutive pages.
    /// Scheduling, reads and retries never depend on it.
    pub(super) fn alarm_on_consecutive_failures(&self, source: &str) {
        let Some(at) = slot(source) else {
            return;
        };
        let failed = self.parse_failures > 0;
        if with_prior_page_failed(|prior| prior[at].swap(failed, Relaxed)) && failed {
            emit(&Record {
                schema_version: SCHEMA_VERSION,
                process_id: std::process::id(),
                stage: "jsonl_repeat_parse_failure_alarm",
                source: Source::from_slug(source),
                observation: Observation::point(),
                counts: BTreeMap::from([("parse_failures", self.parse_failures)]),
            });
        }
    }
}

const NO_COUNTS: Counts = Counts {
    max_line_bytes: 0,
    lines_over_16_mib: 0,
    max_line_buffer_bytes: 0,
    parse_failures: 0,
};
thread_local! {
    static PAGES: Cell<[Counts; 3]> = const { Cell::new([NO_COUNTS; 3]) };
    static SOURCE: Cell<&'static str> = const { Cell::new("unknown") };
}
// Process-wide: a continuation page runs on its own short-lived worker thread.
#[cfg(not(test))]
static PRIOR_PAGE_FAILED: [AtomicBool; 3] = [const { AtomicBool::new(false) }; 3];
#[cfg(test)]
thread_local! {
    static PRIOR_PAGE_FAILED: [AtomicBool; 3] = const { [const { AtomicBool::new(false) }; 3] };
}
fn with_prior_page_failed<T>(f: impl FnOnce(&[AtomicBool; 3]) -> T) -> T {
    #[cfg(test)]
    {
        PRIOR_PAGE_FAILED.with(f)
    }
    #[cfg(not(test))]
    {
        f(&PRIOR_PAGE_FAILED)
    }
}

fn slot(source: &str) -> Option<usize> {
    match source {
        "codex" => Some(0),
        "claude_code" => Some(1),
        "pi" => Some(2),
        _ => None,
    }
}

/// This page's counts for `source`, leaving it empty.
pub(super) fn take(source: &str) -> Counts {
    slot(source).map_or_else(Counts::default, |at| {
        PAGES.with(|pages| {
            let mut counts = pages.get();
            let taken = std::mem::take(&mut counts[at]);
            pages.set(counts);
            taken
        })
    })
}

pub(crate) struct Scope {
    previous: &'static str,
    source: &'static str,
}
impl Scope {
    pub(crate) fn begin(source: &str) -> Self {
        let source = match source {
            "codex" => "codex",
            "claude_code" => "claude_code",
            "pi" => "pi",
            _ => "unknown",
        };
        Self {
            previous: SOURCE.with(|current| current.replace(source)),
            source,
        }
    }
    pub(super) fn take(&self) -> Counts {
        take(self.source)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        SOURCE.with(|source| source.set(self.previous));
    }
}

/// Source rotation may interleave steps; each source keeps separate page totals.
pub(crate) fn page<T>(source: &str, inner: impl FnOnce() -> T) -> T {
    let _scope = Scope::begin(source);
    inner()
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

/// Raw size before parsing, including lines that fail JSON decoding.
pub(crate) fn line(bytes: usize) {
    update(|counts| {
        counts.max_line_bytes = counts.max_line_bytes.max(bytes as u64);
        counts.lines_over_16_mib += u64::from(bytes > crate::snapshots::LINE_BUFFER_RELEASE_BYTES);
    });
}

/// Line-buffer capacity: not RSS, parsed-value storage or an upper bound.
pub(crate) fn line_buffer(capacity: usize) {
    update(|counts| {
        counts.max_line_buffer_bytes = counts.max_line_buffer_bytes.max(capacity as u64);
    });
}

/// A rise of the existing malformed or invalid UTF-8 counter.
pub(crate) fn parse_failure() {
    update(|counts| counts.parse_failures += 1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [behaviour] Only a failure on the page right after a failed page alarms.
    #[test]
    fn consecutive_failed_pages_alarm() {
        let page = |failed: bool| {
            let scope = Scope::begin("codex");
            if failed {
                parse_failure();
            }
            scope.take().alarm_on_consecutive_failures("codex");
        };
        let ((), rows) = capture(|| {
            // Reset first: a serial test run reuses one thread.
            page(false);
            page(true);
            page(false);
            page(true);
            page(true);
        });
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["stage"], "jsonl_repeat_parse_failure_alarm");
        assert_eq!(rows[0]["counts"]["parse_failures"], 1);
    }
}
