//! Counts-only additions to the existing resource carrier. Process totals
//! drained by Claude source_finish; zero keys are absent. Not I/O permission.
use std::collections::BTreeMap;
#[cfg(not(test))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
const KEYS: [&str; 27] = [
    "sidecar_api_selected",
    "sidecar_api_opened",
    "sidecar_api_bytes_read",
    "sidecar_api_guard_bytes",
    "sidecar_api_reuse_hits",
    "sidecar_api_unchanged_reads",
    "sidecar_api_bootstraps",
    "sidecar_api_bootstrap_deferred",
    "sidecar_api_rewrite_rebuilds",
    "sidecar_api_fragments",
    "sidecar_api_fragment_reread_bytes",
    "sidecar_api_failures",
    "sidecar_api_persistent_failures",
    "sidecar_trace_selected",
    "sidecar_trace_opened",
    "sidecar_trace_bytes_read",
    "sidecar_trace_guard_bytes",
    "sidecar_trace_reuse_hits",
    "sidecar_trace_unchanged_reads",
    "sidecar_trace_bootstraps",
    "sidecar_trace_bootstrap_deferred",
    "sidecar_trace_rewrite_rebuilds",
    "sidecar_trace_fragments",
    "sidecar_trace_fragment_reread_bytes",
    "sidecar_trace_failures",
    "sidecar_trace_persistent_failures",
    "sidecar_accepted_body_holds",
];
#[cfg(not(test))]
static COUNTS: [AtomicU64; 27] = [const { AtomicU64::new(0) }; 27];
#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::RefCell<[u64; 27]> = const { std::cell::RefCell::new([0; 27]) };
}
#[cfg(all(test, unix))]
pub(super) fn record(kind: usize, fields: [u64; 13]) {
    COUNTS.with(|counts| {
        for (counter, value) in counts.borrow_mut()[kind * 13..(kind + 1) * 13]
            .iter_mut()
            .zip(fields)
        {
            *counter = counter.saturating_add(value);
        }
    });
}
#[cfg(all(test, unix))]
pub(super) fn record_holds(count: u64) {
    COUNTS.with(|counts| {
        let mut counts = counts.borrow_mut();
        counts[26] = counts[26].saturating_add(count);
    });
}
pub(super) fn take() -> BTreeMap<&'static str, u64> {
    #[cfg(not(test))]
    let values: [u64; 27] = std::array::from_fn(|index| COUNTS[index].swap(0, Relaxed));
    #[cfg(test)]
    let values = COUNTS.with(|counts| std::mem::take(&mut *counts.borrow_mut()));
    let mut counts: BTreeMap<_, _> = KEYS
        .into_iter()
        .zip(values)
        .filter(|(_, value)| *value > 0)
        .collect();
    if counts.contains_key("sidecar_api_persistent_failures")
        || counts.contains_key("sidecar_trace_persistent_failures")
    {
        counts.insert("sidecar_read_alarm", 1);
    }
    counts
}
