//! Counts-only additions to the existing resource carrier. Process totals
//! drained by Claude source_finish; zero keys are absent. Not I/O permission.
use std::collections::BTreeMap;
#[cfg(not(test))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
const KEYS: [&str; 35] = [
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
    "sidecar_s2_hold_entities",
    "sidecar_s2_hold_oldest_age",
    "sidecar_hold_newer_format",
    "sidecar_state_fix_rebuilds",
    "sidecar_u_growth_full_undecodable",
    "sidecar_u_growth_full_unbindable",
    "sidecar_pace_evicted",
    "sidecar_s2_hold_alarm",
    "sidecar_pace_alarm",
];
#[cfg(not(test))]
static COUNTS: [AtomicU64; 35] = [const { AtomicU64::new(0) }; 35];
#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::RefCell<[u64; 35]> = const { std::cell::RefCell::new([0; 35]) };
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
pub(super) fn record_holds(count: u64, age: u64) {
    COUNTS.with(|counts| {
        let mut counts = counts.borrow_mut();
        counts[26] = count;
        counts[27] = age;
        counts[33] = u64::from(age > 24 * 60 * 60);
    });
}
#[cfg(all(test, unix))]
pub(super) fn extra(key: &'static str, value: u64) {
    let index = KEYS
        .iter()
        .position(|name| *name == key)
        .expect("registered count");
    COUNTS.with(|counts| {
        let mut counts = counts.borrow_mut();
        counts[index] = counts[index].saturating_add(value);
        if key == "sidecar_pace_evicted" {
            counts[34] = 1;
        }
    });
}
pub(super) fn take() -> BTreeMap<&'static str, u64> {
    #[cfg(not(test))]
    let values: [u64; 35] = std::array::from_fn(|index| COUNTS[index].swap(0, Relaxed));
    #[cfg(test)]
    let values = COUNTS.with(|counts| std::mem::replace(&mut *counts.borrow_mut(), [0; 35]));
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
