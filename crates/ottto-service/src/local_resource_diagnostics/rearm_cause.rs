//! Process-local clear provenance. Never serialized with an index or upload.
//! Sync reloads indexes between pages, so skipped entry fields are insufficient.
use crate::snapshots::{CandidateParseReason, ScanIndex, ScanIndexEntry};
use crate::transcript_acquisition::ReadMode;
use serde::{ser::SerializeMap, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    NoRetainedTraversal,
    ContextChanged,
    TerminalUnhealthyRetry,
    CarryInvalidation,
    AuditCapDelay,
}
const CAUSES: [(Cause, &str); 5] = [
    (
        Cause::NoRetainedTraversal,
        "rearm_cleared{no_retained_traversal}",
    ),
    (Cause::ContextChanged, "rearm_cleared{context_changed}"),
    (
        Cause::TerminalUnhealthyRetry,
        "rearm_cleared{terminal_unhealthy_retry}",
    ),
    (
        Cause::CarryInvalidation,
        "rearm_cleared{carry_invalidation}",
    ),
    (Cause::AuditCapDelay, "rearm_cleared{audit_cap_delay}"),
];
#[derive(Default)]
struct Tags(BTreeMap<String, Cause>);
impl Tags {
    fn retain(&mut self, index: &ScanIndex) {
        self.0.retain(|key, _| {
            index
                .files
                .get(key)
                .is_some_and(crate::snapshots::ScanIndexEntry::rearmed)
        });
    }
}
#[cfg(not(test))]
fn with_tags<T>(f: impl FnOnce(&mut Tags) -> T) -> T {
    static TAGS: std::sync::Mutex<Tags> = std::sync::Mutex::new(Tags(BTreeMap::new()));
    f(&mut TAGS.lock().unwrap_or_else(|error| error.into_inner()))
}
#[cfg(test)]
fn with_tags<T>(f: impl FnOnce(&mut Tags) -> T) -> T {
    thread_local! { static TAGS: std::cell::RefCell<Tags> = std::cell::RefCell::default(); }
    TAGS.with(|tags| f(&mut tags.borrow_mut()))
}
/// Prune before each clear pass and at page completion: keys are a subset of
/// the current index, one small enum per outstanding clear, no history list.
pub(crate) fn retain(index: &ScanIndex) {
    with_tags(|tags| tags.retain(index));
}
pub(crate) fn clear(key: &str, entry: &mut ScanIndexEntry, cause: Cause) {
    clear_owed(
        key,
        entry,
        cause,
        crate::snapshots::evidence_owed::owes(cause),
    );
}
/// `owe`: evidence owed ON decided this re-arm owes evidence (keeps the
/// fingerprint) instead of clearing it.
pub(crate) fn clear_owed(key: &str, entry: &mut ScanIndexEntry, cause: Cause, owe: bool) {
    if !entry.rearmed() {
        with_tags(|tags| {
            tags.0.insert(key.to_owned(), cause);
        });
    }
    crate::snapshots::evidence_owed::keep_or_clear(entry, owe);
}
pub(crate) fn reproven(key: &str) {
    with_tags(|tags| {
        tags.0.remove(key);
    });
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(super) struct Total {
    pub(super) count: u64,
    pub(super) completed_native_bytes: u64,
}
/// Fixed page aggregates; the underlying acquisition full_reasons stay intact.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counts([Total; CAUSES.len()]);
impl Counts {
    pub(crate) fn is_empty(&self) -> bool {
        self.0
            .iter()
            .all(|n| n.count == 0 && n.completed_native_bytes == 0)
    }
}
// Both fixed aggregates share the existing page registry. Keep them outside
// Probe/OwnedSourceScan so diagnostic growth does not alter admission layout.
#[derive(Default)]
struct Page {
    causes: Counts,
    parse_reasons: super::claude_reread::FullByParseReason,
}
// Probe::drop releases the page, including early exits.
fn with_pages<T>(f: impl FnOnce(&mut BTreeMap<Instant, Page>) -> T) -> T {
    static PAGES: std::sync::Mutex<BTreeMap<Instant, Page>> =
        std::sync::Mutex::new(BTreeMap::new());
    f(&mut PAGES.lock().unwrap_or_else(|error| error.into_inner()))
}
pub(crate) fn selected(page: Instant, key: &str, mode: ReadMode) {
    if matches!(mode, ReadMode::Full(_)) {
        if let Some(cause) = with_tags(|tags| tags.0.get(key).copied()) {
            with_pages(|pages| {
                let n = &mut pages.entry(page).or_default().causes.0[cause as usize];
                n.count = n.count.saturating_add(1);
            });
        }
    }
}
pub(crate) fn completed(page: Instant, key: &str, mode: ReadMode, native_bytes: u64) {
    let cause = with_tags(|tags| tags.0.remove(key));
    if let Some(cause) = cause.filter(|_| matches!(mode, ReadMode::Full(_))) {
        with_pages(|pages| {
            let n = &mut pages.entry(page).or_default().causes.0[cause as usize];
            n.completed_native_bytes = n.completed_native_bytes.saturating_add(native_bytes);
        });
    }
}
pub(crate) fn record_parse_reason(
    page: Instant,
    reason: CandidateParseReason,
    count: u64,
    native_bytes: u64,
) {
    with_pages(|pages| {
        pages
            .entry(page)
            .or_default()
            .parse_reasons
            .record(reason, count, native_bytes)
    });
}
pub(crate) fn page(page: Instant) -> Counts {
    with_pages(|pages| pages.get(&page).map(|page| page.causes).unwrap_or_default())
}
pub(crate) fn full_by_parse_reason(page: Instant) -> super::claude_reread::FullByParseReason {
    with_pages(|pages| {
        pages
            .get(&page)
            .map(|page| page.parse_reasons)
            .unwrap_or_default()
    })
}
pub(crate) fn finish_page(page: Instant) {
    with_pages(|pages| {
        pages.remove(&page);
    });
}

impl Serialize for Counts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (cause, label) in CAUSES {
            let total = &self.0[cause as usize];
            if total.count != 0 || total.completed_native_bytes != 0 {
                map.serialize_entry(label, total)?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_acquisition::FullReason;

    #[test]
    fn tags_are_process_local_and_pruned_to_the_index() {
        let key = "synthetic-cleared-file";
        let mut tags = Tags::default();
        tags.0.insert(key.into(), Cause::CarryInvalidation);
        assert!(
            Tags::default().0.is_empty(),
            "a restarted process has no tags"
        );
        tags.retain(&ScanIndex::default());
        assert!(tags.0.is_empty(), "removed index keys cannot accumulate");
    }

    #[test]
    fn unrelated_fulls_and_reproven_files_have_no_label() {
        let key = "unrelated-full";
        let probe = super::super::Probe::start();
        let mode = ReadMode::Full(FullReason::AuditDue);
        probe.rearm_full_selected(key, mode);
        probe.rearm_full_completed(key, mode, 456);
        assert!(probe.rearm_fulls().is_empty());
        with_tags(|tags| {
            tags.0.insert(key.into(), Cause::ContextChanged);
        });
        probe.rearm_full_completed(key, ReadMode::Unchanged, 0);
        probe.rearm_full_selected(key, mode);
        probe.rearm_full_completed(key, mode, 456);
        assert!(
            probe.rearm_fulls().is_empty(),
            "a non-Full re-proof consumes the tag too"
        );
    }
}

#[cfg(test)]
mod page_lifetime_tests {
    use super::*;
    #[test]
    fn early_probe_drop_releases_page_aggregates() {
        let probe = super::super::Probe::start();
        let key = "probe-lifetime";
        with_tags(|tags| {
            tags.0.insert(key.into(), Cause::CarryInvalidation);
        });
        probe.rearm_full_selected(
            key,
            ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing),
        );
        assert!(!probe.rearm_fulls().is_empty());
        let page_id = probe.started;
        drop(probe);
        assert!(page(page_id).is_empty());
        reproven(key);
    }
}
