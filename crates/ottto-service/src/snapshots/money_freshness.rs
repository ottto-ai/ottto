//! Freshness diagnostics; none grants a read, alters a hold or adds a read.
//! `freshness_alarm` is each source's age of the oldest change not yet settled,
//! derived from stored stamps and live mtimes, so it survives restarts. `Counts`
//! are count-only Claude gauges over the bounded FirstPending stamps. Startup
//! policy probes only its support-directory sentinel once.
use super::SnapshotSource;
use serde::Serialize;
use std::path::Path;

const ALARM_AFTER: u64 = 6 * 60 * 60;

/// One root walk's fold of indexed files whose live stamp differs from the
/// stored settled stamp. A walk spans passes and every pass reloads the index,
/// so the fold stays in this process until the walk ends. Its inputs are
/// durable: only a restart mid-walk loses the pages already walked.
#[derive(Debug, Clone, Copy)]
pub(super) struct WalkFold {
    age_s: u64,
    changed_files: u64,
    over_6h_files: u64,
    unindexed_over_6h: u64,
}
impl WalkFold {
    const EMPTY: Self = Self {
        age_s: 0,
        changed_files: 0,
        over_6h_files: 0,
        unindexed_over_6h: 0,
    };

    pub(super) fn resume(source: SnapshotSource) -> Self {
        with_walks(|walks| std::mem::replace(&mut walks[source as usize], Self::EMPTY))
    }

    /// `settled` is whether the stored stamp matches; None is an unindexed file.
    pub(super) fn file(&mut self, settled: Option<bool>, age_s: u64) {
        let over_6h = u64::from(age_s > ALARM_AFTER);
        match settled {
            Some(true) => {}
            Some(false) => {
                self.age_s = self.age_s.max(age_s);
                self.changed_files += 1;
                self.over_6h_files += over_6h;
            }
            None => self.unindexed_over_6h += over_6h,
        }
    }

    pub(super) fn page_end(self, source: SnapshotSource, walk_ended: bool) {
        if walk_ended {
            emit(source, Some(self.age_s), self, "walk");
        } else {
            with_walks(|walks| walks[source as usize] = self);
        }
    }
}

#[cfg(not(test))]
static WALKS: std::sync::Mutex<[WalkFold; 3]> = std::sync::Mutex::new([WalkFold::EMPTY; 3]);

#[cfg(test)]
thread_local! {
    static WALKS_FOR_TEST: std::cell::RefCell<[WalkFold; 3]> =
        const { std::cell::RefCell::new([WalkFold::EMPTY; 3]) };
}

#[cfg(not(test))]
fn with_walks<T>(body: impl FnOnce(&mut [WalkFold; 3]) -> T) -> T {
    // Each critical section is one scalar copy that only feeds a diagnostic.
    let mut walks = WALKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut walks)
}

#[cfg(test)]
fn with_walks<T>(body: impl FnOnce(&mut [WalkFold; 3]) -> T) -> T {
    WALKS_FOR_TEST.with(|walks| body(&mut walks.borrow_mut()))
}

/// Unknown age alarms: it never reads as fresh.
fn emit(source: SnapshotSource, age_s: Option<u64>, fold: WalkFold, basis: &'static str) {
    crate::local_resource_diagnostics::traversal_point(
        "freshness_alarm",
        source.api_slug(),
        &serde_json::json!({
            "age_s": age_s,
            "changed_files": fold.changed_files,
            "over_6h_files": fold.over_6h_files,
            "unindexed_over_6h": fold.unindexed_over_6h,
            "basis": basis,
            "alarm": age_s.map_or(true, |age| age > ALARM_AFTER),
        }),
    );
}

/// A failed pass may never reach the walk: its age is the newest acceptance.
pub(crate) fn report_failed_pass(source: SnapshotSource, state_dir: &Path) {
    let kind = crate::snapshot_client::receipt_source(source.api_slug());
    let age_s = crate::upload_receipts::newest_accepted_unix_seconds(state_dir, kind)
        .map(|accepted| super::sampled_scan::now_seconds().saturating_sub(accepted));
    emit(source, age_s, WalkFold::EMPTY, "last_ack");
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct Counts {
    pub(super) ages_are_process_local_lower_bounds: bool,
    pub(super) skipped_untracked_entries: u64,
    /// No indexed scan and not a replay: separate from indexed held work.
    pub(super) discovered_unread_tracked_files: u64,
    pub(super) discovered_unread_untracked_entries: u64,
    pub(super) oldest_discovered_unread_age_seconds: u64,
    pub(super) discovered_unread_over_24h_tracked_files: u64,
    pub(super) indexed_or_replay_tracked_files: u64,
}

#[cfg(test)]
#[path = "money_freshness_tests.rs"]
mod tests;

// Default ON, sampled once per process through the shared local switch.
super::local_switch::local_switch!(
    "money_freshness_disabled",
    marker_enables = false,
    test_default = true
);
#[cfg(test)]
pub(super) struct DisabledForTest {
    _switch: super::local_switch::ThreadSwitchForTest,
}
#[cfg(test)]
impl DisabledForTest {
    pub(super) fn new() -> Self {
        Self {
            _switch: super::local_switch::ThreadSwitchForTest::set(&ENABLED, false),
        }
    }
}
