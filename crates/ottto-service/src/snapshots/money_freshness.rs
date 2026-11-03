//! Freshness diagnostics; none grants a read, alters a hold or adds a read.
//! `freshness_alarm` is each source's persisted per-file debt (`g7_debt`) under
//! `debt`, aggregated at each root walk's end, so it survives restarts.
//! `Counts` are count-only Claude gauges over the bounded FirstPending stamps.
use super::g7_debt::{Report, Walk};
use super::SnapshotSource;
use serde::Serialize;

pub(super) const ALARM_AFTER: u64 = 6 * 60 * 60;

/// One root walk's fold. A walk spans passes and every pass reloads the index,
/// so the fold stays in this process until the walk ends. The debt it counts
/// is durable: only a restart mid-walk loses the pages already walked.
#[derive(Debug)]
pub(super) struct WalkFold {
    authority_terminal_files: u64,
    authority_terminal_oldest_age_s: u64,
    pub(super) debt: Walk,
}
impl WalkFold {
    pub(super) const EMPTY: Self = Self {
        authority_terminal_files: 0,
        authority_terminal_oldest_age_s: 0,
        debt: Walk::EMPTY,
    };

    pub(super) fn resume(source: SnapshotSource) -> Self {
        with_walks(|walks| std::mem::replace(&mut walks.folds[source as usize], Self::EMPTY))
    }

    /// An authority-terminal file with debt has real unuploaded growth that no
    /// read can reach, so it carries its own label too.
    pub(super) fn authority_terminal_file(&mut self, age_s: u64) {
        self.authority_terminal_files += 1;
        self.authority_terminal_oldest_age_s = self.authority_terminal_oldest_age_s.max(age_s);
    }

    /// `debt`: the walk's aggregate, `None` for a graph with no Tail store.
    pub(super) fn page_end(self, source: SnapshotSource, walk_ended: bool, debt: Option<Report>) {
        if walk_ended {
            with_walks(|walks| walks.last[source as usize] = debt);
            emit(source, &self, "walk", debt.as_ref());
        } else {
            with_walks(|walks| walks.folds[source as usize] = self);
        }
    }
}

/// Each source's walk in progress and its last walk's aggregate.
struct Walks {
    folds: [WalkFold; 3],
    last: [Option<Report>; 3],
}
const NO_WALKS: Walks = Walks {
    folds: [WalkFold::EMPTY; 3],
    last: [None; 3],
};

#[cfg(not(test))]
static WALKS: std::sync::Mutex<Walks> = std::sync::Mutex::new(NO_WALKS);

#[cfg(test)]
thread_local! {
    static WALKS_FOR_TEST: std::cell::RefCell<Walks> = const { std::cell::RefCell::new(NO_WALKS) };
}

#[cfg(not(test))]
fn with_walks<T>(body: impl FnOnce(&mut Walks) -> T) -> T {
    // Each critical section moves one fold or one scalar aggregate; it only
    // feeds a diagnostic.
    let mut walks = WALKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut walks)
}

#[cfg(test)]
fn with_walks<T>(body: impl FnOnce(&mut Walks) -> T) -> T {
    WALKS_FOR_TEST.with(|walks| body(&mut walks.borrow_mut()))
}

/// A restart forgets every walk in progress and every aggregate.
#[cfg(test)]
pub(super) fn restart_for_test() {
    with_walks(|walks| *walks = NO_WALKS);
}

/// Unknown debt alarms: it never reads as fresh. So does any authority-terminal
/// file, at any age, until its debt settles.
fn emit(source: SnapshotSource, fold: &WalkFold, basis: &'static str, debt: Option<&Report>) {
    let now_ms = super::sampled_scan::now_seconds().saturating_mul(1000);
    crate::local_resource_diagnostics::traversal_point(
        "freshness_alarm",
        source.api_slug(),
        &serde_json::json!({
            "authority_terminal_files": fold.authority_terminal_files,
            "authority_terminal_oldest_age_s": fold.authority_terminal_oldest_age_s,
            "basis": basis,
            "debt": debt.map_or(serde_json::Value::Null, |debt| debt.fields(now_ms)),
            "alarm": fold.authority_terminal_files > 0
                || debt.map_or(true, |debt| debt.alarm(now_ms)),
        }),
    );
}

/// A failed pass may never reach the walk: its debt is this process's last
/// walk aggregate, re-aged now; with none yet it is unknown, never fresh.
pub(crate) fn report_failed_pass(source: SnapshotSource) {
    let debt = with_walks(|walks| walks.last[source as usize]).unwrap_or(Report::UNAVAILABLE);
    emit(source, &WalkFold::EMPTY, "last_walk", Some(&debt));
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
