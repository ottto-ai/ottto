//! Count-only Claude freshness, using the existing queue/replay and bounded
//! FirstPending stamps. Tracking never grants a read, alters a hold or performs
//! I/O; startup policy probes only its support-directory sentinel once.
use super::{CandidateFile, SnapshotSource};
use serde::Serialize;

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

/// Extra fields in the existing bounded stamp, not another per-file map.
/// An epoch binds the observation to this page; older observations are unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Metadata {
    pub(super) epoch: u64,
    pub(super) size: u64,
    pub(super) seconds: u64,
    pub(super) nanos: u64,
}
impl Metadata {
    pub(super) fn new(candidate: &CandidateFile, epoch: u64) -> Self {
        Self {
            epoch,
            size: candidate.size_bytes,
            seconds: candidate.modified_unix_seconds,
            nanos: candidate.modified_unix_nanos,
        }
    }
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
    /// Observed size/mtime compared with the indexed scan, in this pass.
    pub(super) changed_since_scan_files: u64,
    pub(super) unchanged_since_scan_files: u64,
    pub(super) changed_since_scan_unknown_files: u64,
    pub(super) metadata_observed_files: u64,
    /// None means some changed-state coverage is unknown; never encode it as 0.
    pub(super) changed_since_scan_complete_count: Option<u64>,
    pub(super) changed_episode_open: bool,
    pub(super) changed_episode_age_seconds: u64,
    pub(super) changed_over_6h_alarm: bool,
    pub(super) tracker_initialized: bool,
}

/// Scalar state in the existing scope-local shadow runtime. Restart, scope
/// change, zero, an unknown-only pass or clock rollback break continuity.
#[derive(Debug, Default)]
pub(super) struct Episode {
    since: Option<u64>,
    last: Option<u64>,
}
impl Episode {
    pub(super) const fn new() -> Self {
        Self {
            since: None,
            last: None,
        }
    }

    pub(super) fn update(&mut self, row: &mut Counts, now: u64) {
        if self.last.is_some_and(|last| now < last) {
            self.since = None;
        }
        self.last = Some(now);
        if row.changed_since_scan_files > 0 {
            let since = *self.since.get_or_insert(now);
            row.changed_episode_open = true;
            row.changed_episode_age_seconds = now.saturating_sub(since);
            row.changed_over_6h_alarm = row.changed_episode_age_seconds > ALARM_AFTER;
        } else {
            self.since = None;
        }
    }
}

/// Claimed only at a completed emission. No tracker/scope/policy owns or
/// resets this process-wide bit; Relaxed swap gives exactly one true caller.
pub(super) fn first_observation() -> bool {
    static OBSERVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    claim_first_observation(&OBSERVED)
}

fn claim_first_observation(observed: &std::sync::atomic::AtomicBool) -> bool {
    !observed.swap(true, std::sync::atomic::Ordering::Relaxed)
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
