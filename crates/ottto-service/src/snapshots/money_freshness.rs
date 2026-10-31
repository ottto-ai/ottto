//! Count-only Claude freshness, using the existing queue/replay and bounded
//! FirstPending stamps. Tracking never grants a read, alters a hold or performs
//! I/O; startup policy probes only its support-directory sentinel once.
use super::CandidateFile;
use serde::Serialize;

const ALARM_AFTER: u64 = 6 * 60 * 60;

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

// Default ON, sampled once per process like restart_restore/#899 policy.
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
