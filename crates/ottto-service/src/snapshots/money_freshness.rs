//! Count-only Claude freshness, using the existing queue/replay and bounded
//! FirstPending stamps. Never grants a read, alters a hold, or performs I/O.
use super::{claude_family_census_shadow as shadow, CandidateFile, ScanIndex};
use serde::Serialize;

const DAY: u64 = 24 * 60 * 60;
const ALARM_AFTER: u64 = 6 * 60 * 60;

/// Extra fields in the existing bounded stamp, not another per-file map.
/// An epoch binds the observation to this page; older observations are unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Metadata {
    epoch: u64,
    size: u64,
    seconds: u64,
    nanos: u64,
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
    /// Unique stamped files in queue + replay. Unstamped entry multiplicity
    /// is unknown: report it separately rather than invent a distinct count.
    pub(super) skipped_tracked_files: u64,
    pub(super) skipped_untracked_entries: u64,
    pub(super) oldest_skipped_age_seconds: u64,
    pub(super) pending_over_24h_tracked_files: u64,
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
    /// Startup-condition proxy, emitted on the first completed observation
    /// of this process/source/scope only. It does not prove a prior episode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) restart_started_with_open_condition: Option<u64>,
    pub(super) restart_scope_tracking_full: bool,
}

/// One queue pass plus one bit per EXISTING stamp. O(queue × log(stamps)),
/// <=16,384 bytes of transient dedup state; zero stat/open/read calls.
pub(super) fn measure(
    index: &ScanIndex,
    stamps: &shadow::FirstPending,
    epoch: u64,
    now: u64,
) -> Counts {
    let mut row = Counts {
        ages_are_process_local_lower_bounds: true,
        ..Counts::default()
    };
    let mut seen = vec![0_u8; stamps.len()];
    for entry in shadow::skipped_view(index) {
        let key = entry.path.path.to_string_lossy();
        let indexed = index.files.get(key.as_ref());
        let unread = indexed.is_none() && !entry.replay;
        let hash = shadow::hash64(entry.path.path.as_os_str().as_encoded_bytes());
        let Some((position, since, metadata)) = stamps.stamp(hash) else {
            row.skipped_untracked_entries += 1;
            row.discovered_unread_untracked_entries += u64::from(unread);
            continue;
        };
        if seen[position] != 0 {
            // A replay occurrence proves this is not never-read work even
            // when the queue occurrence came first and its index was dropped.
            if entry.replay {
                seen[position] = 2;
            }
            continue;
        }
        seen[position] = if unread { 1 } else { 2 };
        row.skipped_tracked_files += 1;
        let age = now.saturating_sub(since);
        row.oldest_skipped_age_seconds = row.oldest_skipped_age_seconds.max(age);
        row.pending_over_24h_tracked_files += u64::from(age > DAY);
        if metadata.epoch == epoch {
            row.metadata_observed_files += 1;
        }
        if let Some(indexed) = indexed.filter(|_| metadata.epoch == epoch) {
            let changed = indexed.size_bytes != metadata.size
                || indexed.modified_unix_seconds != metadata.seconds
                || indexed
                    .modified_unix_nanos
                    .is_some_and(|nanos| nanos != metadata.nanos);
            row.changed_since_scan_files += u64::from(changed);
            row.unchanged_since_scan_files += u64::from(!changed);
        } else {
            // Includes unindexed files: no last scan to compare against.
            row.changed_since_scan_unknown_files += 1;
        }
    }
    for (position, kind) in seen.iter().enumerate() {
        match kind {
            1 => {
                let age = now.saturating_sub(stamps.since_at(position));
                row.discovered_unread_tracked_files += 1;
                row.oldest_discovered_unread_age_seconds =
                    row.oldest_discovered_unread_age_seconds.max(age);
                row.discovered_unread_over_24h_tracked_files += u64::from(age > DAY);
            }
            2 => row.indexed_or_replay_tracked_files += 1,
            _ => {}
        }
    }
    row.changed_since_scan_complete_count = (row.changed_since_scan_unknown_files == 0
        && row.skipped_untracked_entries == 0)
        .then_some(row.changed_since_scan_files);
    row
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
        row.tracker_initialized = self.last.is_none();
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

/// Fixed process-local scope ledger, not a per-file map. Keep it outside
/// Runtime so switching away from a scope and back cannot count it twice.
/// Hash collisions or exhausted coverage can suppress a count, never duplicate it.
struct ScopeStarts {
    scopes: [Option<u64>; 64],
}
impl ScopeStarts {
    const fn new() -> Self {
        Self { scopes: [None; 64] }
    }

    fn observe(&mut self, scope: u64, row: &mut Counts) {
        row.restart_started_with_open_condition = None;
        row.restart_scope_tracking_full = false;
        if self.scopes.contains(&Some(scope)) {
            return;
        }
        if let Some(slot) = self.scopes.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(scope);
            row.restart_started_with_open_condition =
                Some(u64::from(row.changed_since_scan_files > 0));
        } else {
            row.restart_scope_tracking_full = true;
        }
    }
}

#[cfg(not(test))]
static STARTS: std::sync::Mutex<ScopeStarts> = std::sync::Mutex::new(ScopeStarts::new());
#[cfg(test)]
thread_local! {
    static STARTS: std::cell::RefCell<ScopeStarts> = const { std::cell::RefCell::new(ScopeStarts::new()) };
}

pub(super) fn observe_start(scope: &str, row: &mut Counts) {
    let scope = shadow::hash64(scope.as_bytes());
    #[cfg(not(test))]
    STARTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe(scope, row);
    #[cfg(test)]
    STARTS.with(|starts| starts.borrow_mut().observe(scope, row));
}

pub(super) fn emit(row: &Counts) {
    crate::local_resource_diagnostics::traversal_point("money_freshness", "claude_code", row);
    if row.changed_over_6h_alarm {
        crate::local_resource_diagnostics::traversal_point(
            "money_freshness_alarm",
            "claude_code",
            row,
        );
    }
}

#[cfg(test)]
#[path = "money_freshness_tests.rs"]
mod tests;
