//! The accepted floor (S2): the extent of the body the server accepted,
//! frozen before the working index changes. A file shorter than a verified
//! extent, or an entry from a newer body revision, holds; only an independently
//! proved replacement may clear it. A Tail head behind the floor is not below
//! it: the read replays through it. An evidence clear changes nothing here.
//!
//! A hold has no timer. It ends when the census proves the shrink, or when
//! the file is no longer behind (it grew past the floor); each exit is counted.
//! The floor is the committed index entry, so a restart keeps the hold.
use super::counters;
use crate::snapshot_sync::effective_upload_body_witness_revision;
use crate::snapshots::{state_v2, ScanIndex, SnapshotSource};

#[derive(Clone, Copy)]
pub(crate) struct AcceptedFloor {
    pub(crate) end: u64,
    pub(crate) revision: u64,
    /// A lossy read's raw extent is not a verified accepted-body prefix.
    pub(crate) verified_extent: bool,
}
impl AcceptedFloor {
    pub(crate) fn of(index: &ScanIndex, key: &str) -> Option<Self> {
        let e = index.files.get(key)?;
        Some(Self {
            end: e.size_bytes,
            revision: e.effective_upload_body_witness_revision,
            verified_extent: !e.has_unverified_source(),
        })
    }
    pub(crate) fn behind(self, length: u64) -> bool {
        (self.verified_extent && length < self.end) || !self.permits_real_edit()
    }
    pub(crate) fn permits_real_edit(self) -> bool {
        effective_upload_body_witness_revision(SnapshotSource::ClaudeCode) >= self.revision
    }
    /// R6 at the held extent (`None`: unknown, so held). A hold is counted
    /// with its bytes behind the floor and noted on the route, so its exit is
    /// named. G7: a held file is owed debt; its held revision is recorded here
    /// once the revision rows exist.
    pub(crate) fn holds(self, index: &ScanIndex, key: &str, length: Option<u64>) -> bool {
        let held = length.map_or(true, |length| self.behind(length));
        if held {
            counters::bump("tail_floor_held", "files");
            let behind = length.map_or(0, |length| self.end.saturating_sub(length));
            counters::add("tail_floor_held", "bytes", behind);
            if let Ok(Some(route)) = state_v2::runtime_path(index) {
                let _ = state_v2::hold_floor(&route, key);
            }
        }
        held
    }
}

/// The floor no longer holds `key`. If this process held it, the exit is
/// counted: the census proved the shrink, or the file is no longer behind.
pub(in crate::snapshots) fn release(index: &ScanIndex, key: &str, proven_shrink: bool) {
    let Ok(Some(route)) = state_v2::runtime_path(index) else {
        return;
    };
    if state_v2::release_floor(&route, key) {
        let exit = if proven_shrink {
            "proven_shrink"
        } else {
            "grew_past_floor"
        };
        counters::bump("tail_floor_hold_exit", exit);
    }
}
