//! The accepted floor (S2): the extent of the body the server accepted,
//! frozen before the working index changes. A file shorter than a verified
//! extent, or an entry from a newer body revision, holds; only an independently
//! proved replacement may clear it. A Tail head behind the floor is not below
//! it: the read replays through it. An evidence clear changes nothing here.
use crate::snapshot_sync::effective_upload_body_witness_revision;
use crate::snapshots::{ScanIndex, SnapshotSource};

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
}
