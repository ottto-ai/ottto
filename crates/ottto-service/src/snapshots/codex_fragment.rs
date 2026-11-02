//! RAM-only binding of the cursor's certified prefix + observed EOF fragment.
//! A length difference alone never creates this evidence or grants a Skip.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct Stamp {
    content: sampled_scan::codex_cursor::ContentStamp,
    birth: u64,
}
crate::heap_layout_bound::fields!(Stamp; content, birth);
impl Stamp {
    pub(super) fn candidate(candidate: &CandidateFile) -> Option<Self> {
        (candidate.fingerprint_birth_nanos != 0).then_some(Self {
            content: sampled_scan::codex_cursor::OpenStamp::candidate(candidate)?.content_stamp(),
            birth: candidate.fingerprint_birth_nanos,
        })
    }
    pub(super) fn metadata(metadata: &fs::Metadata) -> Option<Self> {
        let birth = metadata.created().ok().and_then(unix_nanos)?;
        (birth != 0).then_some(Self {
            content: sampled_scan::codex_cursor::OpenStamp::of(metadata).content_stamp(),
            birth,
        })
    }
    pub(super) fn matches_acquisition(
        &self,
        stamp: &crate::transcript_acquisition::FileStamp,
    ) -> bool {
        self.content.matches_acquisition(stamp)
    }
    fn same_content(&self, other: &Self) -> bool {
        self.birth == other.birth && self.content.same_content(&other.content)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct BoundFragment {
    offset: u64,
    stamp: Stamp,
}
crate::heap_layout_bound::fields!(BoundFragment; offset, stamp);
impl BoundFragment {
    /// Called only after the cursor actually withheld an EOF record, with a
    /// retained reduction and a certificate sealed at exactly `offset`.
    pub(super) fn bind(candidate: &CandidateFile, offset: u64) -> Option<Self> {
        (offset < candidate.size_bytes).then_some(Self {
            offset,
            stamp: Stamp::candidate(candidate)?,
        })
    }
    pub(super) fn matches(&self, committed: u64, len: u64, stamp: Option<Stamp>) -> bool {
        committed == self.offset
            && len == self.stamp.content.extent()
            && stamp.is_some_and(|stamp| self.stamp.same_content(&stamp))
    }
}
pub(super) fn grown(entry: &ScanIndexEntry, len: u64, stamp: Option<Stamp>) -> bool {
    len > entry.size_bytes
        && !entry
            .codex_fragment
            .as_ref()
            .is_some_and(|fragment| fragment.matches(entry.size_bytes, len, stamp))
}

/// Actual native body range, captured before completion consumes the plan.
/// No source verification or acquisition decision is derived from this metric.
pub(super) struct TailRead {
    pub(super) mode: crate::transcript_acquisition::ReadMode,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) terminated_end: u64,
}
pub(super) fn note_tail_repeat(
    entry: &ScanIndexEntry,
    candidate: &CandidateFile,
    read: TailRead,
    now: Option<u64>,
    window: u64,
) {
    // Fallback definition approved by Lead A: the revalidated Tail certificate
    // starts at the committed prefix, the unchanged sampled fingerprint binds
    // the previously observed EOF, and no terminated record advanced that prefix.
    if entry.codex_fragment.is_none()
        && entry.has_unverified_source()
        && !entry.source_file_fingerprint.is_empty()
        && entry.source_file_fingerprint == candidate.source_file_fingerprint
        && matches!(read.mode, crate::transcript_acquisition::ReadMode::Tail)
        && read.start == entry.size_bytes
        && read.end == candidate.size_bytes
        && read.end > read.start
        && read.terminated_end == 0
        && now.is_some_and(|now| !is_recent_enough_at(candidate.modified_unix_seconds, now, window))
    {
        crate::local_resource_diagnostics::codex_fragment_tail_repeat(read.end - read.start);
    }
}
