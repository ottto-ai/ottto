//! RAM-only binding of the cursor's certified prefix + observed EOF fragment.
//! A length difference alone never creates this evidence or grants a Skip.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Stamp {
    words: [u64; 6],
}
crate::heap_layout_bound::fields!(Stamp; words);
impl Stamp {
    pub(super) fn candidate(candidate: &CandidateFile) -> Option<Self> {
        let [dev, ino] = candidate.physical_identity?;
        (candidate.fingerprint_birth_nanos != 0).then_some(Self {
            words: [
                candidate.size_bytes,
                candidate.modified_unix_nanos,
                candidate.fingerprint_birth_nanos,
                dev,
                ino,
                candidate.fingerprint_changed_nanos,
            ],
        })
    }
    pub(super) fn metadata(metadata: &fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            let changed = OpenedObjectStat {
                device: metadata.dev(),
                inode: metadata.ino(),
                changed_seconds: metadata.ctime(),
                changed_nanos: metadata.ctime_nsec(),
                birth_nanos: metadata.created().ok().and_then(unix_nanos),
                modified_nanos: metadata.modified().ok().and_then(unix_nanos),
            };
            Some(Self {
                words: [
                    metadata.len(),
                    changed.modified_nanos?,
                    changed.birth_nanos?,
                    changed.device,
                    changed.inode,
                    changed.changed_unix_nanos(),
                ],
            })
            .filter(|stamp| stamp.words[2] != 0)
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
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
        committed == self.offset && len == self.stamp.words[0] && stamp == Some(self.stamp)
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
