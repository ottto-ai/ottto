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
