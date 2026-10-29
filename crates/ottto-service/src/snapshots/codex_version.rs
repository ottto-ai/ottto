//! One bounded MCP sample from the main reader's retained native state.
use super::{OwnedActiveFile, SnapshotSource};
use crate::transcript_acquisition::FileObject;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Clone, Copy)]
pub(crate) struct Sample {
    pub(crate) started_at: OffsetDateTime,
    bytes: [u8; 64],
    len: u8,
}
impl Sample {
    pub(crate) fn new(start: &str, version: Option<&str>) -> Option<Self> {
        let mut sample = Self {
            started_at: OffsetDateTime::parse(start, &Rfc3339).ok()?,
            bytes: [0; 64],
            len: 0,
        };
        if let Some(v) = version.filter(|v| {
            !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
                && crate::mcp_inventory::parse_version(v).is_some()
                && v.split(['-', '+'])
                    .next()
                    .is_some_and(|c| c.split('.').all(|n| n.parse::<u64>().is_ok()))
        }) {
            sample.bytes[..v.len()].copy_from_slice(v.as_bytes());
            sample.len = v.len() as u8;
        }
        Some(sample)
    }
    pub(crate) fn version(&self) -> Option<&str> {
        (self.len != 0).then(|| std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap())
    }
    /// Observations beat equal-time seeds; version-less observations still rank.
    pub(crate) fn newest(seed: Option<Self>, observed: Option<Self>) -> Option<Self> {
        observed
            .filter(|o| seed.map_or(true, |s| o.started_at >= s.started_at))
            .or(seed)
    }
}
#[derive(Default)]
struct Projection {
    winner: Option<(FileObject, Sample)>,
    observed: u64,
    rejected: u64,
}
/// Owned once by the daemon; scans retain only an optional Arc pointer.
pub(crate) struct CodexVersionFeed {
    eligible_root: Option<PathBuf>,
    state: Mutex<Projection>,
}
impl crate::heap_layout_bound::HeapLayoutBound for CodexVersionFeed {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // The mutex/projection are inline and own no heap; never mark them stable.
        let Self {
            eligible_root,
            state: _,
        } = self;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(eligible_root, c)
    }
}
impl std::fmt::Debug for CodexVersionFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexVersionFeed").finish_non_exhaustive()
    }
}
impl CodexVersionFeed {
    pub(crate) fn new(home: Option<&Path>) -> Self {
        Self {
            eligible_root: home
                .and_then(|h| SnapshotSource::Codex.default_roots(h).into_iter().next()),
            state: Mutex::default(),
        }
    }
    /// No I/O: object identity was captured on the primary open already.
    pub(super) fn observe(&self, active: &OwnedActiveFile) {
        if self.eligible_root.as_ref() != Some(&active.candidate.scan_root) {
            return;
        }
        let sample = active
            .parser
            .accumulator
            .started_at
            .as_deref()
            .and_then(|start| {
                Sample::new(
                    start,
                    active.parser.accumulator.session_start.client_version(),
                )
            });
        let object = FileObject::from_opened_identity(
            active.candidate.physical_identity,
            active.candidate.fingerprint_birth_nanos,
        );
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some((object, sample)) = object.zip(sample) else {
            state.rejected = state.rejected.saturating_add(1);
            return;
        };
        state.observed = state.observed.saturating_add(1);
        if state.winner.map_or(true, |(old, s)| {
            old == object || sample.started_at > s.started_at
        }) {
            state.winner = Some((object, sample));
        }
    }
    pub(crate) fn snapshot(&self) -> (Option<Sample>, u64, u64) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (state.winner.map(|(_, s)| s), state.observed, state.rejected)
    }
}
