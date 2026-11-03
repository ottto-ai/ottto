//! One dispatch table for admitted sources.
use super::*;

/// Sources admitted by the durable property table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DurableSource {
    ClaudeCode,
    Codex,
    Pi,
}

pub(crate) struct Properties {
    pub(crate) source: DurableSource,
    pub(crate) snapshot: SnapshotSource,
    /// Registry identity, a stable wire ID; Tail heads bind the source by
    /// its slug instead.
    #[allow(dead_code)]
    pub(crate) tag: u8,
    /// Its index routes through the state v2 store. Only ever set: a published
    /// route's custody wins, and clearing it would let v1 load the frozen
    /// JSON. Leaving needs an explicit export back to v1.
    pub(crate) state_v2: bool,
}

// Enum ordinals index this table and Stores' slots; tags remain independent wire IDs.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        tag: 1,
        state_v2: true,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        tag: 2,
        state_v2: true,
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        tag: 3,
        state_v2: true,
    },
];

impl scan_index_persistence::Source {
    // Lives here, not beside the enum: the integration tests compile that file alone.
    pub(crate) fn snapshot(self) -> SnapshotSource {
        match self {
            Self::Claude => SnapshotSource::ClaudeCode,
            Self::Codex => SnapshotSource::Codex,
            Self::Pi => SnapshotSource::Pi,
        }
    }
}

impl DurableSource {
    pub(crate) fn slot(self) -> usize {
        self as usize
    }

    pub(crate) fn properties(self) -> &'static Properties {
        &SOURCES[self.slot()]
    }

    pub(crate) fn from_snapshot(source: SnapshotSource) -> Option<Self> {
        SOURCES
            .iter()
            .find(|row| row.snapshot == source)
            .map(|row| row.source)
    }
}
