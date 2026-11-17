//! One dispatch table for admitted sources.
use crate::snapshots::*;

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
    /// Queue order during the source's first read (`first_read_order.rs`).
    pub(crate) first_read_newest_first: bool,
}

// Enum ordinals index this table and Stores' slots.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        first_read_newest_first: false,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        first_read_newest_first: true,
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        first_read_newest_first: true,
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
