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
    /// Its index routes through the state v2 store. Only ever set: a published
    /// route's custody wins, and clearing it would let v1 load the frozen
    /// JSON. Leaving needs an explicit export back to v1.
    pub(crate) state_v2: bool,
    /// Support folders of its context-footprint upload witnesses, one
    /// `<workspace>.json` each; a resume drops them so the next pass re-sends.
    pub(crate) footprint_witnesses: &'static [&'static str],
}

// Enum ordinals index this table and Stores' slots.
pub(crate) const SOURCES: &[Properties] = &[
    Properties {
        source: DurableSource::ClaudeCode,
        snapshot: SnapshotSource::ClaudeCode,
        state_v2: true,
        footprint_witnesses: &[crate::context_footprint::STATE_DIR],
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        state_v2: true,
        footprint_witnesses: &[crate::codex_prelude_footprint::STATE_DIR],
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        state_v2: true,
        footprint_witnesses: &[],
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
