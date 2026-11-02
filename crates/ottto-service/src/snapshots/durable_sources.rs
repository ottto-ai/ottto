//! One dispatch table for admitted durable sources. ON admits v3 reductions only.
use super::*;

mod records;

/// Sources admitted by the durable property table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DurableSource {
    ClaudeCode,
    Codex,
    Pi,
}

/// How a durable-restored read that ends strictly below the frozen accepted
/// extent is treated (`restored_behind_accepted`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BelowAccepted {
    /// The accepted floor holds the read.
    Held,
    /// A restored Tail publishes below it.
    Tail,
}

pub(crate) struct Properties {
    pub(crate) source: DurableSource,
    pub(crate) snapshot: SnapshotSource,
    pub(crate) tag: u8,
    pub(crate) below_accepted: BelowAccepted,
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
        below_accepted: BelowAccepted::Held,
        state_v2: true,
    },
    Properties {
        source: DurableSource::Codex,
        snapshot: SnapshotSource::Codex,
        tag: 2,
        below_accepted: BelowAccepted::Tail,
        state_v2: true,
    },
    Properties {
        source: DurableSource::Pi,
        snapshot: SnapshotSource::Pi,
        tag: 3,
        below_accepted: BelowAccepted::Tail,
        // Pi joins the v2 store in its own later step.
        state_v2: false,
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

/// A source without a durable row has no restored read to report.
pub(crate) fn below_accepted(source: SnapshotSource) -> BelowAccepted {
    DurableSource::from_snapshot(source).map_or(BelowAccepted::Held, |source| {
        source.properties().below_accepted
    })
}
