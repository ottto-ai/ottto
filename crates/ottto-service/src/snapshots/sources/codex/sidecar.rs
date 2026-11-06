//! Codex sidecar data: the title metadata merged from the session index,
//! state and logs databases, its per-path, title, state-thread and
//! rollout-extent rows, and the per-turn priority trace map.

use crate::snapshots::*;

#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct CodexTitleMetadata {
    pub(in crate::snapshots) local_diagnostics: CodexScanDiagnostics,
    pub(in crate::snapshots) titles: BTreeMap<String, CodexTitleCandidate>,
    /// Merged maximum for state-only fallback; never use for file binding.
    /// Registered files must use `thread_extent_for_path` and their own home.
    pub(in crate::snapshots) state_threads: BTreeMap<String, CodexStateThread>,
    /// Merged maximum for metadata summaries; never use for file binding.
    pub(in crate::snapshots) rollout_extents: BTreeMap<String, CodexRolloutExtent>,
    /// File-binding evidence stays with the home that supplied it. A merged
    /// usage high-water mark must never seed another copy's creation proof.
    pub(in crate::snapshots) root_sidecars: BTreeMap<PathBuf, codex_root_copies::RootSidecar>,
    /// Canonical session ids whose trusted Codex state row declares
    /// `thread_source=agent_created_thread`. This is deliberately separate
    /// from generic spawn edges: the state declaration is an ownership
    /// classification input, while an edge alone is only lineage evidence.
    pub(in crate::snapshots) state_created_threads: BTreeSet<String>,
    pub(in crate::snapshots) spawn_parents: BTreeMap<String, String>,
    pub(in crate::snapshots) spawn_parent_conflicts: BTreeSet<String>,
    /// Resolved identity keys for which distinct raw sidecar ids collapsed to
    /// the same UUID key. These scoped conflicts directly block their own
    /// rollout. If a conflicted key is named as a parent, only its direct
    /// children lose lineage evidence; each such child remains separately
    /// visible through the ordinary ownership/drop health counters.
    pub(in crate::snapshots) identity_conflicts: BTreeSet<String>,
    /// True only when an existing state DB could not be read completely. A
    /// missing DB means there is no state-only source and is complete-empty.
    pub(in crate::snapshots) state_census_incomplete: bool,
    pub(in crate::snapshots) sidecar_census_incomplete: bool,
    /// An unreadable or structurally incomplete detail source has no
    /// trustworthy key scope. It blocks already-classified created identities;
    /// the separate classification flag below determines source-wide scope.
    pub(in crate::snapshots) state_census_unscoped_incomplete: bool,
    pub(in crate::snapshots) sidecar_census_unscoped_incomplete: bool,
    /// Homes whose created-thread classification query failed before it
    /// could identify a trustworthy key scope. Any rollout whose proof could
    /// depend on such a home could be an omitted created row, so it is held;
    /// see `created_thread_census_incomplete_for`.
    pub(in crate::snapshots) created_thread_census_failed_homes: BTreeSet<PathBuf>,
    /// While a home failed: identity -> rollout path whose created-thread
    /// proof comes from exactly one other, complete home that locates it
    /// exactly, with every spawn ancestor scoped too
    /// (`scope_created_thread_census`).
    pub(in crate::snapshots) created_thread_scoped: BTreeMap<String, PathBuf>,
    pub(in crate::snapshots) legacy_sidecar_fingerprint: String,
    /// The old index retained only config file stats, not content or affected
    /// session ids. Presence therefore requires one conservative corrective
    /// reconciliation; absence plus a matching legacy identity is provable.
    pub(in crate::snapshots) legacy_config_file_present: bool,
}

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct CodexPathSidecarCandidate {
    pub(in crate::snapshots) identity: String,
    pub(in crate::snapshots) recorded_evidence: bool,
    pub(in crate::snapshots) created_thread: bool,
    pub(in crate::snapshots) identity_conflict: bool,
    pub(in crate::snapshots) detail_incomplete: bool,
    pub(in crate::snapshots) rollout_file_matches: bool,
    pub(in crate::snapshots) parent: Option<String>,
    pub(in crate::snapshots) child_created_at_nanos: Option<i128>,
    pub(in crate::snapshots) projected_next_ordinal: Option<u64>,
}

#[derive(Debug, Clone)]
pub(in crate::snapshots) struct CodexTitleCandidate {
    pub(in crate::snapshots) title: String,
    pub(in crate::snapshots) source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct CodexStateThread {
    pub(in crate::snapshots) title: Option<String>,
    pub(in crate::snapshots) tokens_used: u64,
    pub(in crate::snapshots) archived: bool,
    pub(in crate::snapshots) created_at: Option<String>,
    pub(in crate::snapshots) updated_at: Option<String>,
    pub(in crate::snapshots) model: Option<String>,
    pub(in crate::snapshots) rollout_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct CodexRolloutExtent {
    pub(in crate::snapshots) next_byte_offset: u64,
    pub(in crate::snapshots) next_ordinal: u64,
}

/// Per-turn fast-mode signal lifted from Codex's undocumented `logs_2.sqlite`
/// debug DB.
///
/// Existing requested-priority signal from recent `logs_2.sqlite` request rows.
/// The turn id links the tracing span to rollout turn_context. This turn-wide
/// association is inherited application evidence: mixed requests within one
/// turn lack a durable response-level selector join. Absence is not positive
/// proof of standard pricing. File-owned receipts preserve previously applied
/// decisions after traces expire without extending them to new contributions.
#[derive(Debug, Clone, Default)]
pub(in crate::snapshots) struct CodexTurnTraceMap {
    pub(in crate::snapshots) since_epoch: i64,
    pub(in crate::snapshots) priority_turns: BTreeSet<String>,
    /// A present trace DB failed to load, or its row cap was reached: absent
    /// turns are unknown, not standard (R2-H1). A paged job treats a flipped
    /// decision under such a map as unavailable evidence, never a change.
    pub(in crate::snapshots) incomplete: bool,
}

impl CodexTurnTraceMap {
    pub(in crate::snapshots) fn is_priority_turn(&self, turn_id: &str) -> bool {
        self.priority_turns.contains(turn_id)
    }

    pub(in crate::snapshots) fn is_incomplete(&self) -> bool {
        self.incomplete
    }
}

crate::heap_layout_bound::fields!(CodexPathSidecarCandidate; identity, recorded_evidence, created_thread, identity_conflict, detail_incomplete, rollout_file_matches, parent, child_created_at_nanos, projected_next_ordinal);
crate::durable_tail_codec::durable_struct!(CodexPathSidecarCandidate {
    U identity: String,
    N recorded_evidence: bool,
    N created_thread: bool,
    N identity_conflict: bool,
    N detail_incomplete: bool,
    N rollout_file_matches: bool,
    U parent: Option<String>,
    N child_created_at_nanos: Option<i128>,
    N projected_next_ordinal: Option<u64>,
});
crate::heap_layout_bound::fields!(CodexRolloutExtent; next_byte_offset, next_ordinal);
crate::heap_layout_bound::fields!(CodexStateThread; title, tokens_used, archived, created_at, updated_at, model, rollout_path);
crate::heap_layout_bound::fields!(CodexTitleCandidate; title, source);
crate::heap_layout_bound::fields!(CodexTitleMetadata; local_diagnostics, titles, state_threads, rollout_extents, root_sidecars, state_created_threads, spawn_parents, spawn_parent_conflicts, identity_conflicts, state_census_incomplete, sidecar_census_incomplete, state_census_unscoped_incomplete, sidecar_census_unscoped_incomplete, created_thread_census_failed_homes, created_thread_scoped, legacy_sidecar_fingerprint, legacy_config_file_present);
crate::heap_layout_bound::fields!(CodexTurnTraceMap; since_epoch, priority_turns, incomplete);
