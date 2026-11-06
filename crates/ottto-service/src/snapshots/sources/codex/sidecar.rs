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

impl CodexTitleMetadata {
    pub(in crate::snapshots) fn has_identity_evidence(&self, identity: &str) -> bool {
        self.titles.contains_key(identity)
            || self.state_threads.contains_key(identity)
            || self.rollout_extents.contains_key(identity)
            || self.state_created_threads.contains(identity)
            || self.spawn_parents.contains_key(identity)
            || self.spawn_parents.values().any(|parent| parent == identity)
            || self.spawn_parent_conflicts.contains(identity)
            || self.identity_conflicts.contains(identity)
    }

    pub(in crate::snapshots) fn identity_from_path_evidence(&self, path: &Path) -> Option<String> {
        let candidates = codex_session_id_candidates_from_path(path);
        if candidates.len() == 1 {
            return candidates.into_iter().next();
        }
        let supported = candidates
            .into_iter()
            .filter(|identity| self.has_identity_evidence(identity))
            .collect::<Vec<_>>();
        (supported.len() == 1).then(|| supported[0].clone())
    }

    pub(in crate::snapshots) fn path_sidecar_fingerprint(&self, path: &Path) -> String {
        self.path_sidecar_fingerprint_for(path, false)
    }

    pub(in crate::snapshots) fn path_reduction_fingerprint(&self, path: &Path) -> String {
        self.path_sidecar_fingerprint_for(path, true)
    }

    fn path_sidecar_fingerprint_for(&self, path: &Path, reduction_only: bool) -> String {
        if let Some(identity) = self.identity_from_path_evidence(path) {
            return self.session_sidecar_fingerprint_in(
                identity.as_str(),
                reduction_only,
                Some(path),
            );
        }
        let parts = codex_session_id_candidates_from_path(path)
            .into_iter()
            .flat_map(|identity| {
                let fingerprint = self.session_sidecar_fingerprint_in(
                    identity.as_str(),
                    reduction_only,
                    Some(path),
                );
                [identity, fingerprint]
            })
            .collect::<Vec<_>>();
        if parts.is_empty() {
            String::new()
        } else {
            sha256_hex_owned(&parts)
        }
    }

    pub(in crate::snapshots) fn family_position(
        &self,
        child: &str,
    ) -> Option<(String, String, u64)> {
        let child = resolve_codex_identity(child);
        if self.spawn_parent_conflicts.contains(child.as_str()) {
            return None;
        }
        let parent = self.spawn_parents.get(child.as_str())?.clone();
        let mut root = parent.clone();
        let mut depth = 1_u64;
        let mut seen = BTreeSet::from([child]);
        while let Some(next) = self.spawn_parents.get(root.as_str()) {
            if self.spawn_parent_conflicts.contains(root.as_str())
                || !seen.insert(root.clone())
                || depth >= 128
            {
                return None;
            }
            root = next.clone();
            depth += 1;
        }
        Some((parent, root, depth))
    }

    /// The rows `path_reduction_fingerprint(path)` reads: the path's identity
    /// candidates, every spawn edge reachable from them, one child edge each,
    /// every home's sidecar roots and all census flags. Diagnostics are not
    /// carried. Callers compare the two fingerprints before using it.
    pub(in crate::snapshots) fn narrowed_to(&self, path: &Path) -> Self {
        let ids = codex_session_id_candidates_from_path(path)
            .into_iter()
            .flat_map(|id| [resolve_codex_identity(&id), id])
            .collect::<BTreeSet<_>>();
        fn rows<V: Clone>(
            map: &BTreeMap<String, V>,
            ids: &BTreeSet<String>,
        ) -> BTreeMap<String, V> {
            ids.iter()
                .filter_map(|id| map.get_key_value(id))
                .map(|(id, row)| (id.clone(), row.clone()))
                .collect()
        }
        let mut edges = BTreeMap::new();
        for id in &ids {
            if let Some((child, parent)) =
                self.spawn_parents.iter().find(|(_, parent)| *parent == id)
            {
                edges.insert(child.clone(), parent.clone());
            }
            let mut at = id;
            while let Some((child, parent)) = self.spawn_parents.get_key_value(at) {
                if edges.insert(child.clone(), parent.clone()).is_some() {
                    break;
                }
                at = parent;
            }
        }
        let nodes = ids
            .iter()
            .chain(edges.keys())
            .chain(edges.values())
            .cloned()
            .collect::<BTreeSet<_>>();
        let sidecar = |sidecar: &codex_root_copies::RootSidecar| codex_root_copies::RootSidecar {
            threads: rows(&sidecar.threads, &ids),
            extents: rows(&sidecar.extents, &ids),
        };
        Self {
            local_diagnostics: Default::default(),
            titles: rows(&self.titles, &ids),
            state_threads: rows(&self.state_threads, &ids),
            rollout_extents: rows(&self.rollout_extents, &ids),
            root_sidecars: self
                .root_sidecars
                .iter()
                .map(|(root, home)| (root.clone(), sidecar(home)))
                .collect(),
            state_created_threads: self
                .state_created_threads
                .intersection(&ids)
                .cloned()
                .collect(),
            spawn_parent_conflicts: self
                .spawn_parent_conflicts
                .intersection(&nodes)
                .cloned()
                .collect(),
            spawn_parents: edges,
            identity_conflicts: self
                .identity_conflicts
                .intersection(&ids)
                .cloned()
                .collect(),
            state_census_incomplete: self.state_census_incomplete,
            sidecar_census_incomplete: self.sidecar_census_incomplete,
            state_census_unscoped_incomplete: self.state_census_unscoped_incomplete,
            sidecar_census_unscoped_incomplete: self.sidecar_census_unscoped_incomplete,
            created_thread_census_failed_homes: self.created_thread_census_failed_homes.clone(),
            created_thread_scoped: rows(&self.created_thread_scoped, &ids),
            legacy_sidecar_fingerprint: self.legacy_sidecar_fingerprint.clone(),
            legacy_config_file_present: self.legacy_config_file_present,
        }
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn session_sidecar_fingerprint(
        &self,
        source_session_id: &str,
    ) -> String {
        self.session_sidecar_fingerprint_in(source_session_id, false, None)
    }

    pub(in crate::snapshots) fn thread_extent_for_path(
        &self,
        identity: &str,
        path: &Path,
    ) -> (Option<&CodexStateThread>, Option<CodexRolloutExtent>) {
        if let Some((_, sidecar)) = self
            .root_sidecars
            .iter()
            .filter(|(root, _)| path.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
        {
            return (
                sidecar.threads.get(identity),
                sidecar.extents.get(identity).copied(),
            );
        }
        (
            self.state_threads.get(identity),
            self.rollout_extents.get(identity).copied(),
        )
    }

    fn session_sidecar_fingerprint_in(
        &self,
        source_session_id: &str,
        reduction_only: bool,
        path: Option<&Path>,
    ) -> String {
        let source_session_id = resolve_codex_identity(source_session_id);
        let title = (!reduction_only)
            .then(|| self.titles.get(source_session_id.as_str()))
            .flatten();
        let (thread, extent) = path.map_or_else(
            || {
                (
                    self.state_threads.get(source_session_id.as_str()),
                    self.rollout_extents
                        .get(source_session_id.as_str())
                        .copied(),
                )
            },
            |path| self.thread_extent_for_path(source_session_id.as_str(), path),
        );
        let decoration = (!reduction_only).then_some(thread).flatten();
        let extent = (!reduction_only).then_some(extent).flatten();
        let family = self.family_position(source_session_id.as_str());
        let fingerprint = sha256_hex(&[
            "codex_session_sidecar:v4",
            source_session_id.as_str(),
            if self
                .state_created_threads
                .contains(source_session_id.as_str())
            {
                "agent_created_thread"
            } else {
                ""
            },
            title.map(|value| value.title.as_str()).unwrap_or(""),
            title.map(|value| value.source.as_str()).unwrap_or(""),
            decoration
                .and_then(|value| value.title.as_deref())
                .unwrap_or(""),
            &decoration
                .map(|value| value.tokens_used)
                .unwrap_or_default()
                .to_string(),
            decoration
                .map(|value| if value.archived { "archived" } else { "active" })
                .unwrap_or(""),
            thread
                .and_then(|value| value.created_at.as_deref())
                .unwrap_or(""),
            decoration
                .and_then(|value| value.updated_at.as_deref())
                .unwrap_or(""),
            decoration
                .and_then(|value| value.model.as_deref())
                .unwrap_or(""),
            thread
                .and_then(|value| value.rollout_path.as_deref())
                .unwrap_or(""),
            &extent
                .map(|value| value.next_byte_offset)
                .unwrap_or_default()
                .to_string(),
            &extent
                .map(|value| value.next_ordinal)
                .unwrap_or_default()
                .to_string(),
            family
                .as_ref()
                .map(|(parent, _, _)| parent.as_str())
                .unwrap_or_else(|| {
                    if self
                        .spawn_parent_conflicts
                        .contains(source_session_id.as_str())
                    {
                        "conflict"
                    } else if self.spawn_parents.contains_key(source_session_id.as_str())
                        && self
                            .state_created_threads
                            .contains(source_session_id.as_str())
                    {
                        // An edge whose ancestor chain cannot be resolved is still
                        // lineage evidence and must reselect a parentless file.
                        "unresolved"
                    } else {
                        ""
                    }
                }),
            family
                .as_ref()
                .map(|(_, root, _)| root.as_str())
                .unwrap_or(""),
            &family
                .as_ref()
                .map(|(_, _, depth)| *depth)
                .unwrap_or_default()
                .to_string(),
        ]);
        // A per-home row can stay byte-identical while another home's row
        // creates a collision. Invalidate paused ownership decisions as well
        // as fresh parsing; census flags alone are not cursor dependencies.
        if self.identity_conflicts.contains(source_session_id.as_str()) {
            sha256_hex(&["codex_identity_conflict:v1", &fingerprint])
        } else {
            fingerprint
        }
    }

    pub(in crate::snapshots) fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut metadata = Self::default();
        let mut legacy_sidecar_parts = Vec::new();
        let mut parentless_ineligible = BTreeSet::new();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }

        for codex_dir in codex_dirs {
            let config_path = codex_dir.join("config.toml");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&config_path));
            metadata.legacy_config_file_present |= config_path.is_file();

            let state_path = codex_dir.join("state_5.sqlite");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&state_path));
            let state_conflicts_before = metadata.identity_conflicts.len();
            let mut open = SidecarOpenCounts::default();
            let title_census = load_codex_sqlite_titles(
                &state_path,
                &mut open,
                &mut metadata.titles,
                &mut metadata.identity_conflicts,
            );
            metadata.local_diagnostics.state_titles.observe_root(
                &title_census,
                open,
                metadata.identity_conflicts.len() != state_conflicts_before,
                local_index_key(&codex_dir).as_str(),
            );
            let thread_conflicts_before = metadata.identity_conflicts.len();
            let mut root_sidecar = codex_root_copies::RootSidecar::default();
            let mut open = SidecarOpenCounts::default();
            let state_census = load_codex_sqlite_state_threads(
                &state_path,
                &mut open,
                &mut root_sidecar.threads,
                &mut metadata.identity_conflicts,
                &mut metadata.local_diagnostics.identity_conflict_taxonomy,
            );
            codex_root_copies::merge_threads(&mut metadata, &codex_dir, &root_sidecar.threads);
            metadata.local_diagnostics.state_threads.observe_root(
                &state_census,
                open,
                metadata.identity_conflicts.len() != thread_conflicts_before,
                local_index_key(&codex_dir).as_str(),
            );
            let spawn_conflicts_before = metadata.identity_conflicts.len();
            let mut open = SidecarOpenCounts::default();
            let spawn_census = load_codex_sqlite_spawn_edges(
                &state_path,
                &mut open,
                &mut metadata.state_created_threads,
                &mut metadata.spawn_parents,
                &mut metadata.spawn_parent_conflicts,
                &mut metadata.identity_conflicts,
                &mut parentless_ineligible,
            );
            metadata.local_diagnostics.spawn_edges.observe_root(
                &spawn_census,
                open,
                metadata.identity_conflicts.len() != spawn_conflicts_before,
                local_index_key(&codex_dir).as_str(),
            );
            let title_census_incomplete = title_census.is_err();
            let state_census_incomplete = state_census.is_err();
            let spawn_census_incomplete = spawn_census.is_err();
            if title_census_incomplete || state_census_incomplete || spawn_census_incomplete {
                metadata.state_census_incomplete = true;
                metadata.sidecar_census_incomplete = true;
                metadata.state_census_unscoped_incomplete = true;
                metadata.sidecar_census_unscoped_incomplete = true;
            }
            if spawn_census_incomplete {
                metadata
                    .created_thread_census_failed_homes
                    .insert(codex_dir.clone());
            }
            if metadata.identity_conflicts.len() != state_conflicts_before {
                metadata.state_census_incomplete = true;
                metadata.sidecar_census_incomplete = true;
            }

            let history_path = codex_dir.join("thread_history_1.sqlite");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&history_path));
            let history_conflicts_before = metadata.identity_conflicts.len();
            let mut open = SidecarOpenCounts::default();
            let history_census = load_codex_rollout_extents(
                &history_path,
                &mut open,
                &mut root_sidecar.extents,
                &mut metadata.identity_conflicts,
            );
            codex_root_copies::merge_extents(&mut metadata, &root_sidecar.extents);
            metadata.local_diagnostics.rollout_extents.observe_root(
                &history_census,
                open,
                metadata.identity_conflicts.len() != history_conflicts_before,
                local_index_key(&codex_dir).as_str(),
            );
            if history_census.is_err() {
                metadata.sidecar_census_incomplete = true;
                metadata.sidecar_census_unscoped_incomplete = true;
            }
            if metadata.identity_conflicts.len() != history_conflicts_before {
                metadata.sidecar_census_incomplete = true;
            }

            metadata
                .root_sidecars
                .insert(codex_dir.clone(), root_sidecar);
            let index_path = codex_dir.join("session_index.jsonl");
            legacy_sidecar_parts.push(sidecar_stat_fingerprint(&index_path));
            let index_conflicts_before = metadata.identity_conflicts.len();
            let index_census = load_codex_session_index_titles(
                &index_path,
                &mut metadata.titles,
                &mut metadata.identity_conflicts,
            );
            metadata.local_diagnostics.session_index.observe_root(
                &index_census,
                SidecarOpenCounts::default(),
                metadata.identity_conflicts.len() != index_conflicts_before,
                local_index_key(&codex_dir).as_str(),
            );
            if index_census.is_err() {
                metadata.sidecar_census_incomplete = true;
                metadata.sidecar_census_unscoped_incomplete = true;
            }
            if metadata.identity_conflicts.len() != index_conflicts_before {
                metadata.sidecar_census_incomplete = true;
            }
        }
        // Unresolvable lineage evidence blocks only parentless admission. A
        // parent recorded by any home wins, and an id without a parent never
        // appears in a descendant's ancestor walk, so lineage is unaffected.
        for child in parentless_ineligible {
            if metadata.state_created_threads.contains(child.as_str())
                && !metadata.spawn_parents.contains_key(child.as_str())
            {
                metadata.spawn_parent_conflicts.insert(child);
            }
        }
        // A collision found by a later root/loader must also withhold any
        // earlier total-only fallback, even if no rollout can be opened.
        metadata
            .state_threads
            .retain(|id, _| !metadata.identity_conflicts.contains(id));
        metadata
            .rollout_extents
            .retain(|id, _| !metadata.identity_conflicts.contains(id));
        metadata.count_identity_conflict_scope();
        metadata.legacy_sidecar_fingerprint = sha256_hex_owned(&legacy_sidecar_parts);
        metadata
    }

    /// Diagnostics only. Reads the merged maps already in hand; the per-edge
    /// pass runs only when some conflict exists.
    fn count_identity_conflict_scope(&mut self) {
        let conflicts = &self.identity_conflicts;
        let taxonomy = &mut self.local_diagnostics.identity_conflict_taxonomy;
        taxonomy.conflict_keys_total = saturating_count_u32(conflicts.len());
        if conflicts.is_empty() {
            return;
        }
        taxonomy.conflict_keys_state_created = saturating_count_u32(
            conflicts
                .iter()
                .filter(|key| self.state_created_threads.contains(key.as_str()))
                .count(),
        );
        taxonomy.conflict_parent_child_edges = saturating_count_u32(
            self.spawn_parents
                .values()
                .filter(|parent| conflicts.contains(parent.as_str()))
                .count(),
        );
    }

    /// A failed created-thread census holds only
    /// rollouts whose proof could depend on a failing home's state database.
    pub(in crate::snapshots) fn created_thread_census_incomplete_for(&self, path: &Path) -> bool {
        !self.created_thread_census_failed_homes.is_empty()
            && !codex_rollout_thread_id(path).is_some_and(|identity| {
                self.created_thread_scoped
                    .get(&identity)
                    .is_some_and(|rollout| rollout == path)
            })
    }

    /// After a home's created-thread census failed, scope a rollout to
    /// its own home only when the file -> home map is exact. Its one identity
    /// has a state row in exactly one loaded home, whose created-thread census
    /// succeeded, which is the only loaded home containing the row's rollout
    /// path and which locates it exactly (`copy_locator`). Discovery has walked
    /// every failing root (in its scan roots, none pending, no namespace loss)
    /// without finding a rollout of that identity there (a copy whose unread
    /// row could disagree), and every spawn ancestor is scoped too: a spawned
    /// child's lineage (`family_position`) reads every home's edges. Anything
    /// else stays held. Counted in `created_thread_scoped_rollouts`.
    pub(in crate::snapshots) fn scope_created_thread_census(
        &mut self,
        index: &ScanIndex,
        roots: &[PathBuf],
    ) {
        let failed = &self.created_thread_census_failed_homes;
        let under_failed = |path: &Path| failed.iter().any(|home| path.starts_with(home));
        let Some(traversal) = index.traversal.as_ref() else {
            return;
        };
        if failed.is_empty()
            || roots
                .iter()
                .any(|root| under_failed(root) && !traversal.scan_roots.contains(root))
            || traversal
                .pending_directories
                .iter()
                .any(|directory| under_failed(&directory.path))
            || claude_family_census_shadow::Vetoes::current(index, traversal).namespace_loss
        {
            return;
        }
        let in_failed_homes = index
            .files
            .keys()
            .chain(&traversal.observed_index_keys)
            .chain(&traversal.codex_rollout_paths)
            .map(Path::new)
            .chain(
                traversal
                    .pending_candidates
                    .iter()
                    .map(|candidate| candidate.path.as_path()),
            )
            .filter(|path| under_failed(path))
            .flat_map(codex_session_id_candidates_from_path)
            .collect::<BTreeSet<_>>();
        let mut scoped = BTreeMap::new();
        for (home, sidecar) in &self.root_sidecars {
            if failed.contains(home) {
                continue;
            }
            for (identity, thread) in &sidecar.threads {
                let Some(rollout) = thread.rollout_path.as_deref().map(Path::new) else {
                    continue;
                };
                let single_home = self
                    .root_sidecars
                    .iter()
                    .filter(|(other, other_sidecar)| {
                        rollout.starts_with(other) || other_sidecar.threads.contains_key(identity)
                    })
                    .count()
                    == 1;
                if single_home
                    && codex_root_copies::copy_locator(home, identity, thread).is_some()
                    && !in_failed_homes.contains(identity)
                    && !self.identity_conflicts.contains(identity)
                {
                    scoped.insert(identity.clone(), rollout.to_path_buf());
                }
            }
        }
        let held_lineage = |identity: &String| {
            let mut child = resolve_codex_identity(identity);
            let mut seen = BTreeSet::new();
            while let Some(parent) = self.spawn_parents.get(child.as_str()) {
                if self.spawn_parent_conflicts.contains(child.as_str())
                    || !seen.insert(child)
                    || !scoped.contains_key(parent)
                {
                    return true;
                }
                child = parent.clone();
            }
            self.spawn_parent_conflicts.contains(child.as_str())
        };
        let held = scoped
            .keys()
            .filter(|&identity| held_lineage(identity))
            .cloned()
            .collect::<Vec<_>>();
        for identity in held {
            scoped.remove(&identity);
        }
        self.local_diagnostics.created_thread_scoped_rollouts = saturating_count_u32(scoped.len());
        self.created_thread_scoped = scoped;
    }
}

// `logs_2.sqlite` can be ~1GB+ with a live WAL and a concurrent writer (Codex
// itself). The read is best-effort, read-only, time-bounded, and row-capped so
// it can never disrupt Codex or stall the snapshot cycle. Any error (missing
// file, locked DB, schema churn) yields an empty map. Exact file-owned receipts
// retain protected old decisions; absent new signals keep the existing default.
const CODEX_LOGS2_MAX_ROWS: i64 = 50_000;
const CODEX_LOGS2_BUSY_TIMEOUT_MS: u64 = 400;
// The trace read window pads the session backfill window so a turn near a
// window edge still finds its request row. Capped so a stale/huge DB can never
// widen the scan unboundedly.
const CODEX_LOGS2_WINDOW_PAD_DAYS: u64 = 1;
const CODEX_LOGS2_MAX_WINDOW_DAYS: u64 = 14;

impl CodexTurnTraceMap {
    pub(in crate::snapshots) fn load_from_roots(
        roots: &[PathBuf],
        backfill_window_days: u64,
    ) -> Self {
        let mut map = Self::default();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }
        let since_epoch = codex_logs2_since_epoch(backfill_window_days);
        map.since_epoch = since_epoch;
        for codex_dir in codex_dirs {
            // The live DB lives directly under ~/.codex; a `sqlite/` subdir copy
            // exists on some installs. Read whichever is present.
            for db_path in [
                codex_dir.join("logs_2.sqlite"),
                codex_dir.join("sqlite").join("logs_2.sqlite"),
            ] {
                map.incomplete |= !load_codex_logs2_priority_turns(
                    &db_path,
                    since_epoch,
                    &mut map.priority_turns,
                );
            }
        }
        map
    }
}

fn codex_logs2_since_epoch(backfill_window_days: u64) -> i64 {
    let window_days = backfill_window_days
        .saturating_add(CODEX_LOGS2_WINDOW_PAD_DAYS)
        .min(CODEX_LOGS2_MAX_WINDOW_DAYS);
    let span = window_days.saturating_mul(86_400);
    let now = unix_seconds(SystemTime::now()).unwrap_or(0);
    now.saturating_sub(span) as i64
}

/// False when a present DB could not be read completely (open, prepare,
/// query or row error, or the row cap reached); a missing DB is complete.
fn load_codex_logs2_priority_turns(
    path: &Path,
    since_epoch: i64,
    priority_turns: &mut BTreeSet<String>,
) -> bool {
    if !path.exists() {
        return true;
    }
    let Ok(connection) = codex_sqlite_read::CodexSqliteRead::open(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        std::time::Duration::from_millis(CODEX_LOGS2_BUSY_TIMEOUT_MS),
    ) else {
        return false;
    };
    let Ok((turns, complete, read)) = connection.read(|connection| {
        // Only `response.create` request rows carry the *requested* service_tier.
        // The `idx_logs_ts` index bounds the scan to the recent window; the LIKE
        // then filters to the sparse request rows (hundreds, not the full table).
        let mut statement = connection.prepare(
            "SELECT feedback_log_body FROM logs \
             WHERE ts >= ?1 AND feedback_log_body LIKE '%websocket request:%' \
             ORDER BY ts DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            rusqlite::params![since_epoch, CODEX_LOGS2_MAX_ROWS],
            |row| row.get::<_, String>(0),
        )?;
        let mut complete = true;
        let mut read = 0_u64;
        let mut turns = Vec::new();
        for body in rows {
            let Ok(body) = body else {
                complete = false;
                continue;
            };
            read += 1;
            turns.extend(codex_logs2_priority_turn_from_body(&body));
        }
        if read == CODEX_LOGS2_MAX_ROWS as u64 {
            CapCounts::record("codex", 3, 1);
        }
        Ok((turns, complete, read))
    }) else {
        return false;
    };
    priority_turns.extend(turns);
    complete && read < CODEX_LOGS2_MAX_ROWS as u64
}

/// Parse one `feedback_log_body` row. Returns the `turn_id` when the row is a
/// `response.create` request that asked for `service_tier="priority"`.
///
/// Privacy: the row's JSON payload contains the full prompt (`input`,
/// `instructions`, `tools`). We read ONLY the `type` and `service_tier` fields
/// and the `turn.id` tracing span; no prompt or output content is retained.
fn codex_logs2_priority_turn_from_body(body: &str) -> Option<String> {
    const MARKER: &str = "websocket request:";
    let idx = body.rfind(MARKER)?;
    let prefix = &body[..idx];
    let json_text = body[idx + MARKER.len()..].trim();
    let value: Value = serde_json::from_str(json_text).ok()?;
    if value.get("type").and_then(Value::as_str) != Some("response.create") {
        return None;
    }
    let tier = value.get("service_tier").and_then(Value::as_str)?;
    if !tier.eq_ignore_ascii_case("priority") {
        return None;
    }
    codex_logs2_span_field(prefix, "turn.id")
        .or_else(|| codex_logs2_span_field(prefix, "turn_id"))
        .filter(|turn_id| !turn_id.is_empty())
}

/// Extract a `key=value` field from a tracing-span prefix, where the value is
/// terminated by whitespace, `,`, `{`, or `}`. The key must sit on an
/// identifier boundary so `turn_id` does not match inside `parent_turn_id`.
fn codex_logs2_span_field(prefix: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let mut search_start = 0;
    while let Some(rel) = prefix[search_start..].find(&needle) {
        let at = search_start + rel;
        let boundary = at == 0
            || !prefix[..at]
                .chars()
                .next_back()
                .map(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                .unwrap_or(false);
        let value_start = at + needle.len();
        if boundary {
            let value: String = prefix[value_start..]
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, ',' | '{' | '}'))
                .collect();
            if !value.is_empty() {
                return Some(value);
            }
        }
        search_start = value_start;
    }
    None
}

fn load_codex_session_index_titles(
    path: &Path,
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
    identity_conflicts: &mut BTreeSet<String>,
) -> Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("open Codex session index"),
    };
    let mut parsed = BTreeMap::new();
    let mut raw_ids_by_key = BTreeMap::new();
    let mut invalid_shape = false;
    let report = read_bounded_jsonl_lines(BufReader::new(file), |value| {
        let Some(id) = codex_identity_at(value, &["id"]) else {
            invalid_shape = true;
            return;
        };
        let id = record_codex_identity_key(&mut raw_ids_by_key, identity_conflicts, id.as_str());
        if identity_conflicts.contains(id.as_str()) {
            parsed.remove(id.as_str());
            titles.remove(id.as_str());
            return;
        }
        insert_codex_sidecar_title(
            &mut parsed,
            id,
            string_at(value, &["thread_name"])
                .or_else(|| string_at(value, &["title"]))
                .or_else(|| string_at(value, &["name"])),
            "session_index",
            true,
        );
    })
    .context("read Codex session index")?;
    if !report.complete() || invalid_shape {
        return Err(anyhow::Error::new(IncompleteShape)
            .context("Codex session index census was incomplete"));
    }
    titles.extend(parsed);
    Ok(())
}

fn load_codex_sqlite_titles(
    path: &Path,
    open: &mut SidecarOpenCounts,
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
    identity_conflicts: &mut BTreeSet<String>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection =
        open_codex_sidecar_database(path, open).context("open Codex title database")?;
    let loaded = connection.read(|connection| {
        census_rows(
            connection,
            "SELECT id, title FROM threads WHERE title IS NOT NULL AND title != ''",
            "Codex title census",
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
    })?;
    let mut raw_ids_by_key = BTreeMap::new();
    for (raw_id, title) in loaded {
        let id =
            record_codex_identity_key(&mut raw_ids_by_key, identity_conflicts, raw_id.as_str());
        if identity_conflicts.contains(id.as_str()) {
            titles.remove(id.as_str());
            continue;
        }
        insert_codex_sidecar_title(titles, id, Some(title), "session_index", false);
    }
    Ok(())
}

fn load_codex_sqlite_state_threads(
    path: &Path,
    open: &mut SidecarOpenCounts,
    state_threads: &mut BTreeMap<String, CodexStateThread>,
    identity_conflicts: &mut BTreeSet<String>,
    taxonomy: &mut IdentityConflictTaxonomy,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection =
        open_codex_sidecar_database(path, open).context("open Codex state database")?;
    let rows = connection.read(|connection| {
        let columns = sqlite_table_columns(connection, "threads")?;
        if !columns.contains("id") || !columns.contains("tokens_used") {
            return Err(anyhow::Error::new(IncompleteShape)
                .context("Codex state database is missing required thread census columns"));
        }

        let sql = format!(
            "SELECT id, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM threads WHERE tokens_used > 0",
            sqlite_select_expr(&columns, "title", "NULL"),
            sqlite_select_expr(&columns, "tokens_used", "0"),
            sqlite_select_expr(&columns, "archived", "0"),
            sqlite_select_expr(&columns, "created_at", "NULL"),
            sqlite_select_expr(&columns, "updated_at", "NULL"),
            sqlite_select_expr(&columns, "created_at_ms", "NULL"),
            sqlite_select_expr(&columns, "updated_at_ms", "NULL"),
            sqlite_select_expr(&columns, "model", "NULL"),
            sqlite_select_expr(&columns, "rollout_path", "NULL"),
        );
        census_rows(connection, &sql, "Codex state thread census", |row| {
            let id: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let tokens_used = non_negative_i64_to_u64(row.get::<_, i64>(2)?);
            let archived = row.get::<_, i64>(3)? != 0;
            let created_at = codex_state_timestamp(row.get(6)?, row.get(4)?);
            let updated_at = codex_state_timestamp(row.get(7)?, row.get(5)?);
            let model: Option<String> = row.get(8)?;
            let rollout_path: Option<String> = row.get(9)?;
            Ok((
                id,
                CodexStateThread {
                    title,
                    tokens_used,
                    archived,
                    created_at,
                    updated_at,
                    model,
                    rollout_path,
                },
            ))
        })
    })?;
    let mut loaded = BTreeMap::new();
    let mut raw_ids_by_key = BTreeMap::new();
    for (raw_id, thread) in rows {
        let conflicts_before = identity_conflicts.len();
        let id =
            record_codex_identity_key(&mut raw_ids_by_key, identity_conflicts, raw_id.as_str());
        if identity_conflicts.len() != conflicts_before {
            taxonomy.state_alias_keys = taxonomy.state_alias_keys.saturating_add(1);
        }
        if identity_conflicts.contains(id.as_str()) {
            loaded.remove(id.as_str());
            state_threads.remove(id.as_str());
            continue;
        }
        if loaded
            .insert(id.clone(), thread.clone())
            .is_some_and(|existing| existing != thread)
        {
            loaded.remove(id.as_str());
            state_threads.remove(id.as_str());
            identity_conflicts.insert(id);
            taxonomy.state_intra_root_row_keys =
                taxonomy.state_intra_root_row_keys.saturating_add(1);
        }
    }
    for (id, thread) in loaded {
        if let Some(existing) = state_threads
            .insert(id.clone(), thread.clone())
            .filter(|existing| *existing != thread)
        {
            taxonomy.observe_state_cross_root(codex_state_thread_field_diffs(&existing, &thread));
            state_threads.remove(id.as_str());
            identity_conflicts.insert(id);
        }
    }
    Ok(())
}

/// One unit per differing field. Exhaustive so a new row field must be
/// classified before it can take part in the row comparison above.
pub(in crate::snapshots) fn codex_state_thread_field_diffs(
    existing: &CodexStateThread,
    incoming: &CodexStateThread,
) -> StateRowFieldDiffs {
    let CodexStateThread {
        title,
        tokens_used,
        archived,
        created_at,
        updated_at,
        model,
        rollout_path,
    } = existing;
    StateRowFieldDiffs {
        title: u32::from(*title != incoming.title),
        tokens_used: u32::from(*tokens_used != incoming.tokens_used),
        archived: u32::from(*archived != incoming.archived),
        created_at: u32::from(*created_at != incoming.created_at),
        updated_at: u32::from(*updated_at != incoming.updated_at),
        model: u32::from(*model != incoming.model),
        rollout_path: u32::from(*rollout_path != incoming.rollout_path),
    }
}

fn saturating_count_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

pub(in crate::snapshots) fn load_codex_rollout_extents(
    path: &Path,
    open: &mut SidecarOpenCounts,
    rollout_extents: &mut BTreeMap<String, CodexRolloutExtent>,
    identity_conflicts: &mut BTreeSet<String>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection =
        open_codex_sidecar_database(path, open).context("open Codex thread-history database")?;
    let Some(rows) = connection.read(|connection| {
        let columns = sqlite_table_columns(connection, "thread_history_projection_state")?;
        if columns.is_empty() {
            return Ok(None);
        }
        if !columns.contains("thread_id")
            || !columns.contains("next_rollout_byte_offset")
            || !columns.contains("next_rollout_ordinal")
        {
            return Err(anyhow::Error::new(IncompleteShape)
                .context("Codex thread-history database has an incomplete projection schema"));
        }
        census_rows(
            connection,
            "SELECT thread_id, next_rollout_byte_offset, next_rollout_ordinal \
             FROM thread_history_projection_state",
            "Codex rollout-extent census",
            |row| {
                let thread_id: String = row.get(0)?;
                let next_byte_offset: i64 = row.get(1)?;
                let next_ordinal: i64 = row.get(2)?;
                Ok((thread_id, next_byte_offset, next_ordinal))
            },
        )
        .map(Some)
    })?
    else {
        return Ok(());
    };
    let mut loaded = BTreeMap::new();
    let mut raw_ids_by_key = BTreeMap::new();
    for (raw_thread_id, next_byte_offset, next_ordinal) in rows {
        let thread_id = record_codex_identity_key(
            &mut raw_ids_by_key,
            identity_conflicts,
            raw_thread_id.as_str(),
        );
        if identity_conflicts.contains(thread_id.as_str()) {
            loaded.remove(thread_id.as_str());
            rollout_extents.remove(thread_id.as_str());
            continue;
        }
        let next_byte_offset =
            u64::try_from(next_byte_offset).context("negative Codex rollout byte offset")?;
        let next_ordinal = u64::try_from(next_ordinal).context("negative Codex rollout ordinal")?;
        let extent = CodexRolloutExtent {
            next_byte_offset,
            next_ordinal,
        };
        if loaded
            .insert(thread_id.clone(), extent)
            .is_some_and(|existing| existing != extent)
        {
            loaded.remove(thread_id.as_str());
            rollout_extents.remove(thread_id.as_str());
            identity_conflicts.insert(thread_id);
        }
    }
    for (thread_id, extent) in loaded {
        if rollout_extents
            .insert(thread_id.clone(), extent)
            .is_some_and(|existing| existing != extent)
        {
            rollout_extents.remove(thread_id.as_str());
            identity_conflicts.insert(thread_id);
        }
    }
    Ok(())
}

/// `parentless_ineligible` collects ids whose lineage evidence exists but could
/// not be resolved here (delegation text the strict parser refused, an unknown
/// `first_user_message`, a malformed edge row, or no edge table). The caller
/// applies it only after every home is loaded, and only to ids that still have
/// no parent, so it can never remove a parent recorded elsewhere.
fn load_codex_sqlite_spawn_edges(
    path: &Path,
    open: &mut SidecarOpenCounts,
    state_created_threads: &mut BTreeSet<String>,
    spawn_parents: &mut BTreeMap<String, String>,
    spawn_parent_conflicts: &mut BTreeSet<String>,
    identity_conflicts: &mut BTreeSet<String>,
    parentless_ineligible: &mut BTreeSet<String>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let connection =
        open_codex_sidecar_database(path, open).context("open Codex spawn-edge database")?;

    // Newer Codex Desktop builds can create a child task without populating
    // `thread_spawn_edges`. The equivalent provider-native relationship lives
    // in the child row. Only the exact machine-owned source kind and wrapper
    // are eligible: ordinary user prompt text must never manufacture lineage.
    let rows = connection.read(|connection| {
        let thread_columns = sqlite_table_columns(connection, "threads")?;
        for required in ["id", "thread_source", "first_user_message"] {
            if !thread_columns.contains(required) {
                return Err(anyhow::Error::new(IncompleteShape).context(format!(
                    "Codex state database is missing required created-thread census column {required}"
                )));
            }
        }
        census_rows(
            connection,
            "SELECT id, first_user_message FROM threads \
             WHERE thread_source = 'agent_created_thread'",
            "Codex created-thread census",
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
    })?;
    let mut raw_created_ids_by_key = BTreeMap::new();
    let mut created_in_database = Vec::new();
    for (raw_child, first_user_message) in rows {
        let child = record_codex_identity_key(
            &mut raw_created_ids_by_key,
            identity_conflicts,
            raw_child.as_str(),
        );
        if identity_conflicts.contains(child.as_str()) {
            state_created_threads.remove(child.as_str());
            spawn_parents.remove(child.as_str());
            spawn_parent_conflicts.insert(child);
            continue;
        }
        state_created_threads.insert(child.clone());
        created_in_database.push(child.clone());
        if first_user_message
            .as_deref()
            .map(codex_created_thread_mentions_delegation)
            .unwrap_or(true)
        {
            parentless_ineligible.insert(child.clone());
        }
        if let Some(parent) = first_user_message
            .as_deref()
            .and_then(|message| codex_created_thread_parent(&child, message))
        {
            record_codex_spawn_parent(spawn_parents, spawn_parent_conflicts, child, parent);
        }
    }

    let Some(loaded) = connection.read(|connection| {
        let columns = sqlite_table_columns(connection, "thread_spawn_edges")?;
        if !columns.contains("parent_thread_id") || !columns.contains("child_thread_id") {
            return Ok(None);
        }
        census_rows(
            connection,
            "SELECT parent_thread_id, child_thread_id FROM thread_spawn_edges",
            "Codex spawn-edge census",
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map(Some)
    })?
    else {
        // Without the edge table, a missing edge is not evidence of no parent.
        parentless_ineligible.extend(created_in_database);
        return Ok(());
    };
    let mut raw_parent_ids_by_key = BTreeMap::new();
    let mut raw_child_ids_by_key = BTreeMap::new();
    for (raw_parent, raw_child) in loaded {
        let parent = record_codex_identity_key(
            &mut raw_parent_ids_by_key,
            identity_conflicts,
            raw_parent.as_str(),
        );
        let child = record_codex_identity_key(
            &mut raw_child_ids_by_key,
            identity_conflicts,
            raw_child.as_str(),
        );
        if identity_conflicts.contains(child.as_str())
            || identity_conflicts.contains(parent.as_str())
        {
            spawn_parents.remove(child.as_str());
            spawn_parent_conflicts.insert(child);
            continue;
        }
        if !parent.is_empty() && !child.is_empty() && parent != child {
            record_codex_spawn_parent(spawn_parents, spawn_parent_conflicts, child, parent);
        } else if !child.is_empty() {
            // A self or empty-parent edge is broken lineage, not its absence.
            parentless_ineligible.insert(child);
        }
    }
    Ok(())
}

/// Any delegation wrapper text, wherever it appears and in any case, is
/// lineage evidence. Only the strict parser above may turn it into a parent.
fn codex_created_thread_mentions_delegation(first_user_message: &str) -> bool {
    first_user_message
        .to_ascii_lowercase()
        .contains("<codex_delegation")
}

fn record_codex_spawn_parent(
    spawn_parents: &mut BTreeMap<String, String>,
    spawn_parent_conflicts: &mut BTreeSet<String>,
    child: String,
    parent: String,
) {
    let child = resolve_codex_identity(child.as_str());
    let parent = resolve_codex_identity(parent.as_str());
    if spawn_parent_conflicts.contains(child.as_str()) {
        return;
    }
    match spawn_parents.get(child.as_str()) {
        Some(existing) if existing != &parent => {
            spawn_parents.remove(child.as_str());
            spawn_parent_conflicts.insert(child);
        }
        Some(_) => {}
        None => {
            spawn_parents.insert(child, parent);
        }
    }
}

/// Extract the provider-owned parent id from Codex Desktop's create-thread
/// wrapper without retaining or interpreting the delegated prompt body.
///
/// Callers must already have verified `thread_source=agent_created_thread`.
/// The exact wrapper shape, a single UUID-like source id, and a different child
/// id are required so user-authored lookalike text fails closed.
pub(in crate::snapshots) fn codex_created_thread_parent(
    child: &str,
    first_user_message: &str,
) -> Option<String> {
    const OPEN: &str = "<codex_delegation>\n  <source_thread_id>";
    const SOURCE_CLOSE_AND_INPUT_OPEN: &str = "</source_thread_id>\n  <input>";
    const CLOSE: &str = "</input>\n</codex_delegation>";

    let message = first_user_message.trim();
    let remainder = message.strip_prefix(OPEN)?;
    let (parent, input_and_close) = remainder.split_once(SOURCE_CLOSE_AND_INPUT_OPEN)?;
    if !input_and_close.ends_with(CLOSE)
        || input_and_close[..input_and_close.len() - CLOSE.len()].contains(CLOSE)
        || !codex_identity_is_uuid_shaped(parent)
        || !codex_identity_is_uuid_shaped(child)
        || resolve_codex_identity(parent) == resolve_codex_identity(child)
    {
        return None;
    }
    Some(resolve_codex_identity(parent))
}

/// Record one raw identifier at a sidecar-ingress boundary. A single
/// uppercase/mixed-case UUID row is accepted and normalized; distinct raw rows
/// that collapse to the same key are retained in `identity_conflicts` so that
/// key fails closed while unrelated census entries remain usable.
fn record_codex_identity_key(
    raw_ids_by_key: &mut BTreeMap<String, String>,
    identity_conflicts: &mut BTreeSet<String>,
    raw_id: &str,
) -> String {
    let key = resolve_codex_identity(raw_id);
    if raw_ids_by_key
        .get(key.as_str())
        .is_some_and(|existing| existing != raw_id)
    {
        identity_conflicts.insert(key.clone());
    }
    raw_ids_by_key
        .entry(key.clone())
        .or_insert_with(|| raw_id.to_string());
    key
}

/// Bounded retries of a transient sidecar open: on a real install (2026-10-31)
/// `~/.codex/state_5.sqlite` failed SQLITE_CANTOPEN at its first prepare on 11
/// of 175 Codex pages while Codex itself kept it open. BUSY at the open's
/// schema probe, which never waits, is retried too: it usually means Codex
/// is closing the database, and the retry re-checks whether it is now idle.
/// So does CANTOPEN when Codex removed the `-wal` after that check.
pub(in crate::snapshots) const CODEX_SIDECAR_OPEN_RETRIES: u32 = 3;
const CODEX_SIDECAR_OPEN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);
/// Open a Codex sidecar database read-only and read its schema, which opens
/// the WAL and its index for the connection's later statements. A transient
/// CANTOPEN or BUSY is retried; `open` counts the extra attempts and an idle
/// WAL database read as a snapshot, whose rows the caller reads through
/// `CodexSqliteRead::read`.
fn open_codex_sidecar_database(
    path: &Path,
    open: &mut SidecarOpenCounts,
) -> Result<codex_sqlite_read::CodexSqliteRead> {
    let connection = retry_transient_sqlite(&mut open.retries, || {
        codex_sqlite_read::CodexSqliteRead::open(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            CODEX_SIDECAR_BUSY_TIMEOUT,
        )
    })?;
    if connection.is_snapshot() {
        open.snapshots = open.snapshots.saturating_add(1);
    }
    Ok(connection)
}

/// Run `attempt` until it succeeds, fails other than SQLITE_CANTOPEN or
/// SQLITE_BUSY, or has been retried `CODEX_SIDECAR_OPEN_RETRIES` times.
pub(in crate::snapshots) fn retry_transient_sqlite<T>(
    retries: &mut u32,
    mut attempt: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut retried = 0;
    loop {
        match attempt() {
            Err(error)
                if retried < CODEX_SIDECAR_OPEN_RETRIES
                    && matches!(
                        error.downcast_ref::<rusqlite::Error>(),
                        Some(rusqlite::Error::SqliteFailure(failure, _))
                            if matches!(
                                failure.code,
                                rusqlite::ErrorCode::CannotOpen | rusqlite::ErrorCode::DatabaseBusy
                            )
                    ) =>
            {
                retried += 1;
                *retries = retries.saturating_add(1);
                std::thread::sleep(CODEX_SIDECAR_OPEN_BACKOFF * retried);
            }
            result => return result,
        }
    }
}

fn sqlite_table_columns(connection: &Connection, table_name: &str) -> Result<BTreeSet<String>> {
    let columns = census_rows(
        connection,
        &format!("PRAGMA table_info({table_name})"),
        "SQLite table census",
        |row| row.get::<_, String>(1),
    )?;
    Ok(columns.into_iter().collect())
}

/// Every row of one census query. Failures carry their loader stage and
/// "prepare {label}" or "read {label} row".
fn census_rows<T>(
    connection: &Connection,
    sql: &str,
    label: &str,
    map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    use crate::codex_scan_diagnostics::LoaderStage;
    let mut statement = connection
        .prepare(sql)
        .context(LoaderStage::Prepare)
        .with_context(|| format!("prepare {label}"))?;
    let rows = statement.query_map([], map).context(LoaderStage::Query)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context(LoaderStage::Row)
        .with_context(|| format!("read {label} row"))
}

fn sqlite_select_expr(columns: &BTreeSet<String>, column: &str, fallback: &str) -> String {
    if columns.contains(column) {
        column.to_string()
    } else {
        format!("{fallback} AS {column}")
    }
}

fn non_negative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}

fn codex_state_timestamp(ms: Option<i64>, seconds: Option<i64>) -> Option<String> {
    let timestamp_ms = ms.or_else(|| seconds.map(|value| value.saturating_mul(1_000)))?;
    bounded_rfc3339_millis(timestamp_ms)
}

pub(in crate::snapshots) fn insert_codex_sidecar_title(
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
    id: String,
    title: Option<String>,
    source: &str,
    overwrite: bool,
) {
    if id.is_empty() {
        return;
    }
    let id = resolve_codex_identity(id.as_str());
    let Some(title) = title.and_then(|value| normalize_display_title(value, source)) else {
        return;
    };
    if !overwrite && titles.contains_key(id.as_str()) {
        return;
    }
    titles.insert(
        id,
        CodexTitleCandidate {
            title,
            source: source.to_string(),
        },
    );
}

// Pre-semantic-sync indexes embedded one source-wide sidecar stat digest in
// every file fingerprint. Retain this derivation only to prove whether a legacy
// entry can be migrated without parsing; new entries never use it.
fn sidecar_stat_fingerprint(path: &Path) -> String {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            format!(
                "{}:{}:{}",
                path.to_string_lossy(),
                metadata.len(),
                modified_unix_seconds
            )
        }
        Err(_) => format!("{}:missing", path.to_string_lossy()),
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
