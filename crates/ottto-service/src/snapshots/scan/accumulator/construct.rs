//! Building a snapshot accumulator and binding its Codex sidecar parent.

use super::{CodexOwnershipBoundary, SelectorCapture, SnapshotAccumulator};
use crate::snapshots::{
    claude_request_identity, codex_identity_at, codex_session_id_candidates_from_path,
    codex_session_id_is_native_parent, codex_sidecar_rollout_file_matches,
    resolve_codex_identity_option, rfc3339_unix_nanos, ClaudeFileBirth, ClaudeResponseBook,
    CodexCompactionSizes, CodexPathSidecarCandidate, CodexTitleMetadata, LocalContextPoints,
    PiLedger, SnapshotOrigin, SnapshotSource, UsageTotals,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

impl SnapshotAccumulator {
    pub(in crate::snapshots) fn new(source: SnapshotSource) -> Self {
        Self {
            source,
            cache_configuration_witness: None,
            cache_task_complete_at: None,
            cache_pending_idle: None,
            cache_active_turns: BTreeSet::new(),
            context_curve_enabled: false,
            source_session_id: None,
            account_identifier_hash: None,
            title: None,
            title_source: None,
            first_prompt_title: None,
            first_prompt_material: None,
            provider_skills: BTreeSet::new(),
            started_at: None,
            ended_at: None,
            last_activity_at: None,
            workspace_hash: None,
            workspace_path: None,
            repository_binding: None,
            latest_model: None,
            latest_reasoning_effort: None,
            latest_turn_id: None,
            codex_observed_priority_turns: None,
            codex_tier_replay: None,
            codex_counting: None,
            current_selector: SelectorCapture::default(),
            session_cumulative_usage: None,
            codex_session_meta_seen: false,
            codex_record_seen: false,
            codex_creator_header_id: None,
            codex_creator_evidence: None,
            codex_creator_evidence_conflicted: false,
            claude_desktop_identity: None,
            claude_desktop_spawn_lineage: None,
            claude_owned_session_id_observed: false,
            claude_owned_session_id_conflicted: false,
            codex_ownership_boundary: CodexOwnershipBoundary::Undetermined,
            codex_legacy_trigger_seen: false,
            codex_legacy_bootstrap_valid: true,
            codex_sidecar_created_thread: false,
            codex_path_sidecar_candidates: Vec::new(),
            codex_resolved_path_identity: None,
            codex_sidecar_identity_ambiguous: false,
            codex_sidecar_parent: None,
            codex_sidecar_child_created_at_nanos: None,
            codex_bind_seed_len: None,
            codex_sidecar_projected_next_ordinal: None,
            codex_parent_session_ref: None,
            codex_native_created_thread_valid: true,
            codex_created_thread_native_only: false,
            codex_native_created_thread_header_nanos: None,
            codex_native_created_thread_last_nanos: None,
            codex_native_created_thread_task_turn_id: None,
            codex_native_created_thread_first_turn_bound: false,
            codex_ordinal_expected: None,
            codex_ordinal_sequence_valid: true,
            codex_owned_record_seen: false,
            codex_is_fork: false,
            codex_inherited_usage_records_skipped: 0,
            codex_duplicate_usage_records_skipped: 0,
            codex_cumulative_reset_count: 0,
            codex_context_curve_candidates: crate::owned_heap::OwnedVec::new(),
            codex_context_curve_boundaries: crate::owned_heap::OwnedVec::new(),
            codex_context_curve_exact_supported: true,
            codex_last_usage_event_identity: None,
            codex_legacy_bootstrap_buffer: Vec::new(),
            accepted_usage_totals: UsageTotals::default(),
            usage_buckets: BTreeMap::new(),
            origin: SnapshotOrigin::default(),
            codex_root_session_ref: None,
            codex_spawn_depth: None,
            codex_agent_label: None,
            activity_tool_counts: BTreeMap::new(),
            activity_call_tools: BTreeMap::new(),
            activity_mcp_tool_counts: BTreeMap::new(),
            activity_mcp_tool_usage_counts: BTreeMap::new(),
            activity_mcp_call_ids: BTreeMap::new(),
            activity_capability_buckets: BTreeMap::new(),
            seen_claude_capability_tool_uses: crate::owned_heap::OwnedMap::new(),
            activity_skills: BTreeSet::new(),
            skill_detector_incomplete: false,
            activity_changed_file_hashes: BTreeSet::new(),
            activity_patch_operations: 0,
            activity_lines_added: 0,
            activity_lines_deleted: 0,
            activity_web_searches: 0,
            activity_mcp_calls: 0,
            activity_subagent_spawns: 0,
            artifacts: Vec::new(),
            // Default on so direct parse-function callers (mostly tests) keep
            // extracting; the production scan path overrides this from policy.
            artifacts_enabled: true,
            latency_duration_ms_sum: 0,
            latency_duration_ms_count: 0,
            latency_ttft_ms_sum: 0,
            latency_ttft_ms_count: 0,
            latency_duration_ms_max: 0,
            latency_ttft_ms_max: 0,
            claude_responses: ClaudeResponseBook::default(),
            claude_response_sequence: 0,
            claude_response_record_count: 0,
            claude_usage_request_ids: BTreeSet::new(),
            claude_usage_occurrences: BTreeMap::new(),
            // Preserve parser fixtures' capture default; released scans capture Claude only.
            claude_request_identity_capture: cfg!(test)
                || claude_request_identity::captures(source),
            claude_org_markers: None,
            cache_observations: None,
            cache_requests: crate::owned_heap::OwnedVec::new(),
            cache_requests_complete: true,
            claude_context_curve_identity_complete: true,
            claude_context_curve_request_index_complete: true,
            claude_context_curve_owned_start_proven: false,
            claude_file_birth: ClaudeFileBirth::default(),
            claude_fork_parent: None,
            claude_money: None,
            tool_usage_counts: BTreeMap::new(),
            tool_usage_truncated: false,
            seen_pi_usage_keys: PiLedger::default(),
            dropped_usage_record_count: 0,
            claude_last_user_ts: None,
            claude_line_clocks: None,
            peak_context_fill_tokens: 0,
            first_turn_context_tokens: None,
            last_turn_context_tokens: None,
            first_turn_context_window_tokens: None,
            peak_context_fill_window_tokens: None,
            last_turn_context_window_tokens: None,
            compaction_count: 0,
            compaction_timestamps: crate::owned_heap::OwnedVec::new(),
            codex_compaction_sizes: CodexCompactionSizes::default(),
            local_context_points: LocalContextPoints::default(),
            claude_compaction_observations: crate::owned_heap::OwnedVec::new(),
            claude_compaction_link_tip: None,
            session_start: Box::default(),
            codex_dictionary_slots: Default::default(),
            codex_sidecar_binding: None,
        }
    }

    pub(in crate::snapshots) fn seed_codex_sidecar_parent(
        &mut self,
        path: &Path,
        file_metadata: &fs::Metadata,
        metadata: &CodexTitleMetadata,
    ) {
        self.codex_sidecar_binding =
            Some(metadata.path_reduction_fingerprint(path)).filter(|binding| !binding.is_empty());
        self.codex_bind_seed_len = Some(file_metadata.len());
        let identities = codex_session_id_candidates_from_path(path);
        if identities.is_empty() {
            // A provider rollout whose identity cannot be resolved while the
            // trusted state contains created-thread suspects cannot safely be
            // treated as an ordinary file.
            self.codex_sidecar_identity_ambiguous = !metadata.state_created_threads.is_empty()
                || metadata.created_thread_census_incomplete_for(path);
            return;
        }
        self.codex_path_sidecar_candidates = identities
            .into_iter()
            .map(|identity| {
                let (thread, rollout_extent) =
                    metadata.thread_extent_for_path(identity.as_str(), path);
                let parent = metadata
                    .family_position(identity.as_str())
                    .map(|(parent, _, _)| parent);
                let created_thread = metadata.state_created_threads.contains(identity.as_str());
                // A created thread without a trusted parent can be admitted only
                // from its own file proof. Its creation time is usable solely when
                // no lineage evidence exists at all and the state row positively
                // locates this whole rollout (path plus thread-history extent).
                // Otherwise withhold it, so no native creation witness can start.
                let parentless_creation_bound = created_thread
                    && parent.is_none()
                    && !metadata.spawn_parents.contains_key(identity.as_str())
                    && !metadata.spawn_parent_conflicts.contains(identity.as_str())
                    && rollout_extent.is_some()
                    && thread
                        .and_then(|thread| thread.rollout_path.as_deref())
                        .is_some_and(|path| !path.is_empty());
                CodexPathSidecarCandidate {
                    recorded_evidence: metadata.has_identity_evidence(identity.as_str()),
                    created_thread,
                    identity_conflict: metadata.identity_conflicts.contains(identity.as_str()),
                    detail_incomplete: metadata.state_census_unscoped_incomplete
                        || metadata.sidecar_census_unscoped_incomplete,
                    rollout_file_matches: codex_sidecar_rollout_file_matches(
                        path,
                        file_metadata,
                        thread,
                        rollout_extent,
                        created_thread,
                    ),
                    child_created_at_nanos: (parent.is_some() || parentless_creation_bound)
                        .then_some(thread)
                        .flatten()
                        .and_then(|thread| thread.created_at.as_deref())
                        .and_then(rfc3339_unix_nanos),
                    parent,
                    projected_next_ordinal: rollout_extent.map(|extent| extent.next_ordinal),
                    identity,
                }
            })
            .collect();

        if metadata.created_thread_census_incomplete_for(path) {
            self.codex_sidecar_identity_ambiguous = true;
            return;
        }
        if self.codex_path_sidecar_candidates.len() == 1 {
            self.bind_codex_path_sidecar_candidate(0);
            return;
        }
        let supported = self
            .codex_path_sidecar_candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.recorded_evidence.then_some(index))
            .collect::<Vec<_>>();
        if supported.len() == 1 {
            self.bind_codex_path_sidecar_candidate(supported[0]);
        } else if supported.len() > 1
            && supported.iter().any(|index| {
                let candidate = &self.codex_path_sidecar_candidates[*index];
                candidate.created_thread || candidate.identity_conflict
            })
        {
            self.codex_sidecar_identity_ambiguous = true;
        }
    }

    fn bind_codex_path_sidecar_candidate(&mut self, index: usize) {
        let candidate = self.codex_path_sidecar_candidates[index].clone();
        self.codex_resolved_path_identity = Some(candidate.identity.clone());
        // Retain a successfully loaded classification even when an optional
        // title/detail/projection census is unhealthy. Those incomplete facts
        // make a created candidate ambiguous, but they do not reclassify an
        // unrelated ordinary rollout. Only failure of the classification
        // query itself has genuinely source-wide scope.
        self.codex_sidecar_created_thread = candidate.created_thread;
        self.codex_sidecar_identity_ambiguous = candidate.identity_conflict
            || (candidate.created_thread && candidate.detail_incomplete);
        if self.codex_sidecar_identity_ambiguous {
            return;
        }
        // Bind the state-row declaration before validating the optional
        // lineage/file cross-checks. A state-declared created thread whose
        // sidecar conflicts with the opened rollout is still a created thread
        // for admission purposes and must fail closed, never fall through to
        // an ordinary ownership branch.
        if !candidate.rollout_file_matches {
            return;
        }
        let Some(parent) = candidate.parent else {
            if candidate.created_thread {
                // Parentless candidate: the seed withheld the creation time unless
                // lineage is provably absent and the row locates this whole file.
                self.codex_sidecar_child_created_at_nanos = candidate.child_created_at_nanos;
                self.codex_sidecar_projected_next_ordinal = candidate.projected_next_ordinal;
            }
            return;
        };
        self.codex_sidecar_child_created_at_nanos = candidate.child_created_at_nanos;
        self.codex_sidecar_projected_next_ordinal = candidate.projected_next_ordinal;
        self.codex_sidecar_parent = Some((candidate.identity, parent));
    }

    pub(in crate::snapshots) fn resolve_codex_path_sidecar_from_header(&mut self, meta: &Value) {
        if self.codex_resolved_path_identity.is_some()
            || self.codex_sidecar_identity_ambiguous
            || self.codex_path_sidecar_candidates.len() < 2
        {
            return;
        }
        let header_id = resolve_codex_identity_option(codex_identity_at(meta, &["id"]));
        let header_session_id =
            resolve_codex_identity_option(codex_identity_at(meta, &["session_id"]));
        let header_identity = match (header_id, header_session_id) {
            (Some(id), Some(session_id))
                if id == session_id || codex_session_id_is_native_parent(meta, &session_id) =>
            {
                Some(id)
            }
            (Some(id), None) | (None, Some(id)) => Some(id),
            _ => None,
        };
        let header_match = header_identity.as_deref().and_then(|identity| {
            self.codex_path_sidecar_candidates
                .iter()
                .position(|candidate| candidate.identity == identity)
        });
        let recorded = self
            .codex_path_sidecar_candidates
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| candidate.recorded_evidence.then_some(index))
            .collect::<Vec<_>>();
        let created_or_conflicted_evidence = recorded.iter().any(|index| {
            let candidate = &self.codex_path_sidecar_candidates[*index];
            candidate.created_thread || candidate.identity_conflict
        });
        if created_or_conflicted_evidence && recorded.len() != 1 {
            self.codex_sidecar_identity_ambiguous = true;
            return;
        }
        if let Some(index) = header_match.or_else(|| (recorded.len() == 1).then(|| recorded[0])) {
            self.bind_codex_path_sidecar_candidate(index);
        } else if created_or_conflicted_evidence {
            self.codex_sidecar_identity_ambiguous = true;
        }
    }
}
