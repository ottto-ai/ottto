//! Test-only `Debug` for the live accumulator, which derives only `Clone`.
//! Lists the fields that reach the durable body; `E` and `I` fields never do.
impl std::fmt::Debug for crate::snapshots::SnapshotAccumulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotAccumulator")
            .field("source", &self.source)
            .field(
                "cache_configuration_witness",
                &self.cache_configuration_witness,
            )
            .field("cache_task_complete_at", &self.cache_task_complete_at)
            .field("cache_pending_idle", &self.cache_pending_idle)
            .field("cache_active_turns", &self.cache_active_turns)
            .field("context_curve_enabled", &self.context_curve_enabled)
            .field("source_session_id", &self.source_session_id)
            .field("account_identifier_hash", &self.account_identifier_hash)
            .field("title", &self.title)
            .field("title_source", &self.title_source)
            .field("first_prompt_title", &self.first_prompt_title)
            .field("first_prompt_material", &self.first_prompt_material)
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("last_activity_at", &self.last_activity_at)
            .field("workspace_hash", &self.workspace_hash)
            .field("workspace_path", &self.workspace_path)
            .field("latest_model", &self.latest_model)
            .field("latest_reasoning_effort", &self.latest_reasoning_effort)
            .field("latest_turn_id", &self.latest_turn_id)
            .field(
                "codex_observed_priority_turns",
                &self.codex_observed_priority_turns,
            )
            .field(
                "codex_priority_witnesses_uncapped",
                &self.codex_priority_witnesses_uncapped,
            )
            .field("codex_counting", &self.codex_counting)
            .field("current_selector", &self.current_selector)
            .field("session_cumulative_usage", &self.session_cumulative_usage)
            .field("codex_session_meta_seen", &self.codex_session_meta_seen)
            .field("codex_record_seen", &self.codex_record_seen)
            .field("codex_creator_header_id", &self.codex_creator_header_id)
            .field("codex_creator_evidence", &self.codex_creator_evidence)
            .field(
                "codex_creator_evidence_conflicted",
                &self.codex_creator_evidence_conflicted,
            )
            .field(
                "claude_owned_session_id_observed",
                &self.claude_owned_session_id_observed,
            )
            .field(
                "claude_owned_session_id_conflicted",
                &self.claude_owned_session_id_conflicted,
            )
            .field("codex_ownership_boundary", &self.codex_ownership_boundary)
            .field("codex_legacy_trigger_seen", &self.codex_legacy_trigger_seen)
            .field(
                "codex_legacy_bootstrap_valid",
                &self.codex_legacy_bootstrap_valid,
            )
            .field(
                "codex_sidecar_created_thread",
                &self.codex_sidecar_created_thread,
            )
            .field(
                "codex_path_sidecar_candidates",
                &self.codex_path_sidecar_candidates,
            )
            .field(
                "codex_resolved_path_identity",
                &self.codex_resolved_path_identity,
            )
            .field(
                "codex_sidecar_identity_ambiguous",
                &self.codex_sidecar_identity_ambiguous,
            )
            .field("codex_sidecar_parent", &self.codex_sidecar_parent)
            .field(
                "codex_sidecar_child_created_at_nanos",
                &self.codex_sidecar_child_created_at_nanos,
            )
            .field("codex_bind_seed_len", &self.codex_bind_seed_len)
            .field("codex_parent_session_ref", &self.codex_parent_session_ref)
            .field(
                "codex_parent_prefix_digest",
                &self.codex_parent_prefix_digest,
            )
            .field(
                "codex_parent_prefix_decided",
                &self.codex_parent_prefix_decided,
            )
            .field(
                "codex_parent_proof_mismatch",
                &self.codex_parent_proof_mismatch,
            )
            .field("codex_proof_decision_only", &self.codex_proof_decision_only)
            .field(
                "codex_boundary_buffer_count",
                &self.codex_boundary_buffer_count,
            )
            .field("codex_proof_ledger_row", &self.codex_proof_ledger_row)
            .field(
                "codex_parent_ledger_identity_used",
                &self.codex_parent_ledger_identity_used,
            )
            .field("codex_parent_unresolvable", &self.codex_parent_unresolvable)
            .field(
                "codex_parent_ledger_consulted",
                &self.codex_parent_ledger_consulted,
            )
            .field(
                "codex_parent_signature_index",
                &self.codex_parent_signature_index,
            )
            .field(
                "codex_native_created_thread_valid",
                &self.codex_native_created_thread_valid,
            )
            .field(
                "codex_created_thread_native_only",
                &self.codex_created_thread_native_only,
            )
            .field(
                "codex_native_created_thread_header_nanos",
                &self.codex_native_created_thread_header_nanos,
            )
            .field(
                "codex_native_created_thread_last_nanos",
                &self.codex_native_created_thread_last_nanos,
            )
            .field(
                "codex_native_created_thread_task_turn_id",
                &self.codex_native_created_thread_task_turn_id,
            )
            .field(
                "codex_native_created_thread_first_turn_bound",
                &self.codex_native_created_thread_first_turn_bound,
            )
            .field("codex_physical_signatures", &self.codex_physical_signatures)
            .field(
                "codex_physical_signatures_complete",
                &self.codex_physical_signatures_complete,
            )
            .field("codex_ordinal_expected", &self.codex_ordinal_expected)
            .field(
                "codex_ordinal_sequence_valid",
                &self.codex_ordinal_sequence_valid,
            )
            .field("codex_owned_record_seen", &self.codex_owned_record_seen)
            .field("codex_is_fork", &self.codex_is_fork)
            .field(
                "codex_inherited_usage_records_skipped",
                &self.codex_inherited_usage_records_skipped,
            )
            .field(
                "codex_duplicate_usage_records_skipped",
                &self.codex_duplicate_usage_records_skipped,
            )
            .field(
                "codex_cumulative_reset_count",
                &self.codex_cumulative_reset_count,
            )
            .field(
                "codex_context_curve_candidates",
                &self.codex_context_curve_candidates,
            )
            .field(
                "codex_context_curve_boundaries",
                &self.codex_context_curve_boundaries,
            )
            .field(
                "codex_context_curve_exact_supported",
                &self.codex_context_curve_exact_supported,
            )
            .field(
                "codex_last_usage_event_identity",
                &self.codex_last_usage_event_identity,
            )
            .field("accepted_usage_totals", &self.accepted_usage_totals)
            .field("usage_buckets", &self.usage_buckets)
            .field("origin", &self.origin)
            .field("codex_root_session_ref", &self.codex_root_session_ref)
            .field("codex_spawn_depth", &self.codex_spawn_depth)
            .field("codex_agent_label", &self.codex_agent_label)
            .field("activity_tool_counts", &self.activity_tool_counts)
            .field("activity_call_tools", &self.activity_call_tools)
            .field("activity_mcp_tool_counts", &self.activity_mcp_tool_counts)
            .field(
                "activity_mcp_tool_usage_counts",
                &self.activity_mcp_tool_usage_counts,
            )
            .field("activity_mcp_call_ids", &self.activity_mcp_call_ids)
            .field(
                "activity_capability_buckets",
                &self.activity_capability_buckets,
            )
            .field(
                "seen_claude_capability_tool_uses",
                &self.seen_claude_capability_tool_uses,
            )
            .field("skill_detector_incomplete", &self.skill_detector_incomplete)
            .field(
                "activity_changed_file_hashes",
                &self.activity_changed_file_hashes,
            )
            .field("activity_patch_operations", &self.activity_patch_operations)
            .field("activity_lines_added", &self.activity_lines_added)
            .field("activity_lines_deleted", &self.activity_lines_deleted)
            .field("activity_web_searches", &self.activity_web_searches)
            .field("activity_mcp_calls", &self.activity_mcp_calls)
            .field("activity_subagent_spawns", &self.activity_subagent_spawns)
            .field("artifacts_enabled", &self.artifacts_enabled)
            .field("latency_duration_ms_sum", &self.latency_duration_ms_sum)
            .field("latency_duration_ms_count", &self.latency_duration_ms_count)
            .field("latency_ttft_ms_sum", &self.latency_ttft_ms_sum)
            .field("latency_ttft_ms_count", &self.latency_ttft_ms_count)
            .field("latency_duration_ms_max", &self.latency_duration_ms_max)
            .field("latency_ttft_ms_max", &self.latency_ttft_ms_max)
            .field("claude_responses", &self.claude_responses)
            .field("claude_response_sequence", &self.claude_response_sequence)
            .field(
                "claude_response_record_count",
                &self.claude_response_record_count,
            )
            .field(
                "claude_request_identity_capture",
                &self.claude_request_identity_capture,
            )
            .field("claude_org_markers", &self.claude_org_markers)
            .field("cache_requests", &self.cache_requests)
            .field("cache_requests_complete", &self.cache_requests_complete)
            .field(
                "claude_context_curve_identity_complete",
                &self.claude_context_curve_identity_complete,
            )
            .field(
                "claude_context_curve_request_index_complete",
                &self.claude_context_curve_request_index_complete,
            )
            .field(
                "claude_context_curve_owned_start_proven",
                &self.claude_context_curve_owned_start_proven,
            )
            .field("claude_file_birth", &self.claude_file_birth)
            .field("tool_usage_counts", &self.tool_usage_counts)
            .field("tool_usage_truncated", &self.tool_usage_truncated)
            .field(
                "dropped_usage_record_count",
                &self.dropped_usage_record_count,
            )
            .field("claude_last_user_ts", &self.claude_last_user_ts)
            .field("peak_context_fill_tokens", &self.peak_context_fill_tokens)
            .field("first_turn_context_tokens", &self.first_turn_context_tokens)
            .field("last_turn_context_tokens", &self.last_turn_context_tokens)
            .field(
                "first_turn_context_window_tokens",
                &self.first_turn_context_window_tokens,
            )
            .field(
                "peak_context_fill_window_tokens",
                &self.peak_context_fill_window_tokens,
            )
            .field(
                "last_turn_context_window_tokens",
                &self.last_turn_context_window_tokens,
            )
            .field("compaction_count", &self.compaction_count)
            .field("compaction_timestamps", &self.compaction_timestamps)
            .field("codex_compaction_sizes", &self.codex_compaction_sizes)
            .field("local_context_points", &self.local_context_points)
            .field(
                "claude_compaction_observations",
                &self.claude_compaction_observations,
            )
            .field(
                "claude_compaction_link_tip",
                &self.claude_compaction_link_tip,
            )
            .field("session_start", &self.session_start)
            .field("durable_marks", &self.durable_marks)
            .finish()
    }
}
