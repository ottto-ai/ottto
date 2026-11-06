//! Snapshot accumulator methods for Codex ownership, activity and Claude
//! response records.

use crate::snapshots::*;

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
            codex_turn_traces: None,
            codex_observed_priority_turns: None,
            codex_priority_witnesses_uncapped: false,
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

    pub(in crate::snapshots) fn configure_codex_ownership(&mut self, value: &Value) {
        let Some(meta) = codex_session_meta_payload(value) else {
            return;
        };
        if self.codex_ownership_boundary != CodexOwnershipBoundary::Undetermined {
            return;
        }
        self.resolve_codex_path_sidecar_from_header(meta);

        let thread_source = string_at(meta, &["thread_source"]);
        let source_subagent = meta
            .get("source")
            .and_then(Value::as_object)
            .is_some_and(|source| source.contains_key("subagent"));
        let is_subagent = thread_source.as_deref() == Some("subagent") || source_subagent;
        // Capability negotiation controls only whether a context-curve payload
        // is emitted. Ownership attribution is an integrity boundary and must
        // never become weaker when that optional payload is unavailable.
        let rollout_declares_created_thread =
            thread_source.as_deref() == Some("agent_created_thread");
        let state_declares_created_thread = self.codex_sidecar_created_thread;
        let is_created_thread = rollout_declares_created_thread || state_declares_created_thread;
        let forked_from_id =
            resolve_codex_identity_option(codex_identity_at(meta, &["forked_from_id"]));
        self.codex_parent_session_ref = forked_from_id.clone();
        let has_history_base = meta.get("history_base").is_some_and(|base| !base.is_null());
        let exact_start = u64_at(meta, &["subagent_history_start_ordinal"]);
        self.codex_is_fork = is_created_thread
            || forked_from_id.is_some()
            || has_history_base
            || exact_start.is_some();

        if self.codex_sidecar_identity_ambiguous {
            self.codex_is_fork = true;
            self.codex_created_thread_native_only = true;
            self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
            return;
        }

        if is_created_thread {
            // Every provider-created thread has exactly one admission path:
            // the complete native creation witness below. In particular,
            // file-controlled pagination markers can never authorize this shape.
            self.codex_created_thread_native_only = true;
            let source_session_id = resolve_codex_identity_option(
                codex_identity_at(meta, &["id"])
                    .or_else(|| codex_identity_at(meta, &["session_id"])),
            );
            let trusted_parent = self
                .codex_sidecar_parent
                .as_ref()
                .filter(|(child, _)| {
                    source_session_id
                        .as_deref()
                        .is_some_and(|session_id| session_id == child)
                })
                .map(|(_, parent)| parent.clone());
            self.codex_parent_session_ref = trusted_parent.clone();
            // The state row is an independent trusted classification source.
            // If the rollout omits or contradicts that declaration, the
            // disagreement is itself damage/tampering evidence. Do not let a
            // file-controlled marker select an ordinary compatibility branch.
            if state_declares_created_thread && !rollout_declares_created_thread {
                self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
                return;
            }
            if trusted_parent
                .as_ref()
                .zip(forked_from_id.as_ref())
                .is_some_and(|(sidecar_parent, transcript_parent)| {
                    sidecar_parent != transcript_parent
                })
            {
                self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
                return;
            }
            // Without a trusted parent, a created thread is admitted only from its
            // own file proof: a state-declared row bound to this file, no lineage
            // in the header, and the UUID identity of the path, the first physical
            // record and the header all agreeing. A `history_base` can name another
            // session's file, so it is lineage evidence too. The stream conjuncts
            // follow in `validate_parentless_created_thread_record`.
            let parentless = trusted_parent.is_none()
                && self.codex_sidecar_parent.is_none()
                && state_declares_created_thread
                && forked_from_id.is_none()
                && !has_history_base
                && codex_header_declares_no_parent(meta)
                && source_session_id
                    .as_deref()
                    .is_some_and(codex_identity_is_uuid_shaped)
                && self.codex_creator_header_id == source_session_id
                && self.codex_resolved_path_identity == source_session_id;
            if let Some(header_nanos) = (trusted_parent.is_some() || parentless)
                .then(|| {
                    codex_native_created_thread_header(
                        value,
                        source_session_id.as_deref(),
                        self.codex_sidecar_child_created_at_nanos,
                    )
                })
                .flatten()
            {
                self.codex_ordinal_expected = Some(0);
                self.codex_native_created_thread_header_nanos = Some(header_nanos);
                self.codex_native_created_thread_last_nanos = Some(header_nanos);
                self.codex_ownership_boundary = CodexOwnershipBoundary::NativeCreatedThread;
                return;
            }
            // Missing or malformed native evidence fails closed.
            self.codex_ownership_boundary = CodexOwnershipBoundary::AmbiguousFork;
            return;
        }

        self.codex_ownership_boundary = if let Some(start) = exact_start {
            self.codex_ordinal_expected = Some(0);
            CodexOwnershipBoundary::Ordinal { start }
        } else if has_history_base {
            // Paginated forks keep inherited history behind an external
            // history_base reference. Physical records in this file are local.
            // Only a first physical own header may start the optional creator
            // sequence. Other AllLocal arms leave this cursor unset.
            if self.codex_creator_header_id.is_some()
                && codex_paginated_fork_creation_header(value, meta)
            {
                self.codex_ordinal_expected = u64_at(value, &["ordinal"]);
            }
            CodexOwnershipBoundary::AllLocal
        } else if is_subagent && forked_from_id.is_some() {
            CodexOwnershipBoundary::AwaitingLegacyTrigger
        } else {
            CodexOwnershipBoundary::AllLocal
        };
    }

    pub(in crate::snapshots) fn codex_record_is_owned(&mut self, value: &Value) -> bool {
        match self.codex_ownership_boundary {
            CodexOwnershipBoundary::Undetermined => {
                // A reordered or partially-written file may expose usage
                // before its authoritative session header. Treating that
                // prefix as local would defeat fork isolation.
                false
            }
            CodexOwnershipBoundary::AllLocal => {
                // Validate only the optional creation witness. Usage retains its
                // existing AllLocal semantics even if this sequence is broken.
                if self.codex_ordinal_expected.is_some() {
                    let ordinal = u64_at(value, &["ordinal"]);
                    if ordinal.is_none() || ordinal != self.codex_ordinal_expected {
                        self.codex_ordinal_sequence_valid = false;
                    }
                    self.codex_ordinal_expected = ordinal.and_then(|at| at.checked_add(1));
                }
                self.codex_owned_record_seen = true;
                true
            }
            CodexOwnershipBoundary::AwaitingLegacyTrigger => {
                if codex_legacy_trigger_turn(value) {
                    self.codex_legacy_trigger_seen = true;
                    self.codex_ownership_boundary = CodexOwnershipBoundary::AllLocal;
                    self.codex_owned_record_seen = true;
                    true
                } else {
                    self.note_legacy_bootstrap_candidate(value);
                    self.note_inherited_codex_record(value);
                    false
                }
            }
            CodexOwnershipBoundary::AwaitingParentPrefix => false,
            CodexOwnershipBoundary::NativeCreatedThread => {
                self.validate_native_created_thread_record(value);
                self.codex_owned_record_seen = true;
                true
            }
            CodexOwnershipBoundary::Ordinal { start } => {
                let Some(ordinal) = u64_at(value, &["ordinal"]) else {
                    self.codex_ordinal_sequence_valid = false;
                    return false;
                };
                if self.codex_ordinal_expected != Some(ordinal) {
                    self.codex_ordinal_sequence_valid = false;
                }
                self.codex_ordinal_expected = ordinal.checked_add(1);
                if ordinal < start {
                    self.note_inherited_codex_record(value);
                    false
                } else {
                    self.codex_owned_record_seen = true;
                    true
                }
            }
            CodexOwnershipBoundary::AmbiguousFork => {
                self.note_inherited_codex_record(value);
                false
            }
        }
    }

    fn validate_native_created_thread_record(&mut self, value: &Value) {
        let expected_ordinal = self.codex_ordinal_expected;
        let ordinal = u64_at(value, &["ordinal"]);
        if ordinal != expected_ordinal {
            self.codex_ordinal_sequence_valid = false;
        }
        self.codex_ordinal_expected = ordinal.and_then(|value| value.checked_add(1));

        let timestamp_nanos = string_at(value, &["timestamp"])
            .as_deref()
            .and_then(rfc3339_unix_nanos);
        match (
            timestamp_nanos,
            self.codex_native_created_thread_header_nanos,
            self.codex_native_created_thread_last_nanos,
        ) {
            (Some(timestamp), Some(header), Some(previous))
                if timestamp >= header && timestamp >= previous =>
            {
                self.codex_native_created_thread_last_nanos = Some(timestamp);
            }
            _ => self.codex_native_created_thread_valid = false,
        }

        match ordinal {
            Some(0) => {}
            Some(1) => {
                let turn_id = string_at(value, &["payload", "turn_id"]);
                let trace_id = string_at(value, &["payload", "trace_id"]);
                let hex32 = |value: &str| {
                    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                };
                // Codex omits `trace_id` on most parentless created threads. Their
                // anti-copy proof is the start bound, the UUID turn binding and the
                // first-request equality, so only that path accepts a missing key.
                // Any present value, including null, empty or non-string, must be
                // well formed.
                let trace_id_valid = if self.codex_parentless_created_thread() {
                    match value
                        .get("payload")
                        .and_then(|payload| payload.get("trace_id"))
                    {
                        None => true,
                        Some(raw) => raw.as_str().is_some_and(hex32),
                    }
                } else {
                    trace_id.as_deref().is_some_and(hex32)
                };
                let valid = codex_is_task_started(value)
                    && turn_id
                        .as_deref()
                        .is_some_and(codex_identity_is_uuid_shaped)
                    && trace_id_valid
                    && self.codex_task_started_after_creation(value, timestamp_nanos);
                if valid {
                    self.codex_native_created_thread_task_turn_id = turn_id;
                } else {
                    self.codex_native_created_thread_valid = false;
                }
            }
            Some(_) if string_eq_at(value, &["type"], "turn_context") => {
                if !self.codex_native_created_thread_first_turn_bound {
                    self.codex_native_created_thread_first_turn_bound =
                        string_at(value, &["payload", "turn_id"])
                            == self.codex_native_created_thread_task_turn_id;
                    if !self.codex_native_created_thread_first_turn_bound {
                        self.codex_native_created_thread_valid = false;
                    }
                }
            }
            Some(_) if codex_total_usage(value).is_some() => {
                if !self.codex_native_created_thread_first_turn_bound {
                    self.codex_native_created_thread_valid = false;
                }
            }
            Some(_) | None => {}
        }
        if self.codex_parentless_created_thread() {
            self.validate_parentless_created_thread_record(value, ordinal, timestamp_nanos);
        }
    }

    /// A provider task's own `started_at` second lies between the state row's
    /// creation second and the second the record was written. Copies carry
    /// their original payload time, so this binds a task to this thread.
    fn codex_task_started_after_creation(
        &self,
        value: &Value,
        timestamp_nanos: Option<i128>,
    ) -> bool {
        let started_at = u64_at(value, &["payload", "started_at"]);
        let sidecar_second = self
            .codex_sidecar_child_created_at_nanos
            .and_then(|value| u64::try_from(value.div_euclid(1_000_000_000)).ok());
        let record_second =
            timestamp_nanos.and_then(|value| u64::try_from(value.div_euclid(1_000_000_000)).ok());
        started_at
            .zip(sidecar_second.zip(record_second))
            .is_some_and(|(started, (spawned, recorded))| started >= spawned && started <= recorded)
    }

    /// Created thread admitted without a trusted parent. The parented path
    /// always records its trusted parent here while configuring the header.
    pub(in crate::snapshots) fn codex_parentless_created_thread(&self) -> bool {
        self.codex_ownership_boundary == CodexOwnershipBoundary::NativeCreatedThread
            && self.codex_parent_session_ref.is_none()
    }

    /// Extra stream conjuncts for a parentless created thread, which has no
    /// parent ledger to exclude copied history. Any failure holds the file.
    fn validate_parentless_created_thread_record(
        &mut self,
        value: &Value,
        ordinal: Option<u64>,
        timestamp_nanos: Option<i128>,
    ) {
        // Only the line-0 header may describe the session. A later header is a
        // copy or a re-emission and cannot be attributed safely.
        if codex_session_meta_payload(value).is_some() && self.codex_owned_record_seen {
            self.codex_native_created_thread_valid = false;
        }
        // Every later task must start after this thread was created, and only
        // once the first task has bound its turn. The cache tracker opens a turn
        // for any `task_started` payload, so every envelope is checked here.
        if string_eq_at(value, &["payload", "type"], "task_started") && ordinal != Some(1) {
            let turn_id = string_at(value, &["payload", "turn_id"]);
            if codex_is_task_started(value)
                && self.codex_native_created_thread_first_turn_bound
                && turn_id.is_some()
                && self.codex_task_started_after_creation(value, timestamp_nanos)
            {
                self.codex_native_created_thread_task_turn_id = turn_id;
            } else {
                self.codex_native_created_thread_valid = false;
            }
        }
        // Turn contexts and usage must belong to a turn this file opened.
        if string_eq_at(value, &["type"], "turn_context") {
            let turn_id = string_at(value, &["payload", "turn_id"]);
            if !self.codex_parentless_turn_opened(turn_id.as_deref()) {
                self.codex_native_created_thread_valid = false;
            }
        }
        let Some(total) = codex_total_usage(value) else {
            return;
        };
        // Same precedence as `apply_codex_owned_line`, which runs after this
        // check: a turn named by the record wins over the running turn.
        let usage_turn_id = string_at(value, &["turn_context", "payload", "turn_id"])
            .or_else(|| string_at(value, &["payload", "turn_id"]))
            .or_else(|| self.latest_turn_id.clone());
        if !self.codex_parentless_turn_opened(usage_turn_id.as_deref()) {
            self.codex_native_created_thread_valid = false;
        }
        // Before any usage is counted, the first request's cumulative total must
        // equal that request: nothing was accumulated before it in this thread.
        // All-zero pairs are context estimates; `request_count` is a parser
        // default, not provider data, so only token fields are compared.
        if codex_usage_token_fields(&self.accepted_usage_totals) == [0; 5] {
            let total = codex_usage_token_fields(&total);
            let last = codex_last_usage(value).map(|last| codex_usage_token_fields(&last));
            if (total != [0; 5] || last.is_some_and(|last| last != [0; 5])) && last != Some(total) {
                self.codex_native_created_thread_valid = false;
            }
        }
    }

    /// Finalization conjuncts for a parentless created thread: the thread-history
    /// projection proved this file is the whole thread, every physical record was
    /// read under one header, a first request was actually checked, and no record
    /// supplied lineage the sidecar never trusted.
    fn codex_parentless_proof_complete(&self) -> bool {
        self.codex_sidecar_projected_next_ordinal.is_some()
            && !self.codex_creator_evidence_conflicted
            && self.origin.parent_session_ref.is_none()
            && self.origin.source_subagent != Some(true)
            && codex_usage_token_fields(&self.accepted_usage_totals) != [0; 5]
    }

    fn codex_parentless_turn_opened(&self, turn_id: Option<&str>) -> bool {
        turn_id.is_some_and(|turn_id| {
            self.codex_native_created_thread_task_turn_id.as_deref() == Some(turn_id)
                || self.cache_active_turns.contains(turn_id)
        })
    }

    fn note_inherited_codex_record(&mut self, value: &Value) {
        if let Some(usage) = codex_total_usage(value) {
            if !usage.is_zero() {
                self.codex_inherited_usage_records_skipped =
                    self.codex_inherited_usage_records_skipped.saturating_add(1);
            }
            // The last inherited cumulative is the baseline for legacy records
            // that predate `last_token_usage`. It never enters a usage bucket.
            self.session_cumulative_usage = Some(usage);
        }
    }

    fn note_legacy_bootstrap_candidate(&mut self, value: &Value) {
        const MAX_BOOTSTRAP_RECORDS: usize = 64;
        if codex_total_usage(value).is_some() {
            // A completed response proves this was still a copied parent task.
            self.codex_legacy_bootstrap_buffer.clear();
            self.codex_legacy_bootstrap_valid = true;
            return;
        }
        let task_started = string_eq_at(value, &["payload", "type"], "task_started");
        if task_started {
            self.codex_legacy_bootstrap_buffer.clear();
            self.codex_legacy_bootstrap_valid = true;
        }
        if task_started || !self.codex_legacy_bootstrap_buffer.is_empty() {
            if self.codex_legacy_bootstrap_buffer.len() == MAX_BOOTSTRAP_RECORDS {
                CapCounts::record(self.source.api_slug(), 1, 1);
                self.codex_legacy_bootstrap_buffer.clear();
                self.codex_legacy_bootstrap_valid = false;
                return;
            }
            self.codex_legacy_bootstrap_buffer.push(value.clone());
        }
    }

    pub(in crate::snapshots) fn codex_usage_accounting_complete(&self) -> bool {
        match self.codex_ownership_boundary {
            CodexOwnershipBoundary::Undetermined => false,
            CodexOwnershipBoundary::AllLocal => {
                !self.codex_legacy_trigger_seen || self.codex_legacy_bootstrap_valid
            }
            CodexOwnershipBoundary::Ordinal { start } => {
                self.codex_ordinal_sequence_valid
                    && self.codex_owned_record_seen
                    && self.codex_ordinal_expected.is_some_and(|next| next > start)
            }
            CodexOwnershipBoundary::NativeCreatedThread => {
                self.codex_native_created_thread_valid
                    && self.codex_ordinal_sequence_valid
                    && self.codex_owned_record_seen
                    && self.codex_ordinal_expected.is_some_and(|next| next > 1)
                    && self
                        .codex_sidecar_projected_next_ordinal
                        .map(|expected| self.codex_ordinal_expected == Some(expected))
                        .unwrap_or(true)
                    && self.codex_native_created_thread_task_turn_id.is_some()
                    && self.codex_native_created_thread_first_turn_bound
                    && (self.codex_parent_session_ref.is_some()
                        || self.codex_parentless_proof_complete())
            }
            CodexOwnershipBoundary::AwaitingLegacyTrigger
            | CodexOwnershipBoundary::AwaitingParentPrefix
            | CodexOwnershipBoundary::AmbiguousFork => false,
        }
    }

    /// Merge newly scraped artifacts, deduping and capping at
    /// ``MAX_SESSION_ARTIFACTS``. Encounter order is preserved; ``into_items``
    /// sorts for a deterministic fingerprint.
    pub(in crate::snapshots) fn add_artifacts(&mut self, artifacts: Vec<SessionArtifact>) {
        for artifact in artifacts {
            if self.artifacts.len() >= MAX_SESSION_ARTIFACTS {
                break;
            }
            if !self.artifacts.iter().any(|existing| existing == &artifact) {
                self.artifacts.push(artifact);
            }
        }
    }

    pub(in crate::snapshots) fn note_activity_tool(&mut self, name: &str) {
        let Some(name) = bounded_activity_label(name) else {
            return;
        };
        // `exec` is Codex Desktop's transport wrapper. Its nested `tools.*`
        // calls are counted separately so the UI reports actions, not protocol.
        if name == "exec" {
            return;
        }
        self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::Tool, &name);
        *self.activity_tool_counts.entry(name).or_default() += 1;
    }

    pub(in crate::snapshots) fn reclassify_activity_call_as_mcp(&mut self, call_id: &str) {
        let Some(ActivityCallTool { name }) = self.activity_call_tools.remove(call_id) else {
            return;
        };
        let Some(count) = self.activity_tool_counts.get_mut(&name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.activity_tool_counts.remove(&name);
        }
    }

    pub(in crate::snapshots) fn note_activity_mcp_tool(&mut self, server: &str, tool: &str) {
        if let Some(name) = bounded_activity_label(&format!("{server}.{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpActivity, &name);
            *self.activity_mcp_tool_counts.entry(name).or_default() += 1;
        }
        if let Some(name) = bounded_tool_usage_name(&format!("mcp__{server}__{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpUsage, &name);
            *self.activity_mcp_tool_usage_counts.entry(name).or_default() += 1;
        }
    }

    /// A Codex name count's stable Tail slot, first seen here.
    fn note_codex_name_slot(&mut self, map: codex_dictionary_slots::CodexCountMap, name: &str) {
        if self.source == SnapshotSource::Codex {
            self.codex_dictionary_slots
                .name_counts
                .note(&(map, name.to_owned()));
        }
    }

    pub(in crate::snapshots) fn note_activity_tools(&mut self, material: &str) {
        for name in nested_unified_exec_tools(material) {
            self.note_activity_tool(&name);
        }
    }

    /// SKILL.md references in tool input (Codex arguments, Claude Read/Bash).
    /// Keeps one name past the wire cap so the backend still sees truncation.
    /// The first spelling wins: `Foo/SKILL.md` and `foo/SKILL.md` are one
    /// skill, and the backend keys uploaded names by their exact bytes.
    pub(in crate::snapshots) fn note_activity_skills(&mut self, material: &str) {
        let skills = &mut self.activity_skills;
        let named_all = for_each_skill_md_reference(material, |name| {
            if skills.len() <= MAX_ACTIVITY_SKILLS
                && !skills.iter().any(|seen| seen.eq_ignore_ascii_case(&name))
            {
                skills.insert(name);
            }
        });
        self.skill_detector_incomplete |= !named_all;
    }

    pub(in crate::snapshots) fn note_capability_call(
        &mut self,
        timestamp: Option<&str>,
        capability_id: &str,
        raw_origin: &str,
    ) {
        let Some((bucket_start, _)) = timestamp.and_then(activity_bucket_from_timestamp) else {
            return;
        };
        *self
            .activity_capability_buckets
            .entry((
                bucket_start,
                capability_id.to_string(),
                raw_origin.to_string(),
            ))
            .or_default() += 1;
    }

    pub(in crate::snapshots) fn activity_summary(&self) -> Option<SnapshotActivitySummary> {
        let capability_buckets = self
            .activity_capability_buckets
            .iter()
            .map(|((bucket_start, capability_id, raw_origin), call_count)| {
                SnapshotCapabilityBucket {
                    bucket_start: bucket_start.clone(),
                    capability_id: capability_id.clone(),
                    raw_origin: raw_origin.clone(),
                    call_count: *call_count,
                }
            })
            .collect::<Vec<_>>();
        let mut capability_totals: BTreeMap<(String, String), u64> = BTreeMap::new();
        for bucket in &capability_buckets {
            *capability_totals
                .entry((bucket.capability_id.clone(), bucket.raw_origin.clone()))
                .or_default() += bucket.call_count;
        }
        let capability_counts = capability_totals
            .into_iter()
            .map(
                |((capability_id, raw_origin), count)| SnapshotCapabilityCount {
                    capability_id,
                    raw_origin,
                    count,
                },
            )
            .collect::<Vec<_>>();
        let codex_tool_calls = self
            .activity_tool_counts
            .values()
            .copied()
            .sum::<u64>()
            .saturating_add(self.activity_mcp_calls);
        // Codex already has a complete local tool-action classifier. Claude's
        // new capability classifier is intentionally narrower, so do not
        // present its allowlisted subset as the session's total tool/MCP use.
        let tool_calls = if self.source == SnapshotSource::Codex {
            codex_tool_calls
        } else {
            0
        };
        // v2: v1's capability counts plus a skill detector that named every
        // SKILL.md reference it saw. Only v2 may later back "no skill used".
        let capability_collection_version = matches!(
            self.source,
            SnapshotSource::Codex | SnapshotSource::ClaudeCode
        )
        .then(|| {
            if self.skill_detector_incomplete {
                "agent_capability_usage:v1"
            } else {
                "agent_capability_usage:v2"
            }
            .to_string()
        });
        let has_activity = capability_collection_version.is_some()
            || tool_calls > 0
            || self.activity_patch_operations > 0
            || self.activity_web_searches > 0
            || self.activity_subagent_spawns > 0
            || !self.activity_skills.is_empty();
        has_activity.then(|| SnapshotActivitySummary {
            capability_collection_version,
            tool_calls,
            shell_commands: self
                .activity_tool_counts
                .get("exec_command")
                .copied()
                .unwrap_or_default(),
            patch_operations: self.activity_patch_operations,
            changed_files: self.activity_changed_file_hashes.len() as u64,
            lines_added: self.activity_lines_added,
            lines_deleted: self.activity_lines_deleted,
            web_searches: self.activity_web_searches,
            mcp_calls: self.activity_mcp_calls,
            subagent_spawns: self.activity_subagent_spawns,
            tool_counts: bounded_activity_counts(&self.activity_tool_counts, 64),
            mcp_tool_counts: bounded_activity_counts(&self.activity_mcp_tool_counts, 32),
            capability_counts,
            capability_buckets,
            // A reference to an invoked skill uploads the invocation's
            // (lowercased) spelling, the one its `skill_id` fact hashes, so
            // backend promotion of these names finds that fact.
            skills: self
                .activity_skills
                .iter()
                .take(MAX_ACTIVITY_SKILLS)
                .map(|skill| {
                    self.provider_skills
                        .get(&skill.to_ascii_lowercase())
                        .unwrap_or(skill)
                        .clone()
                })
                .collect(),
        })
    }

    pub(in crate::snapshots) fn note_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| timestamp_is_before(&timestamp, current))
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| timestamp_is_after(&timestamp, current))
        {
            self.last_activity_at = Some(timestamp);
        }
    }

    /// Retain one Claude usage-bearing record for response-level resolution.
    /// No session-exclusive metric is mutated here; `finalize_claude_responses`
    /// admits exactly one terminal observation after the full file is read.
    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(in crate::snapshots) fn observe_claude_response(
        &mut self,
        value: &Value,
        usage: UsageTotals,
        model: Option<String>,
        selector: SelectorCapture,
        timestamp: Option<String>,
        reasoning_effort: Option<String>,
        computed_effective_input_context: Option<u64>,
    ) {
        let tool_uses = claude_response_tool_uses(value);
        let cache_slot = claude_cache_request_slot(
            value,
            model.clone(),
            reasoning_effort.clone(),
            timestamp.clone(),
        );
        let request_id =
            string_at(value, &["requestId"]).or_else(|| string_at(value, &["request_id"]));
        let key = claude_response_key(value, self.claude_response_sequence);
        self.claude_response_record_count = self.claude_response_record_count.saturating_add(1);
        let selector = self.claude_responses.selectors.intern(selector);
        // The request's own usage records carry entrypoint. Missing or mixed
        // records fail closed; session-first origin is deliberately irrelevant.
        let desktop_request =
            value.get("entrypoint").and_then(Value::as_str) == Some("claude-desktop");
        if let Some(mut existing) = self.claude_responses.get_mut(&key) {
            existing.desktop_request &= desktop_request;
            existing.push(
                usage,
                model,
                selector,
                reasoning_effort,
                request_id,
                timestamp,
                computed_effective_input_context,
                tool_uses,
                cache_slot,
            );
            return;
        }
        let sequence = self.claude_response_sequence;
        self.claude_response_sequence = self.claude_response_sequence.saturating_add(1);
        let mut response = ClaudeResponseObservation::new(
            sequence,
            usage,
            model,
            selector,
            reasoning_effort,
            request_id,
            timestamp,
            self.claude_last_user_ts.clone(),
            computed_effective_input_context,
            tool_uses,
            cache_slot,
        );
        response.desktop_request = desktop_request;
        let inserted = self.claude_responses.insert(key, response);
        if !inserted {
            self.note_dropped_usage();
        }
    }

    /// Resolve every Claude response in transcript order, then admit its final
    /// cumulative usage exactly once. Conflicting provider records are dropped
    /// and make the enclosing file retryable through the existing diagnostics.
    #[cfg(test)]
    pub(in crate::snapshots) fn finalize_claude_responses(&mut self) {
        self.finalize_claude_responses_e2(None);
    }

    pub(in crate::snapshots) fn finalize_claude_responses_e2(
        &mut self,
        money_context: Option<claude_request_money::e2::ReadContext<'_>>,
    ) {
        let (mut responses, selectors) = std::mem::take(&mut self.claude_responses).into_parts();
        responses.sort_by_key(|response| response.sequence);
        // Gate off, the fold keys by hour only: it never reads the selector.
        let base_selector = self.current_selector.clone();
        // Gate on, a family revision 3 keeps on ordinary money gets no fold:
        // its file is read exactly as gate off publishes it (fold-absent).
        let mut money = (money_context
            .as_ref()
            .map_or(true, claude_request_money::e2::file_applies))
        .then(|| {
            claude_request_money::e2::FileFold::new(
                self.claude_file_birth,
                money_context.as_ref(),
                base_selector,
                self.fallback_bucket_timestamp(None),
            )
        });
        crate::local_resource_diagnostics::claude_record_counts(
            self.claude_response_record_count,
            responses
                .iter()
                .map(|response| response.records.len())
                .max()
                .unwrap_or(0),
            CLAUDE_RECORDS_PER_FILE_ALARM,
        );
        let first_sequence = responses.first().map(|response| response.sequence);
        // Resolve the sorted book first: org lines govern from the first
        // response whose provider time is from `ACCOUNT_RULE_FROM`.
        let responses = responses
            .into_iter()
            .map(|response| response.resolve_classified(&selectors))
            .collect::<Vec<_>>();
        if let Some(money) = money.as_mut() {
            let trust_from = responses
                .iter()
                .flatten()
                .find(|response| {
                    claude_request_identity::from_account_rule(
                        response
                            .terminal_timestamp
                            .as_deref()
                            .and_then(rfc3339_unix_seconds),
                    )
                })
                .map(|response| response.sequence);
            money.set_identity(
                self.claude_org_markers.as_deref(),
                self.account_identifier_hash.as_deref(),
                self.source_session_id.as_deref(),
                money_context.as_ref(),
                first_sequence,
                trust_from,
            );
        }
        let mut shared_selectors = BTreeSet::<Arc<SelectorCapture>>::new();
        // The previous resolved response's end when it ended a turn (no tool
        // use); `None` after a tool use or an unresolved response. A response
        // whose prompt follows it starts a turn: the time between is idle.
        let mut turn_end: Option<String> = None;
        for response in responses {
            let mut response = match response {
                Ok(response) => response,
                // With the `e2` gate on, a resolver conflict is counted
                // and disclosed on the body (resolver_conflict_count) and the
                // root publishes; it is not drop residue held for retry. Gate
                // off (dark): unchanged drop residue, still counted.
                Err(ClaudeResolveFailure::Conflict) => {
                    turn_end = None;
                    if let Some(money) = money.as_mut() {
                        money.note_resolver_conflict();
                    }
                    if money.is_none() {
                        self.note_dropped_usage();
                    }
                    continue;
                }
                // An undecodable compact record is loss held for retry, never
                // a resolver conflict.
                Err(ClaudeResolveFailure::Decode) => {
                    turn_end = None;
                    self.note_dropped_usage();
                    continue;
                }
            };
            let at = response
                .terminal_timestamp
                .as_deref()
                .and_then(rfc3339_unix_nanos);
            if !response.cache_slot.request_ref.is_empty() {
                self.cache_requests.push(OwnedRequest {
                    slot: response.cache_slot.clone(),
                    ordering: "sequential".into(),
                    compaction_before: self
                        .claude_compaction_observations
                        .iter()
                        .any(|b| b.response_count_before == response.sequence),
                    configuration_changed: false,
                    configuration_witness: None,
                    idle_seconds: turn_end
                        .as_deref()
                        .zip(response.preceding_user_timestamp.as_deref())
                        .and_then(|(end, prompt)| cache_observations::elapsed_seconds(end, prompt)),
                });
            }
            turn_end = response
                .tool_uses
                .is_empty()
                .then(|| response.terminal_timestamp.clone())
                .flatten();
            let effective_input_context = response
                .computed_effective_input_context
                .unwrap_or_else(|| response.usage.effective_input_context());
            self.claude_file_birth.observe_response_at(
                response.sequence,
                at,
                effective_input_context,
            );
            if !response.selector.context.contains_key("context_bucket") {
                // Stamped only against the model's catalog line: Haiku 5.5's
                // 100K price line or the 200K analysis line of flat 1M-window
                // models. Models without a catalog line carry no bucket.
                if let Some(context_bucket) = response.model.as_deref().and_then(|model| {
                    provider_context_bucket(
                        model,
                        effective_input_context,
                        response.terminal_timestamp.as_deref(),
                    )
                }) {
                    response.selector.insert(
                        "context_bucket",
                        context_bucket.to_string(),
                        "derived_from_effective_input_volume",
                    );
                }
            }
            let has_request_id = response.request_id.is_some();
            if let Some(request_id) = response.request_id.take() {
                let selector = match shared_selectors.get(&response.selector) {
                    Some(shared) => Arc::clone(shared),
                    None => {
                        let shared = Arc::new(response.selector.clone());
                        shared_selectors.insert(Arc::clone(&shared));
                        shared
                    }
                };
                let prior_occurrence = self.claude_usage_occurrences.insert(
                    request_id.clone(),
                    ClaudeTranscriptUsageOccurrence {
                        sequence: response.sequence,
                        telemetry_attached: false,
                        usage: response.usage.clone(),
                        model: response.model.clone(),
                        selector,
                        reasoning_effort: response.reasoning_effort.clone(),
                        timestamp: response.terminal_timestamp.clone(),
                        event_clock_complete: response.event_clock_complete,
                        desktop_request: response.desktop_request,
                        effective_input_context,
                    },
                );
                if self.claude_usage_request_ids.contains(&request_id) || prior_occurrence.is_some()
                {
                    if let Some(money) = money.as_mut() {
                        money.note_ambiguous(&request_id);
                    }
                }
                let request_id_was_new = self.claude_usage_request_ids.insert(request_id);
                // Identity completeness depends on this file's bytes alone (a
                // repeated id here, an id-less response below).
                // Progressive rows for one response were merged by response
                // key above. Reaching this point twice for one provider request
                // id therefore means two distinct responses claim the same
                // request identity; their request index is not trustworthy.
                if !request_id_was_new || prior_occurrence.is_some() {
                    self.claude_context_curve_identity_complete = false;
                }
            } else {
                self.claude_context_curve_identity_complete = false;
                // An id-less response is never a compaction size. Mark the
                // compaction it sits just before or just after for the fold's
                // local counters; the sizes themselves are unchanged.
                // Parse order makes response_count_before non-decreasing,
                // even when marker timestamps repeat or arrive out of order.
                let first = self
                    .claude_compaction_observations
                    .partition_point(|observation| {
                        observation.response_count_before < response.sequence
                    });
                let next = response.sequence.saturating_add(1);
                let end = self
                    .claude_compaction_observations
                    .partition_point(|observation| observation.response_count_before <= next);
                for index in first..end {
                    if let Some(observation) = self
                        .claude_compaction_observations
                        .get_mut(index)
                        .as_deref_mut()
                    {
                        if observation.response_count_before == response.sequence {
                            observation.id_less_after = true;
                        } else {
                            observation.id_less_before = true;
                        }
                    }
                }
            }
            self.note_claude_turn_duration_between(
                response.preceding_user_timestamp.as_deref(),
                response.first_timestamp.as_deref(),
            );
            if effective_input_context > 0 {
                if self.first_turn_context_tokens.is_none() {
                    self.first_turn_context_tokens = Some(effective_input_context);
                }
                self.peak_context_fill_tokens =
                    self.peak_context_fill_tokens.max(effective_input_context);
                self.last_turn_context_tokens = Some(effective_input_context);
            }
            self.session_start.note_claude_response(
                response.sequence,
                &response.usage,
                effective_input_context,
                response.tool_uses.len(),
            );
            for name in response.tool_uses.into_values() {
                self.note_tool_usage(name);
            }
            // One native placement per response; the money fold reuses it.
            let placed = claude_request_money::e2::timed("native.place", || {
                self.place_usage(
                    response.model,
                    &response.usage,
                    response.selector,
                    response.terminal_timestamp.as_deref(),
                    response.reasoning_effort.as_deref(),
                )
            });
            if let Some(money) = money.as_mut() {
                claude_request_money::e2::timed("e2.observe", || {
                    money.observe(
                        response.sequence,
                        has_request_id,
                        &response.usage,
                        at,
                        placed.as_ref(),
                        response.reasoning_effort.as_deref(),
                    )
                });
            }
            if let Some(placed) = placed {
                claude_request_money::e2::timed("native.add", || {
                    self.add_placed_usage(placed, response.usage, response.reasoning_effort)
                });
            }
        }
        if let Some(mut money) = money {
            claude_request_money::e2::timed("e2.finish_native", || {
                money.finish_native(
                    money_context.as_ref(),
                    self.claude_org_markers.as_deref(),
                    self.claude_fork_parent.as_deref(),
                )
            });
            self.claude_money = Some(Box::new(money));
        }
    }
}
