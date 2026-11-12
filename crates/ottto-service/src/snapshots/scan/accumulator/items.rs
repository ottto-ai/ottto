//! Projecting the accumulated session into snapshot items.

use super::{
    cached_repository_identity, claude_workflows_dir_has_manifest, merge_session_row,
    model_usage_from_row, BucketRowAccumulator, CodexOwnershipBoundary, RowKey,
    SnapshotAccumulator,
};
use crate::snapshots::{
    bounded_compaction_timestamps, bounded_tool_usage_counts, cache_wire,
    claude_compaction_summary, claude_subagent_identity, claude_transcript_excluded_from_snapshots,
    codex_session_id_from_path, codex_tool_usage_rows, creator_time_precedes_start,
    read_claude_agent_meta, session_start, snapshot_fingerprint, snapshot_source_session_id,
    ClaudeTitleMetadata, CompactionMetrics, SnapshotItem, SnapshotModelUsage, SnapshotProvenance,
    SnapshotSource, SnapshotUsageBucket,
};
use std::collections::BTreeMap;
use std::path::Path;

impl SnapshotItem {
    pub(crate) fn neutral_telemetry(root: String, collected_at: String) -> Self {
        Self {
            evidence_basis: Some("otel_only"),
            source_session_id: root,
            status: "final".into(),
            collected_at,
            provenance: SnapshotProvenance {
                collector: "claude_code_jsonl".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

impl SnapshotAccumulator {
    // Production finishes through `into_items_with_repository_identity`.
    #[cfg(test)]
    pub(in crate::snapshots) fn into_items(
        self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Vec<SnapshotItem> {
        self.into_items_with_repository_identity(
            path,
            collected_at,
            source_file_fingerprint,
            attribution_context,
            None,
            false,
        )
    }

    /// The file's first in-file session id, before the wire rule: the parsed
    /// id, else (Codex) the identity bound for this exact file, else the
    /// file stem.
    fn raw_source_session_id(&self, path: &Path) -> Option<String> {
        self.source_session_id
            .clone()
            .or_else(|| {
                (self.source == SnapshotSource::Codex)
                    .then(|| {
                        // Prefer the identity the seeding/header evidence already
                        // bound for this exact file. `codex_session_id_from_path`
                        // is deliberately evidence-free and returns `None` for a
                        // timestamp-shaped name, so without this the ambiguous
                        // grammar would degrade to the raw `rollout-` file stem.
                        self.codex_resolved_path_identity
                            .clone()
                            .or_else(|| codex_session_id_from_path(path))
                    })
                    .flatten()
            })
            .or_else(|| {
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_string())
            })
    }

    /// The `source_session_id` this state's items carry on the wire.
    pub(in crate::snapshots) fn wire_source_session_id(&self, path: &Path) -> Option<String> {
        self.raw_source_session_id(path)
            .map(|id| snapshot_source_session_id(self.source, path, id))
    }

    pub(in crate::snapshots) fn into_items_with_repository_identity(
        mut self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
        measured_repository_identity: Option<crate::context_footprint::RepositoryIdentity>,
        emit_empty_pi_fork: bool,
    ) -> Vec<SnapshotItem> {
        // Defence in depth: the scan already refuses to collect the Workflow
        // journal, but the parse entry points are public, so nothing downstream
        // may mint a `<parentSessionId>_journal` session either.
        if self.source == SnapshotSource::ClaudeCode
            && claude_transcript_excluded_from_snapshots(path)
        {
            return Vec::new();
        }
        // The same session key the head-CAS ledger answers under
        // (`tail_source::load::conflict_owed`).
        let Some(source_session_id) = self.wire_source_session_id(path) else {
            return Vec::new();
        };
        if self.source == SnapshotSource::Codex && !self.codex_usage_accounting_complete() {
            return Vec::new();
        }
        let codex_usage_accounting_proven =
            self.source == SnapshotSource::Codex && self.codex_session_meta_seen;
        let expected_path_id = self
            .codex_resolved_path_identity
            .as_deref()
            .map(str::to_string)
            .or_else(|| codex_session_id_from_path(path));
        let mut session_account_evidence = (self.source == SnapshotSource::Codex
            && !self.codex_creator_evidence_conflicted
            && self.codex_creator_header_id.as_deref() == Some(source_session_id.as_str())
            && expected_path_id.as_deref() == Some(source_session_id.as_str())
            // Native ordinal forks have their own creation-time creator pair.
            // The first physical header/file/time gates prove its origin;
            // the independently validated boundary still owns usage, not identity.
            // AllLocal has a cursor only for the exact external paginated own
            // header; its local sequence and complete acquisition must survive.
            && (!self.codex_is_fork
                || matches!(
                    self.codex_ownership_boundary,
                    CodexOwnershipBoundary::NativeCreatedThread
                        | CodexOwnershipBoundary::Ordinal { .. }
                )
                || (self.codex_ownership_boundary == CodexOwnershipBoundary::AllLocal
                    && self.codex_ordinal_sequence_valid
                    && self.codex_ordinal_expected.is_some())))
        .then(|| self.codex_creator_evidence.clone())
        .flatten()
        .filter(|evidence| {
            creator_time_precedes_start(
                evidence.source_created_at.as_deref(),
                self.started_at.as_deref(),
            )
        });
        if self.source == SnapshotSource::ClaudeCode {
            let mut evidence = self.claude_desktop_identity.clone().unwrap_or_else(|| {
                ClaudeTitleMetadata::default().session_account_evidence(&source_session_id)
            });
            evidence.source_created_at = evidence.source_created_at.take().filter(|created| {
                creator_time_precedes_start(Some(created), self.started_at.as_deref())
            });
            if evidence.source_created_at.is_none()
                && evidence.identity_disposition == Some("complete")
            {
                evidence.identity_disposition = Some("missing");
            }
            // Explicit evaluation is never replaced by omission: otherwise a
            // later missing/conflicting census could inherit an old complete pair.
            session_account_evidence = Some(evidence);
        }
        // A Claude Code subagent transcript (Task tool or Workflow tool) shares
        // its parent's `sessionId`; the wire rule above re-keys it from its PATH
        // to a distinct id so it ingests as its own `isSidechain=true`
        // (ai_agent) session instead of collapsing into -- and overwriting --
        // the human parent. Top-level transcripts are unchanged.
        let claude_subagent = (self.source == SnapshotSource::ClaudeCode)
            .then(|| claude_subagent_identity(path))
            .flatten();
        // Subagent tree position, read from the provider's own sidecar. Absent
        // or malformed metadata simply leaves the derived facts absent.
        let claude_agent_meta = claude_subagent
            .as_ref()
            .map(|_| read_claude_agent_meta(path))
            .unwrap_or_default();
        if let Some(identity) = claude_subagent.as_ref() {
            // DIRECT parent: the top-level session for a depth-1 agent, or the
            // spawning agent's own re-keyed session id when the provider records
            // a `parentAgentId`, so the tree edge is exact rather than flattened
            // onto the root.
            self.origin.parent_session_ref =
                Some(match claude_agent_meta.parent_agent_id.as_deref() {
                    Some(parent_agent_id) => {
                        format!("{}_agent-{parent_agent_id}", identity.root_session_id)
                    }
                    None => identity.root_session_id.clone(),
                });
        }
        // Claude Code dynamic workflow orchestration (the Workflow tool, e.g.
        // `ultracode`) leaves a local manifest at
        // `<projectDir>/<sessionId>/workflows/wf_*.json` -- a sibling directory
        // of the `<sessionId>.jsonl` we just parsed. Stat it so the backend can
        // surface a per-session "workflow orchestration ran" signal. Best-effort
        // only: absence/errors -> false, never load-bearing for collection.
        if self.source == SnapshotSource::ClaudeCode {
            let workflows_dir = path.with_extension("").join("workflows");
            self.origin.used_workflow_orchestration =
                Some(claude_workflows_dir_has_manifest(&workflows_dir));
        }
        let repository_identity = self.workspace_path.as_deref().map(|workspace| {
            measured_repository_identity.unwrap_or_else(|| cached_repository_identity(workspace))
        });
        let workspace_display_label = repository_identity
            .as_ref()
            .filter(|identity| {
                matches!(
                    identity.workspace_kind.as_deref(),
                    Some("non_git" | "unknown")
                )
            })
            .and(self.workspace_path.as_deref())
            .and_then(crate::context_footprint::workspace_label);
        let mut attribution_facts = crate::session_attribution::direct_provider_facts(
            self.source,
            Some(&self.origin),
            &source_session_id,
            collected_at,
            self.source.parser_version(),
        );
        let codex_subagent = self.source == SnapshotSource::Codex
            && (self.origin.thread_source.as_deref() == Some("subagent")
                || self.origin.source_subagent == Some(true));
        if codex_subagent {
            attribution_facts.extend(crate::session_attribution::codex_subagent_facts(
                self.codex_root_session_ref.as_deref(),
                &source_session_id,
                self.codex_spawn_depth,
                self.codex_agent_label.as_deref(),
                collected_at,
                self.source.parser_version(),
            ));
        }
        // Subagent identity rides immediately behind the direct provider facts
        // and ahead of the grouping facts: `enforce_fact_limits` trims from the
        // tail, so the tree edges and the agent identity outrank the derived
        // grouping ids inside the bounded payload budget.
        if let Some(identity) = claude_subagent.as_ref() {
            attribution_facts.extend(crate::session_attribution::claude_subagent_facts(
                &crate::session_attribution::ClaudeSubagentAttribution {
                    root_session_ref: &identity.root_session_id,
                    agent_kind: claude_agent_meta.agent_kind.as_deref(),
                    agent_ref: identity.agent_ref(),
                    spawn_depth: claude_agent_meta.spawn_depth.as_deref(),
                    workflow_ref: identity.workflow_ref.as_deref(),
                },
                &source_session_id,
                collected_at,
                self.source.parser_version(),
            ));
        }
        // The starting session the Claude desktop app recorded for a session
        // another agent opened with its `start_session` tool. Provider-owned
        // lineage, so it sits ahead of launcher facts and never overwrites a
        // field provider-native evidence already filled.
        if let Some(lineage) = self.claude_desktop_spawn_lineage.as_ref() {
            let mut spawn_facts = crate::session_attribution::claude_desktop_spawn_facts(
                &lineage.parent_session_id,
                &source_session_id,
                collected_at,
            );
            spawn_facts.retain(|spawn_fact| {
                !attribution_facts
                    .iter()
                    .any(|fact| fact.field == spawn_fact.field)
            });
            attribution_facts.extend(spawn_facts);
        }
        // The controller edge an instrumented launcher stated at spawn time.
        // Same position and same reason as the subagent identity above: it is
        // exact lineage, so it has to outrank the derived grouping ids when the
        // payload budget trims from the tail.
        //
        // Provider-native evidence wins every field it already filled. A worker
        // the launcher started is a root session in its own provider tree, so in
        // practice nothing collides; when something does, the provider owns the
        // session and the launcher is the one that must be wrong.
        if let Some(context) = attribution_context {
            let mut launch_facts = context.launch_event_facts(&source_session_id, collected_at);
            launch_facts.retain(|launch_fact| {
                !attribution_facts
                    .iter()
                    .any(|fact| fact.field == launch_fact.field)
            });
            attribution_facts.extend(launch_facts);
        }
        if let Some(context) = attribution_context {
            attribution_facts.extend(
                context.grouping_facts(
                    crate::session_attribution::SessionAttributionGroupingInput {
                        source: self.source,
                        origin: Some(&self.origin),
                        source_session_id: &source_session_id,
                        observed_at: collected_at,
                        source_version: self.source.parser_version(),
                        first_prompt: self.first_prompt_material.as_deref(),
                        provider_skills: &self.provider_skills,
                        activity_skills: &self.activity_skills,
                        repository_hash: repository_identity
                            .as_ref()
                            .and_then(|identity| identity.repository_hash.as_deref()),
                        source_started_at: self.started_at.as_deref(),
                        transcript_path: path,
                    },
                ),
            );
        }
        // Unconditional: `direct_provider_facts` bounds only its own output, so
        // anything appended after it (subagent identity, grouping ids) has to be
        // re-bounded here or an item could exceed the payload budget the backend
        // schema rejects.
        crate::session_attribution::enforce_fact_limits(&mut attribution_facts);
        let collector = match self.source {
            SnapshotSource::Codex => "codex_jsonl".to_string(),
            SnapshotSource::ClaudeCode => "claude_code_jsonl".to_string(),
            SnapshotSource::Pi => "pi_jsonl".to_string(),
        };
        let input_token_scope = match self.source {
            SnapshotSource::Codex => Some("inclusive_cached".to_string()),
            SnapshotSource::ClaudeCode => Some("uncached".to_string()),
            SnapshotSource::Pi => Some("uncached".to_string()),
        };
        let activity_summary = self.activity_summary();
        // Emit an explicit empty list for a counted Claude/Codex transcript so
        // a newer cumulative scan can clear a previously observed aggregate.
        // Codex reuses the activity-summary counts (MCP-reclassified calls are
        // already removed from the plain map). Pi's parser does not see tool
        // names, so the field stays omitted there.
        let (tool_usage, tool_usage_truncated) = match self.source {
            SnapshotSource::ClaudeCode => (
                Some(bounded_tool_usage_counts(&self.tool_usage_counts)),
                self.tool_usage_truncated,
            ),
            SnapshotSource::Codex => {
                let (rows, truncated) = codex_tool_usage_rows(
                    &self.activity_tool_counts,
                    &self.activity_mcp_tool_usage_counts,
                );
                (Some(rows), truncated)
            }
            SnapshotSource::Pi => (None, false),
        };
        // Per-row session-wide aggregation (sum across all buckets keyed by
        // RowKey). Drives the top-level model_usage list and the snapshot
        // totals so the backend validator sees the two reconcile exactly.
        let totals = self.accepted_usage_totals.clone();
        let mut session_rows: BTreeMap<RowKey, BucketRowAccumulator> = BTreeMap::new();
        let mut usage_buckets: Vec<SnapshotUsageBucket> = Vec::new();
        // `e2` (gate on): the fold's grains are this body's one per-hour store
        // until `e2::finish_page` emits them; native per-hour rows would only
        // duplicate them on the page. A withheld body never uploads.
        let request_owned_hours =
            self.source == SnapshotSource::ClaudeCode && self.claude_money.is_some();
        for (bucket_start, bucket) in self.usage_buckets {
            if bucket.rows.is_empty() {
                continue;
            }
            if request_owned_hours {
                for (row_key, row) in bucket.rows {
                    merge_session_row(&mut session_rows, row_key, row);
                }
                continue;
            }
            let mut bucket_rows: Vec<SnapshotModelUsage> = Vec::new();
            for (row_key, row) in bucket.rows {
                bucket_rows.push(model_usage_from_row(&row_key, &row));
                merge_session_row(&mut session_rows, row_key, row);
            }
            // Rows in BTreeMap are already RowKey-ordered; emit them so each
            // bucket has at least one model_usage row (backend min_length=1).
            usage_buckets.push(SnapshotUsageBucket {
                bucket_start,
                model_usage: bucket_rows,
                first_activity_at: bucket.first_activity_at,
                last_activity_at: bucket.last_activity_at,
            });
        }
        // `e2` (gate on): a file whose every response is a resolver conflict
        // keeps a zero-usage carrier, so its conflict disclosure publishes
        // through the literal emitter like any request-owned body. No tokens
        // are invented; gate off, nothing changes.
        let conflict_carrier = self.source == SnapshotSource::ClaudeCode
            && self
                .claude_money
                .as_deref()
                .is_some_and(|money| money.entity.resolver_conflicts > 0);
        if session_rows.is_empty() && !conflict_carrier && !emit_empty_pi_fork {
            return Vec::new();
        }
        let mut model_usage: Vec<SnapshotModelUsage> = session_rows
            .iter()
            .map(|(row_key, row)| model_usage_from_row(row_key, row))
            .collect();
        for row in &mut model_usage {
            row.account_identifier_hash = self.account_identifier_hash.clone();
        }
        for bucket in &mut usage_buckets {
            for row in &mut bucket.model_usage {
                row.account_identifier_hash = self.account_identifier_hash.clone();
            }
        }
        // Claude Code events are built by the ownership fold, never here.
        let (compaction_count, compaction_timestamps, compaction_events, compaction_metrics) =
            if self.source == SnapshotSource::ClaudeCode {
                let (count, timestamps, metrics) =
                    claude_compaction_summary(&self.claude_compaction_observations);
                (count, timestamps, Vec::new(), metrics)
            } else {
                let timestamps = self.compaction_timestamps.into_vec();
                let events = if self.source == SnapshotSource::Codex {
                    self.codex_compaction_sizes.into_events()
                } else {
                    Vec::new()
                };
                (
                    self.compaction_count,
                    bounded_compaction_timestamps(timestamps),
                    events,
                    CompactionMetrics::default(),
                )
            };
        let local_context_points = if self.source == SnapshotSource::Codex {
            self.local_context_points
                .into_recent(self.last_activity_at.as_deref(), collected_at)
        } else {
            Vec::new()
        };
        if self.source == SnapshotSource::Codex && codex_usage_accounting_proven {
            // An incomplete physical read report cannot certify an exact
            // omitted count.
            self.cache_observations = Some(cache_wire(
                &source_session_id,
                self.cache_requests.iter(),
                self.cache_requests_complete,
            ));
        }
        let session_start = match self.source {
            SnapshotSource::ClaudeCode => std::mem::take(&mut *self.session_start).finish(
                true,
                self.first_turn_context_tokens,
                session_start::CLAUDE_PARTS_METHOD,
                attribution_context,
                crate::context_file_counts::device_salt().as_ref(),
            ),
            SnapshotSource::Codex => std::mem::take(&mut *self.session_start).finish(
                !self.codex_is_fork,
                self.first_turn_context_tokens,
                session_start::CODEX_PARTS_METHOD,
                attribution_context,
                crate::context_file_counts::device_salt().as_ref(),
            ),
            _ => None,
        }
        .map(Box::new);
        let mut item = SnapshotItem {
            evidence_basis: None,
            request_evidence: Vec::new(),
            request_identity_refusals: 0,
            claude_org_markers: self.claude_org_markers,
            claude_account_withheld_reason: None,
            claude_account_display: None,
            session_account_evidence,
            source_session_id: source_session_id.clone(),
            snapshot_fingerprint: String::new(),
            status: "final".to_string(),
            input_tokens: totals.input_tokens,
            output_tokens: totals.output_tokens,
            cache_read_tokens: totals.cache_read_tokens,
            cache_creation_5m_tokens: totals.cache_creation_5m_tokens,
            cache_creation_1h_tokens: totals.cache_creation_1h_tokens,
            reasoning_output_tokens: totals.reasoning_output_tokens,
            unattributed_total_tokens: totals.unattributed_total_tokens,
            request_count: totals.request_count,
            usage_accounting_contract: codex_usage_accounting_proven
                .then(|| "session_exclusive_reported_usage:v1".to_string()),
            removed_request_count: None,
            removed_usage: None,
            telemetry_owned_complete: None,
            resolver_conflict_count: None,
            copy_unproven_counts: None,
            claude_money: self.claude_money,
            claude_usage_request_ids: self.claude_usage_request_ids,
            claude_usage_occurrences: self.claude_usage_occurrences,
            cache_observations: self.cache_observations,
            cache_observations_state: None,
            cache_base_head_etag: None,
            cache_conflict_answer: None,
            cache_requests: self.cache_requests.into_vec(),
            cache_requests_complete: self.cache_requests_complete,
            avg_duration_ms: (self.latency_duration_ms_count > 0)
                .then(|| self.latency_duration_ms_sum / self.latency_duration_ms_count),
            avg_time_to_first_token_ms: (self.latency_ttft_ms_count > 0)
                .then(|| self.latency_ttft_ms_sum / self.latency_ttft_ms_count),
            max_duration_ms: (self.latency_duration_ms_count > 0)
                .then_some(self.latency_duration_ms_max),
            max_time_to_first_token_ms: (self.latency_ttft_ms_count > 0)
                .then_some(self.latency_ttft_ms_max),
            // Posture-deriving sources only (Claude Code, Codex); Pi emits
            // None. A parsed session with no counted context leaves peak/first
            // at None, while compaction_count is always reported for a parsed
            // transcript (Some(0) = "observed, none" vs None = "daemon can't
            // tell") — both sources log compactions explicitly, so a zero here
            // is a real observation rather than a gap.
            peak_context_fill_tokens: (self.source.derives_context_posture()
                && self.peak_context_fill_tokens > 0)
                .then_some(self.peak_context_fill_tokens),
            first_turn_context_tokens: if self.source.derives_context_posture() {
                self.first_turn_context_tokens
            } else {
                None
            },
            last_turn_context_tokens: if self.source.derives_context_posture() {
                self.last_turn_context_tokens
            } else {
                None
            },
            // Codex only, and each only beside its own emitted watermark.
            first_turn_context_window_tokens: self.first_turn_context_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.first_turn_context_tokens.is_some()
            }),
            peak_context_fill_window_tokens: self.peak_context_fill_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.peak_context_fill_tokens > 0
            }),
            last_turn_context_window_tokens: self.last_turn_context_window_tokens.filter(|_| {
                self.source == SnapshotSource::Codex && self.last_turn_context_tokens.is_some()
            }),
            compaction_count: self
                .source
                .derives_context_posture()
                .then_some(compaction_count),
            compaction_timestamps: if self.source.derives_context_posture() {
                compaction_timestamps
            } else {
                Vec::new()
            },
            compaction_events: if self.source.derives_context_posture() {
                compaction_events
            } else {
                Vec::new()
            },
            // Set by the ownership fold only (design E), never here.
            first_own_request_at: None,
            local_context_points,
            compaction_total_pre_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_pre_tokens)
            } else {
                None
            },
            compaction_total_post_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_post_tokens)
            } else {
                None
            },
            compaction_total_cumulative_dropped_tokens: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_cumulative_dropped_tokens)
            } else {
                None
            },
            compaction_total_duration_ms: if self.source.derives_context_posture()
                && compaction_metrics.metrics_count > 0
            {
                Some(compaction_metrics.total_duration_ms)
            } else {
                None
            },
            context_curve: None,
            claude_context_curve_boundaries: self.claude_compaction_observations.into_vec(),
            claude_context_curve_identity_complete: self.claude_context_curve_identity_complete,
            claude_context_curve_request_index_complete: self
                .claude_context_curve_request_index_complete,
            claude_context_curve_owned_start_proven: self.claude_context_curve_owned_start_proven,
            claude_file_birth: self.claude_file_birth,
            claude_file_birth_verdict: None,
            activity_summary,
            tool_usage,
            tool_usage_truncated,
            session_start,
            model_usage,
            usage_buckets,
            cost: totals.costs.snapshot_cost(),
            session_display_name: self.title.clone(),
            session_display_name_source: self.title_source.clone(),
            source_started_at: self.started_at.clone(),
            source_ended_at: self.ended_at.clone(),
            source_last_activity_at: self.last_activity_at.clone(),
            collected_at: collected_at.to_string(),
            workspace_hash: self.workspace_hash.clone(),
            workspace_label_source: workspace_display_label
                .as_ref()
                .map(|_| "directory_name".into()),
            workspace_display_label,
            repository_hash: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_hash.clone()),
            repository_label: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_label.clone()),
            repository_label_source: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_label_source.clone()),
            repository_identity_source: repository_identity
                .as_ref()
                .and_then(|identity| identity.repository_identity_source.clone()),
            workspace_kind: repository_identity
                .as_ref()
                .and_then(|identity| identity.workspace_kind.clone()),
            source_file_fingerprint: Some(source_file_fingerprint.clone()),
            session_artifacts: {
                let mut artifacts = self.artifacts.clone();
                artifacts.sort();
                artifacts
            },
            provenance: SnapshotProvenance {
                collector: collector.clone(),
                source_file_count: 1,
                input_token_scope: input_token_scope.clone(),
                state_total_tokens: None,
                state_archived: None,
            },
            origin: (!self.origin.is_empty()).then(|| self.origin.clone()),
            // Forward-looking top-level mirror of the Codex `session_meta`
            // originator (e.g. `codex_work_desktop`). `origin.originator` is only
            // ever populated by the Codex line parser, but guard on `source` too
            // so a non-Codex path can never fabricate one.
            originator: match self.source {
                SnapshotSource::Codex => self.origin.originator.clone(),
                SnapshotSource::ClaudeCode | SnapshotSource::Pi => None,
            },
            attribution_facts,
        };
        item.snapshot_fingerprint = snapshot_fingerprint(self.source, &item);
        vec![item]
    }
}
