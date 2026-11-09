//! Which Codex records a file owns: the ownership boundary, the created-thread
//! and parentless proofs, and the inherited and bootstrap records.

use super::{CodexOwnershipBoundary, SnapshotAccumulator};
use crate::snapshots::{
    codex_header_declares_no_parent, codex_identity_at, codex_identity_is_uuid_shaped,
    codex_is_task_started, codex_last_usage, codex_legacy_trigger_turn,
    codex_native_created_thread_header, codex_paginated_fork_creation_header,
    codex_session_meta_payload, codex_total_usage, codex_usage_token_fields,
    resolve_codex_identity_option, rfc3339_unix_nanos, string_at, string_eq_at, u64_at, CapCounts,
};
use serde_json::Value;

impl SnapshotAccumulator {
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

    /// An exact ordinal fork whose every parsed record is inherited prefix:
    /// the contiguous stream ends at its declared start with nothing owned.
    /// Only a closed stream proves zero owned usage; the caller owns that.
    pub(in crate::snapshots) fn codex_ordinal_prefix_only(&self, parsed_records: usize) -> bool {
        matches!(
            self.codex_ownership_boundary,
            CodexOwnershipBoundary::Ordinal { start }
                if self.codex_ordinal_sequence_valid
                    && !self.codex_owned_record_seen
                    && self.codex_ordinal_expected == Some(start)
                    && u64::try_from(parsed_records).ok() == Some(start)
        )
    }
}
