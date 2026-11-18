//! Retaining Claude usage records and resolving them into responses.

use super::{SelectorCapture, SnapshotAccumulator};
use crate::snapshots::{
    cache_observations, claude_cache_request_slot, claude_request_identity, claude_request_money,
    claude_response_key, claude_response_tool_uses, provider_context_bucket, rfc3339_unix_nanos,
    rfc3339_unix_seconds, string_at, ClaudeResolveFailure, ClaudeResponseObservation,
    ClaudeTranscriptUsageOccurrence, OwnedRequest, UsageTotals, CLAUDE_RECORDS_PER_FILE_ALARM,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;

impl SnapshotAccumulator {
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
