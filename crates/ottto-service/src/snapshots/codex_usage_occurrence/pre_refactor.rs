//! Frozen pre-refactor oracle. Test-only; change production on a real differential failure.
//! Only method/function names and their references are renamed.
use super::*;

// 9d384f845576f116de4b54686ba8648420e7e71e, codex_usage_occurrence.rs:620-678.
impl SnapshotAccumulator {
    pub(super) fn observe_codex_counting_line_pre_refactor(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        let Some(counting) = self.codex_counting.as_mut() else {
            return;
        };
        if counting.version.is_none() {
            let version =
                codex_counting_version::decide(value, counting.evidence, counting.cutover_unix_ms);
            counting.version = Some(version);
            if version == CountingVersion::V2 {
                counting.reducer = Some(Box::default());
            }
        }
        let Some(reducer) = counting.reducer.as_mut() else {
            return;
        };
        reducer.line_ui = ui_t6_pair(value);
        let event = string_at(value, &["payload", "type"]);
        match event.as_deref() {
            Some("task_started") => {
                self.close_codex_turn_pre_refactor(None);
                let turn_id = string_at(value, &["payload", "turn_id"])
                    .filter(|id| !id.is_empty() && id.len() <= MAX_TURN_ID_BYTES);
                if let Some(reducer) = self.codex_occurrence() {
                    // Closure is final: a closed id reopens only as an unbound
                    // span (Legacy UI, natives 0), never as a new turn.
                    let closed = turn_id
                        .as_deref()
                        .map_or(Closed::No, |id| reducer.closed(id));
                    match closed {
                        Closed::Recent => reducer.counters.turn_reopened += 1,
                        Closed::Unconfirmed => reducer.counters.closed_filter_hit_unconfirmed += 1,
                        Closed::No => {}
                    }
                    reducer.turn = turn_id
                        .filter(|_| closed == Closed::No)
                        .map(|id| BoundTurn {
                            id,
                            native: false,
                            ui_published: false,
                            staged_events: 0,
                            pending: OwnedMap::new(),
                        });
                }
            }
            Some("task_complete" | "turn_aborted") => {
                let closing = string_at(value, &["payload", "turn_id"]);
                self.close_codex_turn_pre_refactor(closing.as_deref());
            }
            _ => {}
        }
        if string_eq_at(value, &["type"], "token_usage_record") {
            self.admit_codex_native_pre_refactor(value, timestamp, selector);
        }
    }
}

// 9d384f845576f116de4b54686ba8648420e7e71e, codex_usage_occurrence.rs:683-711.
impl SnapshotAccumulator {
    fn close_codex_turn_pre_refactor(&mut self, closing_turn_id: Option<&str>) {
        let Some(reducer) = self.codex_occurrence() else {
            return;
        };
        let closing = closing_turn_id.filter(|id| !id.is_empty() && id.len() <= MAX_TURN_ID_BYTES);
        let Some(turn) = reducer.turn.take() else {
            if let Some(closing) = closing {
                reducer.remember_closed(closing.to_owned());
            }
            return;
        };
        if closing_turn_id.is_some_and(|closing| closing != turn.id) {
            reducer.counters.turn_closure_mismatch += 1;
            if let Some(closing) = closing {
                reducer.remember_closed(closing.to_owned());
            }
        }
        let BoundTurn {
            id,
            native,
            ui_published,
            pending,
            ..
        } = turn;
        reducer.remember_closed(id);
        if !native && !ui_published {
            self.publish_codex_pending(&pending);
        }
    }
}

// 9d384f845576f116de4b54686ba8648420e7e71e, codex_usage_occurrence.rs:713-829.
impl SnapshotAccumulator {
    fn admit_codex_native_pre_refactor(
        &mut self,
        value: &Value,
        timestamp: Option<&str>,
        selector: &SelectorCapture,
    ) {
        let native = native_record(value, self.source_session_id.as_deref());
        let Some(reducer) = self.codex_occurrence() else {
            return;
        };
        let Some(native) = native else {
            reducer.counters.native_not_authority += 1;
            return;
        };
        let mut money = reducer.cover(&native);
        let bound = reducer
            .turn
            .as_mut()
            .filter(|turn| native.turn_id.as_deref() == Some(turn.id.as_str()));
        match bound {
            Some(turn) if turn.ui_published => {
                reducer.counters.native_after_ui_flush += 1;
                add_t6(
                    &mut reducer.counters.native_after_ui_flush_usage,
                    &native.usage,
                );
                money = [0; 6];
            }
            Some(turn) => {
                if !turn.native {
                    turn.native = true;
                    let staged = std::mem::take(&mut turn.staged_events);
                    let pending = std::mem::replace(&mut turn.pending, OwnedMap::new());
                    reducer.counters.ui_in_native_turn_not_counted += staged;
                    for row in pending.values() {
                        add_t6(
                            &mut reducer.counters.ui_in_native_turn_not_counted_usage,
                            &totals_t6(&row.usage),
                        );
                    }
                }
            }
            None => {
                let closed = native
                    .turn_id
                    .as_deref()
                    .map_or(Closed::No, |turn| reducer.closed(turn));
                let (count, usage) = match closed {
                    Closed::Recent => (
                        &mut reducer.counters.native_after_turn_closed,
                        &mut reducer.counters.native_after_turn_closed_usage,
                    ),
                    Closed::Unconfirmed => (
                        &mut reducer.counters.closed_filter_hit_unconfirmed,
                        &mut reducer.counters.closed_filter_hit_unconfirmed_native_usage,
                    ),
                    Closed::No => (
                        &mut reducer.counters.native_outside_open_turn,
                        &mut reducer.counters.native_outside_open_turn_usage,
                    ),
                };
                *count += 1;
                add_t6(usage, &native.usage);
                money = [0; 6];
            }
        }
        if money[..5].iter().all(|value| *value == 0) {
            return;
        }
        reducer.counters.native_counted += 1;
        let mut usage_selector = selector.clone();
        if self.current_turn_is_priority() {
            usage_selector.insert(
                "service_tier",
                "priority".to_string(),
                "derived_from_logs_2",
            );
        }
        let model = string_at(value, &["payload", "model"]);
        let applied_tier = self.codex_tier_replay.as_mut().and_then(|replay| {
            replay.selector(
                value,
                &mut usage_selector,
                &self.current_selector,
                model.as_deref().or(self.latest_model.as_deref()),
                self.latest_reasoning_effort.as_deref(),
                self.latest_turn_id.as_deref(),
            )
        });
        // Match the UI price stamp after tier replay, on this row only. Codex
        // input already includes cached input; price the original request's
        // prompt, even when coverage admits only part of its usage.
        if !usage_selector.context.contains_key("context_bucket") {
            if let Some(bucket) = model
                .as_deref()
                .or(self.latest_model.as_deref())
                .and_then(|model| provider_context_bucket(model, native.usage[0], timestamp))
            {
                usage_selector.insert(
                    "context_bucket",
                    bucket.to_string(),
                    "derived_from_native_usage",
                );
            }
        }
        let effort = self.latest_reasoning_effort.clone();
        self.add_usage_with_selector(
            model,
            native_money(&money),
            usage_selector,
            timestamp,
            effort,
        );
        if let Some(replay) = self.codex_tier_replay.as_mut() {
            replay.admitted(applied_tier);
        }
    }
}

// 9d384f845576f116de4b54686ba8648420e7e71e, codex_usage_occurrence.rs:835-970.
impl SnapshotAccumulator {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn set_codex_v2_cumulative_usage_pre_refactor(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        implicit_request_count: Option<u64>,
        effort: Option<String>,
    ) -> Option<UsageTotals> {
        let resolved_model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(resolved_model.clone());
        if usage_event_identity.is_some()
            && usage_event_identity == self.codex_last_usage_event_identity
        {
            self.codex_duplicate_usage_records_skipped =
                self.codex_duplicate_usage_records_skipped.saturating_add(1);
            return None;
        }
        if usage_event_identity.is_some() {
            self.codex_last_usage_event_identity = usage_event_identity;
        }
        let previous = self.session_cumulative_usage.clone();
        let reset = previous
            .as_ref()
            .is_some_and(|previous| !usage.is_monotonic_after(previous));
        if reset {
            self.codex_cumulative_reset_count = self.codex_cumulative_reset_count.saturating_add(1);
        }
        // Today's delta: `last`, else the cumulative delta, else the whole
        // total on a first event or reset. A bound turn never counts that
        // inherited/reset base.
        let (legacy_delta, bound_delta) = match (&last_usage, &previous) {
            (Some(last), _) => (last.clone(), Some(last.clone())),
            (None, Some(previous)) if !reset => {
                let delta = usage.delta_from(previous);
                (delta.clone(), Some(delta))
            }
            (None, _) => (usage.clone(), None),
        };
        self.session_cumulative_usage = Some(usage.clone());
        let with_count = |mut delta: UsageTotals| {
            if !delta.is_zero() {
                if let Some(count) = implicit_request_count {
                    delta.request_count = count;
                }
            }
            delta
        };
        let legacy_delta = with_count(legacy_delta);
        if legacy_delta.is_zero() {
            return None;
        }
        let reducer = self.codex_occurrence()?;
        let tuple = reducer
            .line_ui
            .take()
            .zip(last_usage)
            .map(|((last_t6, total_t6), last)| UiTuple {
                last,
                total: usage,
                last_t6,
                total_t6,
            });
        if reducer.turn.is_none() {
            reducer.counters.ui_in_unbound_span += 1;
            reducer.note_ui(tuple);
            self.add_usage_with_selector(
                Some(resolved_model),
                legacy_delta.clone(),
                selector,
                timestamp,
                effort,
            );
            return Some(legacy_delta);
        }
        // Rule 2: same `last` and same total as the previous UI candidate with
        // no native between is a re-emission. A decreased total never matches.
        if !reducer.native_since_prev_ui && tuple.is_some() && tuple == reducer.prev_ui {
            reducer.counters.ui_equal_total_repeat += 1;
            add_t6(
                &mut reducer.counters.ui_equal_total_repeat_usage,
                &totals_t6(&legacy_delta),
            );
            return None;
        }
        reducer.note_ui(tuple);
        let Some(delta) = bound_delta.map(with_count).filter(|delta| !delta.is_zero()) else {
            reducer.counters.v2_cumulative_base_uncounted += 1;
            add_t6(
                &mut reducer.counters.v2_cumulative_base_uncounted_usage,
                &totals_t6(&legacy_delta),
            );
            return None;
        };
        let turn = reducer.turn.as_mut()?;
        if turn.native {
            reducer.counters.ui_in_native_turn_not_counted += 1;
            add_t6(
                &mut reducer.counters.ui_in_native_turn_not_counted_usage,
                &totals_t6(&delta),
            );
            return Some(delta);
        }
        if !turn.ui_published {
            match self.stage_codex_ui(
                &resolved_model,
                &delta,
                selector.clone(),
                timestamp,
                effort.as_deref(),
            ) {
                Staging::Staged | Staging::Dropped => return Some(delta),
                Staging::Overflow => {
                    let reducer = self.codex_occurrence()?;
                    reducer.counters.pending_overflow_flushes += 1;
                    let turn = reducer.turn.as_mut()?;
                    turn.ui_published = true;
                    turn.staged_events = 0;
                    let pending = std::mem::replace(&mut turn.pending, OwnedMap::new());
                    self.publish_codex_pending(&pending);
                }
            }
        }
        self.add_usage_with_selector(
            Some(resolved_model),
            delta.clone(),
            selector,
            timestamp,
            effort,
        );
        Some(delta)
    }
}

// 9d384f845576f116de4b54686ba8648420e7e71e, snapshots.rs:20832-20914.
impl SnapshotAccumulator {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn set_cumulative_usage_with_selector_pre_refactor(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        last_usage: Option<UsageTotals>,
        usage_event_identity: Option<String>,
        selector: SelectorCapture,
        timestamp: Option<&str>,
        // Override the delta's request_count when the upstream cumulative did
        // not include an explicit request_count. The cumulative-derived delta
        // would otherwise be 0 (since the cumulative request_count was
        // synthetically defaulted to 1 by the parser), losing the per-event
        // request count. v5 implemented this via a separate note_activity
        // call; v6 folds it in here so the row totals reconcile.
        implicit_request_count: Option<u64>,
        // Per-turn reasoning effort tier (Codex), attached to the same usage row.
        effort: Option<String>,
    ) -> Option<UsageTotals> {
        if self.codex_counting_v2() {
            return self.set_codex_v2_cumulative_usage_pre_refactor(
                model,
                usage,
                last_usage,
                usage_event_identity,
                selector,
                timestamp,
                implicit_request_count,
                effort,
            );
        }
        let resolved_model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(resolved_model.clone());
        // Only an exact repeated physical usage event is a duplicate. Equal
        // cumulative totals are not an occurrence identity: after a restart,
        // a new response can legitimately bring the new epoch to the same
        // counters while `last_token_usage` proves positive work.
        if usage_event_identity.is_some()
            && usage_event_identity == self.codex_last_usage_event_identity
        {
            self.codex_duplicate_usage_records_skipped =
                self.codex_duplicate_usage_records_skipped.saturating_add(1);
            return None;
        }
        if usage_event_identity.is_some() {
            self.codex_last_usage_event_identity = usage_event_identity;
        }

        // `last_token_usage` is Codex's exact current-response usage and stays
        // correct across compaction/restart resets. Older rollouts lack it; in
        // that case use a cumulative delta, beginning a new additive epoch on
        // a reset. Never erase usage already accepted from the same rollout.
        let previous = self.session_cumulative_usage.as_ref();
        let reset = previous.is_some_and(|previous| !usage.is_monotonic_after(previous));
        if reset {
            self.codex_cumulative_reset_count = self.codex_cumulative_reset_count.saturating_add(1);
        }
        let mut delta = match last_usage {
            Some(last) => last,
            None => match previous {
                Some(previous) if !reset => usage.delta_from(previous),
                Some(_) | None => usage.clone(),
            },
        };
        self.session_cumulative_usage = Some(usage.clone());
        if !delta.is_zero() {
            if let Some(count) = implicit_request_count {
                delta.request_count = count;
            }
        }
        if delta.is_zero() {
            return None;
        }
        self.add_usage_with_selector(
            Some(resolved_model),
            delta.clone(),
            selector,
            timestamp,
            effort,
        );
        Some(delta)
    }
}

// 9d384f845576f116de4b54686ba8648420e7e71e, snapshots.rs:39693-40149.
pub(super) fn apply_codex_owned_line_pre_refactor(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator
        .session_start
        .observe_codex_line(value, accumulator.workspace_path.as_deref());
    if string_eq_at(value, &["type"], "turn_context") {
        if let Some(payload) = value.get("payload").and_then(Value::as_object) {
            let metadata = payload
                .iter()
                .filter(|(field, _)| {
                    !matches!(
                        field.as_str(),
                        "turn_id" | "root_turn_id" | "summary" | "timestamp" | "usage"
                    )
                })
                .map(|(field, value)| (field.clone(), value.clone()))
                .collect::<serde_json::Map<_, _>>();
            if !metadata.is_empty() {
                // Domain-separated SHA-256 (an H value in the durable store).
                accumulator.cache_configuration_witness = Some(sha256_hex(&[
                    "ottto-cache-configuration-witness:v1",
                    Value::Object(metadata).to_string().as_str(),
                ]));
            }
        }
    }
    if string_eq_at(value, &["payload", "type"], "task_complete") {
        accumulator.cache_task_complete_at = string_at(value, &["timestamp"]);
        if let Some(turn) = string_at(value, &["payload", "turn_id"]) {
            accumulator.cache_active_turns.remove(&turn);
        }
    }
    if string_eq_at(value, &["payload", "type"], "task_started") {
        accumulator.session_start.note_user_turn();
        if let Some(turn) = string_at(value, &["payload", "turn_id"]) {
            accumulator.cache_active_turns.insert(turn);
        }
        accumulator.cache_pending_idle = accumulator
            .cache_task_complete_at
            .as_deref()
            .zip(value.get("timestamp").and_then(Value::as_str))
            .and_then(|(end, start)| {
                let end = OffsetDateTime::parse(end, &Rfc3339).ok()?;
                let start = OffsetDateTime::parse(start, &Rfc3339).ok()?;
                if start < end {
                    return None;
                }
                u64::try_from((start - end).whole_seconds()).ok()
            });
    }
    if let Some(request) = codex_cache_request(value, accumulator) {
        if accumulator.cache_requests.len() < MAX_CLAUDE_RESPONSE_RECORDS_PER_FILE {
            accumulator.cache_requests.push(request);
        } else {
            accumulator.cache_requests_complete = false;
        }
        accumulator.cache_pending_idle = None;
    }
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = resolve_codex_identity_option(
            codex_identity_at(value, &["session_meta", "payload", "id"])
                .or_else(|| codex_identity_at(value, &["payload", "id"]))
                .or_else(|| codex_identity_at(value, &["session_id"]))
                .or_else(|| codex_identity_at(value, &["sessionId"])),
        );
    }
    // Raw session-origin (siblings of `id` in session_meta.payload). The
    // session_meta line carries these; other lines yield None, so first-seen
    // (guarded by is_none) keeps the authoritative session_meta values.
    if accumulator.origin.thread_source.is_none() {
        accumulator.origin.thread_source =
            string_at(value, &["session_meta", "payload", "thread_source"])
                .or_else(|| string_at(value, &["payload", "thread_source"]));
    }
    if accumulator.origin.source.is_none() && accumulator.origin.source_subagent.is_none() {
        if let Some(src) = raw_value_at(value, &["session_meta", "payload", "source"])
            .or_else(|| raw_value_at(value, &["payload", "source"]))
        {
            if let Some(text) = src.as_str() {
                accumulator.origin.source = Some(text.to_string());
            } else if src.is_object() {
                // Codex subagent form: source = { "subagent": { "thread_spawn": .. } }.
                accumulator.origin.source_subagent = Some(src.get("subagent").is_some());
                accumulator.origin.parent_session_ref = resolve_codex_identity_option(
                    codex_identity_at(src, &["subagent", "thread_spawn", "parent_thread_id"]),
                );
            }
        }
    }
    if accumulator.origin.originator.is_none() {
        accumulator.origin.originator =
            string_at(value, &["session_meta", "payload", "originator"])
                .or_else(|| string_at(value, &["payload", "originator"]));
    }
    if accumulator.origin.agent_role.is_none() {
        accumulator.origin.agent_role =
            string_at(value, &["session_meta", "payload", "agent_role"])
                .or_else(|| string_at(value, &["payload", "agent_role"]));
    }
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["time"]))
        .or_else(|| string_at(value, &["created_at"]));
    accumulator.note_time(timestamp.clone());
    accumulator.set_title(codex_transcript_title(value), "transcript_title");
    accumulator.set_first_prompt_title(codex_first_user_prompt(value));
    accumulator.set_model(
        string_at(value, &["turn_context", "payload", "model"])
            .or_else(|| string_at(value, &["payload", "model"]))
            .or_else(|| string_at(value, &["model"])),
    );
    accumulator.set_workspace_hash(
        string_at(value, &["turn_context", "payload", "cwd"])
            .or_else(|| string_at(value, &["payload", "cwd"]))
            .or_else(|| string_at(value, &["cwd"])),
    );
    let selector = codex_selector_from_line(value);
    accumulator.set_selector(selector.clone());
    if let Some(effort) = codex_reasoning_effort(value) {
        accumulator.latest_reasoning_effort = Some(effort);
    }
    // Track the running turn id from `turn_context` (the token_count event that
    // emits usage carries none). It joins each usage row to its `logs_2`
    // fast-mode signal. Lines without a turn id leave the running value intact.
    if let Some(turn_id) = string_at(value, &["turn_context", "payload", "turn_id"])
        .or_else(|| string_at(value, &["payload", "turn_id"]))
    {
        accumulator.latest_turn_id = Some(turn_id);
    }
    // Codex compaction (auto or manual `/compact`) writes a top-level
    // `type=compacted` rollout record carrying the `replacement_history` that
    // supersedes the compacted turns. Codex also emits an
    // `event_msg`/`context_compacted` UI event for the same compaction a few
    // milliseconds later; the two are strictly paired, so count the rollout
    // record only — counting both would double every compaction. The rollout
    // record is the state mutation itself, which makes it the Codex analogue of
    // the `isCompactSummary` record the Claude parser counts.
    if string_eq_at(value, &["type"], "compacted") {
        accumulator.compaction_count += 1;
        if accumulator.context_curve_enabled {
            accumulator
                .codex_context_curve_boundaries
                .push(ContextCurveCandidateBoundary {
                    observed_at: timestamp.clone(),
                    point_count_before: accumulator.codex_context_curve_candidates.len() as u64,
                });
        }
        if let Some(timestamp) = timestamp.clone() {
            // `before` is the session's current "last" value: the last owned
            // non-zero request before this marker, in the posture measure.
            accumulator
                .codex_compaction_sizes
                .note_marker(&timestamp, accumulator.last_turn_context_tokens);
            accumulator.compaction_timestamps.push(timestamp);
        }
    }
    // Context posture watermarks for this response. Codex states the per-turn
    // usage directly in `last_token_usage`, so read it off the event rather
    // than reusing the cumulative delta computed below. The delta agrees with
    // `last_token_usage` on a healthy sequence, but not on the two cases that
    // matter here: a duplicated `token_count` event (Codex emits these) yields
    // a zero delta while `last_token_usage` still states the turn's true
    // context, and a non-monotonic cumulative (session restart) makes the delta
    // the whole session's input rather than one turn's — which would post a
    // wildly inflated peak.
    //
    // The value needs no cache adjustment: unlike Claude's `message.usage`,
    // Codex `input_tokens` is INCLUSIVE of `cached_input_tokens` (hence
    // `input_token_scope=inclusive_cached` in this snapshot's provenance), so
    // it already IS the prompt volume the model saw. Adding cache reads on top
    // — the Claude-side `effective_input_context()` formula — would nearly
    // double a cache-heavy turn and report a long session as filling more than
    // its own context window.
    if let Some(context_tokens) = codex_last_turn_input_context(value) {
        // The `token_count` event Codex emits at a compaction reports zero
        // usage; it observed no context, so it must not become the baseline.
        if context_tokens > 0 {
            // The window that bounded THIS prompt, read off the same record,
            // so each watermark keeps its own window when Codex changes it
            // mid-session. One lookup on the already parsed record.
            let window = codex_model_context_window(value);
            if accumulator.first_turn_context_tokens.is_none() {
                accumulator.first_turn_context_tokens = Some(context_tokens);
                accumulator.first_turn_context_window_tokens = window;
            }
            // Peak ties: the first record that reached the peak keeps its
            // window; a later equal record only fills a window that is still
            // missing, and never replaces a known one.
            if context_tokens > accumulator.peak_context_fill_tokens
                || (context_tokens == accumulator.peak_context_fill_tokens
                    && accumulator.peak_context_fill_window_tokens.is_none())
            {
                accumulator.peak_context_fill_window_tokens = window;
            }
            accumulator.peak_context_fill_tokens =
                accumulator.peak_context_fill_tokens.max(context_tokens);
            accumulator.last_turn_context_tokens = Some(context_tokens);
            // As-is, including None: a later record without a window must not
            // keep an older record's window under its own watermark.
            accumulator.last_turn_context_window_tokens = window;
            accumulator
                .local_context_points
                .push(timestamp.as_deref(), context_tokens);
        }
    }
    // Usage-counting V2 (configured parsers only): version decision on the
    // first owned record, turn lifecycle and native `token_usage_record`s.
    accumulator.observe_codex_counting_line_pre_refactor(value, timestamp.as_deref(), &selector);
    if let Some(usage) = codex_total_usage(value) {
        // Codex cumulative totals carry request_count as a session-wide count.
        // When the field is missing the parser defaults it to 1 so deltas
        // would yield 0 requests. Track the implicit case and override the
        // delta's request_count to 1 so the bucket row reflects "one turn
        // observed at this hour" — matching v5's note_activity behavior.
        let implicit_request_count = if codex_total_usage_has_request_count(value) {
            None
        } else {
            Some(1)
        };
        // Stamp the fast-mode tier onto THIS turn's usage row only — passed as
        // the per-line selector, never merged into current_selector — so a fast
        // turn prices at the priority rate without leaking into later standard
        // turns of the same session.
        let mut usage_selector = selector;
        if accumulator.current_turn_is_priority() {
            usage_selector.insert(
                "service_tier",
                "priority".to_string(),
                "derived_from_logs_2",
            );
        }
        let model = string_at(value, &["token_count", "info", "model"])
            .or_else(|| string_at(value, &["payload", "info", "model"]))
            .or_else(|| string_at(value, &["turn_context", "payload", "model"]))
            .or_else(|| string_at(value, &["payload", "model"]));
        let applied_tier = accumulator.codex_tier_replay.as_mut().and_then(|replay| {
            replay.selector(
                value,
                &mut usage_selector,
                &accumulator.current_selector,
                model.as_deref().or(accumulator.latest_model.as_deref()),
                accumulator.latest_reasoning_effort.as_deref(),
                accumulator.latest_turn_id.as_deref(),
            )
        });
        // Stamp this response's long-context price bucket on the same per-line
        // selector, after the tier replay key above (which must not change): a
        // prompt over the model's provider line bills the whole request at the
        // long rate. The size is the already-parsed per-response
        // `last_token_usage.input_tokens`; no price line, no stamp.
        if !usage_selector.context.contains_key("context_bucket") {
            let bucket = model
                .as_deref()
                .or(accumulator.latest_model.as_deref())
                .zip(codex_last_turn_input_context(value))
                .and_then(|(model, prompt_tokens)| {
                    provider_context_bucket(model, prompt_tokens, timestamp.as_deref())
                });
            if let Some(bucket) = bucket {
                usage_selector.insert(
                    "context_bucket",
                    bucket.to_string(),
                    "derived_from_last_token_usage",
                );
            }
        }
        let last_usage = codex_last_usage(value);
        let usage_event_identity = codex_usage_event_identity(value);
        let admitted = accumulator.set_cumulative_usage_with_selector_pre_refactor(
            model.clone(),
            usage,
            last_usage.clone(),
            usage_event_identity.clone(),
            usage_selector,
            timestamp.as_deref(),
            implicit_request_count,
            accumulator.latest_reasoning_effort.clone(),
        );
        if admitted.is_some() {
            let v2 = codex_file_join::group_counting_is_v2(accumulator);
            if let Some(replay) = accumulator.codex_tier_replay.as_mut() {
                replay.admitted(applied_tier);
                // S10: the group proof sees only actually admitted usage.
                replay.admitted_usage(
                    value,
                    last_usage.is_some(),
                    usage_event_identity.as_deref(),
                    accumulator.latest_turn_id.as_deref(),
                    v2,
                );
            }
        }
        if let (Some(_), Some(last_usage)) = (admitted.as_ref(), last_usage.as_ref()) {
            accumulator.session_start.note_codex_request(last_usage);
        }
        // A compaction's "after" is the first COUNTED request after it: exact
        // duplicates and re-emissions are not admitted. Same measure as
        // `before` (the posture read of `last_token_usage`).
        if admitted.is_some() {
            if let Some(context_tokens) = codex_last_turn_input_context(value) {
                accumulator
                    .codex_compaction_sizes
                    .note_counted_request(context_tokens);
            }
        }
        if admitted.is_some() && accumulator.context_curve_enabled {
            match (last_usage, usage_event_identity) {
                (Some(last_usage), Some(_)) if last_usage.input_tokens > 0 => {
                    accumulator
                        .codex_context_curve_candidates
                        .push(ContextCurveCandidatePoint {
                            observed_at: timestamp.clone(),
                            // Codex input_tokens already includes cached input.
                            effective_input_tokens: last_usage.input_tokens,
                            model: model.or_else(|| accumulator.latest_model.clone()),
                            context_window_tokens: codex_model_context_window(value),
                        });
                }
                _ => accumulator.codex_context_curve_exact_supported = false,
            }
        }
    }
    if string_eq_at(value, &["type"], "response_item") {
        let payload_type = string_at(value, &["payload", "type"]);
        if matches!(
            payload_type.as_deref(),
            Some("function_call" | "custom_tool_call")
        ) {
            if let Some(name) = string_at(value, &["payload", "name"]) {
                let is_function_call = payload_type.as_deref() == Some("function_call");
                let call_id = is_function_call
                    .then(|| string_at(value, &["payload", "call_id"]))
                    .flatten();
                let mcp_tool = is_function_call
                    .then(|| codex_namespaced_mcp_tool(value, &name))
                    .flatten();
                if call_id
                    .as_ref()
                    .is_some_and(|call_id| accumulator.activity_mcp_call_ids.contains_key(call_id))
                {
                    // Already counted as MCP by its completion event.
                } else if let Some((server, tool)) = mcp_tool {
                    accumulator.activity_mcp_calls += 1;
                    accumulator.note_activity_mcp_tool(&server, &tool);
                    if let Some(call_id) = call_id {
                        accumulator.activity_mcp_call_ids.insert(call_id, false);
                    }
                } else {
                    accumulator.note_activity_tool(&name);
                    if let Some(call_id) = call_id {
                        accumulator
                            .activity_call_tools
                            .insert(ActivityCallId { id: call_id }, ActivityCallTool { name });
                    }
                }
            }
            if let Some(material) = string_at(value, &["payload", "arguments"])
                .or_else(|| string_at(value, &["payload", "input"]))
            {
                accumulator.note_activity_tools(&material);
                accumulator.note_activity_skills(&material);
            }
        }
        if payload_type.as_deref() == Some("function_call_output") {
            if let Some(call_id) = string_at(value, &["payload", "call_id"]) {
                accumulator.activity_call_tools.remove(call_id.as_str());
                accumulator.activity_mcp_call_ids.remove(&call_id);
            }
        }
    }
    if matches!(
        string_at(value, &["type"]).as_deref(),
        Some("event_msg" | "response_item")
    ) {
        match string_at(value, &["payload", "type"]).as_deref() {
            Some("patch_apply_end") => {
                accumulator.activity_patch_operations += 1;
                if let Some(changes) =
                    raw_value_at(value, &["payload", "changes"]).and_then(Value::as_object)
                {
                    for (path, change) in changes {
                        accumulator
                            .activity_changed_file_hashes
                            .insert(sha256_hex(&["ottto-activity-changed-file:v1", path]));
                        if let Some(diff) = change.get("unified_diff").and_then(Value::as_str) {
                            for line in diff.lines() {
                                if line.starts_with('+') && !line.starts_with("+++") {
                                    accumulator.activity_lines_added += 1;
                                } else if line.starts_with('-') && !line.starts_with("---") {
                                    accumulator.activity_lines_deleted += 1;
                                }
                            }
                        }
                    }
                }
            }
            Some("web_search_end") => accumulator.activity_web_searches += 1,
            Some("mcp_tool_call_end") => {
                let call_id = string_at(value, &["payload", "call_id"]);
                let prior = call_id
                    .as_ref()
                    .and_then(|call_id| accumulator.activity_mcp_call_ids.get(call_id).copied());
                // `Some(true)`: a repeated completion event for a counted call.
                if prior != Some(true) {
                    if let Some((capability_id, raw_origin)) = codex_tool_surface_capability(value)
                    {
                        accumulator.note_capability_call(
                            timestamp.as_deref(),
                            capability_id,
                            raw_origin,
                        );
                    }
                    if let Some(call_id) = &call_id {
                        accumulator
                            .activity_mcp_call_ids
                            .insert(call_id.clone(), true);
                    }
                }
                // `Some(false)`: the namespaced function_call already counted it.
                if prior.is_none() {
                    if let Some(call_id) = &call_id {
                        accumulator.reclassify_activity_call_as_mcp(call_id);
                    }
                    accumulator.activity_mcp_calls += 1;
                    let server = string_at(value, &["payload", "app_name"])
                        .or_else(|| string_at(value, &["payload", "invocation", "server"]));
                    let tool = string_at(value, &["payload", "action_name"])
                        .or_else(|| string_at(value, &["payload", "invocation", "tool"]));
                    if let (Some(server), Some(tool)) = (server, tool) {
                        accumulator.note_activity_mcp_tool(&server, &tool);
                    }
                }
            }
            Some("sub_agent_activity") if string_eq_at(value, &["payload", "kind"], "started") => {
                accumulator.activity_subagent_spawns += 1;
            }
            _ => {}
        }
    }
    // Per-turn latency from the rollout `task_complete` event. Codex emits
    // `duration_ms` + `time_to_first_token_ms` only here (never over OTLP), so
    // accumulate them per session for the session-level latency average.
    if string_eq_at(value, &["payload", "type"], "task_complete") {
        if let Some(duration_ms) = u64_at(value, &["payload", "duration_ms"]) {
            accumulator.latency_duration_ms_sum = accumulator
                .latency_duration_ms_sum
                .saturating_add(duration_ms);
            accumulator.latency_duration_ms_count += 1;
            accumulator.latency_duration_ms_max =
                accumulator.latency_duration_ms_max.max(duration_ms);
        }
        if let Some(ttft_ms) = u64_at(value, &["payload", "time_to_first_token_ms"]) {
            accumulator.latency_ttft_ms_sum =
                accumulator.latency_ttft_ms_sum.saturating_add(ttft_ms);
            accumulator.latency_ttft_ms_count += 1;
            accumulator.latency_ttft_ms_max = accumulator.latency_ttft_ms_max.max(ttft_ms);
        }
    }
}
