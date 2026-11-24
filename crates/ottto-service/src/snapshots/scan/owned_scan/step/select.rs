//! Admit and start the one candidate dequeued by the page driver.
//! Selection and parser construction share the same opened descriptor and
//! the source-change evidence collected from it.

use super::*;

impl OwnedSourceScan {
    #[inline(never)]
    pub(super) fn select_and_start(
        &mut self,
        mut candidate: CandidateFile,
        launch_lookup: Option<&crate::launch_events::LaunchEventInventory>,
        active_file: &mut Option<Box<OwnedActiveFile>>,
        codex_cursor_lease: &mut Option<sampled_scan::codex_cursor::CursorLease>,
    ) {
        #[cfg(test)]
        twin_diagnostics::event(&candidate.path, || "candidate dequeued".into());
        // Pulled/forced candidates obey the same walk's growth fence.
        if self.index.traversal.as_ref().is_some_and(|walk| {
            walk.residue
                .growth_retries
                .get(&local_index_key(&candidate.path))
                == Some(&true)
        }) {
            return;
        }
        // Reject budget debt before opening/constructing any body parser.
        // Requeue the original census membership; absence/completion stays owed.
        if self.index.context_only_read(&candidate)
            && !self.context_read_budget.admit(
                self.source,
                &mut self.index,
                &candidate,
                &self.snapshots,
            )
        {
            self.context_read_budget.defer(candidate);
            return;
        }
        if let Some(context) = self
            .sampling
            .as_ref()
            .filter(|_| self.source == SnapshotSource::Codex)
        {
            if context
                .cache
                .cursor_job_owns(&local_index_key(&candidate.path))
            {
                // The paused or active cursor job owns this file (a group
                // job owns every member); it stays pending (holding the
                // census) until that job's attempt ends (§d.1.2 c).
                sampled_scan::codex_cursor::requeue(
                    &mut self.index,
                    &self.selected_flags,
                    &candidate,
                );
                return;
            }
        }
        let preflight_source_file_fingerprint =
            claude_authority_preflight_fingerprint(&self.index, &candidate);
        if let Some(events) = launch_lookup {
            let workers = launch_workers_for_candidate(
                self.source,
                &candidate,
                self.codex_join_inventory.as_ref(),
            );
            match events.prepare_step(&workers) {
                Ok(false) => {
                    self.identified_candidates.push_front(candidate);
                    return;
                }
                Err(()) => {
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    return;
                }
                Ok(true) => {}
            }
        }
        // Keep the prepass physical identity intact while lookup yields. Only
        // replace it with sidecar inputs immediately before the second open.
        prepare_owned_scan_candidate(
            self.source,
            &mut candidate,
            &self.codex_title_metadata,
            &self.claude_title_metadata,
            self.claude_effort_support_dir.as_deref(),
        );
        let unchanged = if self.source == SnapshotSource::Codex {
            let mut side_moved = false;
            let decision = self.index.codex_unchanged_decision(
                &mut candidate,
                &self.codex_title_metadata,
                self.audit_now,
                true,
                &mut side_moved,
            );
            if let Some(context) = self.sampling.as_mut() {
                context.codex_side_only_reselect += usize::from(side_moved);
            }
            match decision {
                Ok(input) => input,
                Err(_) => {
                    sampled_scan::codex_cursor::requeue(
                        &mut self.index,
                        &self.selected_flags,
                        &candidate,
                    );
                    return;
                }
            }
        } else {
            None
        };
        let logical_decision = unchanged
            .as_ref()
            .map(|(_, decision, reason)| (*decision, *reason));
        let acquired = match unchanged {
            Some((file, _, _)) => Some((candidate, file)),
            None => open_and_identify_scan_candidate_with_rescue_at(
                self.source,
                candidate,
                &mut self.census,
                CandidateWindow {
                    census_unix_seconds: self.census_unix_seconds,
                    backfill_window_days: self.backfill_window_days,
                    retention: discovery_retention!(
                        self.index,
                        &self.resource_probe.discovery_growth
                    ),
                    growth: sampled_audit::growth_active(&self.index)
                        .then_some(&self.index.v2().growth_retention),
                },
                self.sampling.as_ref().map(|context| context.cache.as_ref()),
            ),
        };
        let Some((mut candidate, opened_file)) = acquired else {
            return;
        };
        if preflight_source_file_fingerprint
            .as_ref()
            .is_some_and(|fingerprint| fingerprint != &candidate.source_file_fingerprint)
        {
            // A quarantined candidate changed after the family prepass. Do not
            // parse a mixed family or refresh its retry record; keep this
            // generation non-terminal and retry the new exact object together.
            disappearance_diagnostics::increment(
                &mut self.census.disappeared_file_count,
                self.source,
                disappearance_diagnostics::Cause::PreflightFingerprintChanged,
            );
            return;
        }
        // The preflight fences physical/sidecar identity. Local launcher facts
        // are semantic context and must not contaminate that two-open witness.
        if let Some(events) = launch_lookup.filter(|_| logical_decision.is_none()) {
            let workers = launch_workers_for_candidate(
                self.source,
                &candidate,
                self.codex_join_inventory.as_ref(),
            );
            if let Some(witness) = events.witness(&workers) {
                candidate.source_file_fingerprint = sha256_hex(&[
                    "launcher_worker_context:v1",
                    &candidate.source_file_fingerprint,
                    &witness,
                ]);
            }
        }
        // Constructor preflight has only physical identities. Reconcile its
        // family retry decision once launcher context is prepared, while keeping
        // the two-open equality check above physical. Every family member must
        // match the retained revision before withdrawing a forced retry.
        if self.source == SnapshotSource::ClaudeCode {
            if let Some(events) = launch_lookup {
                if let Some((root, _)) = claude_index_path_family_member(&candidate.path) {
                    if self.forced_claude_family_reparses.contains(&root)
                        && claude_held_family_matches_launch_context(
                            &self.index,
                            &root,
                            &candidate,
                            &self.identified_candidates,
                            events,
                        )
                    {
                        self.forced_claude_family_reparses.remove(&root);
                    }
                }
            }
        }
        if self
            .index
            .decode_holds_file(&local_index_key(&candidate.path))
        {
            self.index.mark_bounded_sweep_unsettled();
            return;
        }
        let mut source_change = None;
        let (mut decision, mut parse_reason) = match self
            .claude_twin_schedule
            .forced(&self.forced_claude_family_reparses, &candidate.path)
        {
            // A twin-only forced member that owes only adoption keeps that
            // reason, so the history gate can hold the whole twin group.
            Some(true)
                if self
                    .index
                    .candidate_decision_with_reason_at(&candidate, self.audit_now)
                    == (
                        CandidateDecision::Parse,
                        Some(CandidateParseReason::BodyWitnessAdoption),
                    ) =>
            {
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::BodyWitnessAdoption),
                )
            }
            Some(_) => (
                CandidateDecision::Parse,
                Some(CandidateParseReason::ForcedFamily),
            ),
            // Use the same audit clock as slot preparation.
            None => self.index.candidate_decision_in_window(
                &candidate,
                self.audit_now,
                &mut source_change,
            ),
        };
        if let Some((logical, reason)) = logical_decision {
            decision = logical;
            parse_reason = reason;
        }
        let (mut decision, history_held) =
            self.apply_history_upgrade_gate(&candidate, &opened_file, parse_reason, decision);
        // A file whose Tail failed alone is selected by its set-aside
        // marker before an ordinary Skip, even with equal stamps, and
        // re-reads from its committed head.
        #[cfg(unix)]
        if decision == CandidateDecision::Skip
            && matches!(state_v2::tail_route_path(&self.index), Ok(Some(_)))
            && tail_source::load::set_aside(&self.index, &local_index_key(&candidate.path))
        {
            decision = CandidateDecision::Parse;
        }
        if self.source == SnapshotSource::Codex
            && (sources::codex::counting::version::unchanged_legacy(&self.index, &candidate.path)
                || sources::codex::counting::version::legacy_head_missing(
                    &self.index,
                    &local_index_key(&candidate.path),
                ))
        {
            decision = CandidateDecision::Skip;
            parse_reason = None;
        }
        let stale_input_held = self.index.stale_refusal_holds_unchanged_input(&candidate);
        if stale_input_held {
            decision = CandidateDecision::Skip;
            parse_reason = None;
        }
        #[cfg(test)]
        twin_diagnostics::event(&candidate.path, || {
            format!(
            "decision={decision:?} reason={parse_reason:?} history_held={history_held} stale_input_held={stale_input_held}"
        )
        });
        if self.source == SnapshotSource::ClaudeCode && decision == CandidateDecision::Parse {
            if let Some(reason) = parse_reason {
                let count = &mut self.census.parse_reasons[reason as usize];
                *count = count.saturating_add(1);
            }
        }
        self.index.note_reason_reoffer_cooldown_candidate(
            &candidate,
            decision == CandidateDecision::Skip && parse_reason.is_none(),
        );
        if self.source == SnapshotSource::Codex {
            self.census
                .note_codex_selection(decision, parse_reason, None);
        }
        match decision {
            CandidateDecision::Skip => {
                page_selection(self.source.api_slug(), PageSelection::Skipped, 1);
                if let Some(loss) = self.index.terminal_jsonl_loss(&candidate) {
                    self.census.add_terminal_jsonl_loss(loss);
                }
                return;
            }
            CandidateDecision::Migrate => {
                self.index.migrate(candidate);
                return;
            }
            CandidateDecision::ReconcileLegacy | CandidateDecision::Parse => {}
        }
        if !self.history_upgrade.admit_resident_unit(
            &candidate,
            &mut self.identified_candidates,
            &self.forced_claude_family_reparses,
        ) {
            self.identified_candidates.push_front(candidate);
            self.history_upgrade.defer_resident(
                self.source,
                &mut self.index,
                &self.selected_flags,
                &mut self.identified_candidates,
            );
            return;
        }
        self.pull_claude_copy_holders(&candidate, history_held);
        #[cfg(test)]
        sampled_scan::test_hooks::after_selection(&mut self.index, parse_reason);
        if self.skip_codex_parse(&candidate, &opened_file, decision, codex_cursor_lease) {
            return;
        }
        self.scanned_file_count += 1;
        let previous_snapshot_fingerprint = self.index.last_snapshot_fingerprint(&candidate);
        let previous_upload_body_witness = self.index.last_upload_body_witness(&candidate);
        let projection_adoption_required = self
            .index
            .effective_upload_body_witness_revision_requires_adoption(&local_index_key(
                &candidate.path,
            ));
        let source_file_fingerprint = candidate.source_file_fingerprint.clone();
        let mut parser = match sampled_scan::new_source_parser(
            opened_file,
            &candidate,
            &self.index,
            sampled_scan::ParserOptions {
                source: self.source,
                metadata: &self.codex_title_metadata,
                identity_capture: self.claude_request_identity_capture,
                cache: self.sampling.as_ref().map(|c| &c.cache),
            },
        ) {
            Ok(parser) => parser,

            Err(error) => {
                if sampled_scan::codex_cursor::requeue_refused(
                    self.source,
                    &error,
                    &mut self.index,
                    &self.selected_flags,
                    &candidate,
                ) {
                    return;
                }
                if self.source == SnapshotSource::ClaudeCode {
                    claude_request_census::invalidate_claude_request_census(
                        &mut self.index,
                        &candidate.path,
                    );
                }
                self.census
                    .record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                return;
            }
        };

        let mut resident_loaded_bytes = 0;
        let mut file_sampling = None;
        let mut retained_offset = None;
        let mut tail_restore = "bypass";
        // Counted once the page actually reads the file: a fence
        // or deferral below does not inflate the read diagnostics.
        let mut planned_mode = None;
        if let Some(context) = self
            .sampling
            .as_mut()
            .filter(|_| !parser.reader.reader.is_compressed())
        {
            let key = local_index_key(&candidate.path);
            // Every source's continuation is its committed Tail. A route
            // that cannot be read now holds the file for its next
            // selection.
            #[cfg(unix)]
            let tail_route = match state_v2::tail_route_path(&self.index) {
                Ok(route) => route,
                Err(_) => {
                    #[cfg(test)]
                    twin_diagnostics::event(&candidate.path, || {
                        "defer pre-acquisition tail_route_error residue=true".into()
                    });
                    tail_source::counters::bump(self.source, "tail_db_loads", "held");
                    self.residue_index_keys.insert(key.clone());
                    return;
                }
            };
            // No database route (v1, a paused import, no support dir): its
            // growth reads Full.
            #[cfg(unix)]
            if tail_route.is_none() && self.index.files.contains_key(&key) {
                tail_source::counters::bump(self.source, "tail_bootstrap_full", "unrouted");
            }
            #[cfg(not(unix))]
            let tail_route: Option<PathBuf> = None;
            // On a Tail route the held-new custody is durable: the
            // withheld read's census record, and its committed head.
            let e2_held_new_file = self.source == SnapshotSource::ClaudeCode
                && tail_route.is_some()
                && tail_source::load::held_new(&self.index, &key);
            context.admission.attempts = context.admission.attempts.saturating_add(1);
            let owning_header_is_current = self.source != SnapshotSource::Codex
                || self.codex_join_inventory.as_ref().is_some_and(|inventory| {
                    inventory.complete
                        && inventory
                            .headers
                            .iter()
                            .any(|header| header.candidate.path == candidate.path)
                });
            context
                .admission
                .owning_header_current
                .observe(owning_header_is_current);
            context
                .admission
                .state_census_complete
                .observe(self.state_census_complete);
            context
                .admission
                .sidecar_census_complete
                .observe(self.sidecar_census_complete);
            // Claude's retained reduction is captured before metadata is
            // applied in finish. Its exact per-session dependencies still
            // fence reuse; unrelated inventory coverage cannot force a Full
            // on growth. Coverage/identity/publication gates below remain
            // unchanged, and Codex still needs its closed-world sidecars.
            // Partial Desktop coverage permits continuing a known native
            // session, not admitting a new cold file to sampled acquisition.
            // Without an index entry or its own held-new certificate, keep
            // main's unsampled read and copy-refusal exemption.
            let scoped_claude_metadata = tail_route.is_some()
                && self.source == SnapshotSource::ClaudeCode
                && !self.sidecar_census_complete
                && (self.index.files.contains_key(&key) || e2_held_new_file);
            if owning_header_is_current
                && self.state_census_complete
                && (self.sidecar_census_complete || scoped_claude_metadata)
            {
                if scoped_claude_metadata {
                    crate::local_resource_diagnostics::claude_reread::desktop_scoped_acquisition();
                }
                let reduction_sidecar = sampled_scan::reduction_dependencies(
                    self.source,
                    &candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                );
                context
                    .admission
                    .reduction_dependencies_available
                    .observe(reduction_sidecar.is_some());
                if let Some(reduction_sidecar) = reduction_sidecar {
                    let debt = sampled_audit::debt_for_key(&self.index, &key, self.audit_now);
                    let protected_entry = self.index.files.get(&key);
                    context
                        .admission
                        .index_entry_present
                        .observe(protected_entry.is_some());
                    let protected =
                        protected_entry.is_some_and(ScanIndexEntry::codex_history_is_protected);
                    let forced_family = self
                        .claude_twin_schedule
                        .forced(&self.forced_claude_family_reparses, &candidate.path)
                        .is_some()
                        || claude_index_path_family_member(&candidate.path).is_some_and(
                            |(root, _)| {
                                self.index
                                    .claude_usage_authority_quarantine
                                    .contains_key(&root)
                            },
                        );
                    // Audit population/deadlines never gate ordinary
                    // restore. The legacy prefix/proof paths retain their
                    // own rules. A same-process `e2`-held read may
                    // reuse only its own certificate, without authority.
                    // On Claude's database route a forced member reads natively
                    // only for evidence stored state cannot supply.
                    let forced_native = forced_family
                        && (tail_route.is_none()
                            || claude_request_census::forced_member_needs_native(
                                &self.index,
                                &key,
                            ));
                    let forced_twin = forced_family
                        && !forced_native
                        && self
                            .index
                            .claude_request_census
                            .get(&key)
                            .is_some_and(|r| r.is_twin());
                    // A pulled twin must finish on its holder's page. Native
                    // acquisition avoids both cap pacing and unfunded completion.
                    let mut allow_sample = (self.index.files.contains_key(&key)
                        || e2_held_new_file)
                        && !protected
                        && !forced_native
                        && !(forced_twin
                            && (context.audit_slots == 0
                                || !self.index.can_stage_sampled_audit(&key)));
                    context
                        .admission
                        .audit_metadata_supported
                        .observe(context.audit_metadata_supported);
                    context.admission.protected_history.observe(protected);
                    context.admission.forced_family.observe(forced_family);

                    context.admission.audit_debt_present.observe(debt.is_some());
                    context
                        .admission
                        .audit_slot_available
                        .observe(context.audit_slots > 0);
                    let scope = context.file_scope(self.source, &candidate, &reduction_sidecar);
                    // On a Tail route a read loads the committed Tail.
                    #[cfg(unix)]
                    let tail_load = tail_route.as_deref().filter(|_| {
                        allow_sample
                            && tail_source::load::reuses_stored(
                                &self.index,
                                &key,
                                parse_reason,
                                self.index
                                    .files
                                    .get(&key)
                                    .is_some_and(|entry| candidate.size_bytes > entry.size_bytes),
                                e2_held_new_file,
                            )
                            && !parser.reader.reader.is_compressed()
                    });
                    #[cfg(unix)]
                    if tail_route.is_some()
                        && tail_load.is_none()
                        && parse_reason == Some(CandidateParseReason::NewFile)
                    {
                        tail_source::counters::bump(self.source, "tail_bootstrap_full", "new_file");
                    }
                    #[cfg(unix)]
                    let mut tail_proven_full = None;
                    #[cfg(unix)]
                    let (mut retained, debt) = match tail_load {
                        Some(route) => {
                            let (loaded, loaded_bytes) = tail_source::load_candidate(
                                self.source,
                                &self.index,
                                route,
                                &candidate,
                                &parser.accumulator,
                                self.claude_request_identity_capture,
                                parser.reader.reader.get_mut(),
                                &scope,
                            );
                            resident_loaded_bytes = loaded_bytes;
                            match loaded {
                                tail_source::load::Load::Reused(retained, base) => {
                                    tail_restore = "hit";
                                    if let Some(base) = base {
                                        parser.set_tail_base(base);
                                    }
                                    // A late-evidence re-fold from
                                    // stored state, counted by its reason.
                                    if let Some(reason) = parse_reason
                                        .filter(|reason| tail_source::load::late_evidence(*reason))
                                    {
                                        tail_source::counters::bump(
                                            self.source,
                                            "tail_refold",
                                            CANDIDATE_PARSE_REASON_NAMES[reason as usize],
                                        );
                                    }
                                    retained_offset = Some(retained.checkpoint.sealed_offset());
                                    (Some(retained), debt)
                                }
                                // A pulled twin falls back to this page's native read.
                                tail_source::load::Load::Held if forced_twin => {
                                    tail_restore = "miss";
                                    #[cfg(test)]
                                    twin_diagnostics::event(&candidate.path, || {
                                        "Held forced_twin=true native_fallback".into()
                                    });
                                    allow_sample = false;
                                    (None, debt)
                                }
                                // A newer build's head: untouched, held as residue.
                                tail_source::load::Load::Held => {
                                    #[cfg(test)]
                                    twin_diagnostics::event(&candidate.path, || {
                                        "defer pre-acquisition Held forced_twin=false residue=true"
                                            .into()
                                    });
                                    self.residue_index_keys.insert(key.clone());
                                    return;
                                }
                                tail_source::load::Load::Cold(proven) => {
                                    tail_restore = "miss";
                                    tail_proven_full = proven;
                                    (None, debt)
                                }
                            }
                        }
                        None if allow_sample && !parser.reader.reader.is_compressed() => {
                            // A read with no stored continuation: counted by why.
                            self.resource_probe.full_causes.restore_outcome.record(
                                sampled_scan::ram_miss_class(
                                    &self.index,
                                    &key,
                                    context.cache.quiet_registered(self.source),
                                ),
                            );
                            (None, debt)
                        }
                        None => (None, debt),
                    };
                    // The cap funds NEW obligations, never a global restore
                    // gate. Marked files Tail; quiet debt-free copies reuse.
                    if allow_sample
                        // Account-held reparses belong to withheld_reparse;
                        // central staging still bounds fresh audit markers.
                        && !self.index.claude_account_deferred_holds.contains_key(&key)
                        && context.audit_slots == 0
                        && self.index.files.contains_key(&key)
                        && !self.index
                            .files
                            .get(&key)
                            .is_some_and(ScanIndexEntry::has_unverified_source)
                        && !retained.as_ref().is_some_and(|old| {
                            old.checkpoint.audit_debt().is_none()
                                && old.checkpoint.sealed_offset() == candidate.size_bytes
                                && old.checkpoint.scope() == &scope
                                && old
                                    .checkpoint
                                    .stamp_matches(parser.reader.reader.get_ref())
                                    .unwrap_or(false)
                        })
                    {
                        if !context.cap_candidate(&key) {
                            #[cfg(test)]
                            twin_diagnostics::event(&candidate.path, || {
                                "defer pre-acquisition cap_retry cap_candidate=false slots=0".into()
                            });
                            sampled_audit::queue_cap_retry(&mut self.index, &candidate);
                            self.census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &candidate.path,
                            );
                            return;
                        }
                        allow_sample = false;
                    }
                    #[cfg(test)]
                    twin_diagnostics::event(&candidate.path, || {
                        format!(
                        "sampling forced_family={forced_family} forced_native={forced_native} forced_twin={forced_twin} allow={allow_sample} slots={} can_stage={}",
                        context.audit_slots, self.index.can_stage_sampled_audit(&key),
                    )
                    });
                    context.admission.sampling_allowed.observe(allow_sample);
                    // Only the cap turns sampling off after a kept hit.
                    if !allow_sample && retained.take().is_some() {
                        tail_restore = "hit_discarded_by_cap";
                    }
                    context.admission.prepare_started =
                        context.admission.prepare_started.saturating_add(1);
                    let census_base_bound = retained
                        .as_ref()
                        .zip(self.index.files.get(&key))
                        .is_some_and(|(old, entry)| {
                            old.checkpoint
                                .durable_certificate(candidate.fingerprint_birth_nanos)
                                .is_some_and(|cert| {
                                    cert.length == cert.sealed_offset
                                        && entry.size_bytes == cert.sealed_offset
                                        && entry.modified_unix_nanos.is_some_and(|nanos| {
                                            cert.modified
                                                == (
                                                    (nanos / 1_000_000_000) as i64,
                                                    (nanos % 1_000_000_000) as i64,
                                                )
                                        })
                                        && entry.opened_birth_nanos == cert.birth_nanos
                                        && self.index.claude_request_census.get(&key).is_some_and(
                                            |record| {
                                                claude_request_census::fingerprint_matches(
                                                    record,
                                                    &entry.source_file_fingerprint,
                                                )
                                            },
                                        )
                                })
                        });
                    let mode = match parser.prepare_acquisition(
                        retained,
                        &scope,
                        debt,
                        sampled_scan::now_seconds(),
                    ) {
                        Ok(mode) => mode,
                        Err(_) => {
                            context.admission.prepare_failed =
                                context.admission.prepare_failed.saturating_add(1);
                            if self.source == SnapshotSource::ClaudeCode {
                                claude_request_census::invalidate_claude_request_census(
                                    &mut self.index,
                                    &candidate.path,
                                );
                            }
                            self.census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &candidate.path,
                            );
                            return;
                        }
                    };
                    #[cfg(unix)]
                    let mode = match (tail_proven_full, parser.reader.acquisition.as_mut()) {
                        (Some(reason), Some(plan)) => plan.name_proven_full(reason),
                        _ => mode,
                    };
                    if !sampled_audit::growth_read_admitted(&mut self.index, &candidate, mode) {
                        #[cfg(test)]
                        twin_diagnostics::event(&candidate.path, || {
                            format!(
                                "defer pre-acquisition growth_read_admitted=false mode={mode:?}"
                            )
                        });
                        sampled_audit::defer_growth_read(
                            &mut self.index,
                            &mut self.census,
                            &candidate,
                        );
                        return;
                    }
                    // Restore does not restore/extend an exact-prefix pricing receipt.
                    // Any new priority contribution below forces a real full replay.
                    if self.source == SnapshotSource::Codex {
                        sampled_scan::configure_tier_replay(&mut parser, &candidate, &self.index);
                    }
                    let audit_due = parser
                        .reader
                        .acquisition
                        .as_ref()
                        .and_then(|plan| plan.metrics().audit_due)
                        .or_else(|| {
                            // A grown Full without an older obligation
                            // still owes a quiet audit. Prepare its bound
                            // now, never from the discarded checkpoint.
                            (self.source == SnapshotSource::ClaudeCode
                                && allow_sample
                                && matches!(mode, crate::transcript_acquisition::ReadMode::Full(_)))
                            .then(|| {
                                sampled_scan::now_seconds().saturating_add(
                                    crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
                                )
                            })
                        });
                    planned_mode = Some((mode, audit_due));
                    file_sampling = Some(sampled_scan::Active {
                        key,
                        scope,
                        mode,
                        audit_due,
                        tier_prefix_replay: false,
                        census_base_bound,
                        resident_loaded_bytes,
                    });
                }
            } else if self.source == SnapshotSource::Codex
                && owning_header_is_current
                && crate::heap_layout_bound::layout_supported()
                && parser
                    .reader
                    .reader
                    .get_ref()
                    .metadata()
                    .is_ok_and(|metadata| {
                        metadata.len() > sampled_scan::codex_cursor::Limits::current().singleton()
                    })
            {
                // The state or sidecar census is incomplete, so
                // main's trust rule refuses verification and retention,
                // yet main still reads and publishes this file. A file
                // larger than the singleton budget therefore pages as a
                // cursor-only job: a fresh `Full` acquisition with no
                // retained state and no debt input, used only for the
                // job's object certificate. Its completion keeps no
                // checkpoint and no copy, so it is never source-verified.
                let reduction_sidecar = sampled_scan::reduction_dependencies(
                    self.source,
                    &candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                );
                context
                    .admission
                    .reduction_dependencies_available
                    .observe(reduction_sidecar.is_some());
                if let Some(reduction_sidecar) = reduction_sidecar {
                    let scope = context.file_scope(self.source, &candidate, &reduction_sidecar);
                    context.admission.prepare_started =
                        context.admission.prepare_started.saturating_add(1);
                    let mode = match parser.prepare_acquisition(
                        None,
                        &scope,
                        None,
                        sampled_scan::now_seconds(),
                    ) {
                        Ok(mode) => mode,
                        Err(_) => {
                            context.admission.prepare_failed =
                                context.admission.prepare_failed.saturating_add(1);
                            self.census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &candidate.path,
                            );
                            return;
                        }
                    };
                    sampled_scan::configure_tier_replay(&mut parser, &candidate, &self.index);
                    planned_mode = Some((mode, None));
                    file_sampling = Some(sampled_scan::Active {
                        key,
                        scope,
                        mode,
                        audit_due: None,
                        tier_prefix_replay: false,
                        census_base_bound: false,
                        resident_loaded_bytes,
                    });
                }
            }
        }
        if self.source == SnapshotSource::ClaudeCode
            && file_sampling.is_none()
            && !sampled_audit::growth_read_admitted(
                &mut self.index,
                &candidate,
                crate::transcript_acquisition::ReadMode::Full(
                    crate::transcript_acquisition::FullReason::StateMissing,
                ),
            )
        {
            #[cfg(test)]
            twin_diagnostics::event(&candidate.path, || {
                "defer pre-acquisition growth_read_admitted=false unsampled Full(StateMissing)"
                    .into()
            });
            sampled_audit::defer_growth_read(&mut self.index, &mut self.census, &candidate);
            return;
        }
        if planned_mode.is_none_or(|(mode, _)| {
            matches!(mode, crate::transcript_acquisition::ReadMode::Full(_))
        }) && tail_source::seed_full_job_template(
            &self.index,
            &candidate,
            &[],
            &mut parser.accumulator,
        )
        .is_err()
        {
            tail_source::counters::bump(self.source, "tail_db_loads", "held");
            self.residue_index_keys
                .insert(local_index_key(&candidate.path));
            return;
        }
        // Every physical Full/Tail acquisition stops at its opening extent,
        // including native/forced reads and cursor-only preparation.
        if let Some(plan) = parser.reader.acquisition.as_ref().filter(|plan| {
            matches!(
                plan.mode(),
                crate::transcript_acquisition::ReadMode::Full(_)
                    | crate::transcript_acquisition::ReadMode::Tail
            )
        }) {
            parser
                .reader
                .set_extent_limit(plan.frozen_length() - plan.start_offset());
        }
        self.index.note_change_reason_selected(
            self.source,
            &candidate,
            parse_reason,
            source_change,
        );
        crate::local_resource_diagnostics::change_reason::read_context(
            &local_index_key(&candidate.path),
            tail_restore,
            retained_offset
                .zip(
                    self.index
                        .files
                        .get(&local_index_key(&candidate.path))
                        .map(|entry| entry.size_bytes),
                )
                .zip(
                    parser
                        .reader
                        .acquisition
                        .as_ref()
                        .map(|plan| plan.frozen_length()),
                )
                .map(|((seal, indexed), opening)| (seal, indexed, opening)),
        );
        // Frozen here, before this read can change the index entry.
        let prior_stamp = crate::local_resource_diagnostics::claude_reread::PriorStamp::classify(
            (candidate.size_bytes, candidate.modified_unix_nanos),
            self.index
                .files
                .get(&local_index_key(&candidate.path))
                .filter(|_| parse_reason != Some(CandidateParseReason::NewFile))
                .map(|entry| (entry.size_bytes, entry.modified_unix_nanos)),
        );
        let mut active = Box::new(OwnedActiveFile {
            first_read: crate::local_resource_diagnostics::FirstRead::begin(
                self.source,
                candidate.size_bytes,
                !self
                    .index
                    .files
                    .contains_key(&local_index_key(&candidate.path)),
            ),
            sampling: file_sampling,
            candidate,
            decision,
            parse_reason,
            prior_stamp: Some(prior_stamp),
            previous_snapshot_fingerprint,
            previous_upload_body_witness,
            projection_adoption_required,
            source_file_fingerprint,
            parser,
            aliases: Vec::new(),
            applied_receipts: BTreeMap::new(),
            cursor: None,
            charged_bytes: 0,
            hold_offset: None,
            group: None,
        });
        if !self.admit_paced_codex_read(&mut active, retained_offset, codex_cursor_lease) {
            return;
        }
        if let Some(context) = self.sampling.as_mut() {
            if let Some((mode, audit_due)) = planned_mode {
                context.record_mode(mode, audit_due);
                context.same_size_touch_proven +=
                    usize::from(active.parser.reader.acquisition.as_ref().is_some_and(
                        crate::transcript_acquisition::ReadPlan::same_size_touch_proven,
                    ));
                self.resource_probe
                    .rearm_full_selected(&local_index_key(&active.candidate.path), mode);
                self.resource_probe.full_parse_reason(
                    mode,
                    active.parse_reason,
                    active.prior_stamp,
                    1,
                    0,
                );
            }
        }
        if let Some(delivery) = self.line_delivery.as_mut() {
            delivery.arm();
        }
        *active_file = Some(active);
    }

    /// Pull the live copy holders of a dequeued Claude twin or main into
    /// the queue. History-held mains pull nothing.
    #[inline(never)]
    fn pull_claude_copy_holders(&mut self, candidate: &CandidateFile, history_held: bool) {
        // After ordinary identity, decision and admission (no seed
        // pre-open), content twins and mains pull every overlapping live
        // member of the opposite kind. Pulled candidates pass the ordinary
        // history and resident gates; the emission fence withholds incomplete
        // sessions. History-held mains pull nothing.
        let seed = local_index_key(&candidate.path);
        let record = (self.source == SnapshotSource::ClaudeCode)
            .then(|| self.index.claude_request_census.get(&seed))
            .flatten();
        let walk = std::time::Instant::now();
        let pulls: Vec<String> = match record {
            Some(record) if record.is_twin() => {
                let mains = self
                    .index
                    .claude_request_census
                    .records()
                    .filter(|(key, main)| {
                        !main.is_twin()
                            && claude_request_census::held_candidates(main, record.request_hashes())
                                .next()
                                .is_some()
                            && Path::new(key).is_file()
                    });
                mains.map(|(key, _)| key.clone()).collect()
            }
            // Holder choice for copied history does not define all of a
            // session's contributors.
            Some(record)
                if !history_held
                    && claude_request_census::held_candidates(
                        record,
                        self.claude_twin_schedule
                            .twin_hashes(&self.index.claude_request_census),
                    )
                    .next()
                    .is_some() =>
            {
                let twins = self
                    .index
                    .claude_request_census
                    .records()
                    .filter(|(key, twin)| {
                        twin.is_twin()
                            && claude_request_census::held_candidates(twin, record.request_hashes())
                                .next()
                                .is_some()
                            && Path::new(key).is_file()
                    });
                twins.map(|(key, _)| key.clone()).collect()
            }
            _ => Vec::new(),
        };
        claude_request_money::e2::diag("copy_holder_walk_ms", walk.elapsed().as_millis() as u64);
        for path in pulls.into_iter().map(PathBuf::from) {
            let key = local_index_key(&path);
            #[cfg(test)]
            twin_diagnostics::event(&path, || {
                format!(
                    "pull requested already_scheduled={} fold_present={} queued={}",
                    self.claude_twin_schedule.root_homes.contains(&key),
                    self.snapshots.iter().any(|item| item
                        .claude_money
                        .as_deref()
                        .and_then(claude_request_money::e2::FileFold::location_key)
                        == Some(claude_money_birth_store::location_key(&key))),
                    self.identified_candidates
                        .iter()
                        .any(|queued| queued.path == path),
                )
            });
            if self.claude_twin_schedule.root_homes.contains(&key)
                || self.snapshots.iter().any(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(claude_request_money::e2::FileFold::location_key)
                        == Some(claude_money_birth_store::location_key(&key))
                })
            {
                continue;
            }
            self.claude_twin_schedule.root_homes.insert(key);
            claude_request_money::e2::diag("copy_holder_pulled", 1);
            if self
                .identified_candidates
                .iter()
                .any(|queued| queued.path == path)
            {
                continue;
            }
            let mut discovery = CandidateDiscovery::new(
                &mut self.index,
                Some(&self.resource_probe.discovery_growth),
            );
            if let Some(holder) = scan::owned_scan::forced_index_candidate(
                self.source,
                &self.roots,
                (path, false),
                &mut self.census,
                self.census_unix_seconds,
                self.backfill_window_days,
                &mut discovery,
            ) {
                #[cfg(test)]
                twin_diagnostics::event(&holder.path, || "pull enqueued".into());
                self.identified_candidates.push_back(holder);
            }
        }
    }

    /// Codex before parse: a memo hit, a parked file or this page's pacing
    /// can end this selection step without building a parser. `true`
    /// means selection returns for this page.
    #[inline(never)]
    fn skip_codex_parse(
        &mut self,
        candidate: &CandidateFile,
        opened_file: &std::fs::File,
        decision: CandidateDecision,
        codex_cursor_lease: &Option<sampled_scan::codex_cursor::CursorLease>,
    ) -> bool {
        if let Some(context) = self.sampling.as_ref().filter(|_| {
            self.source == SnapshotSource::Codex && !codex_archive_path(&candidate.path)
        }) {
            let wake_stamp = sampled_scan::codex_cursor::OpenStamp::capture(opened_file)
                .ok()
                .map(|stamp| context.cache.retained_stamp(&candidate.path, stamp));
            let key = local_index_key(&candidate.path);
            // Keyed per namespace: the digest carries the upload
            // context, so concurrent namespaces must not evict each other.
            let memo_key = sampled_scan::codex_cursor::memo_key(&context.namespace, &key);
            use crate::local_resource_diagnostics::codex_memo_lifecycle;
            if let Some(entry) = context.cache.memo_lookup(&memo_key) {
                // The match re-reads two samples of the held file.
                self.codex_page
                    .charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                let sidecar_now = sampled_scan::codex_cursor::sidecar_fingerprint(
                    &self.codex_title_metadata,
                    &candidate.path,
                );
                let digest = sampled_scan::reduction_dependencies(
                    self.source,
                    candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                )
                .and_then(|dependencies| {
                    sampled_scan::codex_cursor::memo_digest(
                        &self.index,
                        candidate,
                        opened_file,
                        &dependencies,
                        &self.codex_title_metadata,
                        sampled_scan::codex_cursor::owner_members(
                            self.codex_join_inventory.as_ref(),
                            &candidate.path,
                        ),
                    )
                });
                let hit = digest.as_deref().and_then(|digest| {
                    entry.matches_stamp(
                        &candidate.path,
                        digest,
                        opened_file,
                        &sidecar_now,
                        wake_stamp.clone()?,
                    )
                });
                if let Some(stamp) = hit {
                    // An append cannot cure this hold and no wake
                    // dependency changed: disclose the same terminal
                    // debt again at zero transcript bytes.
                    codex_memo_lifecycle::add(
                        codex_memo_lifecycle::Event::HitEstimatedAvoidedParserBytes,
                        stamp.extent(),
                    );
                    context.cache.memo_hit(&memo_key, stamp);
                    let keep_previous = decision != CandidateDecision::ReconcileLegacy
                        && !self
                            .index
                            .effective_upload_body_witness_revision_requires_adoption(&key);
                    let previous = (
                        keep_previous
                            .then(|| self.index.last_snapshot_fingerprint(candidate))
                            .flatten(),
                        keep_previous
                            .then(|| self.index.last_upload_body_witness(candidate))
                            .flatten(),
                    );
                    sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                        entry.disclosure(),
                        candidate,
                        previous,
                        &mut self.index,
                        targets!(self),
                    );
                    // The fresh path's session count, replayed.
                    self.scanned_session_count += entry.disclosure().parsed_snapshot_count;
                    return true;
                }
                match digest.as_deref().and_then(|digest| {
                    entry.grew_past_exact(&candidate.path, digest, opened_file, &sidecar_now)
                }) {
                    Some(extent) => {
                        codex_memo_lifecycle::record(codex_memo_lifecycle::Event::MissExactStamp);
                        codex_memo_lifecycle::add(
                            codex_memo_lifecycle::Event::MissExactStampBytes,
                            extent,
                        );
                    }
                    None => codex_memo_lifecycle::record(codex_memo_lifecycle::Event::MissOther),
                }
                context.cache.memo_forget(&memo_key);
            }
            // A parked `JoinStateBound` file is not read again until it
            // is replaced, shrunk or edited, or its reduction dependencies
            // change; growth cannot cure it (§c.2, M-2).
            let parked = context.cache.cursor_parked_stamp(
                &key,
                wake_stamp.clone(),
                sampled_scan::reduction_dependencies(
                    self.source,
                    candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                )
                .as_deref(),
            );
            if let Some(disclosure) = parked {
                let keep_previous = decision != CandidateDecision::ReconcileLegacy
                    && !self
                        .index
                        .effective_upload_body_witness_revision_requires_adoption(&key);
                let previous = (
                    keep_previous
                        .then(|| self.index.last_snapshot_fingerprint(candidate))
                        .flatten(),
                    keep_previous
                        .then(|| self.index.last_upload_body_witness(candidate))
                        .flatten(),
                );
                sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                    &disclosure,
                    candidate,
                    previous,
                    &mut self.index,
                    targets!(self),
                );
                return true;
            }
            #[cfg(test)]
            CODEX_BEFORE_PARSE.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(&candidate.path);
                }
            });
            // Fresh-first page budget, decided before any stored state is
            // consumed: the optimistic read is the tail extent when a
            // continuation exists, the whole file otherwise. The
            // continuation is the committed head on its route, so an
            // append is sized from the head's sealed offset.
            let extent = opened_file.metadata().map_or(0, |metadata| metadata.len());
            let continued = tail_source::committed_sealed_offset(self.source, &self.index, &key);
            let expected = extent.saturating_sub(continued.unwrap_or(0));
            if self.index.context_only_read(candidate) {
                self.context_read_budget
                    .charge_cursor_ordinary(&mut self.codex_page);
            }
            match context.cache.cursor_plan_paced(
                &mut self.codex_page,
                sampled_scan::codex_cursor::Limits::current(),
                expected,
                codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                crate::heap_layout_bound::layout_supported(),
                &context.namespace,
                &key,
                sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                sampled_scan::codex_cursor::census_member(
                    &self.selected_flags,
                    [candidate.path.as_path()],
                ),
                Some(sampled_scan::codex_cursor::PaceProbe { file: opened_file }),
            ) {
                sampled_scan::codex_cursor::StartPlan::Defer => {
                    context.cache.cursor_note_deferred();
                    sampled_scan::codex_cursor::requeue(
                        &mut self.index,
                        &self.selected_flags,
                        candidate,
                    );
                    return true;
                }
                // Processed for this generation (K7 fence): not requeued,
                // so the census can complete; the next generation reads it.
                sampled_scan::codex_cursor::StartPlan::Fenced => return true,
                sampled_scan::codex_cursor::StartPlan::Singleton
                | sampled_scan::codex_cursor::StartPlan::Cursor
                | sampled_scan::codex_cursor::StartPlan::Unpaged => {}
            }
        }
        false
    }

    /// Codex cursor start or deferral for the built file. `true` means the
    /// file may become active: in its page, or as a cursor job with its
    /// lease stored.
    #[inline(never)]
    fn admit_paced_codex_read(
        &mut self,
        active: &mut OwnedActiveFile,
        retained_offset: Option<u64>,
        codex_cursor_lease: &mut Option<sampled_scan::codex_cursor::CursorLease>,
    ) -> bool {
        if let Some(context) = self.sampling.as_ref().filter(|_| {
            self.source == SnapshotSource::Codex && !codex_archive_path(&active.candidate.path)
        }) {
            let extent = active
                .parser
                .reader
                .reader
                .get_ref()
                .metadata()
                .map_or(0, |metadata| metadata.len());
            let expected = match active.sampling.as_ref().map(|acquisition| acquisition.mode) {
                Some(crate::transcript_acquisition::ReadMode::Unchanged) => 0,
                Some(crate::transcript_acquisition::ReadMode::Tail) => {
                    extent.saturating_sub(retained_offset.unwrap_or(0))
                }
                _ => extent,
            };

            let defer = match context.cache.cursor_plan_paced(
                &mut self.codex_page,
                sampled_scan::codex_cursor::Limits::current(),
                expected,
                codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                crate::heap_layout_bound::layout_supported(),
                &context.namespace,
                &local_index_key(&active.candidate.path),
                sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                sampled_scan::codex_cursor::census_member(
                    &self.selected_flags,
                    [active.candidate.path.as_path()],
                ),
                Some(sampled_scan::codex_cursor::PaceProbe {
                    file: active.parser.reader.reader.get_ref(),
                }),
            ) {
                sampled_scan::codex_cursor::StartPlan::Singleton => false,
                sampled_scan::codex_cursor::StartPlan::Unpaged => {
                    // Layout-unsupported build: the cursor is off as a
                    // whole and this file reads in its page, as before.
                    self.codex_page.disclose_disabled(&context.cache);
                    false
                }
                sampled_scan::codex_cursor::StartPlan::Cursor => {
                    let dependencies = sampled_scan::reduction_dependencies(
                        self.source,
                        &active.candidate,
                        &self.codex_title_metadata,
                        &self.claude_title_metadata,
                        self.claude_effort_support_dir.as_deref(),
                    );
                    let owner = self
                        .codex_join_inventory
                        .as_ref()
                        .and_then(|inventory| inventory.owner_for_path(&active.candidate.path))
                        .map(str::to_owned);
                    match context.cache.cursor_start(
                        active,
                        &context.namespace,
                        dependencies,
                        owner,
                        self.state_census_complete && self.sidecar_census_complete,
                        &self.index,
                    ) {
                        Ok(lease) => {
                            // The job's path holds the strict census until
                            // its attempt ends (accepted or debt).
                            sampled_scan::codex_cursor::requeue(
                                &mut self.index,
                                &self.selected_flags,
                                &active.candidate,
                            );
                            *codex_cursor_lease = Some(lease);
                            false
                        }
                        // The slot frees when its job ends: wait in turn.
                        Err(sampled_scan::codex_cursor::StartRefusal::Busy) => true,
                        // No acquisition even cursor-only (no current
                        // owning header or no reduction dependencies, where
                        // main holds the file too). Never requeued: the
                        // path is processed for this generation with a
                        // retryable cause, so discovery finishes and the
                        // bounded unhealthy retry starts the next one.
                        Err(sampled_scan::codex_cursor::StartRefusal::InputsUnavailable) => {
                            self.census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &active.candidate.path,
                            );
                            return false;
                        }
                        Err(sampled_scan::codex_cursor::StartRefusal::Unstartable) => {
                            // Never an unbounded in-page read of a file
                            // larger than the singleton budget.
                            self.census.record_unreadable_file(
                                UnreadableCause::OpenRead,
                                &active.candidate.path,
                            );
                            return false;
                        }
                    }
                }
                sampled_scan::codex_cursor::StartPlan::Defer => true,
                // Processed for this generation (K7 fence).
                sampled_scan::codex_cursor::StartPlan::Fenced => {
                    self.scanned_file_count = self.scanned_file_count.saturating_sub(1);
                    return false;
                }
            };
            if defer {
                // Only a full read reaches here (a tail was planned
                // before its retained state was consumed).
                context.cache.cursor_note_deferred();
                self.scanned_file_count = self.scanned_file_count.saturating_sub(1);
                sampled_scan::codex_cursor::requeue(
                    &mut self.index,
                    &self.selected_flags,
                    &active.candidate,
                );
                return false;
            }
        }
        true
    }

    /// The history-upgrade gate. Returns the decision, unchanged or `Skip`,
    /// and `history_held`: this gate held the file's history emission and
    /// left its decision at `Parse`.
    #[inline(never)]
    fn apply_history_upgrade_gate(
        &mut self,
        candidate: &CandidateFile,
        opened_file: &std::fs::File,
        parse_reason: Option<CandidateParseReason>,
        mut decision: CandidateDecision,
    ) -> (CandidateDecision, bool) {
        // History-upgrade gate, whatever selected the file:
        // unchanged Claude history that would carry a new body-witness
        // revision passes the list, the no-list birth hold, the family
        // skip, the stop latch and this page's budget (reserved once per
        // file). A held file that only owes the upgrade is skipped with
        // its old stamp, and so is one that also owes only its upload
        // context. A held file selected for another reason (re-arm,
        // family, audit, authority, a rebuilt or replayed index) still
        // parses for its local work, but none of its bodies
        // is emitted and its upload tuple stays (`veto_claude_history_emission`).
        // A new Claude file held only by this page's budget is skipped too.
        // A skipped Claude file held only by this page's budget is queued
        // again as a re-read for the next page of the walk. Codex and Pi
        // keep the adoption-only page budget.
        let mut history_held = false;
        if decision == CandidateDecision::Parse {
            let adoption_only = parse_reason == Some(CandidateParseReason::BodyWitnessAdoption)
                && (self
                    .index
                    .candidate_requires_only_body_witness_adoption(candidate, self.audit_now)
                    || (self.source == SnapshotSource::ClaudeCode
                        && claude_copy_prefix_reread::unchanged_requested(
                            &self.index,
                            candidate,
                            self.audit_now,
                        )));
            let history = if self.source == SnapshotSource::ClaudeCode {
                self.index.claude_history_upgrade_decision(
                    candidate,
                    opened_file
                        .metadata()
                        .and_then(|metadata| metadata.created())
                        .ok()
                        .and_then(unix_seconds),
                    &mut self.history_upgrade,
                )
            } else if adoption_only
                && !self.history_upgrade.reserve_admitting_first_file(
                    &local_index_key(&candidate.path),
                    candidate.size_bytes,
                )
            {
                self.history_upgrade.note_denied(
                    HistoryHold::Budget,
                    self.index.claude_reemission_exclusions.state(),
                );
                HistoryDecision::Held(HistoryHold::Budget)
            } else {
                HistoryDecision::NotOwed
            };
            if matches!(history, HistoryDecision::Held(HistoryHold::Budget)) {
                // Held for a later walk: this walk cannot settle it.
                if let Some(traversal) = self.index.traversal.as_mut() {
                    traversal.rewalk_owed = true;
                }
            }
            // A held, unchanged member owed only a proof correction is not
            // re-read every traversal either: its bodies would be vetoed,
            // and the correction waits for the gate (StateMissing).
            let correction_only = parse_reason == Some(CandidateParseReason::AuthorityQuarantine)
                && self.index.claude_authority_correction_only(candidate);
            // A new Claude file held only by this page's budget is not
            // read now: a vetoed read would save it unoffered. It waits
            // in the queue, keeping its census membership. A family root
            // (a `<root>/subagents` directory) still takes the held read:
            // its census record lets a fork read first drop its copy.
            let budget_held_new = self.source == SnapshotSource::ClaudeCode
                && parse_reason == Some(CandidateParseReason::NewFile)
                && history == HistoryDecision::Held(HistoryHold::Budget)
                && !candidate.path.with_extension("").join("subagents").is_dir();
            // A listed genuine change is never held (it is literal-only
            // denied), so a held correction-only member is unchanged.
            match history {
                HistoryDecision::Held(hold)
                    if adoption_only || correction_only || budget_held_new =>
                {
                    if self.source == SnapshotSource::ClaudeCode {
                        let carried = self
                            .index
                            .accepted_rebuild_incidence
                            .get(&local_index_key(&candidate.path))
                            .map_or(0, BTreeSet::len);
                        self.index.claude_history_emission.skipped_carried_entries = self
                            .index
                            .claude_history_emission
                            .skipped_carried_entries
                            .saturating_add(carried);
                        // A budget hold paces the upgrade page by page:
                        // the file goes back to the walk's queue as a
                        // re-read, so the next page of this walk continues
                        // the upgrade (the switch-on
                        // re-read). A re-read is not a census member:
                        // it never holds the census, and a walk
                        // that ends first drops it for the next walk to
                        // list again. Only once this page admitted
                        // history: a file that cannot fit an empty page
                        // waits for the next walk as before.
                        if hold == HistoryHold::Budget && self.history_upgrade.admitted_any() {
                            if let Some(traversal) = self.index.traversal.as_mut() {
                                traversal.pending_candidates.push_back(ScanTraversalPath {
                                    scan_root: candidate.scan_root.clone(),
                                    path: candidate.path.clone(),
                                    census_member: budget_held_new
                                        && self
                                            .selected_flags
                                            .get(&local_index_key(&candidate.path))
                                            .is_some_and(|&(member, _)| member),
                                    watcher_hint: false,
                                });
                            }
                        }
                    }
                    decision = CandidateDecision::Skip;
                }
                HistoryDecision::Held(hold) => {
                    history_held = true;
                    self.index
                        .gate_claude_history_candidate(candidate, Some(hold));
                }
                HistoryDecision::Owed => self.index.gate_claude_history_candidate(candidate, None),
                HistoryDecision::LiteralDenied => {
                    self.index.deny_claude_history_literal(candidate);
                }
                HistoryDecision::NotOwed => {}
            }
        }
        (decision, history_held)
    }
}
