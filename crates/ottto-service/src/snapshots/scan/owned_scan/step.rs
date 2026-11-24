//! The owned source scan's page step: one call reads the next page of the
//! selected files, applies it to the index and returns either the scan to
//! resume or the completed result.
//!
//! The driver checks entry conditions and runs Codex planning or active-file
//! work. When both fall through, it dequeues one candidate for selection and
//! start, or closes the page. Every post-entry pause reaches one exit.
#[cfg(test)]
use crate::snapshots::e2_pipeline_scan_fixture::twin_diagnostics;
use crate::snapshots::*;

// Codex disclosures update the same three scan fields. A macro, not a method:
// a method would borrow the whole scan while callers hold other fields.
macro_rules! targets {
    ($scan:ident) => {
        sampled_scan::codex_cursor::DisclosureTargets {
            census: &mut $scan.census,
            residue_index_keys: &mut $scan.residue_index_keys,
            pending_finalization: &mut $scan.pending_finalization,
        }
    };
}

mod codex_join;

impl OwnedSourceScan {
    pub(crate) fn step(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> OwnedSourceScanStep {
        self.step_inner(attribution_context)
            .expect("ordinary serial collection is available")
    }
    pub(crate) fn step_fallible(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        state_v2::before_collection(&self.index).map_err(|_| {
            crate::source_rotation::LocalRefusal("state_v2_maintenance_before_collection")
        })?;
        self.step_inner(attribution_context)
    }

    fn step_inner(
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let _acquire_window = state_v2::telemetry::acquire_window(&self.index);
        let mut result =
            crate::local_resource_diagnostics::jsonl::page(self.source.api_slug(), || {
                self.step_inner_page(attribution_context)
            });
        match &result {
            Ok(OwnedSourceScanStep::Pending(scan)) => state_v2::telemetry::acquired(&scan.index),
            Ok(OwnedSourceScanStep::Complete { index, .. }) => state_v2::telemetry::acquired(index),
            Err(_) => {}
        }
        let counts = diagnostics.finish();
        if let Ok(OwnedSourceScanStep::Pending(scan)) = &mut result {
            scan.resource_probe.page_events.merge(counts);
        }
        result
    }

    #[inline(never)]
    fn step_inner_page(
        mut self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        if !self.index.persistence_available() {
            return Err(crate::source_rotation::LocalRefusal(
                "scan_index_map_unavailable",
            ));
        }
        if self.walk_idle {
            // The walk gate held this pass: nothing is listed or read.
            let scan = SourceScanResult {
                walk_idle: true,
                backfill_window_days: self.backfill_window_days,
                backfill_file_limit: self.file_limit,
                census_window_end: self.census_window_end,
                ..SourceScanResult::empty(self.source)
            };
            return Ok(OwnedSourceScanStep::Complete {
                index: self.index,
                scan,
            });
        }

        // Prepare one demand batch through bounded native continuations. Group
        // owners come from the completed header census, never arbitrary names.
        if self.active_file.is_none()
            && self.codex_join_active.is_none()
            && (self.source != SnapshotSource::Codex || self.codex_join_prepared)
        {
            let launch_lookup = attribution_context
                .map(|context| context.launch_events())
                .or(self.launch_events.as_deref());
            if let Some(events) = launch_lookup {
                let first = self
                    .codex_join_groups
                    .front()
                    .map(|group| vec![group.owner.clone()])
                    .or_else(|| {
                        self.identified_candidates.front().map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        })
                    })
                    .unwrap_or_default();
                // A completed batch covers its remaining members. Looking at
                // a sliding window here would add one new worker after every
                // file and repeat the complete retained-store sweep per file.
                if !events.prepared(&first) {
                    let mut workers = BTreeSet::new();
                    for worker in self
                        .codex_join_groups
                        .iter()
                        .map(|group| group.owner.clone())
                        .chain(self.identified_candidates.iter().flat_map(|candidate| {
                            launch_workers_for_candidate(
                                self.source,
                                candidate,
                                self.codex_join_inventory.as_ref(),
                            )
                        }))
                        .take(crate::launch_events::MAX_DEMANDED_WORKERS)
                    {
                        if crate::launch_events::valid_worker(&worker) {
                            workers.insert(worker.to_ascii_lowercase());
                        }
                        if workers.len() == crate::launch_events::MAX_DEMANDED_WORKERS {
                            break;
                        }
                    }
                    let workers = workers.into_iter().collect::<Vec<_>>();
                    match events.prepare_step(&workers) {
                        Ok(false) => return Ok(OwnedSourceScanStep::Pending(self)),
                        Err(()) => {} // Candidate handling keeps unreadable evidence owed.
                        Ok(true) => {}
                    }
                }
            }
        }
        let scan_launch_events = self.launch_events.clone();
        let launch_lookup = attribution_context
            .map(|context| context.launch_events())
            .or(scan_launch_events.as_deref());
        // The parser and lease travel separately during a step. Pair them
        // only when returning a scan that can resume.
        let (mut active_file, mut codex_cursor_lease) =
            std::mem::take(&mut self.active_file).into_parts();

        let paused = self.step_codex_join(launch_lookup, &mut active_file, &mut codex_cursor_lease)
            || self.step_active_file(
                attribution_context,
                &mut active_file,
                &mut codex_cursor_lease,
            )
            || match self.identified_candidates.pop_front() {
                Some(candidate) => {
                    self.select_and_start(
                        candidate,
                        launch_lookup,
                        &mut active_file,
                        &mut codex_cursor_lease,
                    );
                    true
                }
                None => false,
            };
        if paused {
            if let (None, Some(delivery)) = (&active_file, self.line_delivery.as_mut()) {
                delivery.left_active();
            }
            self.active_file =
                sampled_scan::codex_cursor::ActiveFrame::new(active_file, codex_cursor_lease);
            self.walk_idle = false;
            Ok(OwnedSourceScanStep::Pending(self))
        } else {
            // Close owns the detached resources. Its parameters drop the lease
            // and parser before ending any remaining line delivery.
            let line_delivery = self.line_delivery.take();
            Ok(self.close_scan_page(
                line_delivery,
                scan_launch_events,
                active_file,
                codex_cursor_lease,
            ))
        }
    }

    #[inline(never)]
    fn step_active_file(
        &mut self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
        active_file: &mut Option<Box<OwnedActiveFile>>,
        codex_cursor_lease: &mut Option<sampled_scan::codex_cursor::CursorLease>,
    ) -> bool {
        if let Some(mut active) = active_file.take() {
            let compressed = active.parser.reader.reader.is_compressed();
            let _input_qos =
                compressed.then(crate::snapshot_sync::continuation::MacPlatformSignals::background);

            if active.parser.reader.reader.is_compressed()
                && self
                    .codex_page
                    .singleton_remaining(sampled_scan::codex_cursor::Limits::current())
                    == 0
            {
                self.codex_page.continue_singleton();
                *active_file = Some(active);
                return true;
            }
            let before_body_read = active.parser.reader.consumed_bytes();
            if let Some(delivery) = self.line_delivery.as_mut() {
                delivery.begin_armed(&active, &self.roots);
            }
            let mut group_end = None;
            let stepped = if active.group.is_some() {
                // A group job: one record of the current member, or one
                // member transition (P2).
                let live_scope = |member: &CandidateFile| {
                    let context = self.sampling.as_ref()?;
                    let dependency = sampled_scan::reduction_dependencies(
                        self.source,
                        member,
                        &self.codex_title_metadata,
                        &self.claude_title_metadata,
                        self.claude_effort_support_dir.as_deref(),
                    )?;
                    Some(context.file_scope(self.source, member, &dependency))
                };
                match codex_file_join::step_group(
                    &mut active,
                    &codex_file_join::StepInputs {
                        metadata: &self.codex_title_metadata,
                        attribution: attribution_context,
                        live_scope: &live_scope,
                        cache: self.sampling.as_ref().map(|context| &context.cache),
                        collected_at: &self.collected_at,
                    },
                ) {
                    codex_file_join::GroupStep::Read(result) => result,
                    codex_file_join::GroupStep::End(end) => {
                        group_end = Some(end);
                        Ok(false)
                    }
                }
            } else if let Some(delivery) = self.line_delivery.as_mut() {
                delivery.step(&mut active.parser)
            } else {
                active.parser.step()
            };
            self.context_read_budget.record(
                &mut self.index,
                &active.candidate,
                active.cursor.is_some(),
                active
                    .parser
                    .reader
                    .consumed_bytes()
                    .saturating_sub(before_body_read),
            );

            if self.source == SnapshotSource::ClaudeCode
                && before_body_read == 0
                && active.parser.reader.consumed_bytes() > 0
            {
                // Count only the first actual body bytes. SourceChanged
                // includes Desktop/usage sidecar and object revisions;
                // ScopeChanged also catches a metadata change concurrent
                // with growth (whose selection reason is TranscriptChanged).
                // LegacyIdentity is the separate one-time legacy upgrade.
                if self
                    .claude_title_metadata
                    .recovered_account_holds
                    .contains(&local_index_key(&active.candidate.path))
                {
                    crate::local_resource_diagnostics::claude_reread::desktop_recovered_hold_body_read();
                } else {
                    match self
                        .index
                        .candidate_decision_with_reason_at(&active.candidate, self.audit_now)
                        .1
                    {
                        Some(CandidateParseReason::LegacyIdentity) => {
                            crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(true);
                        }
                        reason
                            if reason == Some(CandidateParseReason::SourceChanged)
                                || active.sampling.as_ref().is_some_and(|read| {
                                    matches!(
                                        read.mode,
                                        crate::transcript_acquisition::ReadMode::Full(
                                            crate::transcript_acquisition::FullReason::ScopeChanged
                                        )
                                    )
                                }) =>
                        {
                            crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(false);
                        }
                        _ => {}
                    }
                }
            }
            if self.source == SnapshotSource::Codex {
                let consumed = active.parser.reader.consumed_bytes();
                let moved = codex_file_join::take_charge(&mut active);
                self.codex_page.charge(
                    active.cursor.is_some(),
                    consumed
                        .saturating_sub(active.charged_bytes)
                        .saturating_add(moved),
                );
                active.charged_bytes = consumed;
                if active.hold_offset.is_none()
                    && sampled_scan::codex_cursor::held_monotone(&active.parser.accumulator)
                {
                    // File offset: a tail's reader counts from its start.
                    let start = active
                        .parser
                        .reader
                        .acquisition
                        .as_ref()
                        .map_or(0, crate::transcript_acquisition::ReadPlan::start_offset);
                    active.hold_offset =
                        Some(start + active.parser.reader.last_complete_line_end());
                }
            }
            if let Some(end) = group_end {
                codex_file_join::end_group(
                    active,
                    end,
                    codex_cursor_lease.take(),
                    codex_file_join::EndInputs {
                        sampling: self.sampling.as_ref(),
                        index: &mut self.index,
                        targets: targets!(self),
                    },
                );
                return true;
            }
            match stepped {
                Ok(false) => {
                    // Stage 1 (K6): or a continuation page past its
                    // deadline, which pauses without a ticket.
                    if active.cursor.is_some()
                        && self
                            .codex_page
                            .cursor_stop(sampled_scan::codex_cursor::Limits::current())
                    {
                        if let Some(lease) = codex_cursor_lease.take() {
                            // Stage 1 hunk A: minted before the pause
                            // consumes the job, kept only if it pauses.
                            let ticket = self.sampling.as_ref().and_then(|context| {
                                context.cache.continuation_ticket(&active, &self.codex_page)
                            });
                            self.continuation_ticket = None;
                            if let sampled_scan::codex_cursor::PauseEnd::StateBound(
                                job,
                                disclosure,
                            ) = lease.pause(active)
                            {
                                // No unbounded fallback: `JoinStateBound`
                                // debt, prior body kept, file parked.
                                sampled_scan::codex_cursor::disclose_job_debt(
                                    &job,
                                    &disclosure,
                                    &mut self.index,
                                    targets!(self),
                                );
                                sampled_scan::codex_cursor::dequeue_members(
                                    &mut self.index,
                                    sampled_scan::codex_cursor::job_files(&job),
                                );
                            } else {
                                self.continuation_ticket = ticket;
                            }
                            return true;
                        }
                        // A job without its lease is dropped, never
                        // continued in-page past the budget; its pending
                        // path restarts it (L2).
                        if let Some(context) = self.sampling.as_ref() {
                            context.cache.cursor_note_lost();
                        }
                        return true;
                    }
                    *active_file = Some(active);
                    return true;
                }
                Err(error) => {
                    // Static reader text only, never a path or content.
                    eprintln!(
                        "local snapshot scan: {} transcript read failed: {error}",
                        self.source.api_slug()
                    );
                    if let Some(lease) = codex_cursor_lease.take() {
                        lease.release();
                    }
                    if let Some(group) = active.group.as_ref() {
                        // A member read failure: strict, as before P2.
                        codex_file_join::disclose_strict(&group.members, targets!(self));
                        sampled_scan::codex_cursor::dequeue_members(
                            &mut self.index,
                            &group.members,
                        );
                        return true;
                    }
                    if active.cursor.is_some() {
                        sampled_scan::codex_cursor::dequeue(&mut self.index, &active.candidate);
                    }
                    if self.source == SnapshotSource::ClaudeCode {
                        claude_request_census::invalidate_claude_request_census(
                            &mut self.index,
                            &active.candidate.path,
                        );
                    }
                    if sampled_scan::codex_cursor::requeue_refused(
                        self.source,
                        &error,
                        &mut self.index,
                        &self.selected_flags,
                        &active.candidate,
                    ) {
                        active.parser.reader.reader.close();
                        return true;
                    }
                    active.parser.reader.reader.close();
                    self.census
                        .record_unreadable_file(UnreadableCause::OpenRead, &active.candidate.path);
                    return true;
                }
                Ok(true) if self.codex_page.continuation() => {
                    self.continuation_ticket = None;
                    if let Some(lease) = codex_cursor_lease.take() {
                        #[cfg(test)]
                        sampled_scan::codex_cursor::tests::constrain_eof_park(&mut active);
                        drop(lease.pause(active)); // StateBound: ordinary disclosure only.
                    }
                    return true;
                }
                Ok(true) => {}
            }
            #[cfg(test)]
            AFTER_READER_EOF.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(&active);
                }
            });
            // Retain native trailing-line behavior at a genuine
            // unchanged EOF. A grown read keeps this fragment withheld.
            if active.cursor.is_none()
                && active.parser.reader.sealed_fragment()
                && active
                    .parser
                    .reader
                    .acquisition
                    .as_ref()
                    .is_some_and(|plan| {
                        plan.start_offset()
                            .checked_add(active.parser.reader.consumed_bytes())
                            == Some(plan.frozen_length())
                            && active
                                .parser
                                .reader
                                .reader
                                .get_ref()
                                .metadata()
                                .is_ok_and(|held| held.len() == plan.frozen_length())
                    })
            {
                active.parser.apply_sealed_fragment();
            }
            if active.cursor.is_some() && active.group.is_none() {
                // Apply the EOF record before the protected-tier gate below. A group
                // job applies it to its live member in `member_eof`, before
                // that member's proof ends (R2-N1).
                sampled_scan::codex_cursor::apply_eof_record(&mut active);
            }
            // Consumer-only: publish retained native state at primary EOF.
            if active.is_primary_for(SnapshotSource::Codex) {
                if let Some(feed) = self.codex_versions.as_ref() {
                    feed.observe(&active);
                }
            }
            if let Some(context) = attribution_context {
                let workers = launch_workers_for_parsed(
                    self.source,
                    active.parser.accumulator.source_session_id.as_deref(),
                    &active.candidate.path,
                );
                match context.launch_events().prepare_step(&workers) {
                    Ok(false) => {
                        *active_file = Some(active);
                        return true;
                    }
                    Err(()) => {
                        if self.source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                &mut self.index,
                                &active.candidate.path,
                            );
                        }
                        self.census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        return true;
                    }
                    Ok(true) => {}
                }
            }
            if let Some(context) = self.sampling.as_mut() {
                if let Some(plan) = active.parser.reader.acquisition.as_ref() {
                    context.record_input(
                        plan.metrics(),
                        matches!(
                            plan.mode(),
                            crate::transcript_acquisition::ReadMode::Full(_)
                        ),
                    );
                    // From-start replays, with the bytes they read: a group
                    // from its first member, and a file with protected
                    // tiers re-read from its start.
                    #[cfg(unix)]
                    {
                        let replay = if let Some(group) = active.group.as_deref() {
                            Some((
                                tail_source::counters::Replay::Group,
                                group
                                    .consumed_before
                                    .saturating_add(active.parser.reader.consumed_bytes()),
                            ))
                        } else {
                            active
                                .sampling
                                .as_ref()
                                .is_some_and(|acquisition| acquisition.tier_prefix_replay)
                                .then_some((
                                    tail_source::counters::Replay::TierPrefix,
                                    plan.metrics().native_bytes,
                                ))
                        };
                        if let Some((cause, bytes)) = replay {
                            tail_source::counters::replay(self.source, cause, bytes);
                        }
                    }
                    self.resource_probe.rearm_full_completed(
                        &local_index_key(&active.candidate.path),
                        plan.mode(),
                        plan.metrics().native_bytes,
                    );
                    self.resource_probe.full_parse_reason(
                        plan.mode(),
                        active.parse_reason,
                        active.prior_stamp,
                        0,
                        plan.metrics().native_bytes,
                    );
                    crate::local_resource_diagnostics::change_reason::read(
                        self.source.api_slug(),
                        &local_index_key(&active.candidate.path),
                        plan.mode(),
                        plan.metrics().native_bytes,
                        plan.metrics().sample_bytes as u64,
                    );
                }
            }
            crate::local_resource_diagnostics::change_reason::admin_read(
                self.source.api_slug(),
                &local_index_key(&active.candidate.path),
                active
                    .parser
                    .reader
                    .acquisition
                    .as_ref()
                    .filter(|_| self.sampling.is_some())
                    .map(|plan| (plan.mode(), plan.metrics().native_bytes)),
                active.parser.reader.consumed_bytes(),
            );
            if active.sampling.as_ref().is_some_and(|acquisition| {
                !matches!(
                    acquisition.mode,
                    crate::transcript_acquisition::ReadMode::Full(_)
                ) && active
                    .parser
                    .accumulator
                    .codex_tier_replay
                    .as_ref()
                    .is_some_and(codex_file_join::TierReplay::has_protected_tiers)
            }) {
                // Native finish compares the reopened descriptor to the captured
                // identity, so replacement during fallback cannot publish.
                let reopened =
                    reopen_for_replay(self.source, &active.candidate, &active.parser.reader.reader);
                let Ok(file) = reopened else {
                    self.census
                        .record_unreadable_file(UnreadableCause::OpenRead, &active.candidate.path);
                    return true;
                };
                let Ok(mut parser) = sampled_scan::new_source_parser(
                    file,
                    &active.candidate,
                    &self.index,
                    sampled_scan::ParserOptions {
                        source: self.source,
                        metadata: &self.codex_title_metadata,
                        identity_capture: self.claude_request_identity_capture,
                        cache: self.sampling.as_ref().map(|c| &c.cache),
                    },
                ) else {
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &active.candidate.path);
                    return true;
                };

                let acquisition = active.sampling.as_mut().expect("sampled acquisition");
                let debt = sampled_audit::debt_for_key(
                    &self.index,
                    &acquisition.key,
                    sampled_scan::now_seconds(),
                );
                let Ok(mode) = parser.prepare_acquisition(
                    None,
                    &acquisition.scope,
                    debt,
                    sampled_scan::now_seconds(),
                ) else {
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &active.candidate.path);
                    return true;
                };
                if tail_source::seed_full_job_template(
                    &self.index,
                    &active.candidate,
                    &[],
                    &mut parser.accumulator,
                )
                .is_err()
                {
                    self.residue_index_keys
                        .insert(local_index_key(&active.candidate.path));
                    return true;
                }
                acquisition.mode = mode;
                if let Some(plan) = parser.reader.acquisition.as_ref() {
                    parser
                        .reader
                        .set_extent_limit(plan.frozen_length() - plan.start_offset());
                }
                acquisition.tier_prefix_replay = true;
                if let Some(context) = self.sampling.as_mut() {
                    context.priority_replays += 1;
                    context.record_mode(mode, acquisition.audit_due);
                }
                self.resource_probe.full_parse_reason(
                    mode,
                    active.parse_reason,
                    active.prior_stamp,
                    1,
                    0,
                );
                active.parser = parser;
                active.charged_bytes = 0;
                active.hold_offset = None;
                if active.cursor.is_some()
                    && !sampled_scan::codex_cursor::restart_in_place(&mut active)
                {
                    // The full replay cannot be frozen: end this attempt
                    // (a retryable failure), never an unpaged read.
                    active.cursor = None;
                    if let Some(lease) = codex_cursor_lease.take() {
                        lease.release();
                    }
                    sampled_scan::codex_cursor::dequeue(&mut self.index, &active.candidate);
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &active.candidate.path);
                    return true;
                }
                // LD: the replay is a fresh Full delivery from 0.
                if let Some(delivery) = self.line_delivery.as_mut() {
                    delivery.arm();
                }
                *active_file = Some(active);
                return true;
            }
            // The bytes this attempt read, taken before
            // `finish_job` consumes the acquisition's start offset. An
            // exact-stamp memo below must not cover anything past them.
            if self.source == SnapshotSource::Codex && active.group.is_none() {
                if let (Some(entry), Some(plan)) = (
                    active
                        .sampling
                        .as_ref()
                        .and_then(|sampled| self.index.files.get(&sampled.key)),
                    active.parser.reader.acquisition.as_ref(),
                ) {
                    let start = plan.start_offset();
                    sources::codex::eof_fragment::note_tail_repeat(
                        entry,
                        &active.candidate,
                        sources::codex::eof_fragment::TailRead {
                            mode: plan.mode(),
                            start,
                            end: start.saturating_add(active.parser.reader.consumed_bytes()),
                            terminated_end: active.parser.reader.last_complete_line_end(),
                        },
                        self.census_unix_seconds,
                        self.backfill_window_days,
                    );
                }
            }
            let attempt_read_end = sampled_scan::codex_cursor::read_end(&active);
            // S6: a cursor job commits only through its sealed-prefix
            // certificate; an invalidated attempt publishes nothing.
            let mut cursor_certificate = None;
            let mut cursor_publication = None;
            let mut cursor_fragment = None;
            // A certified job's native EOF bit for its Tail write.
            let mut cursor_eof_applied = None;
            if let Some(context) = self.sampling.as_ref().filter(|_| active.cursor.is_some()) {
                let current_scope = sampled_scan::reduction_dependencies(
                    self.source,
                    &active.candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                )
                .map(|dependency| context.file_scope(self.source, &active.candidate, &dependency));
                let group_scope_now = sampled_scan::codex_cursor::group_scope();
                let census_trusted = self.state_census_complete
                    && self.sidecar_census_complete
                    && active
                        .cursor
                        .as_ref()
                        .is_some_and(sampled_scan::codex_cursor::JobMeta::census_trusted);
                // G1: growth past a job's frozen extent is next-generation
                // evidence when the job started in this census generation.
                let job_in_generation = active
                    .cursor
                    .as_ref()
                    .is_some_and(|meta| meta.in_generation(&self.index));
                // The certificate re-reads two samples from the held FD.
                self.codex_page
                    .charge(true, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                match sampled_scan::codex_cursor::finish_job(
                    &context.cache,
                    codex_cursor_lease.take(),
                    &mut active,
                    current_scope.as_ref(),
                    &group_scope_now,
                    census_trusted,
                ) {
                    sampled_scan::codex_cursor::JobEnd::Certified {
                        checkpoint,
                        grown,
                        publication,
                        fragment,
                    } => {
                        // N2: a withheld record keeps the path pending, so
                        // the next page tails it from `s`.
                        let next_generation = grown && fragment.is_none() && job_in_generation;
                        sampled_scan::codex_cursor::release_path(
                            &mut self.index,
                            &active.candidate,
                            grown || fragment.is_some(),
                            next_generation,
                        );
                        context
                            .cache
                            .cursor_note_next_generation(u64::from(next_generation));
                        // N1: a cursor-only job (census incomplete at start
                        // or now) publishes like main's unsampled read: the
                        // certificate fenced the object, but no checkpoint,
                        // copy or verification is kept. A group job retains
                        // no reduction (its replay is joined).
                        cursor_eof_applied = Some(publication.eof_applied());
                        cursor_certificate =
                            Some((census_trusted && active.group.is_none()).then_some(checkpoint));
                        cursor_publication = Some(publication);
                        cursor_fragment = fragment;
                    }
                    sampled_scan::codex_cursor::JobEnd::Uncertified {
                        grown,
                        publication,
                        fragment,
                    } => {
                        // N2: a withheld record keeps the path pending, so
                        // the next page tails it from `s`.
                        let next_generation = grown && fragment.is_none() && job_in_generation;
                        sampled_scan::codex_cursor::release_path(
                            &mut self.index,
                            &active.candidate,
                            grown || fragment.is_some(),
                            next_generation,
                        );
                        context
                            .cache
                            .cursor_note_next_generation(u64::from(next_generation));
                        cursor_certificate = Some(None);
                        cursor_publication = Some(publication);
                        cursor_fragment = fragment;
                    }
                    // Its path is still pending: the next page re-bootstraps.
                    sampled_scan::codex_cursor::JobEnd::Restart => return true,
                    sampled_scan::codex_cursor::JobEnd::MemberChanged(disclosure) => {
                        sampled_scan::codex_cursor::disclose_job_debt(
                            &active,
                            &disclosure,
                            &mut self.index,
                            targets!(self),
                        );
                        sampled_scan::codex_cursor::dequeue_members(
                            &mut self.index,
                            sampled_scan::codex_cursor::job_files(&active),
                        );
                        return true;
                    }
                }
                // A group's sealed members ended with the job; only its
                // live member's path follows `release_path` above.
                if let Some(group) = active.group.as_ref() {
                    sampled_scan::codex_cursor::dequeue_members(
                        &mut self.index,
                        group
                            .members
                            .iter()
                            .filter(|member| member.path != active.candidate.path),
                    );
                }
            }
            // S12: the live member's certified grant reaches validation.
            let group_live = active
                .group
                .as_ref()
                .and_then(|_| sampled_scan::codex_cursor::certified_prefix(&active))
                .map(|prefix| (local_index_key(&active.candidate.path), prefix));
            // PR-1 class 3: a non-monotone held file is memoized too, at the
            // read end; the record gate decides. Only a file the accumulator
            // already holds, and that is not parent-pending (the gate refuses
            // those), pays the two samples.
            let accumulator = &active.parser.accumulator;
            let memo_offset = active
                .hold_offset
                .or_else(|| {
                    (!accumulator.codex_usage_accounting_complete()
                        && !sampled_scan::codex_cursor::held_monotone(accumulator))
                    .then_some(attempt_read_end)
                })
                .filter(|_| {
                    self.source == SnapshotSource::Codex
                        && active.aliases.is_empty()
                        && self.sampling.is_some()
                });
            if memo_offset.is_some() {
                // The live witness reads two samples of the held file.
                self.codex_page
                    .charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
            }
            let memo_candidate = memo_offset.and_then(|offset| {
                let file = active.parser.reader.reader.get_ref();
                let live = sampled_scan::codex_cursor::LiveWitness::read(
                    &active.candidate.path,
                    file,
                    offset,
                )?;
                let stamp = sampled_scan::codex_cursor::OpenStamp::capture(file).ok()?;
                // PR-1: every singleton entry is exact until a counted tail
                // makes growth replayable, so the stamp must cover exactly
                // the bytes read (captured after
                // `finish_job`'s check).
                if stamp.extent() != attempt_read_end {
                    return None;
                }
                // L-6: a curable hold is stamped only at the length its bind saw.
                if sampled_scan::codex_cursor::growth_may_cure(&active.parser.accumulator)
                    && active.parser.accumulator.codex_bind_seed_len != Some(attempt_read_end)
                {
                    return None;
                }
                let dependencies = sampled_scan::reduction_dependencies(
                    self.source,
                    &active.candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                )?;
                let digest = sampled_scan::codex_cursor::memo_digest(
                    &self.index,
                    &active.candidate,
                    file,
                    &dependencies,
                    &self.codex_title_metadata,
                    sampled_scan::codex_cursor::owner_members(
                        self.codex_join_inventory.as_ref(),
                        &active.candidate.path,
                    ),
                )?;
                let sidecar = sampled_scan::codex_cursor::sidecar_wakes(&active.parser.accumulator)
                    .then(|| {
                        sampled_scan::codex_cursor::sidecar_fingerprint(
                            &self.codex_title_metadata,
                            &active.candidate.path,
                        )
                    });
                Some((digest, live, stamp, sidecar))
            });
            let OwnedActiveFile {
                first_read,
                sampling: mut file_sampling,
                candidate,
                decision,
                parse_reason: _,
                prior_stamp: _,
                previous_snapshot_fingerprint,
                previous_upload_body_witness,
                projection_adoption_required,
                source_file_fingerprint,
                parser,
                aliases,
                mut applied_receipts,
                cursor: _,
                charged_bytes: _,
                hold_offset: _,
                mut group,
            } = *active;
            #[cfg(test)]
            let diagnostic_path = candidate.path.clone();
            let mut independent_contributions = Vec::new();
            let mut independent_group = false;
            let group_members = group.as_deref_mut().map_or(0, |group| {
                independent_group = group.independent;
                independent_contributions = std::mem::take(&mut group.contributions);
                group.members.len()
            });
            let _first_read = first_read;
            let mut parser = parser;
            if let Some(replay) = parser.accumulator.codex_tier_replay.take() {
                match replay.finish() {
                    Ok(receipt) => {
                        applied_receipts.insert(local_index_key(&candidate.path), receipt);
                    }

                    Err(_) => {
                        if let Some(group) = group.as_deref().filter(|group| group.independent) {
                            codex_file_join::refuse_independent(
                                group,
                                self.sampling.as_ref(),
                                &mut self.index,
                                targets!(self),
                            );
                            return true;
                        }
                        if let Some((context, publication)) =
                            self.sampling.as_ref().zip(cursor_publication.take())
                        {
                            context.cache.cursor_published(publication, false);
                        }
                        self.census.ownership_incomplete_file_count += 1;
                        self.census.causes.add(ownership::GROUP, 1);
                        self.census
                            .record_unreadable(UnreadableCause::AliasParser, 1);
                        self.residue_index_keys
                            .insert(local_index_key(&candidate.path));
                        return true;
                    }
                }
            }
            // N4 (fe-seam-ack §5): the file branch decides its H3c route
            // before its completion.
            let file_acquisition = file_sampling
                .as_ref()
                .filter(|_| cursor_certificate.is_none());
            let (current_scope, prefix) = match file_acquisition {
                Some(acquisition) => {
                    // Known dependencies and the current path are separate from the
                    // sampled prefix promise. Neither may be stale at completion.
                    let current_scope = sampled_scan::reduction_dependencies(
                        self.source,
                        &candidate,
                        &self.codex_title_metadata,
                        &self.claude_title_metadata,
                        self.claude_effort_support_dir.as_deref(),
                    )
                    .zip(self.sampling.as_ref())
                    .map(|(dependency, context)| {
                        context.file_scope(self.source, &candidate, &dependency)
                    });
                    // H3c: a passed certificate permits native finish of
                    // this prefix only. Discard its checkpoint: no cache copy,
                    // audit credit or source verification can follow it.
                    let prefix = current_scope
                        .as_ref()
                        .filter(|_| aliases.is_empty())
                        .filter(|scope| *scope == &acquisition.scope)
                        .and_then(|scope| {
                            parser.commit_grown_prefix(
                                &candidate.path,
                                scope,
                                self.index
                                    .files
                                    .get(&acquisition.key)
                                    .map_or(0, |entry| entry.size_bytes),
                            )
                        });
                    if prefix.is_none()
                        && current_scope.as_ref() == Some(&acquisition.scope)
                        && parser.reader.acquisition.as_ref().is_some_and(|plan| {
                            // A short EOF proves truncation, even if the file
                            // has regrown by completion. Keep strict failure.
                            plan.start_offset()
                                .checked_add(parser.reader.consumed_bytes())
                                == Some(plan.frozen_length())
                                && parser.reader.reader.get_ref().metadata().is_ok_and(|held| {
                                    held.len() > plan.frozen_length()
                                        && fs::symlink_metadata(&candidate.path).is_ok_and(
                                            |current| metadata_describes_same_file(&held, &current),
                                        )
                                })
                        })
                    {
                        // Unchanged, or a trailing record already applied at
                        // genuine EOF: retry only this file, never the walk.
                        scan::owned_scan::retry_grown_file(
                            &mut self.index,
                            &self.selected_flags,
                            &candidate,
                            &mut self.census,
                            false,
                        );
                        return true;
                    }
                    (current_scope, prefix)
                }
                None => (None, None),
            };
            // Cursor finish grants also occupy sealed_prefix, including
            // quiescent reads and withheld fragments. Only this in-page
            // growth certificate needs the new debt/provenance handling.
            let grown_prefix = prefix.as_ref().is_some_and(|result| result.is_ok());
            let completed_acquisition = if let Some(certificate) = cursor_certificate {
                certificate.map(|checkpoint| sampled_jsonl::CompletedNativeAcquisition {
                    checkpoint,
                    unsealed: true,
                })
            } else if let Some(acquisition) = file_sampling.as_ref() {
                if let Some(prefix) = prefix {
                    match prefix {
                        Ok(grant) => {
                            parser.reader.sealed_prefix = Some(grant);
                            file_sampling
                                .as_mut()
                                .expect("prefix acquisition")
                                .audit_due
                                .get_or_insert_with(|| {
                                    sampled_scan::now_seconds().saturating_add(
                                        crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
                                    )
                                });
                        }
                        Err(crate::transcript_acquisition::PrefixRefusal::Invalidated(
                            crate::transcript_acquisition::FullReason::InvalidCheckpoint,
                        )) if parser.reader.acquisition.is_some() => {
                            // A withheld row would weaken the last committed
                            // body. Keep it and retry this file alone.
                            scan::owned_scan::retry_grown_file(
                                &mut self.index,
                                &self.selected_flags,
                                &candidate,
                                &mut self.census,
                                false,
                            );
                            return true;
                        }
                        Err(crate::transcript_acquisition::PrefixRefusal::AuditDue) => {
                            scan::owned_scan::retry_grown_file(
                                &mut self.index,
                                &self.selected_flags,
                                &candidate,
                                &mut self.census,
                                false,
                            );
                            return true;
                        }
                        Err(_) => {
                            claude_request_census::invalidate_claude_request_census(
                                &mut self.index,
                                &candidate.path,
                            );
                            self.census.record_unreadable_file(
                                UnreadableCause::ScopeObject,
                                &candidate.path,
                            );
                            return true;
                        }
                    }
                    None
                } else {
                    let mut current_path = candidate.clone();
                    if let Some(cause) = sampled_revalidation_cause(
                        current_scope.as_ref() == Some(&acquisition.scope),
                        || {
                            drop(open_candidate_file(self.source, &mut current_path)?);
                            Ok(current_path.opened_object_identity
                                == candidate.opened_object_identity)
                        },
                    ) {
                        if self.source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                &mut self.index,
                                &candidate.path,
                            );
                        }
                        // Nothing of this read is kept. A changed object
                        // or scope uses the file's one same-walk retry,
                        // which holds the walk; a second refusal keeps
                        // the census red.
                        if !matches!(cause, UnreadableCause::ScopeObject)
                            || !scan::owned_scan::retry_file_once(
                                &mut self.index,
                                &self.selected_flags,
                                &candidate,
                                Some(&mut self.discovered_file_count),
                            )
                        {
                            self.census.record_unreadable_file(cause, &candidate.path);
                        }
                        return true;
                    }
                    #[cfg(test)]
                    sampled_scan::test_hooks::fire(sampled_scan::test_hooks::Point::BeforeRetain);
                    match parser.retain_reduction(&acquisition.scope, sampled_scan::now_seconds()) {
                        Ok(completed) => completed,
                        Err(_) => {
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
                            return true;
                        }
                    }
                }
            } else {
                None
            };
            // Retain the obligation until native finish and RAM admission.
            // Only due complete-c Unchanged acquisitions can retire it;
            // incidental telemetry refreshes keep the original obligation.
            let quiet_audit_checked = if let (Some(completed), Some(active), Some(context)) = (
                completed_acquisition.as_ref(),
                file_sampling.as_ref(),
                self.sampling.as_mut(),
            ) {
                if active.mode == crate::transcript_acquisition::ReadMode::Unchanged
                    // Withheld bodies retain their obligation until release.
                    && !self.index.claude_account_deferred_holds.contains_key(&active.key)
                    && self.index.files.get(&active.key).is_some_and(|entry| {
                        entry.audit_requires_full(self.audit_now)
                            && !entry.has_prefix_provenance()
                    })
                    && !self.index.claude_request_census.get(&active.key).is_some_and(
                        claude_request_census::ClaudeRequestCensusRecord::identity_incomplete_hold,
                    )
                {
                    let mut bytes = 0;
                    let checked = completed
                        .checkpoint
                        .quiet_audit_matches(
                            parser.reader.reader.get_mut(),
                            &active.scope,
                            &mut bytes,
                        )
                        .unwrap_or(false);
                    context.sample_bytes = context.sample_bytes.saturating_add(bytes as u64);
                    checked
                } else {
                    false
                }
            } else {
                false
            };
            #[cfg(test)]
            sampled_scan::test_hooks::fire_for_key(
                sampled_scan::test_hooks::Point::AfterRetain,
                &local_index_key(&candidate.path),
            );
            let joined_owner = if aliases.is_empty() {
                None
            } else {
                parser
                    .accumulator
                    .source_session_id
                    .as_deref()
                    .map(resolve_codex_identity)
            };
            let codex_counting_v2 = true;
            // Counting receipts reach the scan's local diagnostics only
            // when this parse finishes: once per finished active file (a
            // joined group is one).
            let codex_counting_receipts =
                parser
                    .accumulator
                    .codex_counting
                    .as_deref()
                    .map(|counting| {
                        let mut receipts =
                            self.census.codex_counting_v2.clone().unwrap_or_default();
                        counting.fold_receipts(&mut receipts);
                        receipts
                    });
            // Before `finish` consumes the parser. Ledger
            // birth: `created()` and identity of the descriptor this parse
            // opened, taken at open (never a path); unknown is None.
            let claude_opened_birth = (self.source == SnapshotSource::ClaudeCode
                && claude_index_path_family_member(&candidate.path).is_some())
            .then_some(parser.claude_opened_birth)
            .flatten();
            let claude_itemless_request_hashes =
                if self.source == SnapshotSource::ClaudeCode && !parser.positive_usage_evidence {
                    claude_request_census::claude_buffered_request_hashes(&parser)
                } else {
                    Vec::new()
                };
            let claude_grown_prefix = self.source == SnapshotSource::ClaudeCode && grown_prefix;
            let finish_request = FinishRequest {
                expected_opened_object_identity: &candidate.opened_object_identity,
                path: &candidate.path,
                collected_at: self.collected_at.as_str(),
                source_file_fingerprint: source_file_fingerprint.clone(),
                codex_title_metadata: (self.source == SnapshotSource::Codex)
                    .then_some(&self.codex_title_metadata),
                claude_title_metadata: (self.source == SnapshotSource::ClaudeCode)
                    .then_some(&self.claude_title_metadata),
                attribution_context,
                repository_identity: None,
                money_context: Some(claude_request_money::e2::ReadContext {
                    index: &self.index,
                    path: &candidate.path,
                    twins: self.history_upgrade.twin_groups(),
                }),
            };
            // This completion's Tail write: encoded at PRE into a local
            // buffer, published only on the native finish's verdict.
            #[cfg(unix)]
            let tail_base = parser.take_tail_base();
            #[cfg(unix)]
            let mut tail = completed_acquisition
                .as_ref()
                .zip(file_sampling.as_ref())
                .filter(|_| self.sampling.is_some())
                .and_then(|(completed, active)| {
                    // `None` off a Tail route.
                    tail_source::pending(
                        self.source,
                        &self.index,
                        completed,
                        active,
                        &candidate,
                        parser.reader.reader.get_ref(),
                        self.claude_request_identity_capture,
                        tail_base,
                        quiet_audit_checked,
                    )
                })
                // A certified cursor job stages its Tail the same way,
                // under its own seal bit.
                .map(|tail| match cursor_eof_applied {
                    Some(eof_applied) => tail.sealed_by_job(eof_applied),
                    None => tail,
                });
            let mut resident_bytes = 0;
            let mut job_template = group.as_mut().and_then(|group| group.job_template.take());
            let job_template_file = group
                .as_deref()
                .map_or(&candidate, |group| &group.members[0]);
            let mut encode = |live: PreFinalization<'_>| {
                if !independent_group {
                    job_template = tail_source::job_update(job_template_file, live.accumulator);
                }
                #[cfg(unix)]
                if let Some(tail) = tail.as_mut() {
                    tail.encode(&live);
                    resident_bytes = tail.resident_bytes();
                    return;
                }
                resident_bytes = tail_source::resident_bytes(self.source, live.accumulator);
            };
            let parsed_file = parser.finish_boxed_native(finish_request, Some(&mut encode));
            self.history_upgrade.charge_resident(
                self.source,
                file_sampling
                    .as_ref()
                    .map_or(0, |s| s.resident_loaded_bytes),
                resident_bytes,
                1 + aliases.len(),
            );
            // On a Tail route: whether this file's committed head stays
            // its continuation (staged, or nothing to restate).
            #[cfg(unix)]
            let tail_reused =
                tail.map(|tail| tail.publish_with_job(&parsed_file, &mut job_template));
            #[cfg(test)]
            sampled_scan::test_hooks::fire(sampled_scan::test_hooks::Point::BeforeNativeEffects);
            // A committed cursor attempt counts as published only now.
            if let Some((context, publication)) =
                self.sampling.as_ref().zip(cursor_publication.take())
            {
                context
                    .cache
                    .cursor_published(publication, parsed_file.is_ok());
            }
            if let Ok(parsed) = &parsed_file {
                if self.source == SnapshotSource::ClaudeCode {
                    for item in &parsed.snapshots {
                        if let Some(fold) = item.claude_money.as_deref() {
                            claude_request_money::e2::remember_birth(
                                &mut self.index,
                                &candidate.path,
                                fold,
                            );
                        }
                    }
                }
            }
            let parsed_file = match parsed_file.and_then(|mut parsed| {
                if !independent_contributions.is_empty() {
                    codex_file_join::fold_independent(
                        &mut parsed.snapshots,
                        independent_contributions,
                    )?;
                }
                Ok(parsed)
            }) {
                Ok(parsed) => parsed,

                Err(_error) => {
                    if let Some(group) = group.as_deref().filter(|group| group.independent) {
                        codex_file_join::refuse_independent(
                            group,
                            self.sampling.as_ref(),
                            &mut self.index,
                            targets!(self),
                        );
                        return true;
                    }
                    if self.source == SnapshotSource::Codex && !aliases.is_empty() {
                        codex_file_join::disclose_strict(&aliases, targets!(self));
                        return true;
                    }
                    #[cfg(test)]
                    sampled_scan::test_hooks::record_finish_error(&_error);
                    if self.source == SnapshotSource::ClaudeCode {
                        claude_request_census::invalidate_claude_request_census(
                            &mut self.index,
                            &candidate.path,
                        );
                    }
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    return true;
                }
            };
            if let Some(receipts) = codex_counting_receipts {
                self.census.codex_counting_v2 = Some(receipts);
            }
            let parse_complete = parsed_file.progress_complete();
            if self.source == SnapshotSource::Codex && parse_complete {
                let mut keys = aliases
                    .iter()
                    .map(|member| local_index_key(&member.path))
                    .collect::<Vec<_>>();
                if keys.is_empty() {
                    keys.push(local_index_key(&candidate.path));
                }
                let total = parsed_file
                    .snapshots
                    .first()
                    .map(usage_totals_from_item)
                    .unwrap_or_default();
                sources::codex::counting::version::note_recount(&self.index, &keys, &total);
            }

            // Claude response conflicts may be discovered only by native
            // finalization. A prefix cannot publish that late loss: it
            // would have neither a committed audit marker nor necessarily
            // a request-census record when the record budget is exhausted.
            if claude_grown_prefix && !parse_complete {
                claude_request_census::invalidate_claude_request_census(
                    &mut self.index,
                    &candidate.path,
                );
                self.census
                    .record_unreadable(UnreadableCause::ScopeObject, 1);
                return true;
            }
            if !aliases.is_empty() && !parse_complete {
                // Joining authorizes a complete replacement only. Native
                // ownership/parser loss cannot publish a partial union body.
                self.census.ownership_incomplete_file_count += aliases.len();
                self.census.causes.add(ownership::GROUP, aliases.len());
                self.census
                    .record_unreadable(UnreadableCause::AliasParser, 1);
                self.residue_index_keys
                    .extend(aliases.iter().map(|member| local_index_key(&member.path)));
                return true;
            }
            if !aliases.is_empty() {
                if aliases
                    .iter()
                    .any(|member| codex_archive_path(&member.path))
                    && codex_file_join::stage_independent_inventory(
                        &self.index,
                        &aliases,
                        joined_owner.as_deref().expect("joined owner"),
                    )
                    .is_err()
                {
                    codex_file_join::disclose_strict(&aliases, targets!(self));
                    return true;
                }
                self.codex_join_completed.push(codex_file_join::Group {
                    owner: joined_owner
                        .expect("joined replay owner was bound before native finish"),
                    home: codex_file_join::member_home(&candidate.scan_root),
                    members: aliases.clone(),
                    live: group_live.clone(),
                });
            }
            let diagnostic_reason = if parse_complete {
                FileReason::Complete
            } else if parsed_file.ownership_incomplete_file_count > 0 {
                FileReason::OwnershipIncomplete
            } else if parsed_file.recognized_usage_drop_count > 0 {
                FileReason::RecognizedUsageDropped
            } else {
                FileReason::ReadOrLineLoss
            };
            let terminal_loss = parsed_file.terminal_loss();
            let index_key = local_index_key(&candidate.path);
            let non_progressing_residue = parsed_file.non_progressing_residue();
            #[cfg(test)]
            twin_diagnostics::event(&candidate.path, || {
                format!(
                    "completion parse_complete={parse_complete} residue={non_progressing_residue}"
                )
            });
            if non_progressing_residue {
                self.residue_index_keys.insert(index_key.clone());
            } else {
                self.settled_residue_index_keys.insert(index_key.clone());
            }
            let report = parsed_file.report;
            let recognized_usage_drop_count = parsed_file.recognized_usage_drop_count;
            let ownership_incomplete_file_count = parsed_file.ownership_incomplete_file_count;
            let zero_snapshot_usage_evidence = parsed_file.zero_snapshot_usage_evidence;
            let dropped_usage_record_count = parsed_file.dropped_usage_record_count;
            let claude_compaction_unlinked_parent_count =
                parsed_file.claude_compaction_unlinked_parent_count;
            if let Some(context) = self
                .sampling
                .as_ref()
                .filter(|_| self.source == SnapshotSource::Codex && aliases.is_empty())
            {
                // Memoize a non-progressing ownership-held singleton.
                // Anything else, completion included, clears a stale entry.
                let held = !parse_complete
                    && non_progressing_residue
                    && ownership_incomplete_file_count > 0;
                match memo_candidate.filter(|_| held) {
                    Some((digest, live, stamp, sidecar)) => {
                        context.cache.memo_record(
                            sampled_scan::codex_cursor::memo_key(&context.namespace, &index_key),
                            sampled_scan::codex_cursor::MemoEntry::new(
                                digest,
                                live,
                                context.cache.retained_stamp(&candidate.path, stamp),
                                sidecar,
                                sampled_scan::codex_cursor::Disclosure {
                                    reason: sampled_scan::codex_cursor::DebtReason::HeldTerminal,
                                    ownership_incomplete_file_count,
                                    cause: parsed_file.cause,
                                    zero_snapshot_usage_evidence,
                                    diagnostic_reason,
                                    parsed_snapshot_count: parsed_file.snapshots.len(),
                                    held: sampled_scan::codex_cursor::HeldCounts {
                                        loss: parsed_file.terminal_loss(),
                                    },
                                },
                            )
                            // Every singleton entry is exact (PR-1).
                            .growth_may_cure(true),
                        )
                    }
                    None => context
                        .cache
                        .memo_forget(&sampled_scan::codex_cursor::memo_key(
                            &context.namespace,
                            &index_key,
                        )),
                }
            }
            // A new prefix/lossy obligation without a slot cannot publish
            // or mutate its index entry. Existing marked files keep custody.
            let needs_marker = cursor_fragment.is_some()
                || completed_acquisition
                    .as_ref()
                    .is_some_and(|completed| completed.checkpoint.audit_debt().is_some())
                || (completed_acquisition.is_none()
                    && file_sampling
                        .as_ref()
                        .is_some_and(|active| active.audit_due.is_some()));
            let slot_unfunded = self
                .sampling
                .as_ref()
                .is_some_and(|context| context.audit_slots == 0)
                && !self
                    .index
                    .files
                    .get(&index_key)
                    .is_some_and(ScanIndexEntry::has_unverified_source);
            if (grown_prefix && slot_unfunded)
                || (needs_marker
                    && !self
                        .index
                        .claude_account_deferred_holds
                        .contains_key(&index_key)
                    && (slot_unfunded || !self.index.can_stage_sampled_audit(&index_key)))
            {
                if grown_prefix {
                    // No new audit slot: retain the committed body and
                    // census membership, without poisoning the traversal.
                    if let Some(context) = self.sampling.as_mut() {
                        context.audit_cap_delay += 1;
                    }
                    scan::owned_scan::retry_grown_file(
                        &mut self.index,
                        &self.selected_flags,
                        &candidate,
                        &mut self.census,
                        true,
                    );
                    return true;
                }
                #[cfg(test)]
                twin_diagnostics::event(&candidate.path, || {
                    format!(
                    "defer completion needs_marker={needs_marker} slot_unfunded={slot_unfunded} can_stage={}",
                    self.index.can_stage_sampled_audit(&index_key),
                )
                });
                // A refused prefix/lossy completion is a delay, not a Full.
                if let Some(context) = self.sampling.as_mut() {
                    context.audit_cap_delay += 1;
                }
                sampled_audit::queue_cap_retry(&mut self.index, &candidate);
                self.census
                    .record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                return true;
            }
            if let Some(job) = job_template.filter(|_| parse_complete) {
                let key = local_index_key(&job_template_file.path);
                let saved = state_v2::tail_route_path(&self.index).and_then(|route| {
                    route.map_or(Ok(()), |route| state_v2::stage_job(&route, &key, job))
                });
                if saved.is_err() {
                    self.census
                        .record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    return true;
                }
            }
            // Debt-free after quiet retirement is scheduling state, not
            // Full authority, including a later forced Unchanged read.
            let source_verified = sampled_jsonl::loss_free_source_report(
                &report,
                recognized_usage_drop_count,
                dropped_usage_record_count,
            ) && (cursor_fragment.is_none()
                && file_sampling.as_ref().is_some_and(|active| {
                    matches!(
                        active.mode,
                        crate::transcript_acquisition::ReadMode::Full(_)
                    )
                })
                && completed_acquisition
                    .as_ref()
                    .is_some_and(|completed| completed.checkpoint.audit_debt().is_none())
                || (file_sampling.is_none()
                    && self.state_census_complete
                    && self.sidecar_census_complete));
            let mut parsed = parsed_file.snapshots;
            if self.source == SnapshotSource::ClaudeCode {
                claude_request_census::record_claude_request_census(
                    &mut self.index,
                    claude_request_census::ClaudeRequestCensusParse {
                        path: &candidate.path,
                        index_key: &index_key,
                        source_file_fingerprint: &source_file_fingerprint,
                        census_window_end: &self.census_window_end,
                        complete: parse_complete,
                        lossy: terminal_loss.is_some(),
                        source_verified,
                        // The loader bound the predecessor; completion must
                        // seal the whole loss-free suffix. This is not Full credit.
                        continued_source: cursor_fragment.is_none()
                            && file_sampling.as_ref().is_some_and(|active| {
                                active.census_base_bound
                                    && matches!(
                                        active.mode,
                                        crate::transcript_acquisition::ReadMode::Unchanged
                                            | crate::transcript_acquisition::ReadMode::Tail
                                    )
                            })
                            && completed_acquisition.as_ref().is_some_and(|completed| {
                                completed.checkpoint.sealed_offset() == candidate.size_bytes
                            })
                            && sampled_jsonl::loss_free_source_report(
                                &report,
                                recognized_usage_drop_count,
                                dropped_usage_record_count,
                            ),
                        itemless_request_hashes: claude_itemless_request_hashes,
                        opened_birth: claude_opened_birth,
                        modified_unix_seconds: candidate.modified_unix_seconds,
                    },
                    &parsed,
                );
            }
            if self.source == SnapshotSource::Codex {
                for snapshot in parsed.iter_mut() {
                    apply_codex_state_evidence(
                        snapshot,
                        &self.codex_title_metadata,
                        &candidate.path,
                    );
                }
            }
            // First-read work: a selected census read that records a path
            // new to the index (any member of a joined group). A re-read of
            // a recorded file, such as a live session's hint, is not.
            let paths = || std::iter::once(&candidate.path).chain(aliases.iter().map(|a| &a.path));
            self.first_read_progress |= parse_complete
                && sampled_scan::codex_cursor::census_member(
                    &self.selected_flags,
                    paths().map(PathBuf::as_path),
                )
                && paths().any(|path| !self.index.files.contains_key(&local_index_key(path)));
            if parse_complete && !aliases.is_empty() {
                self.record_joined_aliases(
                    &aliases,
                    &candidate,
                    &parsed,
                    parse_complete,
                    diagnostic_reason,
                    independent_group,
                );
            }
            self.scanned_session_count += parsed.len();
            let last_snapshot_fingerprint = parsed
                .last()
                .map(|snapshot| snapshot.snapshot_fingerprint.clone());
            let parsed_snapshot_count = parsed.len();
            let sampled_audit_verified = parse_complete
                && cursor_fragment.is_none()
                && completed_acquisition
                    .as_ref()
                    .is_some_and(|completed| completed.checkpoint.audit_debt().is_none())
                && file_sampling
                    .as_ref()
                    .is_some_and(|active| active.audit_due.is_some());
            if sampled_audit_verified {
                if let Some(context) = self.sampling.as_mut() {
                    context.complete_audit(
                        file_sampling
                            .as_ref()
                            .and_then(|active| active.audit_due)
                            .expect("verified audit due"),
                    );
                }
            }
            self.pending_finalization.push(PendingIndexFinalization {
                withheld_content: parse_complete
                    .then(|| self.index.withheld_completed_seen(&candidate))
                    .flatten(),
                sampled_audit_verified,
                codex_pending_recovery: self
                    .index
                    .files
                    .get(&index_key)
                    .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
                index_key: index_key.clone(),
                source_file_fingerprint: source_file_fingerprint.clone(),
                previous_snapshot_fingerprint: (decision != CandidateDecision::ReconcileLegacy
                    && !projection_adoption_required)
                    .then_some(previous_snapshot_fingerprint)
                    .flatten(),
                previous_upload_body_witness: (decision != CandidateDecision::ReconcileLegacy
                    && !projection_adoption_required)
                    .then_some(previous_upload_body_witness)
                    .flatten(),
                parse_complete,
                diagnostic_reason,
                parsed_snapshot_count,
                effective_upload_body_witness_revision: self
                    .index
                    .active_effective_upload_body_witness_revision,
            });
            if self.source == SnapshotSource::Codex
                && parse_complete
                && aliases.is_empty()
                && applied_receipts.values().any(Option::is_some)
            {
                if let Some(item) = parsed.first() {
                    self.codex_join_completed.push(codex_file_join::Group {
                        owner: resolve_codex_identity(&item.source_session_id),
                        home: codex_file_join::member_home(&candidate.scan_root),
                        members: vec![candidate.clone()],
                        live: None,
                    });
                }
            }
            let counting_owner = parsed.first().and_then(|item| {
                if self.source != SnapshotSource::Codex {
                    return None;
                }
                let owner = self
                    .codex_join_inventory
                    .as_ref()?
                    .owner_for_path(&candidate.path)?;
                let binding = codex_protected_owner(owner);
                (binding == codex_protected_owner(&item.source_session_id)).then_some(binding)
            });
            let joined_marker =
                (!aliases.is_empty()).then(|| codex_file_join::member_set_witness(&aliases));
            let protected_owner = (!aliases.is_empty()
                || applied_receipts.values().any(Option::is_some))
            .then(|| {
                parsed
                    .first()
                    .map(|item| codex_protected_owner(&item.source_session_id))
            })
            .flatten();
            let joined_keys = aliases
                .iter()
                .map(|member| local_index_key(&member.path))
                .collect::<Vec<_>>();
            if parse_complete {
                self.index
                    .record_terminal_jsonl_disposition(&candidate, terminal_loss.clone());
                let outcome = if last_snapshot_fingerprint.is_some() {
                    ScanParseOutcome::Snapshot
                } else {
                    ScanParseOutcome::ConfirmedEmpty
                };
                // N2: with the certified prefix continued (its staged
                // Tail head), the entry records only `[0, s)` as read, so
                // the next page tails the withheld record with main's EOF
                // behavior. Without a continuation it records the length
                // read and the staged debt re-selects it at the audit
                // cadence.
                let prefix_continued = tail_reused == Some(true);
                let bound_fragment = cursor_fragment.and_then(|fragment| {
                    completed_acquisition.as_ref().and_then(|completed| {
                        (prefix_continued
                            && completed.checkpoint.sealed_offset() == fragment.offset)
                            .then(|| {
                                sources::codex::eof_fragment::BoundFragment::bind(
                                    &candidate,
                                    fragment.offset,
                                )
                            })
                            .flatten()
                    })
                });
                let mut recorded = candidate;
                if let Some(fragment) =
                    cursor_fragment.filter(|_| prefix_continued && completed_acquisition.is_some())
                {
                    recorded.size_bytes = fragment.offset;
                }
                // record consumes the candidate but does not use its root.
                // Move that existing allocation into the commit-sensitive
                // retry instead of cloning it or guessing a nested root.
                let quiet_scan_root =
                    quiet_audit_checked.then(|| std::mem::take(&mut recorded.scan_root));
                if parse_complete && !non_progressing_residue {
                    sampled_audit::settle_growth(&mut self.index, &index_key);
                }
                self.index
                    .record(recorded, last_snapshot_fingerprint, outcome);
                // The counting version travels in the same entry as the
                // fingerprint it describes; no separate save can split them.
                if let Some(entry) = self.index.files.get_mut(&index_key) {
                    entry.codex_counting_v2 = codex_counting_v2;
                    entry.codex_counting_owner = counting_owner.clone().map(String::into_boxed_str);
                    entry.codex_fragment = bound_fragment.map(Box::new);
                }
                // Each grouped member, aliases included, settles its own
                // audit on its native-created entry: verified retires and counts.
                for member in aliases.iter().take(group_members) {
                    let key = local_index_key(&member.path);
                    let marked = self
                        .index
                        .files
                        .get(&key)
                        .and_then(ScanIndexEntry::unverified_deadline);
                    if let Some(context) = self.sampling.as_mut() {
                        if let Some(owed) = marked.filter(|_| source_verified) {
                            context.complete_audit(owed);
                        }
                    }
                }
                // Native settlement accepts disclosed terminal row loss, even
                // though that acquisition cannot certify a verified prefix.
                // Its sampled publication still owes the prepared deadline;
                // losing a completion certificate must never erase that debt.
                let obligation = match completed_acquisition.as_ref() {
                    Some(completed) => completed.checkpoint.audit_debt(),
                    None => file_sampling
                        .as_ref()
                        .and_then(|active| active.audit_due)
                        .map(
                            |due_unix_seconds| crate::transcript_acquisition::AuditDebt {
                                due_unix_seconds,
                            },
                        ),
                };
                if let Some(debt) = obligation {
                    let was_pending = self
                        .index
                        .files
                        .get(&index_key)
                        .is_some_and(ScanIndexEntry::has_unverified_source);
                    // Held retries bypass cap Full/counting, not the
                    // committed-slot reservation for a NEW marker.
                    if !slot_unfunded
                        && self.index.stage_sampled_audit(
                            &index_key,
                            &source_file_fingerprint,
                            debt,
                        )
                        && !was_pending
                    {
                        if let Some(context) = self.sampling.as_mut() {
                            context.audit_slots = context.audit_slots.saturating_sub(1);
                        }
                    }
                } else if source_verified {
                    self.index
                        .complete_full_audit(&index_key, &source_file_fingerprint);
                }
                if grown_prefix {
                    self.index
                        .mark_sealed_prefix(&index_key, &source_file_fingerprint);
                } else if self.source == SnapshotSource::ClaudeCode
                    && completed_acquisition.is_some()
                    && cursor_fragment.is_none()
                    && file_sampling.as_ref().is_some_and(|active| {
                        !matches!(
                            active.mode,
                            crate::transcript_acquisition::ReadMode::Unchanged
                        )
                    })
                    && self.state_census_complete
                    && self.sidecar_census_complete
                    && parse_complete
                {
                    self.index
                        .complete_native_recomposition(&index_key, &source_file_fingerprint);
                }
                if let Some(fragment) = cursor_fragment {
                    let was_pending = self
                        .index
                        .files
                        .get(&index_key)
                        .is_some_and(ScanIndexEntry::has_unverified_source);
                    if !slot_unfunded
                        && self.index.stage_sampled_audit(
                            &index_key,
                            &source_file_fingerprint,
                            fragment.debt,
                        )
                        && !was_pending
                    {
                        if let Some(context) = self.sampling.as_mut() {
                            context.audit_slots = context.audit_slots.saturating_sub(1);
                        }
                    }
                }
                // Codex: after every audit staging above (staging
                // matches the fingerprint), before this entry's save
                // settles the degraded publication.
                if let Some(mut completed) = completed_acquisition {
                    if let Some(context) = self.sampling.as_mut() {
                        let retained = tail_reused == Some(true);
                        let quiet_retired = quiet_audit_checked
                            && !completed.unsealed
                            && retained
                            && cursor_fragment.is_none()
                            && self.state_census_complete
                            && self.sidecar_census_complete
                            && parse_complete;
                        // All source/census/Full-credit decisions above saw
                        // the owed debt. This clears only scheduling state.
                        if quiet_retired {
                            completed.checkpoint.retire_quiet_audit();
                        }
                        // The completion's continuation is its committed
                        // head on its route, or none.
                        let quiet_proven = quiet_retired
                            && context
                                .cache
                                .quiet_certified(&index_key, &completed.checkpoint);
                        drop(completed);
                        if retained {
                            if quiet_retired {
                                // A partial save may restore the old marker.
                                // Preserve this path AND its exact scope root
                                // until a committed retirement makes it skip.
                                sampled_audit::queue_quiet_retirement(
                                    &mut self.index,
                                    &index_key,
                                    quiet_scan_root.expect("checked quiet retirement root"),
                                );
                            }
                            #[cfg(unix)]
                            let durable_pending = quiet_retired
                                && context.cache.quiet_stage(
                                    self.source,
                                    &index_key,
                                    &source_file_fingerprint,
                                    quiet_proven,
                                );
                            #[cfg(not(unix))]
                            let durable_pending = false;
                            if quiet_retired
                                && !durable_pending
                                && self
                                    .index
                                    .retire_quiet_audit(&index_key, &source_file_fingerprint)
                            {
                                context.audit_quiet_retired += 1;
                                // Reuse only on the next committed scan:
                                // partial-save reconciliation may restore
                                // this marker without accepting its body.
                            }
                        }
                    }
                }
                for key in joined_keys {
                    if let Some(entry) = self.index.files.get_mut(&key) {
                        if source_verified {
                            entry.scan_identity_version =
                                Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
                        }
                        entry.codex_joined_member_set = joined_marker.clone();
                        entry.codex_protected_owner = protected_owner.clone();
                        // Every completed Codex replacement carries V2.
                        entry.codex_counting_v2 = codex_counting_v2;
                        entry.codex_counting_owner =
                            counting_owner.clone().map(String::into_boxed_str);
                    }
                }
            }
            if parse_complete {
                for (key, receipt) in applied_receipts {
                    if let Some(entry) = self.index.files.get_mut(&key) {
                        if receipt.is_some() {
                            entry.codex_protected_owner = protected_owner.clone();
                        }
                        entry.codex_applied_tier_receipt_required = receipt.is_some();
                        entry.codex_applied_tier_receipt = receipt;
                    }
                }
            }
            if let Some(loss) = terminal_loss.as_ref() {
                self.census.add_terminal_jsonl_loss(loss);
            }
            self.census.ownership_incomplete_file_count += ownership_incomplete_file_count;
            self.census
                .causes
                .add(parsed_file.cause, ownership_incomplete_file_count);
            self.census.zero_snapshot_usage_evidence_count +=
                usize::from(zero_snapshot_usage_evidence);
            self.census.claude_compaction_unlinked_parent_count = self
                .census
                .claude_compaction_unlinked_parent_count
                .saturating_add(claude_compaction_unlinked_parent_count);
            // Only classified holds suppress independently valid siblings.
            if parse_complete {
                #[cfg(test)]
                twin_diagnostics::event(&diagnostic_path, || {
                    format!(
                        "page contribution snapshots={} folds={}",
                        parsed.len(),
                        parsed
                            .iter()
                            .filter(|item| item.claude_money.is_some())
                            .count(),
                    )
                });
                self.snapshots.extend(parsed);
            }
            return true;
        }
        false
    }

    #[inline(never)]
    fn record_joined_aliases(
        &mut self,
        aliases: &[CandidateFile],
        candidate: &CandidateFile,
        parsed: &[SnapshotItem],
        parse_complete: bool,
        diagnostic_reason: FileReason,
        independent_group: bool,
    ) {
        for alias in aliases {
            if alias.path == candidate.path {
                continue;
            }
            let alias_fingerprint = alias.source_file_fingerprint.clone();
            self.pending_finalization.push(PendingIndexFinalization {
                withheld_content: None,
                sampled_audit_verified: false,
                codex_pending_recovery: self
                    .index
                    .files
                    .get(&local_index_key(&alias.path))
                    .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
                index_key: local_index_key(&alias.path),
                source_file_fingerprint: alias_fingerprint.clone(),
                previous_snapshot_fingerprint: self.index.last_snapshot_fingerprint(alias),
                previous_upload_body_witness: self.index.last_upload_body_witness(alias),
                parse_complete,
                diagnostic_reason,
                parsed_snapshot_count: parsed.len(),
                effective_upload_body_witness_revision: self
                    .index
                    .active_effective_upload_body_witness_revision,
            });
            let alias_items = parsed
                .iter()
                .cloned()
                .map(|mut item| {
                    if !independent_group {
                        item.source_file_fingerprint = Some(alias_fingerprint.clone());
                        item.snapshot_fingerprint = snapshot_fingerprint(self.source, &item);
                    }
                    item
                })
                .collect::<Vec<_>>();
            self.index.record(
                alias.clone(),
                alias_items
                    .last()
                    .map(|item| item.snapshot_fingerprint.clone()),
                ScanParseOutcome::Snapshot,
            );
            self.census
                .observed_index_keys
                .insert(local_index_key(&alias.path));
            if !independent_group {
                self.snapshots.extend(alias_items);
            }
        }
    }

    #[inline(never)]
    fn close_scan_page(
        mut self,
        mut line_delivery: Option<line_delivery::LineDelivery>,
        _scan_launch_events: Option<Arc<crate::launch_events::LaunchEventInventory>>,
        active_file: Option<Box<OwnedActiveFile>>,
        _codex_cursor_lease: Option<sampled_scan::codex_cursor::CursorLease>,
    ) -> OwnedSourceScanStep {
        self.context_read_budget
            .flush(&mut self.index, &self.selected_flags);
        if self.codex_page.continuation() {
            if let Some(traversal) = self.index.traversal.as_mut() {
                traversal.counts.caps.drain(self.source.api_slug());
            }
            let continuation_evidence = self
                .codex_join_inventory
                .map(|inventory| CodexContinuationEvidence {
                    inventory,
                    codex: self.codex_title_metadata,
                })
                .and_then(|evidence| match self.continuation_ticket.as_ref() {
                    Some(ticket) => evidence.for_paused_job(
                        self.sampling.as_ref().map(|context| context.cache.as_ref()),
                        ticket,
                    ),
                    None => Some(evidence),
                })
                .map(|evidence| Arc::new(Mutex::new(Some(evidence))));
            return OwnedSourceScanStep::Complete {
                index: self.index,
                scan: SourceScanResult {
                    discovery_growth: std::mem::take(&mut self.resource_probe.discovery_growth),
                    continuation_ticket: self.continuation_ticket,
                    continuation_evidence,
                    ..SourceScanResult::empty(SnapshotSource::Codex)
                },
            };
        }
        // Current-page metadata/open uncertainty must reach every F4
        // caller before any hold can retire. The remaining census fold
        // below keeps its existing order; each count is merged once.
        if let Some(traversal) = self.index.traversal.as_mut() {
            traversal.counts.directory_entry_cap_exceeded_count +=
                self.census.directory_entry_cap_exceeded_count;
            traversal.counts.unreadable_path_count += self.census.unreadable_path_count;
            traversal
                .counts
                .unreadable_causes
                .merge(self.census.unreadable_causes);
            traversal.counts.growth_deferred += self.census.growth_deferred;
        }
        // Per-key absence is independent of aggregate terminal authority.
        if self.source == SnapshotSource::ClaudeCode {
            self.index.probe_absent_claude_account_deferred_holds();
        }
        // Preparation recorded this page's held candidates; the fold
        // adds the residue it records now.
        let mut inventory_hold = self.codex_inventory_hold_counts;
        if let Some(traversal) = self.index.traversal.as_mut() {
            // A residue file that this page parsed to completion, or that a
            // watcher hint proved absent, leaves the generation's residue set; a
            // file that reproduced its residue (re)enters it.
            for index_key in self.settled_residue_index_keys.iter().chain(
                self.census.removed_index_keys.iter().filter(|key| {
                    !self
                        .index
                        .files
                        .get(*key)
                        .is_some_and(ScanIndexEntry::codex_history_is_protected)
                }),
            ) {
                traversal.residue.index_keys.remove(index_key);
            }
            if let Some(inventory) = self
                .codex_join_inventory
                .as_ref()
                .filter(|inventory| !inventory.complete)
            {
                let (held, awaiting, outside) =
                    record_codex_inventory_hold(traversal, inventory, &self.residue_index_keys);
                inventory_hold = (
                    inventory_hold.0 + held,
                    inventory_hold.1 || awaiting,
                    inventory_hold.2 + outside,
                );
            }
            traversal.residue.index_keys.extend(self.residue_index_keys);
            // Exact watcher remove/rename hints must amend the same durable
            // observation set used by directory census reconciliation. Apply
            // removals first so a valid observation later in this page wins.
            for index_key in self.census.removed_index_keys.iter() {
                traversal.observed_index_keys.remove(index_key);
            }
            traversal
                .observed_index_keys
                .extend(self.census.observed_index_keys.iter().cloned());
            traversal.counts.symlink_rejected_count += self.census.symlink_rejected_count;
            traversal.counts.oversized_file_count += self.census.oversized_file_count;
            traversal.counts.disappeared_file_count += self.census.disappeared_file_count;
            traversal.counts.malformed_json_line_count += self.census.malformed_json_line_count;
            traversal.counts.invalid_utf8_line_count += self.census.invalid_utf8_line_count;
            traversal.counts.over_line_cap_count += self.census.over_line_cap_count;
            traversal.counts.recognized_usage_drop_count += self.census.recognized_usage_drop_count;
            traversal.counts.ownership_incomplete_file_count +=
                self.census.ownership_incomplete_file_count;
            traversal.counts.causes.merge(&self.census.causes);
            traversal.counts.zero_snapshot_usage_evidence_count +=
                self.census.zero_snapshot_usage_evidence_count;
            traversal.counts.dropped_usage_record_count = traversal
                .counts
                .dropped_usage_record_count
                .saturating_add(self.census.dropped_usage_record_count);
            traversal.counts.terminal_over_line_cap_count = traversal
                .counts
                .terminal_over_line_cap_count
                .saturating_add(self.census.terminal_over_line_cap_count);
            traversal.counts.terminal_recognized_usage_drop_count = traversal
                .counts
                .terminal_recognized_usage_drop_count
                .saturating_add(self.census.terminal_recognized_usage_drop_count);
            traversal.counts.terminal_dropped_usage_record_count = traversal
                .counts
                .terminal_dropped_usage_record_count
                .saturating_add(self.census.terminal_dropped_usage_record_count);
        }
        if self.source == SnapshotSource::Codex {
            // Count-only attribution of why Codex files were selected
            // on this page. No path, session, or identifier is named.
            // An incomplete header inventory appends why, counts only.
            let incomplete = self
                .codex_join_inventory
                .as_ref()
                .and_then(|inventory| inventory.incomplete_fields(inventory_hold));
            if let Some(line) = self.census.codex_parse_reasons_line().or_else(|| {
                incomplete
                    .is_some()
                    .then(|| "local snapshot census codex parse reasons:".to_owned())
            }) {
                eprintln!("{line}{}", incomplete.unwrap_or_default());
            }
        }
        if self.source == SnapshotSource::ClaudeCode
            && (self.census.parse_reasons.iter().any(|count| *count > 0)
                || self.census.claude_compaction_unlinked_parent_count > 0
                || self.history_upgrade.any()
                || self.index.claude_reemission_exclusions.pauses_adoption()
                || claude_reemission_stop_latched())
        {
            claude_history_upgrade::alarm_if_owed_without_list(
                &self.history_upgrade,
                self.index.claude_reemission_exclusions.state(),
            );
            // Count-only attribution of why Claude files were selected
            // on this page. No path, session, or identifier is named.
            eprintln!(
                "local snapshot census claude parse reasons: {} compaction_summary_unlinked_parent={} body_witness_adoption_deferred={} body_witness_adoption_excluded={} body_witness_adoption_held_no_list={} body_witness_adoption_exclusions_invalid={} body_witness_adoption_list={} body_witness_adoption_stop={} body_witness_adoption_stop_withheld_folds={} history_upgrade_owed={} history_upgrade_permitted={} history_emission_denied={} history_listed_literal_roots={} history_reowed={} history_activation_refused={} claude_reemission_family_closure_root_absent_excluded={} identity_incomplete_holds_entered_process_total={} identity_incomplete_holds_cleared_process_total={}",
                census_count_fields(&CANDIDATE_PARSE_REASON_NAMES, &self.census.parse_reasons),
                self.census.claude_compaction_unlinked_parent_count,
                self.history_upgrade.denied_for(&[
                    HistoryHold::UngatedRevision,
                    HistoryHold::ListPaused,
                    HistoryHold::Latched,
                    HistoryHold::Budget,
                ]),
                self.history_upgrade.denied_for(&[HistoryHold::Listed]),
                self.history_upgrade
                    .denied_for(&[HistoryHold::NoListBirth, HistoryHold::MoveNotFull]),
                u8::from(self.index.claude_reemission_exclusions.is_invalid()),
                self.index.claude_reemission_exclusions.status(),
                claude_reemission_stop_reason(),
                claude_reemission_stop_withheld_folds(),
                self.history_upgrade.owed,
                self.history_upgrade.permitted,
                self.history_upgrade.denied_summary(),
                self.history_upgrade.listed_literal_roots.len(),
                claude_history_upgrade::local_count(
                    claude_history_upgrade::LocalCount::Reowed
                ),
                claude_history_upgrade::local_count(
                    claude_history_upgrade::LocalCount::ActivationRefused
                ),
                self.history_upgrade.family_closure_root_absent_excluded,
                claude_request_census::identity_incomplete_hold_totals().0,
                claude_request_census::identity_incomplete_hold_totals().1,
            );
            if self.history_upgrade.family_closure_root_absent_excluded > 0 {
                crate::local_resource_diagnostics::claude_reemission_family_closure_root_absent_excluded(
                    self.history_upgrade.family_closure_root_absent_excluded,
                );
            }
        }
        // A remove/rename hint can arrive after bounded reconciliation has already
        // passed this key. Removing it only from `observed_index_keys` is then too
        // late: the reconciliation cursor will never revisit the stale entry and a
        // terminal manifest can still publish it. The hint was revalidated as
        // absent beneath the configured root above, so retire the corresponding
        // derived index state directly. Any recreation after this absence witness
        // belongs to the next generation.
        if self.source == SnapshotSource::Codex {
            self.census.removed_index_keys.retain(|key| {
                self.index.files.contains_key(key)
                    && !self
                        .index
                        .traversal
                        .as_ref()
                        .is_some_and(|walk| walk.codex_rollout_paths.contains(key))
            });
        }
        let account_members = self.index.observed_account_members();
        let unacked = self
            .index
            .unacked_bodies(self.census.removed_index_keys.iter());
        let mut tally = (0, 0);
        for index_key in self.census.removed_index_keys.iter() {
            if self.source == SnapshotSource::ClaudeCode
                && !self.census.claude_vanished_index_keys.contains(index_key)
                && sampled_audit::revalidate_growth(
                    &mut self.index,
                    index_key,
                    &self.roots,
                    &mut tally,
                )
            {
                continue;
            }
            if self.source == SnapshotSource::ClaudeCode
                && self
                    .index
                    .claude_account_deferred_holds
                    .contains_key(index_key)
            {
                self.index
                    .retire_absent_account_hold(index_key, &account_members);

                // Successful retirement is complete; an uncertain
                // disappearance must not enter the older audit exit.
                continue;
            }
            // F4 or indexed reconciliation may already have retired the
            // audit entry this page. Its retained incidence is
            // not a second ordinary file removal (and grants no ACK).
            if self.source == SnapshotSource::ClaudeCode
                && !self.index.files.contains_key(index_key)
            {
                continue;
            }
            // Codex records its counting evidence before either exit
            // below, as terminal reconciliation does; a refusal keeps
            // the entry whole.
            if !self
                .index
                .files
                .get(index_key)
                .is_some_and(ScanIndexEntry::codex_history_is_protected)
            {
                // A member that vanished beneath its present parent
                // also drops its unverified audit debt, proven again
                // here; every other removal keeps that debt. Both
                // retire its request-census record.
                let vanished = self.census.claude_vanished_index_keys.contains(index_key);
                let census_record =
                    vanished && self.index.claude_request_census.get(index_key).is_some();
                if vanished
                    && self
                        .index
                        .files
                        .get(index_key)
                        .is_some_and(ScanIndexEntry::has_unverified_source)
                    && sampled_audit::proven_absent(Path::new(index_key), &self.roots)
                    && self
                        .index
                        .retire_vanished_claude_audit_debt_entry(index_key)
                {
                    crate::local_resource_diagnostics::audit_retired_absent(self.source.api_slug());
                    disappearance_diagnostics::vanished(
                        self.source,
                        disappearance_diagnostics::Vanished::AuditDebtDropped,
                    );
                } else {
                    self.index.remove_file_entry_unless_held(index_key);
                }
                if census_record && self.index.claude_request_census.get(index_key).is_none() {
                    disappearance_diagnostics::vanished(
                        self.source,
                        disappearance_diagnostics::Vanished::RequestCensusRemoved,
                    );
                }
            }
        }
        crate::local_resource_diagnostics::v2_growth_revalidate(tally);
        self.index.count_unacked_retired(self.source, unacked);
        // G1: only census members hold discovery. A pending re-read
        // (growth after this generation processed its path) is
        // next-generation evidence; retiring drops it and the next
        // walk re-reads the file if it is stale.
        let traversal_discovery_done = self.index.traversal.as_ref().is_some_and(|traversal| {
            traversal.pending_directories.is_empty()
                && !traversal
                    .pending_candidates
                    .iter()
                    .any(|candidate| candidate.census_member)
        });
        if traversal_discovery_done {
            if self.source == SnapshotSource::Codex {
                let missing = self
                    .index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        entry.codex_history_is_protected()
                            && !self
                                .index
                                .traversal
                                .as_ref()
                                .expect("traversal")
                                .codex_rollout_paths
                                .contains(*key)
                    })
                    .map(|(key, _)| key.clone())
                    .collect::<BTreeSet<_>>();
                if !missing.is_empty() {
                    let traversal = self.index.traversal.as_mut().expect("traversal");
                    // Quiet ticks reuse this generation's red witness. Count
                    // each absent protected source once, without rearming the
                    // retry latch or rescanning headers before its deadline.
                    let newly_missing = missing.difference(&traversal.residue.index_keys).count();
                    traversal.counts.ownership_incomplete_file_count += newly_missing;
                    traversal
                        .counts
                        .causes
                        .add(ownership::ABSENT, newly_missing);
                    traversal.counts.record_unreadable(
                        UnreadableCause::ProtectedAbsence,
                        usize::from(newly_missing > 0),
                    );
                    traversal.residue.index_keys.extend(missing);
                }
            }
            // Discovery has visited every directory and parsed every candidate,
            // so the counts are the complete re-derivation for this generation.
            // Loss that only a change to the corpus can move is settled now, so a
            // machine whose only problem is an unresolvable rollout still reaches
            // a terminal census instead of retrying the same bytes forever with
            // every downstream gate (historical backfill, the legacy settlement
            // sweep, the terminal manifest) held behind it. Retryable problems
            // veto the settlement inside the helper.
            if let Some(traversal) = self.index.traversal.as_mut() {
                traversal.settle_non_progressing_residue();
            }
        }
        if let Some(traversal) = self.index.traversal.as_mut() {
            traversal.counts.caps.drain(self.source.api_slug());
        }
        let traversal_snapshot = self
            .index
            .traversal
            .as_ref()
            .cloned()
            .expect("traversal remains active");
        let routine_recensus =
            traversal_transition::routine_recensus(self.source, &traversal_snapshot);
        // A clean walk retiring here may arm the gate.
        let settled_walk = !traversal_snapshot.rewalk_owed
            && traversal_snapshot
                .pending_candidates
                .iter()
                .all(|candidate| candidate.census_member);
        let traversal_healthy = !traversal_snapshot.has_errors();
        let clean_frozen_generation = !traversal_snapshot.watcher_hint_seen;
        let reconciliation_complete = if traversal_discovery_done
            && traversal_healthy
            && clean_frozen_generation
            && self.state_census_complete
            && self.sidecar_census_complete
        {
            reconcile_missing_index_entries_bounded(&mut self.index, self.source)
        } else {
            false
        };
        // Vanished paths are retired from `files` just above - by exact watcher
        // remove/rename hints and by bounded census reconciliation. Terminal
        // dispositions are keyed identically, so retire their orphans in the same
        // place instead of carrying a renamed or deleted file's record forever.
        // This keeps the map a subset of `files`, which is the whole bound it
        // needs.
        self.index.prune_terminal_jsonl_dispositions();
        let raw_census_complete = traversal_discovery_done
            && traversal_healthy
            && clean_frozen_generation
            && self.state_census_complete
            && self.sidecar_census_complete
            && reconciliation_complete;
        let needs_clean_followup =
            raw_census_complete && self.index.bounded_sweep_had_unsettled_upload;
        // Path-(a) bridge: RetryPending authority debt no longer marks
        // the sweep, but it still withholds the ordinary census (and so
        // its complete fold and upload-context adoption), as the mark
        // did. It owes no clean follow-up of its own.
        let authority_debt_withholds_census = raw_census_complete
            && self.source == SnapshotSource::ClaudeCode
            && self.index.claude_usage_authority_pending_count() > 0;
        let census_complete =
            raw_census_complete && !needs_clean_followup && !authority_debt_withholds_census;
        // Prune and measure only, before any fold.
        let claude_request_census_shadow =
            (self.source == SnapshotSource::ClaudeCode && census_complete).then(|| {
                claude_request_census::settle_claude_request_census_terminal(
                    &mut self.index,
                    &traversal_snapshot.residue.index_keys,
                    &self.census_window_end,
                )
            });
        let reconciliation_pending = traversal_discovery_done
            && traversal_healthy
            && clean_frozen_generation
            && self.state_census_complete
            && self.sidecar_census_complete
            && !reconciliation_complete;
        let pending_work_count = self
            .index
            .traversal
            .as_ref()
            .map(|traversal| {
                traversal
                    .pending_candidates
                    .len()
                    .saturating_add(traversal.pending_directories.len())
                    .saturating_add(usize::from(reconciliation_pending))
            })
            .unwrap_or_default();
        let skipped_file_count_due_to_limit = self.index.skipped_census_member_count();
        let restart_after_hints =
            traversal_discovery_done && traversal_healthy && !clean_frozen_generation;
        let terminal_unhealthy = traversal_discovery_done && !traversal_healthy;
        if terminal_unhealthy {
            let now = rfc3339_unix_seconds(self.collected_at.as_str()).unwrap_or_default();
            let traversal = self
                .index
                .traversal
                .as_mut()
                .expect("traversal remains active");
            if traversal.unhealthy_retry_not_before_unix_seconds.is_none() {
                let previous_attempt = traversal.unhealthy_retry_attempt;
                // The counter saturates at the attempt whose delay is already the
                // hourly ceiling. A persistent problem therefore costs at most one
                // bounded re-walk per hour and the persisted witness stays small.
                traversal.unhealthy_retry_attempt = previous_attempt
                    .saturating_add(1)
                    .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS);
                traversal.unhealthy_retry_not_before_unix_seconds = Some(now.saturating_add(
                    unhealthy_scan_retry_delay_seconds(traversal.unhealthy_retry_attempt),
                ));
                if previous_attempt < UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                    && traversal.unhealthy_retry_attempt == UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                {
                    eprintln!(
            "ottto-service: bounded scan retry for {} reached attempt {}; the traversal \
                     stays a durable red witness and is re-walked at most hourly until the \
                     problem clears or the scan context changes",
            self.source.api_slug(),
            UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
        );
                }
            }
        }
        let pending_work_count = pending_work_count
            .saturating_add(usize::from(restart_after_hints))
            .saturating_add(usize::from(terminal_unhealthy))
            .saturating_add(usize::from(needs_clean_followup));
        let traversal = self
            .index
            .traversal
            .as_ref()
            .expect("traversal remains active");
        let loaders = &self.codex_title_metadata.local_diagnostics;
        let census_status = CensusStatus {
            pending_work: !traversal.pending_directories.is_empty()
                || !traversal.pending_candidates.is_empty(),
            retryable_problem: traversal.has_retryable_problems(),
            transport_reservation_refused: self
                .index
                .context_read_counts
                .transport_reservation_refused,
            // Completeness also falls on identity conflicts: require
            // an actual failed loader, not just a false gate.
            state_loader_failed: self.source == SnapshotSource::Codex
                && (!self.state_census_complete || !self.sidecar_census_complete)
                && [
                    loaders.state_titles.failed_roots,
                    loaders.state_threads.failed_roots,
                    loaders.spawn_edges.failed_roots,
                    loaders.rollout_extents.failed_roots,
                    loaders.session_index.failed_roots,
                ]
                .into_iter()
                .any(|failed| failed > 0),
            reconciliation_incomplete: !reconciliation_complete,
            retry_attempt: traversal.unhealthy_retry_attempt,
            retry_not_before_unix_seconds: traversal.unhealthy_retry_not_before_unix_seconds,
        };
        if raw_census_complete {
            self.index
                .record_scan_residue_witness(self.source, &traversal_snapshot);
        }
        let mut carried_next_generation = Vec::new();
        if (raw_census_complete
            && !self.pending_finalization.iter().any(|pending| {
                self.index
                    .files
                    .get(&pending.index_key)
                    .is_some_and(|entry| {
                        entry.codex_applied_tier_receipt.is_some()
                            || entry.codex_joined_member_set.is_some()
                    })
            }))
            || restart_after_hints
        {
            traversal_transition::retiring(
                self.source,
                self.index.generation,
                &traversal_snapshot,
                raw_census_complete,
                self.index.unsettled_cause_bits(),
                CensusGates {
                    discovery_done: traversal_discovery_done,
                    traversal_healthy,
                    frozen_generation: clean_frozen_generation,
                    state_complete: self.state_census_complete,
                    sidecar_complete: self.sidecar_census_complete,
                    reconciliation_complete,

                    clean_followup: needs_clean_followup,
                    census_complete,
                },
            );
            // G1 carry: the closing generation's waiting re-reads
            // (watcher hints, budget-deferred re-reads, growth past
            // its window end) are next-generation evidence. Hand them
            // to the next generation as members rather than dropping
            // them; they never re-enter the generation closing here.
            carried_next_generation = self
                .index
                .traversal
                .as_ref()
                .filter(|_| self.source == SnapshotSource::Codex)
                .map_or_else(Vec::new, |traversal| {
                    traversal
                        .pending_candidates
                        .iter()
                        .filter(|candidate| !candidate.census_member)
                        .map(|candidate| candidate.path.clone())
                        .collect::<Vec<_>>()
                });
            self.index.traversal = None;
            self.index.resume_after_path = None;
            self.index.resume_upper_bound_path = None;
            self.index.resume_census_window_end = None;
        }
        let counts = traversal_snapshot.counts;
        let zero_snapshot_confirmed_count = self.index.confirmed_empty_files.len();
        let zero_snapshot_usage_evidence_count = counts.zero_snapshot_usage_evidence_count;
        let dropped_usage_record_count = counts.dropped_usage_record_count;
        // The witness just recorded above describes THIS generation only when the
        // generation completed; otherwise the durable one is an earlier census's
        // and must not be reported as this scan's evidence. Counts only: the
        // witness's index keys never leave the local index.
        let (census_residue_index_key_count, census_residue_archived_rollout_count) =
            if raw_census_complete {
                self.index
                    .scan_residue_witness
                    .as_ref()
                    .map(|witness| {
                        (
                            witness.index_keys.len(),
                            witness.archived_residue_file_count(),
                        )
                    })
                    .unwrap_or_default()
            } else {
                (0, 0)
            };
        // Full context-curve upload is retired: a restored old curve
        // never leaves the Mac.
        for snapshot in &mut self.snapshots {
            snapshot.context_curve = None;
        }
        self.index.preserve_decode_held_files(
            self.source,
            &self.snapshots,
            &mut self.pending_finalization,
        );
        self.snapshots
            .retain(|item| !self.index.decode_holds_snapshot(self.source, item));
        let census_complete = census_complete && self.index.decode_holds.is_empty();
        if census_complete {
            // Only a healthy EFFECTIVE terminal can prove a
            // carried file gone. A raw terminal, another file's census,
            // or an unknown original association cannot retire its ACKs.
            self.index.accepted_rebuild_incidence.retain(|key, _| {
                key.is_empty()
                    || traversal_snapshot.observed_index_keys.contains(key)
                    || traversal_snapshot.residue.index_keys.contains(key)
                    || self.index.files.contains_key(key)
            });
            self.index.accepted_incidence_pending_census =
                !self.index.accepted_rebuild_incidence.is_empty();
            // A4d: the same proof retires a Tail whose file is gone.
            #[cfg(unix)]
            tail_source::load::retire_absent(
                self.source,
                &self.index,
                &traversal_snapshot.observed_index_keys,
                &traversal_snapshot.residue.index_keys,
            );
        }
        if !self.index.decode_holds.is_empty() {
            self.index.mark_bounded_sweep_unsettled();
        }
        // Only a settled close starts the next generation in this
        // page. A partially settled sweep (including a decode hold
        // just marked) keeps its marker for the clean follow-up the
        // next page starts, and that walk re-reads the stale files.
        if !carried_next_generation.is_empty() && !self.index.bounded_sweep_had_unsettled_upload {
            ensure_bounded_traversal(
                self.source,
                &self.roots,
                &mut self.index,
                &self.collected_at,
                self.backfill_window_days,
            );
            if let Some(next) = self.index.traversal.as_mut() {
                enqueue_watcher_hints(self.source, next, &carried_next_generation, false);
            }
        }
        let local_diagnostics = self.codex_title_metadata.local_diagnostics;
        let continuation_evidence = (self.codex_join_completed.is_empty()
            && self.continuation_ticket.is_some())
        .then(|| self.codex_join_inventory.take())
        .flatten()
        .filter(|inventory| inventory.complete)
        .map(|inventory| CodexContinuationEvidence {
            inventory,
            codex: self.codex_title_metadata,
        });
        if self.continuation_ticket.is_some() && continuation_evidence.is_none() {
            crate::local_resource_diagnostics::codex_continuation_mint(
                if self.codex_join_completed.is_empty() {
                    "inventory_incomplete"
                } else {
                    "groups_completed"
                },
            );
        }
        if self.source == SnapshotSource::Codex {
            crate::local_resource_diagnostics::codex_zst_refused_flush();
        }
        let continuation_evidence = continuation_evidence
            .zip(self.continuation_ticket.as_ref())
            .and_then(|(evidence, ticket)| {
                evidence.for_paused_job(
                    self.sampling.as_ref().map(|context| context.cache.as_ref()),
                    ticket,
                )
            });
        let codex_join_validation = self.codex_join_inventory.and_then(|inventory| {
            let surviving: BTreeSet<_> = self
                .pending_finalization
                .iter()
                .filter_map(|pending| inventory.owner_for_path(Path::new(&pending.index_key)))
                .map(str::to_owned)
                .collect();
            (!surviving.is_empty()).then(|| {
                codex_file_join::Validation::new(
                    inventory,
                    self.codex_join_completed,
                    &surviving,
                    traversal_snapshot.codex_rollout_paths,
                )
            })
        });
        let scan = SourceScanResult {
            census_status,
            walk_idle: false,
            settled_walk: settled_walk && census_complete,
            charge_deferred: self.history_upgrade.charge_deferred > 0,
            page_file_limit_hit: self.page_file_limit_hit,
            routine_recensus,
            page_byte_budget_hit: self.codex_page.budget_deferred(),
            first_read_progress: self.first_read_progress,
            claude_queued_family_deferred_paths: std::mem::take(
                &mut self.history_upgrade.queued_family_deferred_paths,
            ),
            discovery_growth: std::mem::take(&mut self.resource_probe.discovery_growth),
            source: self.source,
            backfill_window_days: self.backfill_window_days,
            backfill_file_limit: self.file_limit,
            discovered_file_count: self.discovered_file_count,
            skipped_file_count_due_to_limit,
            scan_cap_hit: pending_work_count > 0,
            scanned_file_count: self.scanned_file_count,
            scanned_session_count: self.scanned_session_count,
            semantic_noop_count: self.semantic_noop_count,
            census_complete,
            census_window_end: self.census_window_end,
            state_census_complete: self.state_census_complete,
            sidecar_census_complete: self.sidecar_census_complete,
            symlink_rejected_count: counts.symlink_rejected_count,
            directory_entry_cap_exceeded_count: counts.directory_entry_cap_exceeded_count,
            unreadable_path_count: counts.unreadable_path_count,
            oversized_file_count: counts.oversized_file_count,
            disappeared_file_count: counts.disappeared_file_count,
            malformed_json_line_count: counts.malformed_json_line_count,
            invalid_utf8_line_count: counts.invalid_utf8_line_count,
            over_line_cap_count: counts.over_line_cap_count,
            recognized_usage_drop_count: counts.recognized_usage_drop_count,
            ownership_incomplete_file_count: counts.ownership_incomplete_file_count,
            causes: counts.causes,
            zero_snapshot_confirmed_count,
            zero_snapshot_usage_evidence_count,
            dropped_usage_record_count,
            terminal_ownership_incomplete_file_count: counts
                .terminal_ownership_incomplete_file_count,
            terminal_zero_snapshot_usage_evidence_count: counts
                .terminal_zero_snapshot_usage_evidence_count,
            terminal_recognized_usage_drop_count: counts.terminal_recognized_usage_drop_count,
            terminal_dropped_usage_record_count: counts.terminal_dropped_usage_record_count,
            terminal_over_line_cap_count: counts.terminal_over_line_cap_count,
            census_residue_index_key_count,
            census_residue_archived_rollout_count,
            snapshots: self.snapshots,
            pending_finalization: self.pending_finalization,
            claude_request_census_shadow,
            continuation_ticket: self.continuation_ticket,
            continuation_evidence: continuation_evidence.map(|e| Arc::new(Mutex::new(Some(e)))),
            codex_join_validation,
            // Moved, not copied: the box was charged with the census.
            codex_counting_v2: self.census.codex_counting_v2.take(),
            local_codex_diagnostics: (self.source == SnapshotSource::Codex).then_some(
                CodexScanDiagnostics {
                    version: 1,
                    generation: self.index.generation,
                    unreadable_causes: counts.unreadable_causes,
                    // PR-P: traversal-cumulative per-page counts, as
                    // `unreadable_causes`.
                    gates: CensusGates {
                        discovery_done: traversal_discovery_done,
                        traversal_healthy,
                        frozen_generation: clean_frozen_generation,
                        state_complete: self.state_census_complete,
                        sidecar_complete: self.sidecar_census_complete,
                        reconciliation_complete,

                        clean_followup: needs_clean_followup,
                        census_complete,
                    },
                    ..local_diagnostics
                },
            ),
        };
        if self.source == SnapshotSource::ClaudeCode {
            rearm_cause::retain(&self.index);
        }
        let sampled_acquisition = self.sampling.as_ref().map(|context| {
            let audit_now = sampled_scan::now_seconds();
            let pending = self.index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count();
            let overdue = self.index
                .files
                .values()
                .filter(|entry| entry.audit_requires_full(audit_now))
                .count();
            let oldest_due_age = self.index
                .files
                .values()
                .filter_map(|entry| entry.audit_obligation(audit_now))
                .map(|debt| audit_now.saturating_sub(debt.due_unix_seconds))
                .max()
                .unwrap_or(0);
            if context.audit_cap_full > 0 {
                crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_alarm", self.source.api_slug(),
                    &serde_json::json!({"audit_cap_full": context.audit_cap_full, "pending_audits": pending}));
            }
            if context.audit_cap_delay > 0 {
                crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_delay", self.source.api_slug(),
                    &serde_json::json!({"audit_cap_delay": context.audit_cap_delay}));
            }
            if context.pace_evicted > 0 {
                crate::local_resource_diagnostics::traversal_point("sampled_audit_pace_alarm", self.source.api_slug(),
                    &serde_json::json!({"pace_evicted": context.pace_evicted}));
            }
            if context.same_size_touch_proven > 0 {
                crate::local_resource_diagnostics::traversal_point("same_size_touch_proven", self.source.api_slug(),
                    &serde_json::json!({"same_size_touch_proven": context.same_size_touch_proven}));
            }
            crate::local_resource_diagnostics::ReadCounts {
                full_selections: context.full_files,
                tail_selections: context.tail_files,
                unchanged_selections: context.unchanged_files,
                completed_native_bytes: context.native_bytes,
                completed_full_native_bytes: context.full_native_bytes,
                completed_guard_bytes: context.sample_bytes,
                acquisition_admission: context.admission,
                page_events: crate::local_resource_diagnostics::PageEvents {
                    full_cause: self.resource_probe.rearm_fulls(),
                    full_by_parse_reason: self.resource_probe.full_by_parse_reason(),
                    full_reasons: crate::local_resource_diagnostics::FullReasons(
                        context.full_reasons,
                    ),
                    priority_full_replays: context.priority_replays,
                    audits_started: context.audits_started,
                    audits_completed: context.audits_completed,
                    max_start_overdue_seconds: context.start_overdue_seconds,
                    max_completion_overdue_seconds: context.completion_overdue_seconds,
                },
                index_state_at_page_end: crate::local_resource_diagnostics::IndexState {
                    audit_quiet_retired: context.audit_quiet_retired,
                    audit_cap_full: context.audit_cap_full,
                    pending_audits: pending,
                    overdue_audits: overdue,
                    oldest_due_age_seconds: oldest_due_age,
                },
                codex_cursor: context.cache.cursor_diagnostics(&self.codex_page),
            }
        });
        if sampled_acquisition.is_some() {
            crate::local_resource_diagnostics::cache_lifecycle_totals();
            crate::local_resource_diagnostics::codex_memo_lifecycle_totals(self.source.api_slug());
        }
        if let Some(delivery) = line_delivery.as_mut() {
            if active_file.is_none() {
                delivery.left_active();
            }
            self.resource_probe.line_delivery = Some(delivery.take_page());
        }
        let full_causes = std::mem::take(&mut self.resource_probe.full_causes);
        crate::local_resource_diagnostics::page_selection(
            self.source.api_slug(),
            crate::local_resource_diagnostics::PageSelection::ByteBudgetHit,
            u64::from(scan.page_byte_budget_hit),
        );
        self.resource_probe.page_schedule = BTreeMap::from([
            ("routine_recensus", scan.routine_recensus),
            ("page_file_limit_hit", scan.page_file_limit_hit),
            ("pending_work", scan.census_status.pending_work),
            ("first_read_progress", scan.first_read_progress),
            (
                "first_import_default_qos",
                crate::snapshot_sync::continuation::first_import_default_qos(),
            ),
        ]);
        // Only a page that read the larger singleton aggregate carries
        // the key, so ordinary rows keep their size.
        if self.codex_page.first_import() {
            self.resource_probe
                .page_schedule
                .insert("codex_first_import_page_total", true);
        }
        self.resource_probe.collection(
            self.source.api_slug(),
            crate::local_resource_diagnostics::CollectionCounts {
                scanned_files: self.scanned_file_count,
                semantic_noops: self.semantic_noop_count,
                sampled_acquisition,
                full_causes,
            },
        );
        OwnedSourceScanStep::Complete {
            index: self.index,
            scan,
        }
    }

    #[inline(never)]
    fn select_and_start(
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
            match self.index.codex_unchanged_decision(
                &mut candidate,
                &self.codex_title_metadata,
                self.audit_now,
                true,
            ) {
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
                    .candidate_requires_only_body_witness_adoption(&candidate, self.audit_now)
                    || (self.source == SnapshotSource::ClaudeCode
                        && claude_copy_prefix_reread::unchanged_requested(
                            &self.index,
                            &candidate,
                            self.audit_now,
                        )));
            let history = if self.source == SnapshotSource::ClaudeCode {
                self.index.claude_history_upgrade_decision(
                    &candidate,
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
                && self.index.claude_authority_correction_only(&candidate);
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
                        // re-read). A re-read is not a census member
                        // (G1): it never holds the census, and a walk
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
                        .gate_claude_history_candidate(&candidate, Some(hold));
                }
                HistoryDecision::Owed => self.index.gate_claude_history_candidate(&candidate, None),
                HistoryDecision::LiteralDenied => {
                    self.index.deny_claude_history_literal(&candidate);
                }
                HistoryDecision::NotOwed => {}
            }
        }
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
        #[cfg(test)]
        sampled_scan::test_hooks::after_selection(&mut self.index, parse_reason);
        if let Some(context) = self.sampling.as_ref().filter(|_| {
            self.source == SnapshotSource::Codex && !codex_archive_path(&candidate.path)
        }) {
            let wake_stamp = sampled_scan::codex_cursor::OpenStamp::capture(&opened_file)
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
                    &candidate,
                    &self.codex_title_metadata,
                    &self.claude_title_metadata,
                    self.claude_effort_support_dir.as_deref(),
                )
                .and_then(|dependencies| {
                    sampled_scan::codex_cursor::memo_digest(
                        &self.index,
                        &candidate,
                        &opened_file,
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
                        &opened_file,
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
                            .then(|| self.index.last_snapshot_fingerprint(&candidate))
                            .flatten(),
                        keep_previous
                            .then(|| self.index.last_upload_body_witness(&candidate))
                            .flatten(),
                    );
                    sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                        entry.disclosure(),
                        &candidate,
                        previous,
                        &mut self.index,
                        targets!(self),
                    );
                    // The fresh path's session count, replayed.
                    self.scanned_session_count += entry.disclosure().parsed_snapshot_count;
                    return;
                }
                match digest.as_deref().and_then(|digest| {
                    entry.grew_past_exact(&candidate.path, digest, &opened_file, &sidecar_now)
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
                    &candidate,
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
                        .then(|| self.index.last_snapshot_fingerprint(&candidate))
                        .flatten(),
                    keep_previous
                        .then(|| self.index.last_upload_body_witness(&candidate))
                        .flatten(),
                );
                sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                    &disclosure,
                    &candidate,
                    previous,
                    &mut self.index,
                    targets!(self),
                );
                return;
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
            if self.index.context_only_read(&candidate) {
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
                Some(sampled_scan::codex_cursor::PaceProbe { file: &opened_file }),
            ) {
                sampled_scan::codex_cursor::StartPlan::Defer => {
                    context.cache.cursor_note_deferred();
                    sampled_scan::codex_cursor::requeue(
                        &mut self.index,
                        &self.selected_flags,
                        &candidate,
                    );
                    return;
                }
                // Processed for this generation (K7 fence): not requeued,
                // so the census can complete; the next generation reads it.
                sampled_scan::codex_cursor::StartPlan::Fenced => return,
                sampled_scan::codex_cursor::StartPlan::Singleton
                | sampled_scan::codex_cursor::StartPlan::Cursor
                | sampled_scan::codex_cursor::StartPlan::Unpaged => {}
            }
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
                // N1 (K9): the state or sidecar census is incomplete, so
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
                        &mut active,
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
                        // N1: no acquisition even cursor-only (no current
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
                            return;
                        }
                        Err(sampled_scan::codex_cursor::StartRefusal::Unstartable) => {
                            // Never an unbounded in-page read of a file
                            // larger than the singleton budget.
                            self.census.record_unreadable_file(
                                UnreadableCause::OpenRead,
                                &active.candidate.path,
                            );
                            return;
                        }
                    }
                }
                sampled_scan::codex_cursor::StartPlan::Defer => true,
                // Processed for this generation (K7 fence).
                sampled_scan::codex_cursor::StartPlan::Fenced => {
                    self.scanned_file_count = self.scanned_file_count.saturating_sub(1);
                    return;
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
                return;
            }
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
}
