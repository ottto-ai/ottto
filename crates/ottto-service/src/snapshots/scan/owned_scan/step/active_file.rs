//! Carry one active file through reading, sealing and credit.
//! The parser, cursor proofs and read guards stay in the same scope until
//! this attempt yields. Joined aliases record their credit in that scope.

use super::*;

impl OwnedSourceScan {
    #[inline(never)]
    pub(super) fn step_active_file(
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

            self.note_claude_first_body_read(&active, before_body_read);
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
            self.record_completed_read(&active);
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
            self.note_codex_tail_repeat(&active);
            // The bytes this attempt read, taken before
            // `finish_job` consumes the acquisition's start offset. An
            // exact-stamp memo below must not cover anything past them.
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
                    entry.codex_counting_v2 = true;
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
                        entry.codex_counting_v2 = true;
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

    /// Count a Claude file's first body bytes under the reason it was read.
    #[inline(never)]
    fn note_claude_first_body_read(&self, active: &OwnedActiveFile, before_body_read: u64) {
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
                crate::local_resource_diagnostics::claude_reread::desktop_recovered_hold_body_read(
                );
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
    }

    /// Report what a file's read to its end cost: input bytes by mode,
    /// from-start replays and the read's reason.
    #[inline(never)]
    fn record_completed_read(&mut self, active: &OwnedActiveFile) {
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
    }

    /// Note a Codex singleton tail that read the same bytes again.
    #[inline(never)]
    fn note_codex_tail_repeat(&self, active: &OwnedActiveFile) {
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
    }
}
