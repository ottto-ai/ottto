//! Finish a page after selection is exhausted, consuming the scan.
//! Continuation-only pages carry their ticket and evidence out early.
//! Ordinary close folds the census before reporting the completed page.

use super::*;

impl OwnedSourceScan {
    #[inline(never)]
    pub(super) fn close_scan_page(
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
}
