//! The owned source scan's page step: one call reads the next page of the
//! selected files, applies it to the index and returns either the scan to
//! resume or the completed result.
use crate::snapshots::*;
use tail_source::refold_moved::unchanged;
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
        self,
        attribution_context: Option<&crate::session_attribution::SessionAttributionContext>,
    ) -> Result<OwnedSourceScanStep, crate::source_rotation::LocalRefusal> {
        if !self.index.persistence_available() {
            return Err(crate::source_rotation::LocalRefusal(
                "scan_index_map_unavailable",
            ));
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
        let Self {
            mut resource_probe,
            mut sampling,
            index: mut index_storage,
            source,
            roots,
            collected_at,
            audit_now,
            backfill_window_days,
            file_limit,
            claude_request_identity_capture,
            claude_effort_support_dir,
            codex_title_metadata,
            claude_title_metadata,
            state_census_complete,
            sidecar_census_complete,
            codex_turn_traces,
            codex_census_valid,
            census_window_end,
            discovered_file_count,
            census_unix_seconds,
            mut census,
            mut snapshots,
            mut scanned_file_count,
            mut scanned_session_count,
            mut semantic_noop_count,
            mut history_upgrade,
            mut context_read_budget,
            mut residue_index_keys,
            mut settled_residue_index_keys,
            mut pending_finalization,
            claude_authority_preflight,
            mut forced_claude_family_reparses,
            claude_twin_schedule,
            claude_family_shadow,
            mut identified_candidates,
            active_file: active_frame,
            mut codex_join_inventory,
            mut codex_join_prepared,
            mut codex_join_groups,
            mut codex_join_active,
            mut codex_join_completed,
            mut codex_legacy_join_baselines,
            mut codex_page,
            codex_selected_flags,
            mut continuation_ticket,
            mut line_delivery,
            codex_versions,
            launch_events,
        } = self;
        let scan_launch_events = launch_events.clone();
        let launch_lookup = attribution_context
            .map(|context| context.launch_events())
            .or(scan_launch_events.as_deref());
        // Held while this scan object runs the shared cursor job.
        let (mut active_file, mut codex_cursor_lease) = active_frame.into_parts();
        let index = &mut index_storage;
        let claude_effort_support_dir_ref = claude_effort_support_dir.as_deref();
        // Construct the large continuation once. Repeating it in every yield
        // branch multiplies debug-build stack slots and can overflow native
        // callers even though the retained scanner state is unchanged.
        'scan_step: {
            macro_rules! pending {
                () => {
                    break 'scan_step
                };
            }
            // Every Codex disclosure in this step writes into the same five
            // step-local sinks.
            macro_rules! targets {
                () => {
                    sampled_scan::codex_cursor::DisclosureTargets {
                        census: &mut census,
                        residue_index_keys: &mut residue_index_keys,
                        pending_finalization: &mut pending_finalization,
                    }
                };
            }
            if source == SnapshotSource::Codex && !codex_join_prepared {
                if let Some(inventory) = codex_join_inventory.as_mut() {
                    if !inventory.step_selected(
                        &codex_title_metadata,
                        index,
                        &codex_selected_flags,
                        sampling.as_ref().map(|context| &context.cache),
                    ) {
                        pending!();
                    }
                    let selected = identified_candidates
                        .iter()
                        .map(|candidate| local_index_key(&candidate.path))
                        .collect::<BTreeSet<_>>();
                    let inventoried = inventory
                        .headers
                        .iter()
                        .map(|header| local_index_key(&header.candidate.path))
                        .collect::<BTreeSet<_>>();
                    inventory.complete &= selected.difference(&inventoried).all(|key| {
                        let owners = codex_session_id_candidates_from_path(Path::new(key));
                        !owners.is_empty()
                            && owners
                                .iter()
                                .all(|owner| inventory.held_owners.contains(owner))
                    });
                    let current_owners = inventory
                        .headers
                        .iter()
                        .map(|header| {
                            (
                                local_index_key(&header.candidate.path),
                                codex_protected_owner(&header.owner),
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    let absence_coverage = inventory.held_owners.is_empty()
                        && codex_counting_version::absence_coverage_complete(index, inventory);
                    codex_counting_version::note_inventory_created(index, inventory);
                    codex_counting_version::prepare_moved_evidence(
                        index,
                        &current_owners,
                        absence_coverage,
                    );
                    let mut repurposed_protected_paths = BTreeSet::new();
                    let mut missing_protected_owners = BTreeSet::new();
                    let mut missing_unknown_owner = false;
                    for owner in index.decode_held_codex_owners() {
                        match owner {
                            Some(owner) => {
                                missing_protected_owners.insert(owner.to_owned());
                            }
                            None => missing_unknown_owner = true,
                        }
                    }
                    for (key, entry) in &index.files {
                        let repurposed = entry.codex_history_is_protected()
                            && entry
                                .codex_protected_owner
                                .as_ref()
                                .is_some_and(|previous| {
                                    current_owners
                                        .get(key)
                                        .is_some_and(|current| current != previous)
                                });
                        if repurposed {
                            repurposed_protected_paths.insert(key.clone());
                        }
                        if entry.codex_history_is_protected()
                            && (!inventoried.contains(key) || repurposed)
                        {
                            if let Some(owner) = entry
                                .codex_protected_owner
                                .as_ref()
                                .filter(|owner| valid_codex_protected_owner(owner))
                            {
                                missing_protected_owners.insert(owner.clone());
                            } else {
                                missing_unknown_owner = true;
                            }
                        }
                    }
                    let affected_owners = inventory.affected_owners();
                    census.unreadable_path_count += inventory.refused.len();
                    census.unreadable_causes.merge(inventory.unreadable_causes);
                    let mut grouped_paths = BTreeSet::new();
                    let mut used = 0usize;
                    // R2-N6: a group with more members than the page's file
                    // limit is never excluded; it goes first and takes a page
                    // of its own (it pages through the cursor like any group).
                    // So does a group whose probes outran a page's
                    // remaining singleton budget (`ProbeBudgetOrder`).
                    let fence = sampled_scan::codex_cursor::census_token(index);
                    let own_page = |group: &codex_file_join::Group| {
                        group.members.len() > file_limit
                            || sampling.as_ref().is_some_and(|context| {
                                context.cache.group_own_page(
                                    &context.namespace,
                                    &codex_file_join::job_key(group),
                                    fence.as_deref(),
                                )
                            })
                    };
                    let mut groups = inventory
                        .groups()
                        .into_values()
                        .map(|group| (own_page(&group), group))
                        .collect::<Vec<_>>();
                    // Context-only groups spend only the file allowance left by
                    // ordinary groups. Partition before admission can defer a
                    // group; sorting the admitted queue would be too late.
                    groups.sort_by_key(|(own, group)| {
                        (
                            index.file_upload_context_enabled()
                                && group
                                    .members
                                    .iter()
                                    .all(|member| index.context_only_read(member)),
                            !*own,
                            !sampled_scan::codex_cursor::census_member(
                                &codex_selected_flags,
                                group.members.iter().map(|member| member.path.as_path()),
                            ),
                        )
                    });
                    let mut ordinary_singleton_slots = None;
                    for (own, group) in groups {
                        if group
                            .members
                            .iter()
                            .any(|member| index.decode_holds_file(&local_index_key(&member.path)))
                        {
                            grouped_paths.extend(
                                group
                                    .members
                                    .iter()
                                    .map(|member| local_index_key(&member.path)),
                            );
                            index.mark_bounded_sweep_unsettled();
                            continue;
                        }
                        let protected_history_missing = missing_unknown_owner
                            || missing_protected_owners
                                .contains(&codex_protected_owner(&group.owner));
                        let previously_joined = group.members.iter().any(|member| {
                            index
                                .files
                                .get(&local_index_key(&member.path))
                                .is_some_and(|entry| {
                                    entry.codex_joined_member_set.is_some()
                                        || entry.codex_captured_joined_member_set.is_some()
                                })
                        });
                        if (group.members.len() < 2
                            && !previously_joined
                            && !protected_history_missing
                            && inventory
                                .membership_complete(&group.owner, affected_owners.as_ref()))
                            || !group
                                .members
                                .iter()
                                .any(|member| selected.contains(&local_index_key(&member.path)))
                        {
                            continue;
                        }
                        grouped_paths.extend(
                            group
                                .members
                                .iter()
                                .map(|member| local_index_key(&member.path)),
                        );
                        // §d.1.2 c: a paused or active cursor job owns a
                        // member. Its selected members stay pending (holding
                        // the census) and are not read again while it lives.
                        if sampling.as_ref().is_some_and(|context| {
                            group.members.iter().any(|member| {
                                context
                                    .cache
                                    .cursor_job_owns(&local_index_key(&member.path))
                            })
                        }) {
                            let owned = group
                                .members
                                .iter()
                                .filter(|member| selected.contains(&local_index_key(&member.path)))
                                .collect::<Vec<_>>();
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                owned,
                            );
                            continue;
                        }
                        let malformed_pending = group.members.iter().any(|member| {
                            index
                                .files
                                .get(&local_index_key(&member.path))
                                .is_some_and(|entry| {
                                    entry
                                        .codex_captured_joined_member_set
                                        .as_deref()
                                        .is_some_and(|marker| {
                                            !codex_file_join::valid_captured_join(marker)
                                        })
                                })
                        });
                        if !inventory.membership_complete(&group.owner, affected_owners.as_ref())
                            || malformed_pending
                            || protected_history_missing
                            || group.members.iter().any(|member| {
                                repurposed_protected_paths.contains(&local_index_key(&member.path))
                            })
                            || group.members.len() < 2
                        {
                            census.ownership_incomplete_file_count += group.members.len();
                            census.causes.add(ownership::INVENTORY, group.members.len());
                            census.record_unreadable(UnreadableCause::AliasParser, 1);
                            residue_index_keys.extend(
                                group
                                    .members
                                    .iter()
                                    .map(|member| local_index_key(&member.path)),
                            );
                            continue;
                        }
                        // G1: a group whose attempt already ended in this
                        // generation is fenced at its pop (M-5 b) and reads
                        // nothing. Decide it here, so it takes no file
                        // allowance a waiting census member needs.
                        let fenced = sampling.as_ref().is_some_and(|context| {
                            context.cache.group_fenced(
                                &context.namespace,
                                &codex_file_join::job_key(&group),
                                fence.as_deref(),
                            )
                        });
                        // G1: a group whose selected members are all re-reads
                        // never takes file allowance a waiting census-member
                        // singleton needs (own page or not). It waits for a
                        // page without one; its members stay pending as
                        // re-reads.
                        let rereads_crowd_members = !fenced
                            && !sampled_scan::codex_cursor::census_member(
                                &codex_selected_flags,
                                group.members.iter().map(|member| member.path.as_path()),
                            )
                            && {
                                let waiting = identified_candidates
                                    .iter()
                                    .filter(|candidate| {
                                        let key = local_index_key(&candidate.path);
                                        !grouped_paths.contains(&key)
                                            && sampled_scan::codex_cursor::selected_census_member(
                                                &codex_selected_flags,
                                                &candidate.path,
                                            )
                                    })
                                    .count();
                                waiting > 0
                                    && (own || used + group.members.len() + waiting > file_limit)
                            };
                        // Ordinary groups have already spent their slots. Before
                        // the first context group, reserve the remaining ordinary
                        // singletons too; catch-up must never evict one below.
                        let context_group = index.file_upload_context_enabled()
                            && group
                                .members
                                .iter()
                                .all(|member| index.context_only_read(member));
                        let waiting_ordinary = if context_group {
                            *ordinary_singleton_slots.get_or_insert_with(|| {
                                identified_candidates
                                    .iter()
                                    .filter(|candidate| {
                                        !grouped_paths.contains(&local_index_key(&candidate.path))
                                            && !index.context_only_read(candidate)
                                            && index
                                                .candidate_decision_with_reason_at(
                                                    candidate,
                                                    sampled_scan::now_seconds(),
                                                )
                                                .0
                                                != CandidateDecision::Skip
                                    })
                                    .count()
                            })
                        } else {
                            0
                        };
                        let context_crowds_ordinary = !fenced
                            && waiting_ordinary > 0
                            && (own
                                || used
                                    .saturating_add(group.members.len())
                                    .saturating_add(waiting_ordinary)
                                    > file_limit);
                        if context_crowds_ordinary
                            || rereads_crowd_members
                            || (!fenced
                                && used > 0
                                && (own || used + group.members.len() > file_limit))
                        {
                            // Keep the existing traversal as the only queue. A whole
                            // group is selected on a subsequent ordinary page.
                            if let Some(traversal) = index.traversal.as_mut() {
                                for member in &group.members {
                                    if selected.contains(&local_index_key(&member.path)) {
                                        traversal.pending_candidates.push_back(ScanTraversalPath {
                                            scan_root: member.scan_root.clone(),
                                            path: member.path.clone(),
                                            // G1: a re-read is not re-enrolled.
                                            census_member:
                                                sampled_scan::codex_cursor::selected_census_member(
                                                    &codex_selected_flags,
                                                    &member.path,
                                                ),
                                            watcher_hint: false,
                                        });
                                    }
                                }
                            }
                            continue;
                        }
                        if !fenced {
                            used += group.members.len();
                            if own {
                                // Nothing else joins its page.
                                used = used.max(file_limit);
                            }
                        }
                        if let Some(traversal) = index.traversal.as_mut() {
                            // R2-L3: one set per group, not a member scan per
                            // pending path.
                            let paths = group
                                .members
                                .iter()
                                .map(|member| member.path.as_path())
                                .collect::<std::collections::HashSet<_>>();
                            traversal
                                .pending_candidates
                                .retain(|pending| !paths.contains(pending.path.as_path()));
                        }
                        if !fenced {
                            codex_join_groups.push_back(group);
                        }
                    }
                    identified_candidates.retain(|candidate| {
                        !grouped_paths.contains(&local_index_key(&candidate.path))
                    });
                    let held = identified_candidates
                        .iter()
                        .filter(|candidate| {
                            !inventory
                                .owner_for_path(&candidate.path)
                                .is_some_and(|owner| {
                                    inventory.membership_complete(owner, affected_owners.as_ref())
                                })
                        })
                        .map(|candidate| local_index_key(&candidate.path))
                        .collect::<BTreeSet<_>>();
                    census.ownership_incomplete_file_count += held.len();
                    census.causes.add(ownership::INVENTORY, held.len());
                    residue_index_keys.extend(held.iter().cloned());
                    identified_candidates
                        .retain(|candidate| !held.contains(&local_index_key(&candidate.path)));
                    while !identified_candidates.is_empty()
                        && used + identified_candidates.len() > file_limit
                    {
                        // G1: re-reads leave before any census member.
                        let context_evict = index
                            .file_upload_context_enabled()
                            .then(|| {
                                let disposable = |candidate: &CandidateFile| {
                                    index.context_only_read(candidate)
                                        || index
                                            .candidate_decision_with_reason_at(
                                                candidate,
                                                sampled_scan::now_seconds(),
                                            )
                                            .0
                                            == CandidateDecision::Skip
                                };
                                identified_candidates
                                    .iter()
                                    .rposition(|candidate| {
                                        disposable(candidate)
                                            && !sampled_scan::codex_cursor::selected_census_member(
                                                &codex_selected_flags,
                                                &candidate.path,
                                            )
                                    })
                                    .or_else(|| identified_candidates.iter().rposition(disposable))
                            })
                            .flatten();
                        let evict = context_evict
                            .or_else(|| {
                                identified_candidates.iter().rposition(|candidate| {
                                    !sampled_scan::codex_cursor::selected_census_member(
                                        &codex_selected_flags,
                                        &candidate.path,
                                    )
                                })
                            })
                            .unwrap_or(identified_candidates.len() - 1);
                        if let Some(candidate) = identified_candidates.remove(evict) {
                            if let Some(traversal) = index.traversal.as_mut() {
                                // G1: a re-read is not re-enrolled.
                                let census_member =
                                    sampled_scan::codex_cursor::selected_census_member(
                                        &codex_selected_flags,
                                        &candidate.path,
                                    );
                                traversal.pending_candidates.push_front(ScanTraversalPath {
                                    scan_root: candidate.scan_root,
                                    path: candidate.path,
                                    census_member,
                                    watcher_hint: false,
                                });
                            }
                        }
                    }
                }
                if index.file_upload_context_enabled() {
                    codex_join_groups
                        .make_contiguous()
                        .sort_by_cached_key(|group| {
                            group
                                .members
                                .iter()
                                .all(|candidate| index.context_only_read(candidate))
                        });
                }
                codex_join_prepared = true;
                pending!();
            }
            if let Some(mut boot) = codex_join_active.take() {
                if boot
                    .group
                    .members
                    .iter()
                    .any(|candidate| context_read_budget.is_admitted(candidate))
                {
                    // The group's cursor shares the room left by ordinary
                    // native reads, just like a singleton or resumed cursor.
                    context_read_budget.charge_cursor_ordinary(&mut codex_page);
                }
                // R2-N2: a group larger than the singleton budget asks for
                // the cursor before its first header read; one that would
                // wait (or is fenced) reads no header or probe this page.
                // Only after the unchanged decision, and
                // never for a group with a memo entry or parked record: those
                // reach their lookups first and leave without the slot.
                if let Some(context) = sampling.as_ref().filter(|context| {
                    boot.awaits_read()
                        && !boot.independent()
                        && crate::heap_layout_bound::layout_supported()
                        && boot.expected_bytes()
                            > sampled_scan::codex_cursor::Limits::current().singleton()
                        && !context.cache.group_recorded(&context.namespace, &boot.key)
                }) {
                    match context.cache.cursor_plan(
                        &mut codex_page,
                        sampled_scan::codex_cursor::Limits::current(),
                        boot.expected_bytes(),
                        codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                        true,
                        &context.namespace,
                        &boot.key,
                        sampled_scan::codex_cursor::census_token(index).as_deref(),
                        sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            boot.group
                                .members
                                .iter()
                                .map(|member| member.path.as_path()),
                        ),
                    ) {
                        sampled_scan::codex_cursor::StartPlan::Defer => {
                            context.cache.cursor_note_deferred();
                            if boot.own_page {
                                context
                                    .cache
                                    .request_group_own_page(&context.namespace, &boot.key);
                            }
                            scanned_file_count =
                                scanned_file_count.saturating_sub(boot.group.members.len());
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &boot.group.members,
                            );
                            pending!();
                        }
                        sampled_scan::codex_cursor::StartPlan::Fenced => {
                            scanned_file_count =
                                scanned_file_count.saturating_sub(boot.group.members.len());
                            pending!();
                        }
                        _ => {}
                    }
                }
                boot.allow_probe_bytes(
                    codex_page.singleton_remaining(sampled_scan::codex_cursor::Limits::current()),
                );
                let outcome = boot.step_with_cache(
                    launch_lookup,
                    index,
                    sampling.as_ref().map(|context| &context.cache),
                );
                // Header and probe bytes are singleton-budget reads (§d.2).
                let boot_input = boot.take_charge();
                codex_page.charge(false, boot_input);
                let members = boot.group.members.len();
                match outcome {
                    codex_file_join::Boot::Pending => {
                        codex_join_active = Some(boot);
                        pending!();
                    }
                    codex_file_join::Boot::Unchanged => {
                        // The accepted joined body is current, with no job
                        // or debt. Nothing read for a job; it does not wait.
                        if let Some(context) = sampling.as_ref() {
                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                        }
                        semantic_noop_count += members;
                        census.note_codex_group(CodexSelection::GroupUnchanged, members);
                        if !boot.independent() {
                            codex_join_completed.push(boot.group);
                        }
                        pending!();
                    }
                    codex_file_join::Boot::Strict => {
                        if let Some(context) = sampling.as_ref() {
                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                        }
                        codex_file_join::disclose_strict(&boot.group.members, targets!());
                        pending!();
                    }
                    codex_file_join::Boot::Refused(_reason) => {
                        // Decided from headers at no replay cost: terminal
                        // debt (outcome R), fenced, never memoized.
                        if let Some(context) = sampling.as_ref() {
                            context.cache.group_attempted(
                                &context.namespace,
                                &boot.key,
                                sampled_scan::codex_cursor::census_token(index).as_deref(),
                            );
                        }
                        codex_file_join::disclose_members(
                            &codex_file_join::refusal_disclosure(),
                            &boot.group.members,
                            index,
                            targets!(),
                        );
                        pending!();
                    }
                    codex_file_join::Boot::Ready => {
                        census.note_codex_group(CodexSelection::GroupSelected, members);
                    }
                }
                let expected = boot.expected_bytes();
                let dependencies = boot.dependencies(&codex_title_metadata);
                let mut paged = false;
                if let Some(context) = sampling.as_ref() {
                    let live_file = boot.live().and_then(|(live, _)| {
                        open_candidate_file_stat_retained(
                            SnapshotSource::Codex,
                            &mut live.clone(),
                            Some(&context.cache),
                            false,
                        )
                        .ok()
                        .map(|(file, _)| file)
                    });
                    let wake_stamp =
                        boot.live()
                            .zip(live_file.as_ref())
                            .and_then(|((live, _), file)| {
                                sampled_scan::codex_cursor::OpenStamp::capture(file)
                                    .ok()
                                    .map(|stamp| context.cache.retained_stamp(&live.path, stamp))
                            });
                    let memo_key =
                        sampled_scan::codex_cursor::memo_key(&context.namespace, &boot.key);
                    if let Some(entry) = context.cache.memo_lookup(&memo_key) {
                        // The match re-reads two samples of the live member.
                        codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                        let hit = boot
                            .memo_digest(index, &codex_title_metadata)
                            .zip(live_file.as_ref())
                            .and_then(|(digest, file)| {
                                entry.matches_stamp(
                                    &boot.live()?.0.path,
                                    &digest,
                                    file,
                                    "",
                                    wake_stamp.clone()?,
                                )
                            });
                        if let Some(stamp) = hit {
                            // No wake dependency changed: the same terminal
                            // debt again, per member, at zero replay bytes.
                            context.cache.memo_hit(&memo_key, stamp);

                            context.cache.cursor_unwait(&context.namespace, &boot.key);
                            codex_file_join::disclose_members(
                                entry.disclosure(),
                                &boot.group.members,
                                index,
                                targets!(),
                            );
                            pending!();
                        }
                        context.cache.memo_forget(&memo_key);
                    }
                    let parked = context.cache.cursor_parked_stamp(
                        &boot.key,
                        wake_stamp,
                        dependencies.as_deref(),
                    );
                    if let Some(disclosure) = parked {
                        context.cache.cursor_unwait(&context.namespace, &boot.key);
                        codex_file_join::disclose_members(
                            &disclosure,
                            &boot.group.members,
                            index,
                            targets!(),
                        );
                        pending!();
                    }
                    match context.cache.cursor_plan(
                        &mut codex_page,
                        sampled_scan::codex_cursor::Limits::current(),
                        expected,
                        codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                        crate::heap_layout_bound::layout_supported() && !boot.independent(),
                        &context.namespace,
                        &boot.key,
                        sampled_scan::codex_cursor::census_token(index).as_deref(),
                        sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            boot.group
                                .members
                                .iter()
                                .map(|member| member.path.as_path()),
                        ),
                    ) {
                        sampled_scan::codex_cursor::StartPlan::Singleton => {}
                        sampled_scan::codex_cursor::StartPlan::Cursor => paged = true,
                        sampled_scan::codex_cursor::StartPlan::Unpaged => {
                            codex_page.disclose_disabled(&context.cache);
                        }
                        sampled_scan::codex_cursor::StartPlan::Defer => {
                            // The whole group waits its turn on a later page.
                            context.cache.cursor_note_deferred();
                            if boot.own_page {
                                context
                                    .cache
                                    .request_group_own_page(&context.namespace, &boot.key);
                            }
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &boot.group.members,
                            );
                            pending!();
                        }
                        // Processed for this generation (K7 fence).
                        sampled_scan::codex_cursor::StartPlan::Fenced => {
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            pending!();
                        }
                    }
                }
                // No group byte or member cap: a group larger than
                // the singleton budget pages through the cursor; without one
                // (unsupported layout, uncached scan) it is read in one page
                // like an ordinary unpaged read; group bytes are uncapped.
                let active_dependencies = boot.live().map(|(live, _)| {
                    sampled_scan::codex_cursor::group_dependencies(
                        &boot.group.members,
                        &live.path,
                        &codex_title_metadata,
                        |member| member.opened_object_identity.clone(),
                    )
                });
                let group_members = boot.group.members.clone();
                let boot_key = boot.key.clone();
                let job = boot.into_job(codex_file_join::JobInputs {
                    metadata: &codex_title_metadata,
                    traces: codex_turn_traces.clone(),
                    cache: sampling.as_ref().map(|context| &context.cache),
                    index,
                });
                let Ok(mut job) = job else {
                    // No lease exists yet; a waiter it left is
                    // dropped like the boot-`Strict` exit's.
                    if let Some(context) = sampling.as_ref() {
                        context.cache.cursor_unwait(&context.namespace, &boot_key);
                    }
                    codex_file_join::disclose_strict(&group_members, targets!());
                    pending!();
                };
                if let Some(context) = sampling.as_ref().filter(|_| paged) {
                    match context.cache.cursor_start_group(
                        &mut job,
                        &context.namespace,
                        active_dependencies,
                        state_census_complete && sidecar_census_complete,
                        index,
                    ) {
                        Ok(lease) => {
                            // The members hold the strict census until the
                            // job's attempt ends (accepted or debt).
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &group_members,
                            );
                            codex_cursor_lease = Some(lease);
                        }
                        Err(sampled_scan::codex_cursor::StartRefusal::Busy) => {
                            context.cache.cursor_note_deferred();
                            scanned_file_count = scanned_file_count.saturating_sub(members);
                            sampled_scan::codex_cursor::requeue_members(
                                index,
                                &codex_selected_flags,
                                &group_members,
                            );
                            pending!();
                        }
                        // Never an unbounded in-page read of a group larger
                        // than the singleton budget (compressed members > B
                        // keep refusing, named debt).
                        Err(_) => {
                            match group_members.first() {
                                Some(member) => census.record_unreadable_file(
                                    UnreadableCause::OpenRead,
                                    &member.path,
                                ),
                                None => census.record_unreadable(UnreadableCause::OpenRead, 1),
                            }
                            pending!();
                        }
                    }
                }
                active_file = Some(job);
                pending!();
            }
            if source == SnapshotSource::Codex
                && active_file.is_none()
                && codex_join_active.is_none()
            {
                // A lease without an active file means this scan lost its job
                // on an error path; dropping the lease frees the slot.
                codex_cursor_lease = None;
                if let Some(context) = sampling.as_ref() {
                    codex_page.note_page(&context.cache);
                }
                // At most one resume attempt per page, and none on a page
                // that selected no candidates (no header inventory: no
                // evidence for the job this page). A deferred job therefore
                // never spins within a page.
                if let Some(context) = sampling.as_ref().filter(|_| {
                    !codex_page.cursor_exhausted(sampled_scan::codex_cursor::Limits::current())
                        && codex_join_inventory.is_some()
                        && (!codex_page.continuation() || codex_census_valid)
                        && (!index.file_upload_context_enabled()
                            || !identified_candidates.iter().any(|candidate| {
                                !index.context_only_read(candidate)
                                    && index
                                        .candidate_decision_with_reason_at(
                                            candidate,
                                            sampled_scan::now_seconds(),
                                        )
                                        .0
                                        == CandidateDecision::Parse
                            }))
                        && (!index.file_upload_context_enabled()
                            || !codex_join_groups.iter().any(|group| {
                                group
                                    .members
                                    .iter()
                                    .any(|candidate| !index.context_only_read(candidate))
                            }))
                        && codex_page.claim_resume()
                }) {
                    // Continuing the paused job is the highest scheduling class.
                    match sampled_scan::codex_cursor::resume_paused_job(
                        sampled_scan::codex_cursor::ResumeContext {
                            source,
                            sampling: context,
                            codex: &codex_title_metadata,
                            claude: &claude_title_metadata,
                            support: claude_effort_support_dir_ref,
                            traces: codex_turn_traces.clone(),
                            inventory: codex_join_inventory.as_ref(),
                            flags: &codex_selected_flags,
                            census_complete: state_census_complete && sidecar_census_complete,
                            continuation: codex_page.continuation(),
                            ordinary_equivalent: codex_page.ordinary_equivalent(),
                        },
                        index,
                        &mut identified_candidates,
                        targets!(),
                    ) {
                        sampled_scan::codex_cursor::Resumed::Active(job, lease) => {
                            if index.context_only_read(&job.candidate) {
                                let admitted = if job.aliases.is_empty() {
                                    context_read_budget.admit(
                                        source,
                                        index,
                                        &job.candidate,
                                        &snapshots,
                                    )
                                } else {
                                    context_read_budget.admit_unit(
                                        source,
                                        index,
                                        &job.aliases,
                                        &snapshots,
                                    )
                                };
                                if !admitted {
                                    // Return the intact parser and lease, never restart a Full.
                                    drop(sampled_scan::codex_cursor::ActiveFrame::new(
                                        Some(job),
                                        Some(lease),
                                    ));
                                    pending!();
                                }
                                context_read_budget.charge_cursor_ordinary(&mut codex_page);
                            }
                            codex_cursor_lease = Some(lease);
                            active_file = Some(job);
                            pending!();
                        }
                        // Deferred, invalidated or ended as strict debt: this
                        // page is spent; a pending path resumes or restarts.
                        sampled_scan::codex_cursor::Resumed::Spent => pending!(),
                        sampled_scan::codex_cursor::Resumed::Idle => {}
                    }
                }
                // Stage 1 hunk D: a continuation page only resumes. Without
                // an active job it plans and starts nothing: every path it
                // identified, and every group it prepared, goes back to the
                // queue untouched, and the page finishes.
                if codex_page.continuation() {
                    for candidate in identified_candidates.drain(..) {
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                    }
                    for group in codex_join_groups.drain(..) {
                        sampled_scan::codex_cursor::requeue_members(
                            index,
                            &codex_selected_flags,
                            &group.members,
                        );
                    }
                }
            }
            // G1 (fix 2): a group whose selected members are all re-reads
            // waits until this page's census singletons are read, so its
            // replay cannot spend the singleton budget a first read needs.
            // Evaluated between files only, and the candidate scan only when
            // the next group is a re-read.
            let rereads_wait = || {
                codex_join_groups.front().is_some_and(|group| {
                    (!index.file_upload_context_enabled()
                        || group
                            .members
                            .iter()
                            .all(|candidate| index.context_only_read(candidate)))
                        && !sampled_scan::codex_cursor::census_member(
                            &codex_selected_flags,
                            group.members.iter().map(|member| member.path.as_path()),
                        )
                }) && identified_candidates.iter().any(|candidate| {
                    sampled_scan::codex_cursor::selected_census_member(
                        &codex_selected_flags,
                        &candidate.path,
                    )
                })
            };
            let context_group_waits = index.file_upload_context_enabled()
                && codex_join_groups.front().is_some_and(|group| {
                    group
                        .members
                        .iter()
                        .all(|candidate| index.context_only_read(candidate))
                })
                && identified_candidates.iter().any(|candidate| {
                    !index.context_only_read(candidate)
                        && index
                            .candidate_decision_with_reason_at(
                                candidate,
                                sampled_scan::now_seconds(),
                            )
                            .0
                            == CandidateDecision::Parse
                });
            if active_file.is_none() && !rereads_wait() && !context_group_waits {
                if let Some(group) = codex_join_groups.pop_front() {
                    if index.file_upload_context_enabled()
                        && group
                            .members
                            .iter()
                            .all(|candidate| index.context_only_read(candidate))
                        && !context_read_budget.admit_unit(
                            source,
                            index,
                            &group.members,
                            &snapshots,
                        )
                    {
                        sampled_scan::codex_cursor::requeue_members(
                            index,
                            &codex_selected_flags,
                            &group.members,
                        );
                        pending!();
                    }
                    if group
                        .members
                        .iter()
                        .any(|member| index.decode_holds_file(&local_index_key(&member.path)))
                    {
                        index.mark_bounded_sweep_unsettled();
                        pending!();
                    }
                    // M-5 (b): a group whose attempt already ended as terminal
                    // debt in this generation is not attempted again; its
                    // members were disclosed then.
                    let fenced = sampling.as_ref().is_some_and(|context| {
                        context.cache.group_fenced(
                            &context.namespace,
                            &codex_file_join::job_key(&group),
                            sampled_scan::codex_cursor::census_token(index).as_deref(),
                        )
                    });
                    if !fenced {
                        scanned_file_count += group.members.len();
                        let mut boot = Box::new(codex_file_join::GroupBoot::new(group, index));
                        if let Some(context) = sampling.as_ref() {
                            boot.own_page = context
                                .cache
                                .take_group_own_page(&context.namespace, &boot.key);
                        }
                        codex_join_active = Some(boot);
                    }
                    pending!();
                }
            }
            if let Some(mut active) = active_file.take() {
                let compressed = active.parser.reader.reader.is_compressed();
                let _input_qos = compressed
                    .then(crate::snapshot_sync::continuation::MacPlatformSignals::background);

                if active.parser.reader.reader.is_compressed()
                    && codex_page.singleton_remaining(sampled_scan::codex_cursor::Limits::current())
                        == 0
                {
                    codex_page.continue_singleton();
                    active_file = Some(active);
                    pending!();
                }
                let before_body_read = active.parser.reader.consumed_bytes();
                if let Some(delivery) = line_delivery.as_mut() {
                    delivery.begin_armed(&active, &roots);
                }
                let mut group_end = None;
                let stepped = if active.group.is_some() {
                    // A group job: one record of the current member, or one
                    // member transition (P2).
                    let live_scope = |member: &CandidateFile| {
                        let context = sampling.as_ref()?;
                        let dependency = sampled_scan::reduction_dependencies(
                            source,
                            member,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        )?;
                        Some(context.file_scope(source, member, &dependency))
                    };
                    match codex_file_join::step_group(
                        &mut active,
                        &codex_file_join::StepInputs {
                            metadata: &codex_title_metadata,
                            attribution: attribution_context,
                            live_scope: &live_scope,
                            cache: sampling.as_ref().map(|context| &context.cache),
                            collected_at: &collected_at,
                            index,
                        },
                    ) {
                        codex_file_join::GroupStep::Read(result) => result,
                        codex_file_join::GroupStep::End(end) => {
                            group_end = Some(end);
                            Ok(false)
                        }
                    }
                } else if let Some(delivery) = line_delivery.as_mut() {
                    delivery.step(&mut active.parser)
                } else {
                    active.parser.step()
                };
                context_read_budget.record(
                    index,
                    &active.candidate,
                    active.cursor.is_some(),
                    active
                        .parser
                        .reader
                        .consumed_bytes()
                        .saturating_sub(before_body_read),
                );

                if source == SnapshotSource::ClaudeCode
                    && before_body_read == 0
                    && active.parser.reader.consumed_bytes() > 0
                {
                    // Count only the first actual body bytes. SourceChanged
                    // includes Desktop/usage sidecar and object revisions;
                    // ScopeChanged also catches a metadata change concurrent
                    // with growth (whose selection reason is TranscriptChanged).
                    // LegacyIdentity is the separate one-time legacy upgrade.
                    if claude_title_metadata
                        .recovered_account_holds
                        .contains(&local_index_key(&active.candidate.path))
                    {
                        crate::local_resource_diagnostics::claude_reread::desktop_recovered_hold_body_read();
                    } else {
                        match index.candidate_decision_with_reason_at(&active.candidate, audit_now).1 {
                            Some(CandidateParseReason::LegacyIdentity) => {
                                crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(true);
                            }
                            reason if reason == Some(CandidateParseReason::SourceChanged)
                                || active.sampling.as_ref().is_some_and(|read| matches!(read.mode,
                                    crate::transcript_acquisition::ReadMode::Full(crate::transcript_acquisition::FullReason::ScopeChanged))) => {
                                crate::local_resource_diagnostics::claude_reread::desktop_revision_body_read(false);
                            }
                            _ => {}
                        }
                    }
                }
                if source == SnapshotSource::Codex {
                    let consumed = active.parser.reader.consumed_bytes();
                    let moved = codex_file_join::take_charge(&mut active);
                    codex_page.charge(
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
                            sampling: sampling.as_ref(),
                            index,
                            targets: targets!(),
                        },
                    );
                    pending!();
                }
                match stepped {
                    Ok(false) => {
                        // Stage 1 (K6): or a continuation page past its
                        // deadline, which pauses without a ticket.
                        if active.cursor.is_some()
                            && codex_page.cursor_stop(sampled_scan::codex_cursor::Limits::current())
                        {
                            if let Some(lease) = codex_cursor_lease.take() {
                                // Stage 1 hunk A: minted before the pause
                                // consumes the job, kept only if it pauses.
                                let ticket = sampling.as_ref().and_then(|context| {
                                    context.cache.continuation_ticket(&active, &codex_page)
                                });
                                continuation_ticket = None;
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
                                        index,
                                        targets!(),
                                    );
                                    sampled_scan::codex_cursor::dequeue_members(
                                        index,
                                        sampled_scan::codex_cursor::job_files(&job),
                                    );
                                } else {
                                    continuation_ticket = ticket;
                                }
                                pending!();
                            }
                            // A job without its lease is dropped, never
                            // continued in-page past the budget; its pending
                            // path restarts it (L2).
                            if let Some(context) = sampling.as_ref() {
                                context.cache.cursor_note_lost();
                            }
                            pending!();
                        }
                        active_file = Some(active);
                        pending!();
                    }
                    Err(error) => {
                        // Static reader text only, never a path or content. A
                        // live rollout appended while it is read reports
                        // "acquisition exceeds stable source"; that file is
                        // retried when its next write is hinted.
                        eprintln!(
                            "local snapshot scan: {} transcript read failed: {error}",
                            source.api_slug()
                        );
                        if let Some(lease) = codex_cursor_lease.take() {
                            lease.release();
                        }
                        if let Some(group) = active.group.as_ref() {
                            // A member read failure: strict, as before P2.
                            codex_file_join::disclose_strict(&group.members, targets!());
                            sampled_scan::codex_cursor::dequeue_members(index, &group.members);
                            pending!();
                        }
                        if active.cursor.is_some() {
                            sampled_scan::codex_cursor::dequeue(index, &active.candidate);
                        }
                        if source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                index,
                                &active.candidate.path,
                            );
                        }
                        if sampled_scan::codex_cursor::requeue_refused(
                            source,
                            &error,
                            index,
                            &codex_selected_flags,
                            &active.candidate,
                        ) {
                            active.parser.reader.reader.close();
                            pending!();
                        }
                        active.parser.reader.reader.close();
                        census.record_unreadable_file(
                            UnreadableCause::OpenRead,
                            &active.candidate.path,
                        );
                        pending!();
                    }
                    Ok(true) if codex_page.continuation() => {
                        continuation_ticket = None;
                        if let Some(lease) = codex_cursor_lease.take() {
                            #[cfg(test)]
                            sampled_scan::codex_cursor::tests::constrain_eof_park(&mut active);
                            drop(lease.pause(active)); // StateBound: ordinary disclosure only.
                        }
                        pending!();
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
                if source == SnapshotSource::ClaudeCode
                    && active.cursor.is_none()
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
                    if let Some(feed) = codex_versions.as_ref() {
                        feed.observe(&active);
                    }
                }
                if let Some(context) = attribution_context {
                    let workers = launch_workers_for_parsed(
                        source,
                        active.parser.accumulator.source_session_id.as_deref(),
                        &active.candidate.path,
                    );
                    match context.launch_events().prepare_step(&workers) {
                        Ok(false) => {
                            active_file = Some(active);
                            pending!();
                        }
                        Err(()) => {
                            if source == SnapshotSource::ClaudeCode {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &active.candidate.path,
                                );
                            }
                            census.record_unreadable_file(
                                UnreadableCause::Reduction,
                                &active.candidate.path,
                            );
                            pending!();
                        }
                        Ok(true) => {}
                    }
                }
                if let Some(context) = sampling.as_mut() {
                    if let Some(plan) = active.parser.reader.acquisition.as_ref() {
                        context.record_input(
                            plan.metrics(),
                            matches!(
                                plan.mode(),
                                crate::transcript_acquisition::ReadMode::Full(_)
                            ),
                        );
                        // D168's replays, with the bytes they read: a group
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
                                tail_source::counters::replay(source, cause, bytes);
                            }
                        }
                        resource_probe.rearm_full_completed(
                            &local_index_key(&active.candidate.path),
                            plan.mode(),
                            plan.metrics().native_bytes,
                        );
                        resource_probe.full_parse_reason(
                            plan.mode(),
                            active.parse_reason,
                            0,
                            plan.metrics().native_bytes,
                        );
                        crate::local_resource_diagnostics::change_reason::read(
                            source.api_slug(),
                            &local_index_key(&active.candidate.path),
                            plan.mode(),
                            plan.metrics().native_bytes,
                            plan.metrics().sample_bytes as u64,
                        );
                    }
                }
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
                        reopen_for_replay(source, &active.candidate, &active.parser.reader.reader);
                    let Ok(file) = reopened else {
                        census.record_unreadable_file(
                            UnreadableCause::OpenRead,
                            &active.candidate.path,
                        );
                        pending!();
                    };
                    let Ok(mut parser) = sampled_scan::new_source_parser(
                        file,
                        &active.candidate,
                        index,
                        sampled_scan::ParserOptions {
                            source,
                            metadata: &codex_title_metadata,
                            traces: codex_turn_traces.clone(),
                            identity_capture: claude_request_identity_capture,
                            cache: sampling.as_ref().map(|c| &c.cache),
                        },
                    ) else {
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    };

                    let acquisition = active.sampling.as_mut().expect("sampled acquisition");
                    let debt = sampled_audit::debt_for_key(
                        index,
                        &acquisition.key,
                        sampled_scan::now_seconds(),
                    );
                    let Ok(mode) = parser.prepare_acquisition(
                        None,
                        &acquisition.scope,
                        debt,
                        sampled_scan::now_seconds(),
                    ) else {
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    };
                    acquisition.mode = mode;
                    acquisition.tier_prefix_replay = true;
                    if let Some(context) = sampling.as_mut() {
                        context.priority_replays += 1;
                        context.record_mode(mode, acquisition.audit_due);
                    }
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
                        sampled_scan::codex_cursor::dequeue(index, &active.candidate);
                        census.record_unreadable_file(
                            UnreadableCause::Reduction,
                            &active.candidate.path,
                        );
                        pending!();
                    }
                    // LD: the replay is a fresh Full delivery from 0.
                    if let Some(delivery) = line_delivery.as_mut() {
                        delivery.arm();
                    }
                    active_file = Some(active);
                    pending!();
                }
                // #631 review: the bytes this attempt read, taken before
                // `finish_job` consumes the acquisition's start offset. An
                // exact-stamp memo below must not cover anything past them.
                if source == SnapshotSource::Codex && active.group.is_none() {
                    if let (Some(entry), Some(plan)) = (
                        active
                            .sampling
                            .as_ref()
                            .and_then(|sampled| index.files.get(&sampled.key)),
                        active.parser.reader.acquisition.as_ref(),
                    ) {
                        let start = plan.start_offset();
                        codex_fragment::note_tail_repeat(
                            entry,
                            &active.candidate,
                            codex_fragment::TailRead {
                                mode: plan.mode(),
                                start,
                                end: start.saturating_add(active.parser.reader.consumed_bytes()),
                                terminated_end: active.parser.reader.last_complete_line_end(),
                            },
                            census_unix_seconds,
                            backfill_window_days,
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
                if let Some(context) = sampling.as_ref().filter(|_| active.cursor.is_some()) {
                    let current_scope = sampled_scan::reduction_dependencies(
                        source,
                        &active.candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .map(|dependency| context.file_scope(source, &active.candidate, &dependency));
                    let counting_now =
                        sampled_scan::codex_cursor::job_counting_view(&active, index);
                    let group_scope_now = sampled_scan::codex_cursor::group_scope();
                    let census_trusted = state_census_complete
                        && sidecar_census_complete
                        && active
                            .cursor
                            .as_ref()
                            .is_some_and(sampled_scan::codex_cursor::JobMeta::census_trusted);
                    // G1: growth past a job's frozen extent is next-generation
                    // evidence when the job started in this census generation.
                    let job_in_generation = active
                        .cursor
                        .as_ref()
                        .is_some_and(|meta| meta.in_generation(index));
                    // The certificate re-reads two samples from the held FD.
                    codex_page.charge(true, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                    match sampled_scan::codex_cursor::finish_job(
                        &context.cache,
                        codex_cursor_lease.take(),
                        &mut active,
                        current_scope.as_ref(),
                        &counting_now,
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
                                index,
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
                            cursor_certificate = Some(
                                Some(checkpoint)
                                    .filter(|_| census_trusted && active.group.is_none()),
                            );
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
                                index,
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
                        sampled_scan::codex_cursor::JobEnd::Restart => pending!(),
                        sampled_scan::codex_cursor::JobEnd::MemberChanged(disclosure) => {
                            sampled_scan::codex_cursor::disclose_job_debt(
                                &active,
                                &disclosure,
                                index,
                                targets!(),
                            );
                            sampled_scan::codex_cursor::dequeue_members(
                                index,
                                sampled_scan::codex_cursor::job_files(&active),
                            );
                            pending!();
                        }
                    }
                    // A group's sealed members ended with the job; only its
                    // live member's path follows `release_path` above.
                    if let Some(group) = active.group.as_ref() {
                        sampled_scan::codex_cursor::dequeue_members(
                            index,
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
                        source == SnapshotSource::Codex
                            && active.aliases.is_empty()
                            && sampling.is_some()
                    });
                if memo_offset.is_some() {
                    // The live witness reads two samples of the held file.
                    codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
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
                    // the bytes read (#631 review: captured after
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
                        source,
                        &active.candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )?;
                    let digest = sampled_scan::codex_cursor::memo_digest(
                        index,
                        &active.candidate,
                        file,
                        &dependencies,
                        &codex_title_metadata,
                        sampled_scan::codex_cursor::owner_members(
                            codex_join_inventory.as_ref(),
                            &active.candidate.path,
                        ),
                        &sampled_scan::codex_cursor::counting_view(&active.candidate, index),
                    )?;
                    let sidecar = sampled_scan::codex_cursor::sidecar_wakes(
                        &active.parser.accumulator,
                    )
                    .then(|| {
                        sampled_scan::codex_cursor::sidecar_fingerprint(
                            &codex_title_metadata,
                            &active.candidate.path,
                        )
                    });
                    Some((digest, live, stamp, sidecar))
                });
                let OwnedActiveFile {
                    first_read,
                    sampling: file_sampling,
                    candidate,
                    decision,
                    parse_reason,
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
                let mut independent_contributions = Vec::new();
                let mut independent_group = false;
                let group_members = group.as_deref_mut().map_or(0, |group| {
                    independent_group = group.independent;
                    independent_contributions = std::mem::take(&mut group.contributions);
                    codex_legacy_join_baselines.extend(group.take_legacy_baselines());
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
                            if let Some(group) = group.as_deref().filter(|group| group.independent)
                            {
                                codex_file_join::refuse_independent(
                                    group,
                                    sampling.as_ref(),
                                    index,
                                    targets!(),
                                );
                                pending!();
                            }
                            if let Some((context, publication)) =
                                sampling.as_ref().zip(cursor_publication.take())
                            {
                                context.cache.cursor_published(publication, false);
                            }
                            census.ownership_incomplete_file_count += 1;
                            census.causes.add(ownership::GROUP, 1);
                            census.record_unreadable(UnreadableCause::AliasParser, 1);
                            residue_index_keys.insert(local_index_key(&candidate.path));
                            pending!();
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
                            source,
                            &candidate,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        )
                        .zip(sampling.as_ref())
                        .map(|(dependency, context)| {
                            context.file_scope(source, &candidate, &dependency)
                        });
                        // H3c: a passed certificate permits native finish of
                        // this prefix only. Discard its checkpoint: no cache copy,
                        // audit credit or source verification can follow it.
                        let prefix = current_scope
                            .as_ref()
                            .filter(|scope| *scope == &acquisition.scope)
                            .filter(|_| {
                                // H3c preserves an already-read prefix while an
                                // audit waits. A byte-zero Full must instead
                                // reach normal completion and discharge its
                                // audit, even when RAM retention is unavailable.
                                acquisition.audit_due.is_some()
                                    && sampling.as_ref().is_some_and(|context| {
                                        context.audit_metadata_supported
                                            && (context.audit_slots > 0
                                                || index.files.get(&acquisition.key).is_some_and(
                                                    ScanIndexEntry::has_unverified_source,
                                                ))
                                    })
                            })
                            .and_then(|scope| {
                                parser.commit_claude_grown_prefix(
                                    &candidate.path,
                                    scope,
                                    index
                                        .files
                                        .get(&acquisition.key)
                                        .map_or(0, |entry| entry.size_bytes),
                                )
                            });
                        (current_scope, prefix)
                    }
                    None => (None, None),
                };
                let completed_acquisition = if let Some(certificate) = cursor_certificate {
                    certificate.map(|checkpoint| sampled_jsonl::CompletedNativeAcquisition {
                        checkpoint,
                        unsealed: true,
                    })
                } else if let Some(acquisition) = file_sampling.as_ref() {
                    if let Some(prefix) = prefix {
                        match prefix {
                            Ok(grant) => parser.reader.sealed_prefix = Some(grant),
                            Err(refusal) => {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &candidate.path,
                                );
                                let cause = match refusal {
                                    crate::transcript_acquisition::PrefixRefusal::AuditDue => {
                                        UnreadableCause::Reduction
                                    }
                                    _ => UnreadableCause::ScopeObject,
                                };
                                census.record_unreadable_file(cause, &candidate.path);
                                pending!();
                            }
                        }
                        None
                    } else {
                        let mut current_path = candidate.clone();
                        if let Some(cause) = sampled_revalidation_cause(
                            current_scope.as_ref() == Some(&acquisition.scope),
                            || {
                                drop(open_candidate_file(source, &mut current_path)?);
                                Ok(current_path.opened_object_identity
                                    == candidate.opened_object_identity)
                            },
                        ) {
                            if source == SnapshotSource::ClaudeCode {
                                claude_request_census::invalidate_claude_request_census(
                                    index,
                                    &candidate.path,
                                );
                            }
                            census.record_unreadable_file(cause, &candidate.path);
                            pending!();
                        }
                        #[cfg(test)]
                        sampled_scan::test_hooks::fire(
                            sampled_scan::test_hooks::Point::BeforeRetain,
                        );
                        match parser
                            .retain_reduction(&acquisition.scope, sampled_scan::now_seconds())
                        {
                            Ok(completed) => completed,
                            Err(_) => {
                                if source == SnapshotSource::ClaudeCode {
                                    claude_request_census::invalidate_claude_request_census(
                                        index,
                                        &candidate.path,
                                    );
                                }
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
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
                    sampling.as_mut(),
                ) {
                    if active.mode == crate::transcript_acquisition::ReadMode::Unchanged
                        // Withheld bodies retain their obligation until release.
                        && !index.claude_account_deferred_holds.contains_key(&active.key)
                        && index.files.get(&active.key).is_some_and(|entry| {
                            entry.audit_requires_full(audit_now)
                                && !entry.has_prefix_provenance()
                        })
                        && !index.claude_request_census.get(&active.key).is_some_and(
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
                let codex_counting_v2 = parser.accumulator.codex_counting_v2();
                let evicted_legacy_v2_owner = parser
                    .accumulator
                    .source_session_id
                    .as_deref()
                    .filter(|_| {
                        codex_counting_version::evicted_legacy_selected_v2(
                            &parser.accumulator,
                            index,
                        )
                    })
                    .map(codex_protected_owner);
                // Counting receipts reach the scan's local diagnostics only
                // when this parse finishes: once per finished active file (a
                // joined group is one).
                let codex_counting_receipts =
                    parser
                        .accumulator
                        .codex_counting
                        .as_deref()
                        .map(|counting| {
                            let mut receipts = census.codex_counting_v2.clone().unwrap_or_default();
                            counting.fold_receipts(&mut receipts);
                            if evicted_legacy_v2_owner.is_some() {
                                receipts.legacy_to_v2_after_tombstone_eviction = receipts
                                    .legacy_to_v2_after_tombstone_eviction
                                    .saturating_add(1);
                            }
                            receipts
                        });
                // Before `finish` consumes the parser. Ledger
                // birth: `created()` and identity of the descriptor this parse
                // opened, taken at open (never a path); unknown is None.
                let claude_opened_birth = (source == SnapshotSource::ClaudeCode
                    && claude_index_path_family_member(&candidate.path).is_some())
                .then_some(parser.claude_opened_birth)
                .flatten();
                let claude_itemless_request_hashes =
                    if source == SnapshotSource::ClaudeCode && !parser.positive_usage_evidence {
                        claude_request_census::claude_buffered_request_hashes(&parser)
                    } else {
                        Vec::new()
                    };
                let claude_grown_prefix =
                    source == SnapshotSource::ClaudeCode && parser.reader.sealed_prefix.is_some();
                let finish_request = FinishRequest {
                    expected_opened_object_identity: &candidate.opened_object_identity,
                    path: &candidate.path,
                    collected_at: collected_at.as_str(),
                    source_file_fingerprint: source_file_fingerprint.clone(),
                    codex_title_metadata: (source == SnapshotSource::Codex)
                        .then_some(&codex_title_metadata),
                    claude_title_metadata: (source == SnapshotSource::ClaudeCode)
                        .then_some(&claude_title_metadata),
                    attribution_context,
                    repository_identity: None,
                    money_context: Some(claude_request_money::e2::ReadContext {
                        index,
                        path: &candidate.path,
                        twins: history_upgrade.twin_groups(),
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
                    .filter(|_| sampling.is_some())
                    .and_then(|(completed, active)| {
                        // `None` off a Tail route.
                        tail_source::pending(
                            source,
                            index,
                            completed,
                            active,
                            &candidate,
                            parser.reader.reader.get_ref(),
                            claude_request_identity_capture,
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
                #[cfg(unix)]
                let parsed_file = {
                    let tailed = tail.is_some();
                    let mut encode = |live: PreFinalization<'_>| {
                        if let Some(tail) = tail.as_mut() {
                            tail.encode(&live);
                        }
                    };
                    let pre = tailed.then_some(&mut encode as &mut dyn FnMut(PreFinalization<'_>));
                    parser.finish_boxed_native(finish_request, pre)
                };
                // On a Tail route: whether this file's committed head stays
                // its continuation (staged, or nothing to restate).
                #[cfg(unix)]
                let tail_reused = tail.map(|tail| tail.publish(&parsed_file));
                #[cfg(not(unix))]
                let parsed_file = parser.finish_boxed_native(finish_request, None);
                #[cfg(test)]
                sampled_scan::test_hooks::fire(
                    sampled_scan::test_hooks::Point::BeforeNativeEffects,
                );
                // A committed cursor attempt counts as published only now.
                if let Some((context, publication)) =
                    sampling.as_ref().zip(cursor_publication.take())
                {
                    context
                        .cache
                        .cursor_published(publication, parsed_file.is_ok());
                }
                if let Ok(parsed) = &parsed_file {
                    if source == SnapshotSource::ClaudeCode {
                        for item in &parsed.snapshots {
                            if let Some(fold) = item.claude_money.as_deref() {
                                claude_request_money::e2::remember_birth(
                                    index,
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
                                sampling.as_ref(),
                                index,
                                targets!(),
                            );
                            pending!();
                        }
                        if source == SnapshotSource::Codex && !aliases.is_empty() {
                            codex_file_join::disclose_strict(&aliases, targets!());
                            pending!();
                        }
                        #[cfg(test)]
                        sampled_scan::test_hooks::record_finish_error(&_error);
                        if source == SnapshotSource::ClaudeCode {
                            claude_request_census::invalidate_claude_request_census(
                                index,
                                &candidate.path,
                            );
                        }
                        census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                        pending!();
                    }
                };
                if let Some(receipts) = codex_counting_receipts {
                    if let Some(owner) = evicted_legacy_v2_owner {
                        codex_counting_version::note_evicted_legacy_v2_selection(index, &owner);
                    }
                    census.codex_counting_v2 = Some(receipts);
                }
                let parse_complete = parsed_file.progress_complete();
                // Claude response conflicts may be discovered only by native
                // finalization. A prefix cannot publish that late loss: it
                // would have neither a committed audit marker nor necessarily
                // a request-census record when the record budget is exhausted.
                if claude_grown_prefix && !parse_complete {
                    claude_request_census::invalidate_claude_request_census(index, &candidate.path);
                    census.record_unreadable(UnreadableCause::ScopeObject, 1);
                    pending!();
                }
                if !aliases.is_empty() && !parse_complete {
                    // Joining authorizes a complete replacement only. Native
                    // ownership/parser loss cannot publish a partial union body.
                    census.ownership_incomplete_file_count += aliases.len();
                    census.causes.add(ownership::GROUP, aliases.len());
                    census.record_unreadable(UnreadableCause::AliasParser, 1);
                    residue_index_keys
                        .extend(aliases.iter().map(|member| local_index_key(&member.path)));
                    pending!();
                }
                if !aliases.is_empty() {
                    if aliases
                        .iter()
                        .any(|member| codex_archive_path(&member.path))
                        && codex_file_join::stage_independent_inventory(
                            index,
                            &aliases,
                            joined_owner.as_deref().expect("joined owner"),
                        )
                        .is_err()
                    {
                        codex_file_join::disclose_strict(&aliases, targets!());
                        pending!();
                    }
                    codex_join_completed.push(codex_file_join::Group {
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
                if non_progressing_residue {
                    residue_index_keys.insert(index_key.clone());
                } else {
                    settled_residue_index_keys.insert(index_key.clone());
                }
                let report = parsed_file.report;
                let recognized_usage_drop_count = parsed_file.recognized_usage_drop_count;
                let ownership_incomplete_file_count = parsed_file.ownership_incomplete_file_count;
                let zero_snapshot_usage_evidence = parsed_file.zero_snapshot_usage_evidence;
                let dropped_usage_record_count = parsed_file.dropped_usage_record_count;
                let claude_compaction_unlinked_parent_count =
                    parsed_file.claude_compaction_unlinked_parent_count;
                if let Some(context) = sampling
                    .as_ref()
                    .filter(|_| source == SnapshotSource::Codex && aliases.is_empty())
                {
                    // Memoize a non-progressing ownership-held singleton.
                    // Anything else, completion included, clears a stale entry.
                    let held = !parse_complete
                        && non_progressing_residue
                        && ownership_incomplete_file_count > 0;
                    match memo_candidate.filter(|_| held) {
                        Some((digest, live, stamp, sidecar)) => {
                            context.cache.memo_record(
                                sampled_scan::codex_cursor::memo_key(
                                    &context.namespace,
                                    &index_key,
                                ),
                                sampled_scan::codex_cursor::MemoEntry::new(
                                    digest,
                                    live,
                                    context.cache.retained_stamp(&candidate.path, stamp),
                                    sidecar,
                                    sampled_scan::codex_cursor::Disclosure {
                                        reason:
                                            sampled_scan::codex_cursor::DebtReason::HeldTerminal,
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
                let slot_unfunded = sampling
                    .as_ref()
                    .is_some_and(|context| context.audit_slots == 0)
                    && !index
                        .files
                        .get(&index_key)
                        .is_some_and(ScanIndexEntry::has_unverified_source);
                if needs_marker
                    && !index.claude_account_deferred_holds.contains_key(&index_key)
                    && (slot_unfunded || !index.can_stage_sampled_audit(&index_key))
                {
                    // A refused prefix/lossy completion is a delay, not a Full.
                    if let Some(context) = sampling.as_mut() {
                        context.audit_cap_delay += 1;
                    }
                    sampled_audit::queue_cap_retry(index, &candidate);
                    census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    pending!();
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
                        && state_census_complete
                        && sidecar_census_complete));
                let mut parsed = parsed_file.snapshots;
                if source == SnapshotSource::ClaudeCode {
                    claude_request_census::record_claude_request_census(
                        index,
                        claude_request_census::ClaudeRequestCensusParse {
                            path: &candidate.path,
                            index_key: &index_key,
                            source_file_fingerprint: &source_file_fingerprint,
                            census_window_end: &census_window_end,
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
                if source == SnapshotSource::Codex {
                    for snapshot in parsed.iter_mut() {
                        apply_codex_state_evidence(
                            snapshot,
                            &codex_title_metadata,
                            &candidate.path,
                        );
                    }
                }
                if parse_complete && !aliases.is_empty() {
                    for alias in &aliases {
                        if alias.path == candidate.path {
                            continue;
                        }
                        let alias_fingerprint = alias.source_file_fingerprint.clone();
                        pending_finalization.push(PendingIndexFinalization {
                            refold_unchanged: false,
                            withheld_content: None,
                            sampled_audit_verified: false,
                            codex_pending_recovery: index
                                .files
                                .get(&local_index_key(&alias.path))
                                .is_some_and(ScanIndexEntry::codex_recovery_is_pending),
                            index_key: local_index_key(&alias.path),
                            source_file_fingerprint: alias_fingerprint.clone(),
                            previous_snapshot_fingerprint: index.last_snapshot_fingerprint(alias),
                            previous_upload_body_witness: index.last_upload_body_witness(alias),
                            parse_complete,
                            diagnostic_reason,
                            parsed_snapshot_count: parsed.len(),
                            effective_upload_body_witness_revision: index
                                .active_effective_upload_body_witness_revision,
                        });
                        let alias_items = parsed
                            .iter()
                            .cloned()
                            .map(|mut item| {
                                if !independent_group {
                                    item.source_file_fingerprint = Some(alias_fingerprint.clone());
                                    item.snapshot_fingerprint = snapshot_fingerprint(source, &item);
                                }
                                item
                            })
                            .collect::<Vec<_>>();
                        index.record(
                            alias.clone(),
                            alias_items
                                .last()
                                .map(|item| item.snapshot_fingerprint.clone()),
                            ScanParseOutcome::Snapshot,
                        );
                        census
                            .observed_index_keys
                            .insert(local_index_key(&alias.path));
                        if !independent_group {
                            snapshots.extend(alias_items);
                        }
                    }
                }
                scanned_session_count += parsed.len();
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
                    if let Some(context) = sampling.as_mut() {
                        context.complete_audit(
                            file_sampling
                                .as_ref()
                                .and_then(|active| active.audit_due)
                                .expect("verified audit due"),
                        );
                    }
                }
                pending_finalization.push(PendingIndexFinalization {
                    refold_unchanged: unchanged(parse_reason, file_sampling.as_ref()),
                    withheld_content: parse_complete
                        .then(|| index.withheld_completed_seen(&candidate))
                        .flatten(),
                    sampled_audit_verified,
                    codex_pending_recovery: index
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
                    effective_upload_body_witness_revision: index
                        .active_effective_upload_body_witness_revision,
                });
                if source == SnapshotSource::Codex
                    && parse_complete
                    && aliases.is_empty()
                    && applied_receipts.values().any(Option::is_some)
                {
                    if let Some(item) = parsed.first() {
                        codex_join_completed.push(codex_file_join::Group {
                            owner: resolve_codex_identity(&item.source_session_id),
                            home: codex_file_join::member_home(&candidate.scan_root),
                            members: vec![candidate.clone()],
                            live: None,
                        });
                    }
                }
                let counting_owner = parsed.first().and_then(|item| {
                    if source != SnapshotSource::Codex {
                        return None;
                    }
                    let owner = codex_join_inventory
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
                    index.record_terminal_jsonl_disposition(&candidate, terminal_loss.clone());
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
                                    codex_fragment::BoundFragment::bind(&candidate, fragment.offset)
                                })
                                .flatten()
                        })
                    });
                    let mut recorded = candidate;
                    if let Some(fragment) = cursor_fragment
                        .filter(|_| prefix_continued && completed_acquisition.is_some())
                    {
                        recorded.size_bytes = fragment.offset;
                    }
                    // record consumes the candidate but does not use its root.
                    // Move that existing allocation into the commit-sensitive
                    // retry instead of cloning it or guessing a nested root.
                    let quiet_scan_root =
                        quiet_audit_checked.then(|| std::mem::take(&mut recorded.scan_root));
                    if parse_complete && !non_progressing_residue {
                        sampled_audit::settle_growth(index, &index_key);
                    }
                    index.record(recorded, last_snapshot_fingerprint, outcome);
                    // The counting version travels in the same entry as the
                    // fingerprint it describes; no separate save can split them.
                    if let Some(entry) = index.files.get_mut(&index_key) {
                        entry.codex_counting_v2 = codex_counting_v2;
                        entry.codex_counting_owner =
                            counting_owner.clone().map(String::into_boxed_str);
                        entry.codex_fragment = bound_fragment.map(Box::new);
                    }
                    // Each grouped member, aliases included, settles its own
                    // audit on its native-created entry: verified retires and counts.
                    for member in aliases.iter().take(group_members) {
                        let key = local_index_key(&member.path);
                        let marked = index
                            .files
                            .get(&key)
                            .and_then(ScanIndexEntry::unverified_deadline);
                        if let Some(context) = sampling.as_mut() {
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
                        let was_pending = index
                            .files
                            .get(&index_key)
                            .is_some_and(ScanIndexEntry::has_unverified_source);
                        // Held retries bypass cap Full/counting, not the
                        // committed-slot reservation for a NEW marker.
                        if !slot_unfunded
                            && index.stage_sampled_audit(&index_key, &source_file_fingerprint, debt)
                            && !was_pending
                        {
                            if let Some(context) = sampling.as_mut() {
                                context.audit_slots = context.audit_slots.saturating_sub(1);
                            }
                        }
                    } else if source_verified {
                        index.complete_full_audit(&index_key, &source_file_fingerprint);
                    }
                    if source == SnapshotSource::ClaudeCode {
                        if claude_grown_prefix {
                            if !slot_unfunded {
                                index.mark_sealed_prefix(&index_key, &source_file_fingerprint);
                            }
                        } else if completed_acquisition.is_some()
                            && cursor_fragment.is_none()
                            && file_sampling.as_ref().is_some_and(|active| {
                                !matches!(
                                    active.mode,
                                    crate::transcript_acquisition::ReadMode::Unchanged
                                )
                            })
                            && state_census_complete
                            && sidecar_census_complete
                            && parse_complete
                        {
                            index.complete_native_recomposition(
                                &index_key,
                                &source_file_fingerprint,
                            );
                        }
                    }
                    if let Some(fragment) = cursor_fragment {
                        let was_pending = index
                            .files
                            .get(&index_key)
                            .is_some_and(ScanIndexEntry::has_unverified_source);
                        if !slot_unfunded
                            && index.stage_sampled_audit(
                                &index_key,
                                &source_file_fingerprint,
                                fragment.debt,
                            )
                            && !was_pending
                        {
                            if let Some(context) = sampling.as_mut() {
                                context.audit_slots = context.audit_slots.saturating_sub(1);
                            }
                        }
                    }
                    // Codex: after every audit staging above (staging
                    // matches the fingerprint), before this entry's save
                    // settles the degraded publication.
                    if let Some(mut completed) = completed_acquisition {
                        if let Some(context) = sampling.as_mut() {
                            let retained = tail_reused == Some(true);
                            let quiet_retired = quiet_audit_checked
                                && !completed.unsealed
                                && retained
                                && cursor_fragment.is_none()
                                && state_census_complete
                                && sidecar_census_complete
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
                                        index,
                                        &index_key,
                                        quiet_scan_root.expect("checked quiet retirement root"),
                                    );
                                }
                                #[cfg(unix)]
                                let durable_pending = quiet_retired
                                    && context.cache.quiet_stage(
                                        source,
                                        &index_key,
                                        &source_file_fingerprint,
                                        quiet_proven,
                                    );
                                #[cfg(not(unix))]
                                let durable_pending = false;
                                if quiet_retired
                                    && !durable_pending
                                    && index
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
                        if let Some(entry) = index.files.get_mut(&key) {
                            if source_verified {
                                entry.scan_identity_version =
                                    Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
                            }
                            entry.codex_joined_member_set = joined_marker.clone();
                            entry.codex_protected_owner = protected_owner.clone();
                            // Set only by a V2 decision; a Legacy group clears
                            // any stale mark with the ACK it rewrites.
                            entry.codex_counting_v2 = codex_counting_v2;
                            entry.codex_counting_owner =
                                counting_owner.clone().map(String::into_boxed_str);
                        }
                    }
                }
                if parse_complete {
                    for (key, receipt) in applied_receipts {
                        if let Some(entry) = index.files.get_mut(&key) {
                            if receipt.is_some() {
                                entry.codex_protected_owner = protected_owner.clone();
                            }
                            entry.codex_applied_tier_receipt_required = receipt.is_some();
                            entry.codex_applied_tier_receipt = receipt;
                        }
                    }
                }
                if let Some(loss) = terminal_loss.as_ref() {
                    census.add_terminal_jsonl_loss(loss);
                }
                census.ownership_incomplete_file_count += ownership_incomplete_file_count;
                census
                    .causes
                    .add(parsed_file.cause, ownership_incomplete_file_count);
                census.zero_snapshot_usage_evidence_count +=
                    usize::from(zero_snapshot_usage_evidence);
                census.claude_compaction_unlinked_parent_count = census
                    .claude_compaction_unlinked_parent_count
                    .saturating_add(claude_compaction_unlinked_parent_count);
                // Only classified holds suppress independently valid siblings.
                if parse_complete {
                    snapshots.extend(parsed);
                }
                pending!();
            }
            let Some(mut candidate) = identified_candidates.pop_front() else {
                context_read_budget.flush(index, &codex_selected_flags);
                if codex_page.continuation() {
                    if let Some(traversal) = index.traversal.as_mut() {
                        traversal.counts.caps.drain(source.api_slug());
                    }
                    let continuation_evidence = codex_join_inventory
                        .map(|inventory| CodexContinuationEvidence {
                            inventory,
                            codex: codex_title_metadata,
                            traces: codex_turn_traces,
                        })
                        .and_then(|evidence| match continuation_ticket.as_ref() {
                            Some(ticket) => evidence.for_paused_job(
                                sampling.as_ref().map(|context| context.cache.as_ref()),
                                ticket,
                            ),
                            None => Some(evidence),
                        })
                        .map(|evidence| Arc::new(Mutex::new(Some(evidence))));
                    return Ok(OwnedSourceScanStep::Complete {
                        index: index_storage,
                        scan: SourceScanResult {
                            discovery_growth: std::mem::take(&mut resource_probe.discovery_growth),
                            continuation_ticket,
                            continuation_evidence,
                            ..SourceScanResult::empty(SnapshotSource::Codex)
                        },
                    });
                }
                // Current-page metadata/open uncertainty must reach every F4
                // caller before any hold can retire. The remaining census fold
                // below keeps its existing order; each count is merged once.
                if let Some(traversal) = index.traversal.as_mut() {
                    traversal.counts.directory_entry_cap_exceeded_count +=
                        census.directory_entry_cap_exceeded_count;
                    traversal.counts.unreadable_path_count += census.unreadable_path_count;
                    traversal
                        .counts
                        .unreadable_causes
                        .merge(census.unreadable_causes);
                    traversal.counts.growth_deferred += census.growth_deferred;
                }
                // Per-key absence is independent of aggregate terminal authority.
                if source == SnapshotSource::ClaudeCode {
                    index.probe_absent_claude_account_deferred_holds();
                }
                if let Some(traversal) = index.traversal.as_mut() {
                    // A residue file that this page parsed to completion, or that a
                    // watcher hint proved absent, leaves the generation's residue set; a
                    // file that reproduced its residue (re)enters it.
                    for index_key in settled_residue_index_keys.iter().chain(
                        census.removed_index_keys.iter().filter(|key| {
                            !index
                                .files
                                .get(*key)
                                .is_some_and(ScanIndexEntry::codex_history_is_protected)
                        }),
                    ) {
                        traversal.residue.index_keys.remove(index_key);
                    }
                    if let Some(inventory) = codex_join_inventory
                        .as_ref()
                        .filter(|inventory| !inventory.complete)
                    {
                        record_codex_inventory_hold(traversal, inventory, &residue_index_keys);
                    }
                    traversal.residue.index_keys.extend(residue_index_keys);
                    // Exact watcher remove/rename hints must amend the same durable
                    // observation set used by directory census reconciliation. Apply
                    // removals first so a valid observation later in this page wins.
                    for index_key in census.removed_index_keys.iter() {
                        traversal.observed_index_keys.remove(index_key);
                    }
                    traversal
                        .observed_index_keys
                        .extend(census.observed_index_keys.iter().cloned());
                    traversal.counts.symlink_rejected_count += census.symlink_rejected_count;
                    traversal.counts.oversized_file_count += census.oversized_file_count;
                    traversal.counts.disappeared_file_count += census.disappeared_file_count;
                    traversal.counts.malformed_json_line_count += census.malformed_json_line_count;
                    traversal.counts.invalid_utf8_line_count += census.invalid_utf8_line_count;
                    traversal.counts.over_line_cap_count += census.over_line_cap_count;
                    traversal.counts.recognized_usage_drop_count +=
                        census.recognized_usage_drop_count;
                    traversal.counts.ownership_incomplete_file_count +=
                        census.ownership_incomplete_file_count;
                    traversal.counts.causes.merge(&census.causes);
                    traversal.counts.zero_snapshot_usage_evidence_count +=
                        census.zero_snapshot_usage_evidence_count;
                    traversal.counts.dropped_usage_record_count = traversal
                        .counts
                        .dropped_usage_record_count
                        .saturating_add(census.dropped_usage_record_count);
                    traversal.counts.terminal_over_line_cap_count = traversal
                        .counts
                        .terminal_over_line_cap_count
                        .saturating_add(census.terminal_over_line_cap_count);
                    traversal.counts.terminal_recognized_usage_drop_count = traversal
                        .counts
                        .terminal_recognized_usage_drop_count
                        .saturating_add(census.terminal_recognized_usage_drop_count);
                    traversal.counts.terminal_dropped_usage_record_count = traversal
                        .counts
                        .terminal_dropped_usage_record_count
                        .saturating_add(census.terminal_dropped_usage_record_count);
                }
                if source == SnapshotSource::Codex {
                    // Count-only attribution of why Codex files were selected
                    // on this page. No path, session, or identifier is named.
                    if let Some(line) = census.codex_parse_reasons_line() {
                        eprintln!("{line}");
                    }
                }
                if source == SnapshotSource::ClaudeCode
                    && (census.parse_reasons.iter().any(|count| *count > 0)
                        || census.claude_compaction_unlinked_parent_count > 0
                        || history_upgrade.any()
                        || index.claude_reemission_exclusions.pauses_adoption()
                        || claude_reemission_stop_latched())
                {
                    claude_history_upgrade::alarm_if_owed_without_list(
                        &history_upgrade,
                        index.claude_reemission_exclusions.state(),
                    );
                    // Count-only attribution of why Claude files were selected
                    // on this page. No path, session, or identifier is named.
                    eprintln!(
                        "local snapshot census claude parse reasons: {} compaction_summary_unlinked_parent={} body_witness_adoption_deferred={} body_witness_adoption_excluded={} body_witness_adoption_held_no_list={} body_witness_adoption_exclusions_invalid={} body_witness_adoption_list={} body_witness_adoption_stop={} body_witness_adoption_stop_withheld_folds={} history_upgrade_owed={} history_upgrade_permitted={} history_emission_denied={} history_listed_literal_roots={} history_reowed={} history_activation_refused={} claude_reemission_family_closure_root_absent_excluded={} identity_incomplete_holds_entered_process_total={} identity_incomplete_holds_cleared_process_total={}",
                        census_count_fields(&CANDIDATE_PARSE_REASON_NAMES, &census.parse_reasons),
                        census.claude_compaction_unlinked_parent_count,
                        history_upgrade.denied_for(&[
                            HistoryHold::UngatedRevision,
                            HistoryHold::ListPaused,
                            HistoryHold::Latched,
                            HistoryHold::Budget,
                        ]),
                        history_upgrade.denied_for(&[HistoryHold::Listed]),
                        history_upgrade
                            .denied_for(&[HistoryHold::NoListBirth, HistoryHold::MoveNotFull]),
                        u8::from(index.claude_reemission_exclusions.is_invalid()),
                        index.claude_reemission_exclusions.status(),
                        claude_reemission_stop_reason(),
                        claude_reemission_stop_withheld_folds(),
                        history_upgrade.owed,
                        history_upgrade.permitted,
                        history_upgrade.denied_summary(),
                        history_upgrade.listed_literal_roots.len(),
                        claude_history_upgrade::local_count(
                            claude_history_upgrade::LocalCount::Reowed
                        ),
                        claude_history_upgrade::local_count(
                            claude_history_upgrade::LocalCount::ActivationRefused
                        ),
                        history_upgrade.family_closure_root_absent_excluded,
                        claude_request_census::identity_incomplete_hold_totals().0,
                        claude_request_census::identity_incomplete_hold_totals().1,
                    );
                    if history_upgrade.family_closure_root_absent_excluded > 0 {
                        crate::local_resource_diagnostics::claude_reemission_family_closure_root_absent_excluded(
                            history_upgrade.family_closure_root_absent_excluded,
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
                if source == SnapshotSource::Codex {
                    census.removed_index_keys.retain(|key| {
                        index.files.contains_key(key)
                            && !index
                                .traversal
                                .as_ref()
                                .is_some_and(|walk| walk.codex_rollout_paths.contains(key))
                    });
                }
                let account_members = index.observed_account_members();
                let unacked = index.unacked_bodies(census.removed_index_keys.iter());
                let mut tally = (0, 0);
                for index_key in census.removed_index_keys.iter() {
                    if source == SnapshotSource::ClaudeCode
                        && !census.claude_vanished_index_keys.contains(index_key)
                        && sampled_audit::revalidate_growth(index, index_key, &roots, &mut tally)
                    {
                        continue;
                    }
                    if source == SnapshotSource::ClaudeCode
                        && index.claude_account_deferred_holds.contains_key(index_key)
                    {
                        index.retire_absent_account_hold(index_key, &account_members);

                        // Successful retirement is complete; an uncertain
                        // disappearance must not enter the older audit exit.
                        continue;
                    }
                    // F4 or indexed reconciliation may already have retired the
                    // audit entry this page. Its retained incidence is
                    // not a second ordinary file removal (and grants no ACK).
                    if source == SnapshotSource::ClaudeCode && !index.files.contains_key(index_key)
                    {
                        continue;
                    }
                    // Codex records its counting evidence before either exit
                    // below, as terminal reconciliation does; a refusal keeps
                    // the entry whole.
                    if !index
                        .files
                        .get(index_key)
                        .is_some_and(ScanIndexEntry::codex_history_is_protected)
                        && (source != SnapshotSource::Codex
                            || codex_counting_version::tombstone_before_retire(index, index_key))
                    {
                        // A member that vanished beneath its present parent
                        // also drops its unverified audit debt, proven again
                        // here; every other removal keeps that debt. Both
                        // retire its request-census record.
                        let vanished = census.claude_vanished_index_keys.contains(index_key);
                        let census_record =
                            vanished && index.claude_request_census.get(index_key).is_some();
                        if vanished
                            && index
                                .files
                                .get(index_key)
                                .is_some_and(ScanIndexEntry::has_unverified_source)
                            && sampled_audit::proven_absent(Path::new(index_key), &roots)
                            && index.retire_vanished_claude_audit_debt_entry(index_key)
                        {
                            crate::local_resource_diagnostics::audit_retired_absent(
                                source.api_slug(),
                            );
                            disappearance_diagnostics::vanished(
                                source,
                                disappearance_diagnostics::Vanished::AuditDebtDropped,
                            );
                        } else {
                            index.remove_file_entry_unless_held(index_key);
                        }
                        if census_record && index.claude_request_census.get(index_key).is_none() {
                            disappearance_diagnostics::vanished(
                                source,
                                disappearance_diagnostics::Vanished::RequestCensusRemoved,
                            );
                        }
                    }
                }
                crate::local_resource_diagnostics::v2_growth_revalidate(tally);
                index.count_unacked_retired(source, unacked);
                // G1: only census members hold discovery. A pending re-read
                // (growth after this generation processed its path) is
                // next-generation evidence; retiring drops it and the next
                // walk re-reads the file if it is stale.
                let traversal_discovery_done = index.traversal.as_ref().is_some_and(|traversal| {
                    traversal.pending_directories.is_empty()
                        && !traversal
                            .pending_candidates
                            .iter()
                            .any(|candidate| candidate.census_member)
                });
                if traversal_discovery_done {
                    if source == SnapshotSource::Codex {
                        let missing = index
                            .files
                            .iter()
                            .filter(|(key, entry)| {
                                entry.codex_history_is_protected()
                                    && !index
                                        .traversal
                                        .as_ref()
                                        .expect("traversal")
                                        .codex_rollout_paths
                                        .contains(*key)
                            })
                            .map(|(key, _)| key.clone())
                            .collect::<BTreeSet<_>>();
                        if !missing.is_empty() {
                            let traversal = index.traversal.as_mut().expect("traversal");
                            // Quiet ticks reuse this generation's red witness. Count
                            // each absent protected source once, without rearming the
                            // retry latch or rescanning headers before its deadline.
                            let newly_missing =
                                missing.difference(&traversal.residue.index_keys).count();
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
                    if let Some(traversal) = index.traversal.as_mut() {
                        traversal.counts.settle_non_progressing_residue();
                    }
                }
                if let Some(traversal) = index.traversal.as_mut() {
                    traversal.counts.caps.drain(source.api_slug());
                }
                let traversal_snapshot = index
                    .traversal
                    .as_ref()
                    .cloned()
                    .expect("traversal remains active");
                let traversal_healthy = !traversal_snapshot.counts.has_errors();
                let clean_frozen_generation = !traversal_snapshot.watcher_hint_seen;
                // Count-only per-family completion, from the page's
                // settled state before any terminal effect. Acts on nothing.
                if source == SnapshotSource::ClaudeCode {
                    claude_family_census_shadow::observe_page(
                        index,
                        &claude_family_shadow,
                        &pending_finalization,
                        &census,
                        &sampling,
                        audit_now,
                    );
                }
                let reconciliation_complete = if traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                {
                    reconcile_missing_index_entries_bounded(index, source)
                } else {
                    false
                };
                // Vanished paths are retired from `files` just above - by exact watcher
                // remove/rename hints and by bounded census reconciliation. Terminal
                // dispositions are keyed identically, so retire their orphans in the same
                // place instead of carrying a renamed or deleted file's record forever.
                // This keeps the map a subset of `files`, which is the whole bound it
                // needs.
                index.prune_terminal_jsonl_dispositions();
                // Retirements on this page can already have a moved header in
                // the inventory, even while that file's parse is deferred.
                if let Some(inventory) = codex_join_inventory.as_ref() {
                    codex_counting_version::note_inventory_created(index, inventory);
                }
                let raw_census_complete = traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                    && reconciliation_complete;
                let needs_clean_followup =
                    raw_census_complete && index.bounded_sweep_had_unsettled_upload;
                // Path-(a) bridge: RetryPending authority debt no longer marks
                // the sweep, but it still withholds the ordinary census (and so
                // its complete fold and upload-context adoption), as the mark
                // did. It owes no clean follow-up of its own.
                let authority_debt_withholds_census = raw_census_complete
                    && source == SnapshotSource::ClaudeCode
                    && index.claude_usage_authority_pending_count() > 0;
                let census_complete = raw_census_complete
                    && !needs_clean_followup
                    && !authority_debt_withholds_census;
                // Prune and measure only, before any fold.
                let claude_request_census_shadow =
                    (source == SnapshotSource::ClaudeCode && census_complete).then(|| {
                        claude_request_census::settle_claude_request_census_terminal(
                            index,
                            &traversal_snapshot.residue.index_keys,
                            &census_window_end,
                        )
                    });
                let reconciliation_pending = traversal_discovery_done
                    && traversal_healthy
                    && clean_frozen_generation
                    && state_census_complete
                    && sidecar_census_complete
                    && !reconciliation_complete;
                let pending_work_count = index
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
                let skipped_file_count_due_to_limit =
                    claude_family_census_shadow::skipped_view(index).count();
                let restart_after_hints =
                    traversal_discovery_done && traversal_healthy && !clean_frozen_generation;
                let terminal_unhealthy = traversal_discovery_done && !traversal_healthy;
                if terminal_unhealthy {
                    let now = rfc3339_unix_seconds(collected_at.as_str()).unwrap_or_default();
                    let traversal = index.traversal.as_mut().expect("traversal remains active");
                    if traversal.unhealthy_retry_not_before_unix_seconds.is_none() {
                        let previous_attempt = traversal.unhealthy_retry_attempt;
                        // The counter saturates at the attempt whose delay is already the
                        // hourly ceiling. A persistent problem therefore costs at most one
                        // bounded re-walk per hour and the persisted witness stays small.
                        traversal.unhealthy_retry_attempt = previous_attempt
                            .saturating_add(1)
                            .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS);
                        traversal.unhealthy_retry_not_before_unix_seconds =
                            Some(now.saturating_add(unhealthy_scan_retry_delay_seconds(
                                traversal.unhealthy_retry_attempt,
                            )));
                        if previous_attempt < UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                            && traversal.unhealthy_retry_attempt
                                == UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                        {
                            eprintln!(
                    "ottto-service: bounded scan retry for {} reached attempt {}; the traversal \
                     stays a durable red witness and is re-walked at most hourly until the \
                     problem clears or the scan context changes",
                    source.api_slug(),
                    UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS
                );
                        }
                    }
                }
                let pending_work_count = pending_work_count
                    .saturating_add(usize::from(restart_after_hints))
                    .saturating_add(usize::from(terminal_unhealthy))
                    .saturating_add(usize::from(needs_clean_followup));
                let traversal = index.traversal.as_ref().expect("traversal remains active");
                let loaders = &codex_title_metadata.local_diagnostics;
                let census_status = CensusStatus {
                    pending_work: !traversal.pending_directories.is_empty()
                        || !traversal.pending_candidates.is_empty(),
                    retryable_problem: traversal.counts.has_retryable_problems(),
                    transport_reservation_refused: index
                        .context_read_counts
                        .transport_reservation_refused,
                    // Completeness also falls on identity conflicts: require
                    // an actual failed loader (#985), not just a false gate.
                    state_loader_failed: source == SnapshotSource::Codex
                        && (!state_census_complete || !sidecar_census_complete)
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
                    retry_not_before_unix_seconds: traversal
                        .unhealthy_retry_not_before_unix_seconds,
                };
                if raw_census_complete {
                    index.record_scan_residue_witness(source, &traversal_snapshot);
                }
                let mut carried_next_generation = Vec::new();
                if (raw_census_complete
                    && codex_legacy_join_baselines.is_empty()
                    && !pending_finalization.iter().any(|pending| {
                        index.files.get(&pending.index_key).is_some_and(|entry| {
                            entry.codex_applied_tier_receipt.is_some()
                                || entry.codex_joined_member_set.is_some()
                        })
                    }))
                    || restart_after_hints
                {
                    traversal_transition::retiring(
                        source,
                        index.generation,
                        &traversal_snapshot,
                        raw_census_complete,
                        index.unsettled_cause_bits(),
                        CensusGates {
                            discovery_done: traversal_discovery_done,
                            traversal_healthy,
                            frozen_generation: clean_frozen_generation,
                            state_complete: state_census_complete,
                            sidecar_complete: sidecar_census_complete,
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
                    carried_next_generation = index
                        .traversal
                        .as_ref()
                        .filter(|_| source == SnapshotSource::Codex)
                        .map_or_else(Vec::new, |traversal| {
                            traversal
                                .pending_candidates
                                .iter()
                                .filter(|candidate| !candidate.census_member)
                                .map(|candidate| candidate.path.clone())
                                .collect::<Vec<_>>()
                        });
                    index.traversal = None;
                    index.resume_after_path = None;
                    index.resume_upper_bound_path = None;
                    index.resume_census_window_end = None;
                }
                let counts = traversal_snapshot.counts;
                let zero_snapshot_confirmed_count = index.confirmed_empty_files.len();
                let zero_snapshot_usage_evidence_count = counts.zero_snapshot_usage_evidence_count;
                let dropped_usage_record_count = counts.dropped_usage_record_count;
                // The witness just recorded above describes THIS generation only when the
                // generation completed; otherwise the durable one is an earlier census's
                // and must not be reported as this scan's evidence. Counts only: the
                // witness's index keys never leave the local index.
                let (census_residue_index_key_count, census_residue_archived_rollout_count) =
                    if raw_census_complete {
                        index
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
                for snapshot in &mut snapshots {
                    snapshot.context_curve = None;
                }
                index.preserve_decode_held_files(source, &snapshots, &mut pending_finalization);
                snapshots.retain(|item| !index.decode_holds_snapshot(source, item));
                let census_complete = census_complete && index.decode_holds.is_empty();
                if census_complete {
                    // Only a healthy EFFECTIVE terminal can prove a
                    // carried file gone. A raw terminal, another file's census,
                    // or an unknown original association cannot retire its ACKs.
                    index.accepted_rebuild_incidence.retain(|key, _| {
                        key.is_empty()
                            || traversal_snapshot.observed_index_keys.contains(key)
                            || traversal_snapshot.residue.index_keys.contains(key)
                            || index.files.contains_key(key)
                    });
                    index.accepted_incidence_pending_census =
                        !index.accepted_rebuild_incidence.is_empty();
                    // A4d: the same proof retires a Tail whose file is gone.
                    #[cfg(unix)]
                    tail_source::load::retire_absent(
                        source,
                        index,
                        &traversal_snapshot.observed_index_keys,
                        &traversal_snapshot.residue.index_keys,
                    );
                }
                if !index.decode_holds.is_empty() {
                    index.mark_bounded_sweep_unsettled();
                }
                // Only a settled close starts the next generation in this
                // page. A partially settled sweep (including a decode hold
                // just marked) keeps its marker for the clean follow-up the
                // next page starts, and that walk re-reads the stale files.
                if !carried_next_generation.is_empty() && !index.bounded_sweep_had_unsettled_upload
                {
                    ensure_bounded_traversal(
                        source,
                        &roots,
                        index,
                        &collected_at,
                        backfill_window_days,
                    );
                    if let Some(next) = index.traversal.as_mut() {
                        enqueue_watcher_hints(source, next, &carried_next_generation, false);
                    }
                }
                let mut local_diagnostics = codex_title_metadata.local_diagnostics;
                if source == SnapshotSource::Codex {
                    let cutoff = codex_turn_traces
                        .as_ref()
                        .map_or(0, |traces| traces.since_epoch as u64);
                    local_diagnostics.price_tier_old_files_without_receipt = index
                        .file_snapshot_fingerprints
                        .iter()
                        .filter(|(key, fingerprints)| {
                            index
                                .files
                                .get(*key)
                                .is_some_and(|entry| entry.codex_applied_tier_receipt.is_none())
                                && !fingerprints.is_empty()
                                && fingerprints.iter().all(|fingerprint| {
                                    index
                                        .snapshot_activity_at
                                        .get(fingerprint)
                                        .and_then(Option::as_deref)
                                        .and_then(rfc3339_unix_seconds)
                                        .is_some_and(|activity| activity < cutoff)
                                })
                        })
                        .count()
                        as u64;
                }
                let continuation_evidence = (codex_join_completed.is_empty()
                    && continuation_ticket.is_some())
                .then(|| codex_join_inventory.take())
                .flatten()
                .filter(|inventory| inventory.complete)
                .map(|inventory| CodexContinuationEvidence {
                    inventory,
                    codex: codex_title_metadata,
                    traces: codex_turn_traces,
                });
                if continuation_ticket.is_some() && continuation_evidence.is_none() {
                    crate::local_resource_diagnostics::codex_continuation_mint(
                        if codex_join_completed.is_empty() {
                            "inventory_incomplete"
                        } else {
                            "groups_completed"
                        },
                    );
                }
                if source == SnapshotSource::Codex {
                    crate::local_resource_diagnostics::codex_zst_refused_flush();
                }
                let continuation_evidence = continuation_evidence
                    .zip(continuation_ticket.as_ref())
                    .and_then(|(evidence, ticket)| {
                        evidence.for_paused_job(
                            sampling.as_ref().map(|context| context.cache.as_ref()),
                            ticket,
                        )
                    });
                let codex_join_validation = codex_join_inventory.and_then(|inventory| {
                    let surviving: BTreeSet<_> = pending_finalization
                        .iter()
                        .filter_map(|pending| {
                            inventory.owner_for_path(Path::new(&pending.index_key))
                        })
                        .map(str::to_owned)
                        .collect();
                    (!surviving.is_empty()).then(|| {
                        codex_file_join::Validation::new(
                            inventory,
                            codex_join_completed,
                            &surviving,
                            traversal_snapshot.codex_rollout_paths,
                        )
                    })
                });
                let scan = SourceScanResult {
                    census_status,
                    claude_queued_family_deferred_paths: std::mem::take(
                        &mut history_upgrade.queued_family_deferred_paths,
                    ),
                    discovery_growth: std::mem::take(&mut resource_probe.discovery_growth),
                    source,
                    backfill_window_days,
                    backfill_file_limit: file_limit,
                    discovered_file_count,
                    skipped_file_count_due_to_limit,
                    scan_cap_hit: pending_work_count > 0,
                    scanned_file_count,
                    scanned_session_count,
                    semantic_noop_count,
                    census_complete,
                    census_window_end,
                    state_census_complete,
                    sidecar_census_complete,
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
                    terminal_recognized_usage_drop_count: counts
                        .terminal_recognized_usage_drop_count,
                    terminal_dropped_usage_record_count: counts.terminal_dropped_usage_record_count,
                    terminal_over_line_cap_count: counts.terminal_over_line_cap_count,
                    census_residue_index_key_count,
                    census_residue_archived_rollout_count,
                    snapshots,
                    pending_finalization,
                    codex_legacy_join_baselines,
                    claude_request_census_shadow,
                    continuation_ticket,
                    continuation_evidence: continuation_evidence
                        .map(|e| Arc::new(Mutex::new(Some(e)))),
                    codex_join_validation,
                    // Moved, not copied: the box was charged with the census.
                    codex_counting_v2: if source == SnapshotSource::Codex {
                        codex_counting_version::take_local_receipts(
                            index,
                            census.codex_counting_v2.take(),
                        )
                    } else {
                        census.codex_counting_v2.take()
                    },
                    local_codex_diagnostics: (source == SnapshotSource::Codex).then_some(
                        CodexScanDiagnostics {
                            version: 1,
                            generation: index.generation,
                            unreadable_causes: counts.unreadable_causes,
                            // PR-P: traversal-cumulative per-page counts, as
                            // `unreadable_causes`.
                            gates: CensusGates {
                                discovery_done: traversal_discovery_done,
                                traversal_healthy,
                                frozen_generation: clean_frozen_generation,
                                state_complete: state_census_complete,
                                sidecar_complete: sidecar_census_complete,
                                reconciliation_complete,

                                clean_followup: needs_clean_followup,
                                census_complete,
                            },
                            ..local_diagnostics
                        },
                    ),
                };
                if source == SnapshotSource::ClaudeCode {
                    rearm_cause::retain(index);
                }
                let sampled_acquisition = sampling.as_ref().map(|context| {
                    let audit_now = sampled_scan::now_seconds();
                    let pending = index
                        .files
                        .values()
                        .filter(|entry| entry.has_unverified_source())
                        .count();
                    let overdue = index
                        .files
                        .values()
                        .filter(|entry| entry.audit_requires_full(audit_now))
                        .count();
                    let oldest_due_age = index
                        .files
                        .values()
                        .filter_map(|entry| entry.audit_obligation(audit_now))
                        .map(|debt| audit_now.saturating_sub(debt.due_unix_seconds))
                        .max()
                        .unwrap_or(0);
                    if context.audit_cap_full > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_alarm", source.api_slug(),
                            &serde_json::json!({"audit_cap_full": context.audit_cap_full, "pending_audits": pending}));
                    }
                    if context.audit_cap_delay > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_cap_delay", source.api_slug(),
                            &serde_json::json!({"audit_cap_delay": context.audit_cap_delay}));
                    }
                    if context.pace_evicted > 0 {
                        crate::local_resource_diagnostics::traversal_point("sampled_audit_pace_alarm", source.api_slug(),
                            &serde_json::json!({"pace_evicted": context.pace_evicted}));
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
                            full_cause: resource_probe.rearm_fulls(),
                            full_by_parse_reason: resource_probe.full_by_parse_reason(),
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
                        codex_cursor: context.cache.cursor_diagnostics(&codex_page),
                    }
                });
                if sampled_acquisition.is_some() {
                    crate::local_resource_diagnostics::cache_lifecycle_totals();
                    crate::local_resource_diagnostics::codex_memo_lifecycle_totals(
                        source.api_slug(),
                    );
                }
                if let Some(delivery) = line_delivery.as_mut() {
                    if active_file.is_none() {
                        delivery.left_active();
                    }
                    resource_probe.line_delivery = Some(delivery.take_page());
                }
                let full_causes = std::mem::take(&mut resource_probe.full_causes);
                resource_probe.collection(
                    source.api_slug(),
                    crate::local_resource_diagnostics::CollectionCounts {
                        scanned_files: scanned_file_count,
                        semantic_noops: semantic_noop_count,
                        sampled_acquisition,
                        full_causes,
                    },
                );
                return Ok(OwnedSourceScanStep::Complete {
                    index: index_storage,
                    scan,
                });
            };
            // Reject budget debt before opening/constructing any body parser.
            // Requeue the original census membership; absence/completion stays owed.
            if index.context_only_read(&candidate)
                && !context_read_budget.admit(source, index, &candidate, &snapshots)
            {
                context_read_budget.defer(candidate);
                pending!();
            }
            if let Some(context) = sampling
                .as_ref()
                .filter(|_| source == SnapshotSource::Codex)
            {
                if context
                    .cache
                    .cursor_job_owns(&local_index_key(&candidate.path))
                {
                    // The paused or active cursor job owns this file (a group
                    // job owns every member); it stays pending (holding the
                    // census) until that job's attempt ends (§d.1.2 c).
                    sampled_scan::codex_cursor::requeue(index, &codex_selected_flags, &candidate);
                    pending!();
                }
            }
            let preflight_source_file_fingerprint =
                claude_authority_preflight_fingerprint(index, &candidate);
            if let Some(events) = launch_lookup {
                let workers =
                    launch_workers_for_candidate(source, &candidate, codex_join_inventory.as_ref());
                match events.prepare_step(&workers) {
                    Ok(false) => {
                        identified_candidates.push_front(candidate);
                        pending!();
                    }
                    Err(()) => {
                        census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                        pending!();
                    }
                    Ok(true) => {}
                }
            }
            // Keep the prepass physical identity intact while lookup yields. Only
            // replace it with sidecar inputs immediately before the second open.
            prepare_owned_scan_candidate(
                source,
                &mut candidate,
                &codex_title_metadata,
                &claude_title_metadata,
                claude_effort_support_dir_ref,
            );
            let unchanged = if source == SnapshotSource::Codex {
                match index.codex_unchanged_decision(
                    &mut candidate,
                    &codex_title_metadata,
                    audit_now,
                    true,
                ) {
                    Ok(input) => input,
                    Err(_) => {
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                        pending!();
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
                    source,
                    candidate,
                    &mut census,
                    CandidateWindow {
                        census_unix_seconds,
                        backfill_window_days,
                        retention: discovery_retention!(index, &resource_probe.discovery_growth),
                        growth: sampled_audit::growth_active(index)
                            .then_some(&index.v2().growth_retention),
                    },
                    sampling.as_ref().map(|context| context.cache.as_ref()),
                ),
            };
            let Some((mut candidate, opened_file)) = acquired else {
                pending!();
            };
            if preflight_source_file_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| fingerprint != &candidate.source_file_fingerprint)
            {
                // A quarantined candidate changed after the family prepass. Do not
                // parse a mixed family or refresh its retry record; keep this
                // generation non-terminal and retry the new exact object together.
                disappearance_diagnostics::increment(
                    &mut census.disappeared_file_count,
                    source,
                    disappearance_diagnostics::Cause::PreflightFingerprintChanged,
                );
                pending!();
            }
            // The preflight fences physical/sidecar identity. Local launcher facts
            // are semantic context and must not contaminate that two-open witness.
            if let Some(events) = launch_lookup.filter(|_| logical_decision.is_none()) {
                let workers =
                    launch_workers_for_candidate(source, &candidate, codex_join_inventory.as_ref());
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
            if source == SnapshotSource::ClaudeCode {
                if let Some(events) = launch_lookup {
                    if let Some((root, _)) = claude_index_path_family_member(&candidate.path) {
                        if forced_claude_family_reparses.contains(&root)
                            && claude_held_family_matches_launch_context(
                                index,
                                &root,
                                &candidate,
                                &identified_candidates,
                                events,
                            )
                        {
                            forced_claude_family_reparses.remove(&root);
                        }
                    }
                }
            }
            if index.decode_holds_file(&local_index_key(&candidate.path)) {
                index.mark_bounded_sweep_unsettled();
                pending!();
            }
            let mut source_change = None;
            let (mut decision, mut parse_reason) = match claude_twin_schedule
                .forced(&forced_claude_family_reparses, &candidate.path)
            {
                // A twin-only forced member that owes only adoption keeps that
                // reason, so the history gate can hold the whole twin group.
                Some(true)
                    if index.candidate_decision_with_reason_at(&candidate, audit_now)
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
                None => {
                    index.candidate_decision_in_window(&candidate, audit_now, &mut source_change)
                }
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
            // A skipped Claude file held only by this page's budget is queued
            // again as a re-read for the next page of the walk. Codex and Pi
            // keep the adoption-only page budget.
            if decision == CandidateDecision::Parse {
                let adoption_only = parse_reason == Some(CandidateParseReason::BodyWitnessAdoption)
                    && (index.candidate_requires_only_body_witness_adoption(&candidate, audit_now)
                        || (source == SnapshotSource::ClaudeCode
                            && claude_copy_prefix_reread::unchanged_requested(
                                index, &candidate, audit_now,
                            )));
                let history = if source == SnapshotSource::ClaudeCode {
                    index.claude_history_upgrade_decision(
                        &candidate,
                        opened_file
                            .metadata()
                            .and_then(|metadata| metadata.created())
                            .ok()
                            .and_then(unix_seconds),
                        &mut history_upgrade,
                    )
                } else if adoption_only
                    && !history_upgrade.reserve_admitting_first_file(
                        &local_index_key(&candidate.path),
                        candidate.size_bytes,
                    )
                {
                    history_upgrade.note_denied(
                        HistoryHold::Budget,
                        index.claude_reemission_exclusions.state(),
                    );
                    HistoryDecision::Held(HistoryHold::Budget)
                } else {
                    HistoryDecision::NotOwed
                };
                // A held, unchanged member owed only a proof correction is not
                // re-read every traversal either: its bodies would be vetoed,
                // and the correction waits for the gate (StateMissing).
                let correction_only = parse_reason
                    == Some(CandidateParseReason::AuthorityQuarantine)
                    && index.claude_authority_correction_only(&candidate);
                // A listed genuine change is never held (it is literal-only
                // denied), so a held correction-only member is unchanged.
                match history {
                    HistoryDecision::Held(hold) if adoption_only || correction_only => {
                        if source == SnapshotSource::ClaudeCode {
                            let carried = index
                                .accepted_rebuild_incidence
                                .get(&local_index_key(&candidate.path))
                                .map_or(0, BTreeSet::len);
                            index.claude_history_emission.skipped_carried_entries = index
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
                            if hold == HistoryHold::Budget && history_upgrade.admitted_any() {
                                if let Some(traversal) = index.traversal.as_mut() {
                                    traversal.pending_candidates.push_back(ScanTraversalPath {
                                        scan_root: candidate.scan_root.clone(),
                                        path: candidate.path.clone(),
                                        census_member: false,
                                        watcher_hint: false,
                                    });
                                }
                            }
                        }
                        decision = CandidateDecision::Skip;
                    }
                    HistoryDecision::Held(hold) => {
                        index.gate_claude_history_candidate(&candidate, Some(hold));
                    }
                    HistoryDecision::Owed => index.gate_claude_history_candidate(&candidate, None),
                    HistoryDecision::LiteralDenied => {
                        index.deny_claude_history_literal(&candidate);
                    }
                    HistoryDecision::NotOwed => {}
                }
            }
            // A file whose Tail failed alone is selected by its set-aside
            // marker before an ordinary Skip, even with equal stamps, and
            // re-reads from its committed head.
            #[cfg(unix)]
            if decision == CandidateDecision::Skip
                && matches!(state_v2::tail_route_path(index), Ok(Some(_)))
                && tail_source::load::set_aside(index, &local_index_key(&candidate.path))
            {
                decision = CandidateDecision::Parse;
            }
            let stale_input_held = index.stale_refusal_holds_unchanged_input(&candidate);
            if stale_input_held {
                decision = CandidateDecision::Skip;
                parse_reason = None;
            }
            if source == SnapshotSource::ClaudeCode && decision == CandidateDecision::Parse {
                if let Some(reason) = parse_reason {
                    let count = &mut census.parse_reasons[reason as usize];
                    *count = count.saturating_add(1);
                }
            }
            index.note_reason_reoffer_cooldown_candidate(
                &candidate,
                decision == CandidateDecision::Skip && parse_reason.is_none(),
            );
            if source == SnapshotSource::Codex {
                census.note_codex_selection(decision, parse_reason, None);
            }
            match decision {
                CandidateDecision::Skip => {
                    page_selection(source.api_slug(), PageSelection::Skipped, 1);
                    if let Some(loss) = index.terminal_jsonl_loss(&candidate) {
                        census.add_terminal_jsonl_loss(loss);
                    }
                    // The ordinary equality Skip attests this revision
                    // for the shadow family census. Counts only.
                    if source == SnapshotSource::ClaudeCode && parse_reason.is_none() {
                        claude_family_census_shadow::attest_equality_skip(
                            index, &candidate, &sampling, audit_now,
                        );
                    }
                    pending!();
                }
                CandidateDecision::Migrate => {
                    index.migrate(candidate);
                    pending!();
                }
                CandidateDecision::ReconcileLegacy | CandidateDecision::Parse => {}
            }
            #[cfg(test)]
            sampled_scan::test_hooks::after_selection(index, parse_reason);
            if let Some(context) = sampling
                .as_ref()
                .filter(|_| source == SnapshotSource::Codex && !codex_archive_path(&candidate.path))
            {
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
                    codex_page.charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                    let sidecar_now = sampled_scan::codex_cursor::sidecar_fingerprint(
                        &codex_title_metadata,
                        &candidate.path,
                    );
                    let digest = sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .and_then(|dependencies| {
                        sampled_scan::codex_cursor::memo_digest(
                            index,
                            &candidate,
                            &opened_file,
                            &dependencies,
                            &codex_title_metadata,
                            sampled_scan::codex_cursor::owner_members(
                                codex_join_inventory.as_ref(),
                                &candidate.path,
                            ),
                            &sampled_scan::codex_cursor::counting_view(&candidate, index),
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
                            && !index
                                .effective_upload_body_witness_revision_requires_adoption(&key);
                        let previous = (
                            keep_previous
                                .then(|| index.last_snapshot_fingerprint(&candidate))
                                .flatten(),
                            keep_previous
                                .then(|| index.last_upload_body_witness(&candidate))
                                .flatten(),
                        );
                        sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                            entry.disclosure(),
                            &candidate,
                            previous,
                            index,
                            targets!(),
                        );
                        // The fresh path's session count, replayed.
                        scanned_session_count += entry.disclosure().parsed_snapshot_count;
                        pending!();
                    }
                    match digest.as_deref().and_then(|digest| {
                        entry.grew_past_exact(&candidate.path, digest, &opened_file, &sidecar_now)
                    }) {
                        Some(extent) => {
                            codex_memo_lifecycle::record(
                                codex_memo_lifecycle::Event::MissExactStamp,
                            );
                            codex_memo_lifecycle::add(
                                codex_memo_lifecycle::Event::MissExactStampBytes,
                                extent,
                            );
                        }
                        None => {
                            codex_memo_lifecycle::record(codex_memo_lifecycle::Event::MissOther)
                        }
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
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    )
                    .as_deref(),
                );
                if let Some(disclosure) = parked {
                    let keep_previous = decision != CandidateDecision::ReconcileLegacy
                        && !index.effective_upload_body_witness_revision_requires_adoption(&key);
                    let previous = (
                        keep_previous
                            .then(|| index.last_snapshot_fingerprint(&candidate))
                            .flatten(),
                        keep_previous
                            .then(|| index.last_upload_body_witness(&candidate))
                            .flatten(),
                    );
                    sampled_scan::codex_cursor::disclose_terminal_codex_debt(
                        &disclosure,
                        &candidate,
                        previous,
                        index,
                        targets!(),
                    );
                    pending!();
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
                let continued = tail_source::committed_sealed_offset(source, index, &key);
                let expected = extent.saturating_sub(continued.unwrap_or(0));
                if index.context_only_read(&candidate) {
                    context_read_budget.charge_cursor_ordinary(&mut codex_page);
                }
                match context.cache.cursor_plan_paced(
                    &mut codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    expected,
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    crate::heap_layout_bound::layout_supported(),
                    &context.namespace,
                    &key,
                    sampled_scan::codex_cursor::census_token(index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &codex_selected_flags,
                        [candidate.path.as_path()],
                    ),
                    Some(sampled_scan::codex_cursor::PaceProbe { file: &opened_file }),
                ) {
                    sampled_scan::codex_cursor::StartPlan::Defer => {
                        context.cache.cursor_note_deferred();
                        sampled_scan::codex_cursor::requeue(
                            index,
                            &codex_selected_flags,
                            &candidate,
                        );
                        pending!();
                    }
                    // Processed for this generation (K7 fence): not requeued,
                    // so the census can complete; the next generation reads it.
                    sampled_scan::codex_cursor::StartPlan::Fenced => pending!(),
                    sampled_scan::codex_cursor::StartPlan::Singleton
                    | sampled_scan::codex_cursor::StartPlan::Cursor
                    | sampled_scan::codex_cursor::StartPlan::Unpaged => {}
                }
            }
            scanned_file_count += 1;
            let previous_snapshot_fingerprint = index.last_snapshot_fingerprint(&candidate);
            let previous_upload_body_witness = index.last_upload_body_witness(&candidate);
            let projection_adoption_required = index
                .effective_upload_body_witness_revision_requires_adoption(&local_index_key(
                    &candidate.path,
                ));
            let source_file_fingerprint = candidate.source_file_fingerprint.clone();
            let mut parser = match sampled_scan::new_source_parser(
                opened_file,
                &candidate,
                index,
                sampled_scan::ParserOptions {
                    source,
                    metadata: &codex_title_metadata,
                    traces: codex_turn_traces.clone(),
                    identity_capture: claude_request_identity_capture,
                    cache: sampling.as_ref().map(|c| &c.cache),
                },
            ) {
                Ok(parser) => parser,

                Err(error) => {
                    if sampled_scan::codex_cursor::requeue_refused(
                        source,
                        &error,
                        index,
                        &codex_selected_flags,
                        &candidate,
                    ) {
                        pending!();
                    }
                    if source == SnapshotSource::ClaudeCode {
                        claude_request_census::invalidate_claude_request_census(
                            index,
                            &candidate.path,
                        );
                    }
                    census.record_unreadable_file(UnreadableCause::Reduction, &candidate.path);
                    pending!();
                }
            };

            let mut file_sampling = None;
            let mut retained_offset = None;
            // Counted once the page actually reads the file: a fence
            // or deferral below does not inflate the read diagnostics.
            let mut planned_mode = None;
            if let Some(context) = sampling
                .as_mut()
                .filter(|_| !parser.reader.reader.is_compressed())
            {
                let key = local_index_key(&candidate.path);
                // Every source's continuation is its committed Tail. A route
                // that cannot be read now holds the file for its next
                // selection.
                #[cfg(unix)]
                let tail_route = match state_v2::tail_route_path(index) {
                    Ok(route) => route,
                    Err(_) => {
                        tail_source::counters::bump(source, "tail_db_loads", "held");
                        residue_index_keys.insert(key.clone());
                        pending!();
                    }
                };
                // No database route (v1, a paused import, no support dir): its
                // growth reads Full.
                #[cfg(unix)]
                if tail_route.is_none() && index.files.contains_key(&key) {
                    tail_source::counters::bump(source, "tail_bootstrap_full", "unrouted");
                }
                #[cfg(not(unix))]
                let tail_route: Option<PathBuf> = None;
                // On a Tail route the held-new custody is durable: the
                // withheld read's census record, and its committed head.
                let e2_held_new_file = source == SnapshotSource::ClaudeCode
                    && tail_route.is_some()
                    && tail_source::load::held_new(index, &key);
                context.admission.attempts = context.admission.attempts.saturating_add(1);
                let owning_header_is_current = source != SnapshotSource::Codex
                    || codex_join_inventory.as_ref().is_some_and(|inventory| {
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
                    .observe(state_census_complete);
                context
                    .admission
                    .sidecar_census_complete
                    .observe(sidecar_census_complete);
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
                    && source == SnapshotSource::ClaudeCode
                    && !sidecar_census_complete
                    && (index.files.contains_key(&key) || e2_held_new_file);
                if owning_header_is_current
                    && state_census_complete
                    && (sidecar_census_complete || scoped_claude_metadata)
                {
                    if scoped_claude_metadata {
                        crate::local_resource_diagnostics::claude_reread::desktop_scoped_acquisition();
                    }
                    let reduction_sidecar = sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    );
                    context
                        .admission
                        .reduction_dependencies_available
                        .observe(reduction_sidecar.is_some());
                    if let Some(reduction_sidecar) = reduction_sidecar {
                        let debt = sampled_audit::debt_for_key(index, &key, audit_now);
                        let protected_entry = index.files.get(&key);
                        context
                            .admission
                            .index_entry_present
                            .observe(protected_entry.is_some());
                        let protected =
                            protected_entry.is_some_and(ScanIndexEntry::codex_history_is_protected);
                        let forced_family = claude_twin_schedule
                            .forced(&forced_claude_family_reparses, &candidate.path)
                            .is_some()
                            || claude_index_path_family_member(&candidate.path).is_some_and(
                                |(root, _)| {
                                    index.claude_usage_authority_quarantine.contains_key(&root)
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
                                || claude_request_census::forced_member_needs_native(index, &key));
                        let mut allow_sample = (index.files.contains_key(&key) || e2_held_new_file)
                            && !protected
                            && !forced_native;
                        context
                            .admission
                            .audit_metadata_supported
                            .observe(context.audit_metadata_supported);
                        context.admission.protected_history.observe(protected);
                        context.admission.forced_family.observe(forced_family);
                        context.admission.comparison_target.observe(false);

                        context.admission.audit_debt_present.observe(debt.is_some());
                        context
                            .admission
                            .audit_slot_available
                            .observe(context.audit_slots > 0);
                        let scope = context.file_scope(source, &candidate, &reduction_sidecar);
                        // On a Tail route a read loads the committed Tail.
                        #[cfg(unix)]
                        let tail_load = tail_route.as_deref().filter(|_| {
                            allow_sample
                                && tail_source::load::reuses_stored(
                                    index,
                                    &key,
                                    parse_reason,
                                    index.files.get(&key).is_some_and(|entry| {
                                        candidate.size_bytes > entry.size_bytes
                                    }),
                                    e2_held_new_file,
                                )
                                && !parser.reader.reader.is_compressed()
                        });
                        #[cfg(unix)]
                        if tail_route.is_some()
                            && tail_load.is_none()
                            && parse_reason == Some(CandidateParseReason::NewFile)
                        {
                            tail_source::counters::bump(source, "tail_bootstrap_full", "new_file");
                        }
                        #[cfg(unix)]
                        let mut tail_proven_full = None;
                        #[cfg(unix)]
                        let (mut retained, debt) = match tail_load {
                            Some(route) => {
                                match tail_source::load_candidate(
                                    source,
                                    index,
                                    route,
                                    &candidate,
                                    &parser.accumulator,
                                    claude_request_identity_capture,
                                    parser.reader.reader.get_mut(),
                                    &scope,
                                ) {
                                    tail_source::load::Load::Reused(retained, base) => {
                                        if let Some(base) = base {
                                            parser.set_tail_base(base);
                                        }
                                        // A late-evidence re-fold from
                                        // stored state, counted by its reason.
                                        if let Some(reason) = parse_reason.filter(|reason| {
                                            tail_source::load::late_evidence(*reason)
                                        }) {
                                            tail_source::counters::bump(
                                                source,
                                                "tail_refold",
                                                CANDIDATE_PARSE_REASON_NAMES[reason as usize],
                                            );
                                        }
                                        retained_offset = Some(retained.checkpoint.sealed_offset());
                                        (Some(retained), debt)
                                    }
                                    // A newer build's head: untouched, held as residue.
                                    tail_source::load::Load::Held => {
                                        residue_index_keys.insert(key.clone());
                                        pending!();
                                    }
                                    tail_source::load::Load::Cold(proven) => {
                                        tail_proven_full = proven;
                                        (None, debt)
                                    }
                                }
                            }
                            None if allow_sample && !parser.reader.reader.is_compressed() => {
                                // A read with no stored continuation: counted by why.
                                resource_probe.full_causes.restore_outcome.record(
                                    sampled_scan::ram_miss_class(
                                        index,
                                        &key,
                                        context.cache.quiet_registered(source),
                                    ),
                                );
                                (None, debt)
                            }
                            None => (None, debt),
                        };
                        // The cap funds NEW obligations, never a global restore
                        // gate. Marked files Tail; quiet debt-free copies reuse.
                        let mut cap_full = false;
                        if allow_sample
                            // Account-held reparses belong to withheld_reparse;
                            // central staging still bounds fresh audit markers.
                            && !index.claude_account_deferred_holds.contains_key(&key)
                            && context.audit_slots == 0
                            && index.files.contains_key(&key)
                            && !index
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
                                sampled_audit::queue_cap_retry(index, &candidate);
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                            cap_full = true;
                            allow_sample = false;
                        }
                        context.admission.sampling_allowed.observe(allow_sample);
                        if !allow_sample {
                            drop(retained.take());
                        }
                        context.admission.prepare_started =
                            context.admission.prepare_started.saturating_add(1);
                        let census_base_bound = retained
                            .as_ref()
                            .zip(index.files.get(&key))
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
                                            && index.claude_request_census.get(&key).is_some_and(
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
                                if source == SnapshotSource::ClaudeCode {
                                    claude_request_census::invalidate_claude_request_census(
                                        index,
                                        &candidate.path,
                                    );
                                }
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                        };
                        #[cfg(unix)]
                        let mode = match (tail_proven_full, parser.reader.acquisition.as_mut()) {
                            (Some(reason), Some(plan)) => plan.name_proven_full(reason),
                            _ => mode,
                        };
                        if !sampled_audit::growth_read_admitted(index, &candidate, mode) {
                            sampled_audit::defer_growth_read(index, &mut census, &candidate);
                            pending!();
                        }
                        // H1c: the plan uses absolute offsets; the reader's
                        // extent is relative to its Full/Tail start.
                        if source == SnapshotSource::ClaudeCode
                            && (allow_sample || cap_full)
                            && matches!(
                                mode,
                                crate::transcript_acquisition::ReadMode::Full(_)
                                    | crate::transcript_acquisition::ReadMode::Tail
                            )
                        {
                            if let Some(plan) = parser.reader.acquisition.as_ref() {
                                parser
                                    .reader
                                    .set_extent_limit(plan.frozen_length() - plan.start_offset());
                            }
                        }
                        // Restore does not restore/extend an exact-prefix pricing receipt.
                        // Any new priority contribution below forces a real full replay.
                        if source == SnapshotSource::Codex {
                            sampled_scan::configure_tier_replay(&mut parser, &candidate, index);
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
                                (source == SnapshotSource::ClaudeCode
                                    && allow_sample
                                    && matches!(
                                        mode,
                                        crate::transcript_acquisition::ReadMode::Full(_)
                                    ))
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
                        });
                    }
                } else if source == SnapshotSource::Codex
                    && owning_header_is_current
                    && crate::heap_layout_bound::layout_supported()
                    && parser
                        .reader
                        .reader
                        .get_ref()
                        .metadata()
                        .is_ok_and(|metadata| {
                            metadata.len()
                                > sampled_scan::codex_cursor::Limits::current().singleton()
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
                        source,
                        &candidate,
                        &codex_title_metadata,
                        &claude_title_metadata,
                        claude_effort_support_dir_ref,
                    );
                    context
                        .admission
                        .reduction_dependencies_available
                        .observe(reduction_sidecar.is_some());
                    if let Some(reduction_sidecar) = reduction_sidecar {
                        let scope = context.file_scope(source, &candidate, &reduction_sidecar);
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
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &candidate.path,
                                );
                                pending!();
                            }
                        };
                        sampled_scan::configure_tier_replay(&mut parser, &candidate, index);
                        planned_mode = Some((mode, None));
                        file_sampling = Some(sampled_scan::Active {
                            key,
                            scope,
                            mode,
                            audit_due: None,
                            tier_prefix_replay: false,
                            census_base_bound: false,
                        });
                    }
                }
            }
            if source == SnapshotSource::ClaudeCode
                && file_sampling.is_none()
                && !sampled_audit::growth_read_admitted(
                    index,
                    &candidate,
                    crate::transcript_acquisition::ReadMode::Full(
                        crate::transcript_acquisition::FullReason::StateMissing,
                    ),
                )
            {
                sampled_audit::defer_growth_read(index, &mut census, &candidate);
                pending!();
            }
            index.note_change_reason_selected(source, &candidate, parse_reason, source_change);
            let mut active = Box::new(OwnedActiveFile {
                first_read: crate::local_resource_diagnostics::FirstRead::begin(
                    source,
                    candidate.size_bytes,
                    !index.files.contains_key(&local_index_key(&candidate.path)),
                ),
                sampling: file_sampling,
                candidate,
                decision,
                parse_reason: parse_reason.filter(|_| source == SnapshotSource::ClaudeCode),
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
            if let Some(context) = sampling.as_ref().filter(|_| {
                source == SnapshotSource::Codex && !codex_archive_path(&active.candidate.path)
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
                    &mut codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    expected,
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    crate::heap_layout_bound::layout_supported(),
                    &context.namespace,
                    &local_index_key(&active.candidate.path),
                    sampled_scan::codex_cursor::census_token(index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &codex_selected_flags,
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
                        codex_page.disclose_disabled(&context.cache);
                        false
                    }
                    sampled_scan::codex_cursor::StartPlan::Cursor => {
                        let dependencies = sampled_scan::reduction_dependencies(
                            source,
                            &active.candidate,
                            &codex_title_metadata,
                            &claude_title_metadata,
                            claude_effort_support_dir_ref,
                        );
                        let owner = codex_join_inventory
                            .as_ref()
                            .and_then(|inventory| inventory.owner_for_path(&active.candidate.path))
                            .map(str::to_owned);
                        match context.cache.cursor_start(
                            &mut active,
                            &context.namespace,
                            dependencies,
                            owner,
                            state_census_complete && sidecar_census_complete,
                            index,
                        ) {
                            Ok(lease) => {
                                // The job's path holds the strict census until
                                // its attempt ends (accepted or debt).
                                sampled_scan::codex_cursor::requeue(
                                    index,
                                    &codex_selected_flags,
                                    &active.candidate,
                                );
                                codex_cursor_lease = Some(lease);
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
                                census.record_unreadable_file(
                                    UnreadableCause::Reduction,
                                    &active.candidate.path,
                                );
                                pending!();
                            }
                            Err(sampled_scan::codex_cursor::StartRefusal::Unstartable) => {
                                // Never an unbounded in-page read of a file
                                // larger than the singleton budget.
                                census.record_unreadable_file(
                                    UnreadableCause::OpenRead,
                                    &active.candidate.path,
                                );
                                pending!();
                            }
                        }
                    }
                    sampled_scan::codex_cursor::StartPlan::Defer => true,
                    // Processed for this generation (K7 fence).
                    sampled_scan::codex_cursor::StartPlan::Fenced => {
                        scanned_file_count = scanned_file_count.saturating_sub(1);
                        pending!();
                    }
                };
                if defer {
                    // Only a full read reaches here (a tail was planned
                    // before its retained state was consumed).
                    context.cache.cursor_note_deferred();
                    scanned_file_count = scanned_file_count.saturating_sub(1);
                    sampled_scan::codex_cursor::requeue(
                        index,
                        &codex_selected_flags,
                        &active.candidate,
                    );
                    pending!();
                }
            }
            if let Some(context) = sampling.as_mut() {
                if let Some((mode, audit_due)) = planned_mode {
                    context.record_mode(mode, audit_due);
                    resource_probe
                        .rearm_full_selected(&local_index_key(&active.candidate.path), mode);
                    resource_probe.full_parse_reason(mode, active.parse_reason, 1, 0);
                }
            }
            if let Some(delivery) = line_delivery.as_mut() {
                delivery.arm();
            }
            active_file = Some(active);
            pending!();
        }
        if let (None, Some(delivery)) = (&active_file, line_delivery.as_mut()) {
            delivery.left_active();
        }
        Ok(OwnedSourceScanStep::Pending(Self {
            resource_probe,
            sampling,
            source,
            roots,
            index: index_storage,
            collected_at,
            audit_now,
            backfill_window_days,
            file_limit,
            claude_request_identity_capture,
            claude_effort_support_dir,
            codex_title_metadata,
            claude_title_metadata,
            state_census_complete,
            sidecar_census_complete,
            codex_turn_traces,
            codex_census_valid,
            census_window_end,
            discovered_file_count,
            census_unix_seconds,
            census,
            snapshots,
            scanned_file_count,
            scanned_session_count,
            semantic_noop_count,
            history_upgrade,
            context_read_budget,
            residue_index_keys,
            settled_residue_index_keys,
            pending_finalization,
            claude_authority_preflight,
            forced_claude_family_reparses,
            claude_twin_schedule,
            claude_family_shadow,
            identified_candidates,
            active_file: sampled_scan::codex_cursor::ActiveFrame::new(
                active_file,
                codex_cursor_lease,
            ),
            codex_join_inventory,
            codex_join_prepared,
            codex_join_groups,
            codex_join_active,
            codex_join_completed,
            codex_legacy_join_baselines,
            codex_page,
            codex_selected_flags,
            continuation_ticket,
            line_delivery,
            codex_versions,
            launch_events,
        }))
    }
}
