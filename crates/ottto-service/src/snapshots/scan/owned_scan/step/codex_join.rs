//! Plan Codex groups, advance group boot and try the shared cursor.
//! Boot and resume yield after transferring a job; an idle continuation can
//! drain its selection and proceed to page close in the same call.

use super::*;

impl OwnedSourceScan {
    #[inline(never)]
    pub(super) fn step_codex_join(
        &mut self,
        launch_lookup: Option<&crate::launch_events::LaunchEventInventory>,
        active_file: &mut Option<Box<OwnedActiveFile>>,
        codex_cursor_lease: &mut Option<sampled_scan::codex_cursor::CursorLease>,
    ) -> bool {
        if self.source == SnapshotSource::Codex && !self.codex_join_prepared {
            if let Some(inventory) = self.codex_join_inventory.as_mut() {
                if let Some(context) = self.sampling.as_ref() {
                    // The inventory's lookups count in this scan's window;
                    // the page clock still ticks at `note_page`.
                    self.codex_page.open_window(&context.cache);
                }
                if !inventory.step_selected(
                    &self.codex_title_metadata,
                    &mut self.index,
                    &self.selected_flags,
                    self.sampling.as_ref().map(|context| &context.cache),
                ) {
                    return true;
                }
                let selected = self
                    .identified_candidates
                    .iter()
                    .map(|candidate| local_index_key(&candidate.path))
                    .collect::<BTreeSet<_>>();
                let inventoried = inventory
                    .headers
                    .iter()
                    .map(|header| local_index_key(&header.candidate.path))
                    .collect::<BTreeSet<_>>();
                let missing = selected
                    .difference(&inventoried)
                    .filter(|key| {
                        let owners = codex_session_id_candidates_from_path(Path::new(key));
                        owners.is_empty()
                            || !owners
                                .iter()
                                .all(|owner| inventory.held_owners.contains(owner))
                    })
                    .count();
                inventory
                    .mark_incomplete(codex_file_join::Incomplete::SelectedNotInventoried, missing);
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
                let mut repurposed_protected_paths = BTreeSet::new();
                let mut missing_protected_owners = BTreeSet::new();
                let mut missing_unknown_owner = false;
                for owner in self.index.decode_held_codex_owners() {
                    match owner {
                        Some(owner) => {
                            missing_protected_owners.insert(owner.to_owned());
                        }
                        None => missing_unknown_owner = true,
                    }
                }
                for (key, entry) in &self.index.files {
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
                self.census.unreadable_path_count += inventory.refused.len();
                self.census
                    .unreadable_causes
                    .merge(inventory.unreadable_causes);
                let mut grouped_paths = BTreeSet::new();
                let mut inventory_held = BTreeSet::new();
                let mut used = 0usize;
                // R2-N6: a group with more members than the page's file
                // limit is never excluded; it goes first and takes a page
                // of its own (it pages through the cursor like any group).
                // So does a group whose probes outran a page's
                // remaining singleton budget (`ProbeBudgetOrder`).
                let fence = sampled_scan::codex_cursor::census_token(&self.index);
                let own_page = |group: &codex_file_join::Group| {
                    group.members.len() > self.file_limit
                        || self.sampling.as_ref().is_some_and(|context| {
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
                        self.index.file_upload_context_enabled()
                            && group
                                .members
                                .iter()
                                .all(|member| self.index.context_only_read(member)),
                        !*own,
                        !sampled_scan::codex_cursor::census_member(
                            &self.selected_flags,
                            group.members.iter().map(|member| member.path.as_path()),
                        ),
                        // First read: newest groups admit first (order only;
                        // each group's fold stays chronological).
                        self.index
                            .first_read_pending
                            .then(|| first_read_order::newest_member(&group.members)),
                    )
                });
                let mut ordinary_singleton_slots = None;
                for (own, group) in groups {
                    if group
                        .members
                        .iter()
                        .any(|member| self.index.decode_holds_file(&local_index_key(&member.path)))
                    {
                        grouped_paths.extend(
                            group
                                .members
                                .iter()
                                .map(|member| local_index_key(&member.path)),
                        );
                        self.index.mark_bounded_sweep_unsettled();
                        continue;
                    }
                    let protected_history_missing = missing_unknown_owner
                        || missing_protected_owners.contains(&codex_protected_owner(&group.owner));
                    let previously_joined = group.members.iter().any(|member| {
                        self.index
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
                        && inventory.membership_complete(&group.owner, affected_owners.as_ref()))
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
                    if self.sampling.as_ref().is_some_and(|context| {
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
                        scan::owned_scan::requeue_members(
                            &mut self.index,
                            &self.selected_flags,
                            owned,
                        );
                        continue;
                    }
                    let malformed_pending = group.members.iter().any(|member| {
                        self.index
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
                        let members = group
                            .members
                            .iter()
                            .map(|member| local_index_key(&member.path));
                        if !inventory.complete {
                            // Owed to the inventory hold, which keeps the
                            // generation red until it is released.
                            inventory_held.extend(members);
                            continue;
                        }
                        self.census.ownership_incomplete_file_count += group.members.len();
                        self.census
                            .causes
                            .add(ownership::INVENTORY, group.members.len());
                        self.census
                            .record_unreadable(UnreadableCause::AliasParser, 1);
                        self.residue_index_keys.extend(members);
                        continue;
                    }
                    // G1: a group whose attempt already ended in this
                    // generation is fenced at its pop (M-5 b) and reads
                    // nothing. Decide it here, so it takes no file
                    // allowance a waiting census member needs.
                    let fenced = self.sampling.as_ref().is_some_and(|context| {
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
                            &self.selected_flags,
                            group.members.iter().map(|member| member.path.as_path()),
                        )
                        && {
                            let waiting = self
                                .identified_candidates
                                .iter()
                                .filter(|candidate| {
                                    let key = local_index_key(&candidate.path);
                                    !grouped_paths.contains(&key)
                                        && sampled_scan::codex_cursor::selected_census_member(
                                            &self.selected_flags,
                                            &candidate.path,
                                        )
                                })
                                .count();
                            waiting > 0
                                && (own || used + group.members.len() + waiting > self.file_limit)
                        };
                    // Ordinary groups have already spent their slots. Before
                    // the first context group, reserve the remaining ordinary
                    // singletons too; catch-up must never evict one below.
                    let context_group = self.index.file_upload_context_enabled()
                        && group
                            .members
                            .iter()
                            .all(|member| self.index.context_only_read(member));
                    let waiting_ordinary = if context_group {
                        *ordinary_singleton_slots.get_or_insert_with(|| {
                            self.identified_candidates
                                .iter()
                                .filter(|candidate| {
                                    !grouped_paths.contains(&local_index_key(&candidate.path))
                                        && !self.index.context_only_read(candidate)
                                        && self
                                            .index
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
                                > self.file_limit);
                    if context_crowds_ordinary
                        || rereads_crowd_members
                        || (!fenced
                            && used > 0
                            && (own || used + group.members.len() > self.file_limit))
                    {
                        // Keep the existing traversal as the only queue. A whole
                        // group is selected on a subsequent ordinary page.
                        if let Some(traversal) = self.index.traversal.as_mut() {
                            for member in &group.members {
                                if selected.contains(&local_index_key(&member.path)) {
                                    traversal.pending_candidates.push_back(ScanTraversalPath {
                                        scan_root: member.scan_root.clone(),
                                        path: member.path.clone(),
                                        // G1: a re-read is not re-enrolled.
                                        census_member:
                                            sampled_scan::codex_cursor::selected_census_member(
                                                &self.selected_flags,
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
                            used = used.max(self.file_limit);
                        }
                    }
                    if let Some(traversal) = self.index.traversal.as_mut() {
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
                        self.codex_join_groups.push_back(group);
                    }
                }
                self.identified_candidates
                    .retain(|candidate| !grouped_paths.contains(&local_index_key(&candidate.path)));
                let held = self
                    .identified_candidates
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
                self.identified_candidates
                    .retain(|candidate| !held.contains(&local_index_key(&candidate.path)));
                if inventory.complete {
                    self.census.ownership_incomplete_file_count += held.len();
                    self.census.causes.add(ownership::INVENTORY, held.len());
                    self.residue_index_keys.extend(held);
                } else {
                    inventory_held.extend(held);
                }
                // Record the hold now: preparation yields below, and a
                // resumed step does not come back here.
                if !inventory_held.is_empty() {
                    if let Some(traversal) = self.index.traversal.as_mut() {
                        inventory_held.extend(self.residue_index_keys.iter().cloned());
                        let (held, awaiting, outside) =
                            record_codex_inventory_hold(traversal, inventory, &inventory_held);
                        // The fold records and counts the residue keys
                        // again, so its census line carries only the rest.
                        let residue_outside = self
                            .residue_index_keys
                            .iter()
                            .filter(|key| !traversal.codex_rollout_paths.contains(*key))
                            .count();
                        self.codex_inventory_hold_counts = (
                            held.saturating_sub(self.residue_index_keys.len()),
                            awaiting,
                            outside.saturating_sub(residue_outside),
                        );
                    }
                }
                while !self.identified_candidates.is_empty()
                    && used + self.identified_candidates.len() > self.file_limit
                {
                    // G1: re-reads leave before any census member.
                    let context_evict = self
                        .index
                        .file_upload_context_enabled()
                        .then(|| {
                            let disposable = |candidate: &CandidateFile| {
                                self.index.context_only_read(candidate)
                                    || self
                                        .index
                                        .candidate_decision_with_reason_at(
                                            candidate,
                                            sampled_scan::now_seconds(),
                                        )
                                        .0
                                        == CandidateDecision::Skip
                            };
                            self.identified_candidates
                                .iter()
                                .rposition(|candidate| {
                                    disposable(candidate)
                                        && !sampled_scan::codex_cursor::selected_census_member(
                                            &self.selected_flags,
                                            &candidate.path,
                                        )
                                })
                                .or_else(|| self.identified_candidates.iter().rposition(disposable))
                        })
                        .flatten();
                    let evict = context_evict
                        .or_else(|| {
                            self.identified_candidates.iter().rposition(|candidate| {
                                !sampled_scan::codex_cursor::selected_census_member(
                                    &self.selected_flags,
                                    &candidate.path,
                                )
                            })
                        })
                        .unwrap_or(self.identified_candidates.len() - 1);
                    if let Some(candidate) = self.identified_candidates.remove(evict) {
                        if let Some(traversal) = self.index.traversal.as_mut() {
                            // G1: a re-read is not re-enrolled.
                            let census_member = sampled_scan::codex_cursor::selected_census_member(
                                &self.selected_flags,
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
            if self.index.file_upload_context_enabled() {
                self.codex_join_groups
                    .make_contiguous()
                    .sort_by_cached_key(|group| {
                        group
                            .members
                            .iter()
                            .all(|candidate| self.index.context_only_read(candidate))
                    });
            }
            self.codex_join_prepared = true;
            return true;
        }
        if let Some(mut boot) = self.codex_join_active.take() {
            if boot
                .group
                .members
                .iter()
                .any(|candidate| self.context_read_budget.is_admitted(candidate))
            {
                // The group's cursor shares the room left by ordinary
                // native reads, just like a singleton or resumed cursor.
                self.context_read_budget
                    .charge_cursor_ordinary(&mut self.codex_page);
            }
            // R2-N2: a group larger than the singleton budget asks for
            // the cursor before its first header read; one that would
            // wait (or is fenced) reads no header or probe this page.
            // Only after the unchanged decision, and
            // never for a group with a memo entry or parked record: those
            // reach their lookups first and leave without the slot.
            if let Some(context) = self.sampling.as_ref().filter(|context| {
                boot.awaits_read()
                    && !boot.independent()
                    && crate::heap_layout_bound::layout_supported()
                    && boot.expected_bytes()
                        > sampled_scan::codex_cursor::Limits::current().singleton()
                    && !context.cache.group_recorded(&context.namespace, &boot.key)
            }) {
                match context.cache.cursor_plan(
                    &mut self.codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    boot.expected_bytes(),
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    true,
                    &context.namespace,
                    &boot.key,
                    sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &self.selected_flags,
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
                        self.scanned_file_count = self
                            .scanned_file_count
                            .saturating_sub(boot.group.members.len());
                        scan::owned_scan::requeue_members(
                            &mut self.index,
                            &self.selected_flags,
                            &boot.group.members,
                        );
                        return true;
                    }
                    sampled_scan::codex_cursor::StartPlan::Fenced => {
                        self.scanned_file_count = self
                            .scanned_file_count
                            .saturating_sub(boot.group.members.len());
                        return true;
                    }
                    _ => {}
                }
            }
            boot.allow_probe_bytes(
                self.codex_page
                    .singleton_remaining(sampled_scan::codex_cursor::Limits::current()),
            );
            let outcome = boot.step_with_cache(
                launch_lookup,
                &self.index,
                self.sampling.as_ref().map(|context| &context.cache),
            );
            // Header and probe bytes are singleton-budget reads (§d.2).
            let boot_input = boot.take_charge();
            self.codex_page.charge(false, boot_input);
            let members = boot.group.members.len();
            match outcome {
                codex_file_join::Boot::Pending => {
                    self.codex_join_active = Some(boot);
                    return true;
                }
                codex_file_join::Boot::Unchanged => {
                    // The accepted joined body is current, with no job
                    // or debt. Nothing read for a job; it does not wait.
                    if let Some(context) = self.sampling.as_ref() {
                        context.cache.cursor_unwait(&context.namespace, &boot.key);
                    }
                    self.semantic_noop_count += members;
                    self.census
                        .note_codex_group(CodexSelection::GroupUnchanged, members);
                    if !boot.independent()
                        && boot
                            .group
                            .members
                            .iter()
                            .all(|member| !member.opened_object_identity.is_empty())
                    {
                        self.codex_join_completed.push(boot.group);
                    }
                    return true;
                }
                codex_file_join::Boot::Strict => {
                    if let Some(context) = self.sampling.as_ref() {
                        context.cache.cursor_unwait(&context.namespace, &boot.key);
                    }
                    codex_file_join::disclose_strict(&boot.group.members, targets!(self));
                    return true;
                }
                codex_file_join::Boot::Refused(_reason) => {
                    // Decided from headers at no replay cost: terminal
                    // debt (outcome R), fenced, never memoized.
                    if let Some(context) = self.sampling.as_ref() {
                        context.cache.group_attempted(
                            &context.namespace,
                            &boot.key,
                            sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                        );
                    }
                    codex_file_join::disclose_members(
                        &codex_file_join::refusal_disclosure(),
                        &boot.group.members,
                        &mut self.index,
                        targets!(self),
                    );
                    return true;
                }
                codex_file_join::Boot::Ready => {
                    self.census
                        .note_codex_group(CodexSelection::GroupSelected, members);
                }
            }
            let expected = boot.expected_bytes();
            let dependencies = boot.dependencies(&self.codex_title_metadata);
            let mut paged = false;
            if let Some(context) = self.sampling.as_ref() {
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
                let memo_key = sampled_scan::codex_cursor::memo_key(&context.namespace, &boot.key);
                if let Some(entry) = context.cache.memo_lookup(&memo_key) {
                    // The match re-reads two samples of the live member.
                    self.codex_page
                        .charge(false, sampled_scan::codex_cursor::SAMPLE_READ_BYTES);
                    let hit = boot
                        .memo_digest(&self.codex_title_metadata)
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
                            &mut self.index,
                            targets!(self),
                        );
                        return true;
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
                        &mut self.index,
                        targets!(self),
                    );
                    return true;
                }
                match context.cache.cursor_plan(
                    &mut self.codex_page,
                    sampled_scan::codex_cursor::Limits::current(),
                    expected,
                    codex_cursor_lease.is_none() && context.cache.cursor_slot_free(),
                    crate::heap_layout_bound::layout_supported() && !boot.independent(),
                    &context.namespace,
                    &boot.key,
                    sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                    sampled_scan::codex_cursor::census_member(
                        &self.selected_flags,
                        boot.group
                            .members
                            .iter()
                            .map(|member| member.path.as_path()),
                    ),
                ) {
                    sampled_scan::codex_cursor::StartPlan::Singleton => {}
                    sampled_scan::codex_cursor::StartPlan::Cursor => paged = true,
                    sampled_scan::codex_cursor::StartPlan::Unpaged => {
                        self.codex_page.disclose_disabled(&context.cache);
                    }
                    sampled_scan::codex_cursor::StartPlan::Defer => {
                        // The whole group waits its turn on a later page.
                        context.cache.cursor_note_deferred();
                        if boot.own_page {
                            context
                                .cache
                                .request_group_own_page(&context.namespace, &boot.key);
                        }
                        self.scanned_file_count = self.scanned_file_count.saturating_sub(members);
                        scan::owned_scan::requeue_members(
                            &mut self.index,
                            &self.selected_flags,
                            &boot.group.members,
                        );
                        return true;
                    }
                    // Processed for this generation (K7 fence).
                    sampled_scan::codex_cursor::StartPlan::Fenced => {
                        self.scanned_file_count = self.scanned_file_count.saturating_sub(members);
                        return true;
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
                    &self.codex_title_metadata,
                    |member| member.opened_object_identity.clone(),
                )
            });
            let group_members = boot.group.members.clone();
            let boot_key = boot.key.clone();
            let job = boot.into_job(codex_file_join::JobInputs {
                metadata: &self.codex_title_metadata,
                cache: self.sampling.as_ref().map(|context| &context.cache),
                index: &self.index,
            });
            let Ok(mut job) = job else {
                // No lease exists yet; a waiter it left is
                // dropped like the boot-`Strict` exit's.
                if let Some(context) = self.sampling.as_ref() {
                    context.cache.cursor_unwait(&context.namespace, &boot_key);
                }
                if matches!(job, Err(codex_file_join::GroupEnd::Unavailable)) {
                    self.residue_index_keys.extend(
                        group_members
                            .iter()
                            .map(|member| local_index_key(&member.path)),
                    );
                    scan::owned_scan::requeue_members(
                        &mut self.index,
                        &self.selected_flags,
                        &group_members,
                    );
                    return true;
                }
                codex_file_join::disclose_strict(&group_members, targets!(self));
                return true;
            };
            if let Some(context) = self.sampling.as_ref().filter(|_| paged) {
                match context.cache.cursor_start_group(
                    &mut job,
                    &context.namespace,
                    active_dependencies,
                    self.state_census_complete && self.sidecar_census_complete,
                    &self.index,
                ) {
                    Ok(lease) => {
                        // The members hold the strict census until the
                        // job's attempt ends (accepted or debt).
                        scan::owned_scan::requeue_members(
                            &mut self.index,
                            &self.selected_flags,
                            &group_members,
                        );
                        *codex_cursor_lease = Some(lease);
                    }
                    Err(sampled_scan::codex_cursor::StartRefusal::Busy) => {
                        context.cache.cursor_note_deferred();
                        self.scanned_file_count = self.scanned_file_count.saturating_sub(members);
                        scan::owned_scan::requeue_members(
                            &mut self.index,
                            &self.selected_flags,
                            &group_members,
                        );
                        return true;
                    }
                    // Never an unbounded in-page read of a group larger
                    // than the singleton budget (compressed members > B
                    // keep refusing, named debt).
                    Err(_) => {
                        match group_members.first() {
                            Some(member) => self
                                .census
                                .record_unreadable_file(UnreadableCause::OpenRead, &member.path),
                            None => self.census.record_unreadable(UnreadableCause::OpenRead, 1),
                        }
                        return true;
                    }
                }
            }
            *active_file = Some(job);
            return true;
        }
        if self.source == SnapshotSource::Codex
            && active_file.is_none()
            && self.codex_join_active.is_none()
        {
            // A lease without an active file means this scan lost its job
            // on an error path; dropping the lease frees the slot.
            *codex_cursor_lease = None;
            if let Some(context) = self.sampling.as_ref() {
                self.codex_page.note_page(&context.cache);
            }
            // At most one resume attempt per page, and none on a page
            // that selected no candidates (no header inventory: no
            // evidence for the job this page). A deferred job therefore
            // never spins within a page.
            if let Some(context) = self.sampling.as_ref().filter(|_| {
                !self
                    .codex_page
                    .cursor_exhausted(sampled_scan::codex_cursor::Limits::current())
                    && self.codex_join_inventory.is_some()
                    && (!self.codex_page.continuation() || self.codex_census_valid)
                    && (!self.index.file_upload_context_enabled()
                        || !self.identified_candidates.iter().any(|candidate| {
                            !self.index.context_only_read(candidate)
                                && self
                                    .index
                                    .candidate_decision_with_reason_at(
                                        candidate,
                                        sampled_scan::now_seconds(),
                                    )
                                    .0
                                    == CandidateDecision::Parse
                        }))
                    && (!self.index.file_upload_context_enabled()
                        || !self.codex_join_groups.iter().any(|group| {
                            group
                                .members
                                .iter()
                                .any(|candidate| !self.index.context_only_read(candidate))
                        }))
                    && self.codex_page.claim_resume()
            }) {
                // Continuing the paused job is the highest scheduling class.
                match sampled_scan::codex_cursor::resume_paused_job(
                    sampled_scan::codex_cursor::ResumeContext {
                        source: self.source,
                        sampling: context,
                        codex: &self.codex_title_metadata,
                        claude: &self.claude_title_metadata,
                        support: self.claude_effort_support_dir.as_deref(),
                        inventory: self.codex_join_inventory.as_ref(),
                        flags: &self.selected_flags,
                        census_complete: self.state_census_complete && self.sidecar_census_complete,
                        continuation: self.codex_page.continuation(),
                        ordinary_equivalent: self.codex_page.ordinary_equivalent(),
                    },
                    &mut self.index,
                    &mut self.identified_candidates,
                    targets!(self),
                ) {
                    sampled_scan::codex_cursor::Resumed::Active(job, lease) => {
                        if self.index.context_only_read(&job.candidate) {
                            let admitted = if job.aliases.is_empty() {
                                self.context_read_budget.admit(
                                    self.source,
                                    &mut self.index,
                                    &job.candidate,
                                    &self.snapshots,
                                )
                            } else {
                                self.context_read_budget.admit_unit(
                                    self.source,
                                    &mut self.index,
                                    &job.aliases,
                                    &self.snapshots,
                                )
                            };
                            if !admitted {
                                // Return the intact parser and lease, never restart a Full.
                                drop(sampled_scan::codex_cursor::ActiveFrame::new(
                                    Some(job),
                                    Some(lease),
                                ));
                                return true;
                            }
                            self.context_read_budget
                                .charge_cursor_ordinary(&mut self.codex_page);
                        }
                        *codex_cursor_lease = Some(lease);
                        *active_file = Some(job);
                        return true;
                    }
                    // Deferred, invalidated or ended as strict debt: this
                    // page is spent; a pending path resumes or restarts.
                    sampled_scan::codex_cursor::Resumed::Spent => return true,
                    sampled_scan::codex_cursor::Resumed::Idle => {}
                }
            }
            // Stage 1 hunk D: a continuation page only resumes. Without
            // an active job it plans and starts nothing: every path it
            // identified, and every group it prepared, goes back to the
            // queue untouched, and the page finishes.
            if self.codex_page.continuation() {
                for candidate in self.identified_candidates.drain(..) {
                    sampled_scan::codex_cursor::requeue(
                        &mut self.index,
                        &self.selected_flags,
                        &candidate,
                    );
                }
                for group in self.codex_join_groups.drain(..) {
                    scan::owned_scan::requeue_members(
                        &mut self.index,
                        &self.selected_flags,
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
            self.codex_join_groups.front().is_some_and(|group| {
                (!self.index.file_upload_context_enabled()
                    || group
                        .members
                        .iter()
                        .all(|candidate| self.index.context_only_read(candidate)))
                    && !sampled_scan::codex_cursor::census_member(
                        &self.selected_flags,
                        group.members.iter().map(|member| member.path.as_path()),
                    )
            }) && self.identified_candidates.iter().any(|candidate| {
                sampled_scan::codex_cursor::selected_census_member(
                    &self.selected_flags,
                    &candidate.path,
                )
            })
        };
        let context_group_waits = self.index.file_upload_context_enabled()
            && self.codex_join_groups.front().is_some_and(|group| {
                group
                    .members
                    .iter()
                    .all(|candidate| self.index.context_only_read(candidate))
            })
            && self.identified_candidates.iter().any(|candidate| {
                !self.index.context_only_read(candidate)
                    && self
                        .index
                        .candidate_decision_with_reason_at(candidate, sampled_scan::now_seconds())
                        .0
                        == CandidateDecision::Parse
            });
        if active_file.is_none() && !rereads_wait() && !context_group_waits {
            if let Some(group) = self.codex_join_groups.pop_front() {
                if !self.history_upgrade.resident_can_start() {
                    let mut members = group.members;
                    members.extend(self.codex_join_groups.drain(..).flat_map(|g| g.members));
                    // Admission consumed pending entries for the whole join,
                    // including census members outside this page's selection.
                    scan::owned_scan::requeue_members(
                        &mut self.index,
                        &self.selected_flags,
                        &members,
                    );
                    members.extend(self.identified_candidates.drain(..));
                    self.identified_candidates = members.into();
                    self.history_upgrade.defer_resident(
                        self.source,
                        &mut self.index,
                        &self.selected_flags,
                        &mut self.identified_candidates,
                    );
                    return true;
                }
                if self.index.file_upload_context_enabled()
                    && group
                        .members
                        .iter()
                        .all(|candidate| self.index.context_only_read(candidate))
                    && !self.context_read_budget.admit_unit(
                        self.source,
                        &mut self.index,
                        &group.members,
                        &self.snapshots,
                    )
                {
                    scan::owned_scan::requeue_members(
                        &mut self.index,
                        &self.selected_flags,
                        &group.members,
                    );
                    return true;
                }
                if group
                    .members
                    .iter()
                    .any(|member| self.index.decode_holds_file(&local_index_key(&member.path)))
                {
                    self.index.mark_bounded_sweep_unsettled();
                    return true;
                }
                // M-5 (b): a group whose attempt already ended as terminal
                // debt in this generation is not attempted again; its
                // members were disclosed then.
                let fenced = self.sampling.as_ref().is_some_and(|context| {
                    context.cache.group_fenced(
                        &context.namespace,
                        &codex_file_join::job_key(&group),
                        sampled_scan::codex_cursor::census_token(&self.index).as_deref(),
                    )
                });
                if !fenced {
                    self.scanned_file_count += group.members.len();
                    let mut boot = Box::new(codex_file_join::GroupBoot::new(group, &self.index));
                    if let Some(context) = self.sampling.as_ref() {
                        boot.own_page = context
                            .cache
                            .take_group_own_page(&context.namespace, &boot.key);
                    }
                    self.codex_join_active = Some(boot);
                }
                return true;
            }
        }
        false
    }
}
