//! What a save after an upload may commit: the committable subset of a
//! scan's index given this pass's ACKs, quarantines and local holds.

use crate::snapshots::*;

impl ScanIndex {
    #[cfg(test)]
    pub fn committable_subset(
        &self,
        previous: &ScanIndex,
        accepted: &BTreeSet<String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) -> ScanIndex {
        self.committable_subset_with_local_holds(previous, accepted, quarantined, &BTreeSet::new())
    }

    #[cfg(test)]
    pub(crate) fn committable_subset_with_local_holds(
        &self,
        previous: &ScanIndex,
        accepted: &BTreeSet<String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
        locally_held: &BTreeSet<String>,
    ) -> ScanIndex {
        self.committable_subset_for_upload(previous, accepted, quarantined, locally_held, false)
    }

    /// What a save after an upload may commit. Exact ACKs and quarantines
    /// settle; locally held and decode-held entities never do and keep their
    /// committed revision. With `every_batch_sent` (Completed, Deferred and
    /// Rejected: refusals already have quarantine custody) every other entity
    /// settles exactly as on a clean page, including unchanged ones this pass
    /// did not resend. Without it (a shed, interrupted or failed upload) only
    /// this pass's ACKs and quarantines settle.
    pub(crate) fn committable_subset_for_upload(
        &self,
        previous: &ScanIndex,
        accepted: &BTreeSet<String>,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
        locally_held: &BTreeSet<String>,
        every_batch_sent: bool,
    ) -> ScanIndex {
        if !self.persistence_available() || !previous.persistence_available() {
            let mut held = self.clone();
            held.retain_persistence_baseline_from(previous);
            return held;
        }

        let accepted = accepted
            .iter()
            .filter(|fingerprint| !locally_held.contains(*fingerprint))
            .cloned()
            .collect::<BTreeSet<_>>();
        let quarantined = quarantined
            .iter()
            .filter(|(fingerprint, _)| !locally_held.contains(*fingerprint))
            .map(|(fingerprint, record)| (fingerprint.clone(), record.clone()))
            .collect::<BTreeMap<_, _>>();
        let empty_advances = self.claude_empty_map_advances(previous);
        let settled = |fingerprint: &str| {
            !self.decode_holds_entity(fingerprint)
                && (accepted.contains(fingerprint)
                    || quarantined.contains_key(fingerprint)
                    || (every_batch_sent && !locally_held.contains(fingerprint)))
        };
        let safe = |key: &String, fingerprint: Option<&str>| {
            if self.decode_holds_file(key) {
                return false;
            }
            if self.confirmed_empty_files.contains(key) {
                // A newly discovered empty file has no remote entity to lose.
                // A file that PREVIOUSLY produced an entity is different: a
                // shed/partial pass has not acknowledged removal of that old
                // server entity, so retain the prior checkpoint and retry the
                // complete generation instead of publishing false agreement.
                let previous_had_entity = previous
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|fingerprints| !fingerprints.is_empty())
                    || previous
                        .files
                        .get(key)
                        .and_then(|entry| entry.last_snapshot_fingerprint.as_ref())
                        .is_some();
                return !previous_had_entity;
            }
            if let Some(exact) = self.file_snapshot_fingerprints.get(key) {
                return exact.iter().all(|fingerprint| settled(fingerprint));
            }
            match fingerprint {
                None => true,
                Some(fingerprint) => {
                    settled(fingerprint)
                        || previous
                            .files
                            .get(key)
                            .and_then(|entry| entry.last_snapshot_fingerprint.as_deref())
                            == Some(fingerprint)
                }
            }
        };
        let mut files = BTreeMap::<String, Shared<ScanIndexEntry>>::new();
        let mut safe_keys = BTreeSet::new();
        for (key, entry) in self.files.iter_shared() {
            if safe(key, entry.last_snapshot_fingerprint.as_deref()) {
                files.insert(key.clone(), entry.clone());
                safe_keys.insert(key.clone());
            } else if let Some(committed) = previous.files.get_shared(key) {
                if !entry.source_file_fingerprint.is_empty()
                    && crate::local_resource_diagnostics::claude_reread::active()
                {
                    let held = self.file_is_held(key, entry, locally_held);
                    // Exactly the early exact-incidence branch, and the legacy
                    // head/equality fallback would have admitted this sibling.
                    let exact_only = !held
                        && !self.confirmed_empty_files.contains(key)
                        && self
                            .file_snapshot_fingerprints
                            .get(key)
                            .is_some_and(|fps| !fps.iter().all(|fp| settled(fp)))
                        && entry
                            .last_snapshot_fingerprint
                            .as_deref()
                            .map_or(true, |fp| {
                                settled(fp)
                                    || committed.last_snapshot_fingerprint.as_deref() == Some(fp)
                            });
                    crate::local_resource_diagnostics::claude_reread::restored(
                        committed.source_file_fingerprint.is_empty(),
                        held,
                        exact_only,
                    );
                }
                files.insert(key.clone(), committed.clone());
            }
        }
        // A partial save commits a Tail head only for an entry it keeps or a
        // held file's custody: any other restored or omitted file keeps its
        // committed head, and its next read starts there. A route error here
        // also fails the save that would commit.
        if !every_batch_sent {
            if let Ok(Some(route)) = state_v2::runtime_path(self) {
                let unkept = self.files.iter().filter(|(key, entry)| {
                    !safe_keys.contains(*key) && !self.file_is_held(key, entry, locally_held)
                });
                let _ = state_v2::unstage_tail(&route, unkept.map(|(key, _)| key.clone()));
            }
        }

        // A complete census may prune vanished/aged paths from `self`, but a
        // partial upload must never make that deletion durable. Only the final
        // all-accepted save may publish pruning.
        for (key, entry) in previous.files.iter_shared() {
            files.entry(key.clone()).or_insert_with(|| entry.clone());
        }
        let mut confirmed_empty_files = previous.confirmed_empty_files.clone();
        let mut file_snapshot_fingerprints = previous.file_snapshot_fingerprints.clone();
        for key in &safe_keys {
            if self.confirmed_empty_files.contains(key) {
                confirmed_empty_files.insert(key.clone());
            } else {
                confirmed_empty_files.remove(key);
            }
            match self.file_snapshot_fingerprints.get_shared(key) {
                Some(fingerprints) => {
                    if file_snapshot_fingerprints.get_shared(key) != Some(fingerprints) {
                        file_snapshot_fingerprints.insert_shared(key.clone(), fingerprints.clone());
                    }
                }
                None => {
                    file_snapshot_fingerprints.remove(key);
                }
            }
        }
        let committable_fingerprints = file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .collect::<BTreeSet<_>>();
        let mut retained_quarantine = quarantined.clone();
        // If an old quarantine was retried under a newer contract but this
        // pass stopped before settlement, preserve the old witness. Its
        // mismatch is the durable instruction to retry again next cycle.
        for (fingerprint, witness) in &previous.quarantined_snapshot_fingerprints {
            if committable_fingerprints.contains(fingerprint)
                && !accepted.contains(fingerprint)
                && !quarantined.contains_key(fingerprint)
            {
                retained_quarantine.insert(fingerprint.clone(), witness.clone());
            }
        }
        let mut accepted_snapshot_fingerprints = previous.accepted_snapshot_fingerprints.clone();
        accepted_snapshot_fingerprints.extend(accepted.iter().cloned());
        // Use the incidence this partial commit will publish, which can still
        // be UNKNOWN even if working state tentatively learned an exact set.
        let opaque_incidence = self
            .decode_held_file_keys()
            .any(|key| !file_snapshot_fingerprints.contains_key(key));
        // Retire carried incidence only for file revisions this partial commit
        // actually publishes. A tentative parse must not consume prior debt.
        let mut accepted_rebuild_incidence = previous.accepted_rebuild_incidence.clone();
        for (key, fingerprints) in &self.accepted_rebuild_incidence {
            accepted_rebuild_incidence
                .entry(key.clone())
                .or_insert_with(|| fingerprints.clone());
        }
        for key in &safe_keys {
            if !self.accepted_rebuild_incidence.contains_key(key) {
                accepted_rebuild_incidence.remove(key);
            }
        }
        let carried = accepted_rebuild_incidence
            .values()
            .flat_map(BTreeSet::iter)
            .collect::<BTreeSet<_>>();
        let accepted_incidence_pending = !accepted_rebuild_incidence.is_empty();
        accepted_snapshot_fingerprints.retain(|fingerprint| {
            (opaque_incidence
                || carried.contains(fingerprint)
                || committable_fingerprints.contains(fingerprint))
                && !retained_quarantine.contains_key(fingerprint)
        });
        let mut snapshot_activity_at = self.snapshot_activity_at.clone();
        snapshot_activity_at
            .retain(|fingerprint, _| committable_fingerprints.contains(fingerprint));
        for fingerprint in committable_fingerprints {
            if let Some(activity_at) = previous.snapshot_activity_at.get(fingerprint) {
                snapshot_activity_at.insert_if_absent(fingerprint.clone(), || activity_at.clone());
            }
        }
        let mut claude_money_birth_store = self.claude_money_birth_store.clone();
        claude_money_birth_store.preserve_missing_from(&previous.claude_money_birth_store);
        self.note_claude_history_not_accepted(
            previous,
            self.files
                .keys()
                .filter(|key| !safe_keys.contains(*key))
                .chain(
                    previous
                        .files
                        .keys()
                        .filter(|key| !self.files.contains_key(*key)),
                ),
        );
        let mut result = ScanIndex {
            claude_money_birth_store,
            codex_counting_moved_evidence: self.codex_counting_moved_evidence.clone(),
            // The working map, bounded: its slots were freed only against the
            // committed state this page loaded or by its eviction order, and a
            // tombstone for a retirement this subset does not publish only
            // repeats the evidence of the entry it keeps.
            codex_counting_tombstones: self.codex_counting_tombstones.clone(),
            codex_counting_evicted_legacy: self.codex_counting_evicted_legacy.clone(),
            codex_counting_evictions: self.codex_counting_evictions,
            v2: previous.v2.as_ref().map(|state| {
                Box::new(state_v2::IndexState {
                    persistence_v2: state.persistence_v2.clone(),
                    growth_claim_context: state.growth_claim_context.clone(),
                    growth_retention: sampled_audit::growth_subset(self, previous, &safe_keys),
                })
            }),
            persistence_root: previous.persistence_root.clone(),
            persistence_controls: previous.persistence_controls.clone(),
            persistence_legacy_recovery: self
                .persistence_legacy_recovery
                .clone()
                .or_else(|| previous.persistence_legacy_recovery.clone()),
            persistence_unavailable: std::array::from_fn(|i| {
                self.persistence_unavailable[i].or(previous.persistence_unavailable[i])
            }),
            decode_holds: self.decode_holds.clone(),
            withheld_memo: self.withheld_memo.clone(),
            schema_version: SCAN_INDEX_SCHEMA_VERSION,
            generation: previous.generation,
            upload_ack_retirement_handoff: previous.upload_ack_retirement_handoff.clone(),
            retired_upload_context_fingerprint: serde::de::IgnoredAny,
            retired_archives: serde::de::IgnoredAny,
            retired_archive_deferred_alarm_count: serde::de::IgnoredAny,
            retired_reread_guard: serde::de::IgnoredAny,
            files: files.into(),
            session_account_bindings: self.session_account_bindings.clone(),
            terminal_jsonl_dispositions: previous.terminal_jsonl_dispositions.clone(),
            known_configured_scan_roots: self.known_configured_scan_roots.clone(),
            legacy_unresolved_root_file_witnesses: self
                .legacy_unresolved_root_file_witnesses
                .clone(),
            retired_codex_state_only_snapshot_fingerprints: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_session_ids: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_by_file: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_unattributed: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_legacy: serde::de::IgnoredAny,
            retired_codex_state_only_blocked_attributed: serde::de::IgnoredAny,
            codex_parent_ownership_refs: Default::default(),
            codex_parent_ownership_ledgers: Default::default(),
            codex_parent_side_requests: Default::default(),
            codex_parent_side: Default::default(),
            codex_parent_side_generation: Default::default(),
            codex_parent_proof_wrap_epoch: Default::default(),
            codex_parent_prefix_proofs: Default::default(),
            codex_parent_proof_cursor: Default::default(),
            codex_parent_side_cursor: Default::default(),
            codex_parent_proof_seq: Default::default(),
            codex_proof_index_incarnation: Default::default(),
            claude_desktop_title_files: self.claude_desktop_title_files.clone(),
            retired_claude_account_family_witnesses: serde::de::IgnoredAny,
            retired_claude_account_family_pending: serde::de::IgnoredAny,
            claude_usage_family_witnesses: self.claude_usage_family_witnesses.clone(),
            retired_claude_usage_family_pending: serde::de::IgnoredAny,
            retired_family_requests: serde::de::IgnoredAny,
            claude_request_census: self.claude_request_census.clone(),
            claude_request_census_shadow: self.claude_request_census_shadow.clone(),
            claude_usage_authority_quarantine: self.claude_usage_authority_quarantine.clone(),
            retired_claude_retired_family_tombstones: serde::de::IgnoredAny,
            retired_claude_retired_family_tombstones_initialized: serde::de::IgnoredAny,
            retired_claude_retired_family_tombstones_uncertain: serde::de::IgnoredAny,
            retired_claude_duplicate_request_owners: serde::de::IgnoredAny,
            retired_claude_duplicate_request_witness_overflowed: serde::de::IgnoredAny,
            retired_claude_owned_start_census: serde::de::IgnoredAny,
            claude_account_deferred_holds: self.claude_account_deferred_holds.clone(),
            retired_claude_duplicate_fence_rearm_attempt: serde::de::IgnoredAny,
            retired_claude_duplicate_fence_next_full_rearm_unix_seconds: serde::de::IgnoredAny,
            retired_claude_full_rearm_progress: serde::de::IgnoredAny,
            claude_request_identity_contract: self.claude_request_identity_contract.clone(),
            retired_claude_request_identity_contract_changed: serde::de::IgnoredAny,
            claude_desktop_store_inventory: self.claude_desktop_store_inventory.clone(),
            claude_copy_removals: self.claude_copy_removals.clone(),
            upload_context_proof: self.upload_context_proof.clone(),
            copy_unproven_enabled: self.copy_unproven_enabled,
            copy_prefix_base_upload_context: self.copy_prefix_base_upload_context.clone(),
            copy_prefix_last_accepted_nonce: self.copy_prefix_last_accepted_nonce.clone(),
            retired_claude_folder_login_ledger: serde::de::IgnoredAny,
            tail_discovery: self.tail_discovery,
            claude_desktop_store_cursor: self.claude_desktop_store_cursor.clone(),
            claude_desktop_store_upper_bound: self.claude_desktop_store_upper_bound.clone(),
            claude_desktop_store_sweep_had_errors: self.claude_desktop_store_sweep_had_errors,
            claude_desktop_identity_census_complete: self.claude_desktop_identity_census_complete,
            claude_desktop_lineage_census_complete: self.claude_desktop_lineage_census_complete,
            retired_claude_desktop_census_witness: serde::de::IgnoredAny,
            claude_desktop_store_retry_attempt: self.claude_desktop_store_retry_attempt,
            claude_desktop_store_retry_not_before_unix_seconds: self
                .claude_desktop_store_retry_not_before_unix_seconds,
            resume_after_path: self.resume_after_path.clone(),
            resume_upper_bound_path: self.resume_upper_bound_path.clone(),
            resume_census_window_end: self.resume_census_window_end.clone(),
            retired_held_audit_progress: serde::de::IgnoredAny,
            bounded_sweep_had_unsettled_upload: self.bounded_sweep_had_unsettled_upload,
            bounded_sweep_unsettled_causes: self.bounded_sweep_unsettled_causes,
            traversal: self.traversal.clone(),
            retired_claude_stale_family_carry: serde::de::IgnoredAny,
            scan_residue_witness: self.scan_residue_witness.clone(),
            historical_replay_generation: self.historical_replay_generation.clone(),
            retired_context_curve_capability_enabled: serde::de::IgnoredAny,
            retired_context_curve_replay_epoch: serde::de::IgnoredAny,
            retired_completed_context_curve_replay_generation: serde::de::IgnoredAny,
            confirmed_empty_files,
            file_snapshot_fingerprints,
            snapshot_activity_at,
            accepted_snapshot_fingerprints,
            accepted_snapshot_fingerprint_ledger_version: self
                .accepted_snapshot_fingerprint_ledger_version
                .max(previous.accepted_snapshot_fingerprint_ledger_version),
            legacy_settlement_reconcile_after_fingerprint: self
                .legacy_settlement_reconcile_after_fingerprint
                .clone()
                .or_else(|| {
                    previous
                        .legacy_settlement_reconcile_after_fingerprint
                        .clone()
                }),
            quarantined_snapshot_fingerprints: retained_quarantine.clone(),
            active_quarantine_witness: self.active_quarantine_witness.clone(),
            active_upload_context_fingerprint: self.active_upload_context_fingerprint.clone(),
            context_read_counts: self.context_read_counts.clone(),
            active_effective_upload_body_witness_revision: self
                .active_effective_upload_body_witness_revision,
            active_effective_upload_body_witness_revision_monotone: self
                .active_effective_upload_body_witness_revision_monotone,
            effective_upload_body_witness_revision_excluded_source_files: self
                .effective_upload_body_witness_revision_excluded_source_files
                .clone(),
            claude_reemission_exclusions: self.claude_reemission_exclusions.clone(),
            reason_reoffer_retries: self.reason_reoffer_retries.clone(),
            terminal_contract_retries: self.terminal_contract_retries.clone(),
            head_conflict_sessions: self.head_conflict_sessions.clone(),
            refusal_exposure: self.refusal_exposure,
            reason_reoffer_cooldowns: self.reason_reoffer_cooldowns.clone(),
            claude_history_cutoff_unix_seconds: self
                .claude_history_cutoff_unix_seconds
                .or(previous.claude_history_cutoff_unix_seconds),
            claude_history_gate_loaded: self.claude_history_gate_loaded
                || previous.claude_history_gate_loaded,
            // Not OR-ed with the previous index: a `full` claim clears it.
            claude_history_move_not_full: self.claude_history_move_not_full,
            claude_history_move_released: self.claude_history_move_released
                || previous.claude_history_move_released,
            accepted_incidence_pending_census: accepted_incidence_pending,
            accepted_rebuild_incidence,
            accepted_rebuild_pending_since_unix_seconds: if accepted_incidence_pending {
                previous
                    .accepted_rebuild_pending_since_unix_seconds
                    .or(self.accepted_rebuild_pending_since_unix_seconds)
            } else {
                None
            },
            accepted_rebuild_last_alarm_unix_seconds: if accepted_incidence_pending {
                previous
                    .accepted_rebuild_last_alarm_unix_seconds
                    .max(self.accepted_rebuild_last_alarm_unix_seconds)
            } else {
                None
            },
            claude_no_list_policy: self.claude_no_list_policy,
            claude_history_emission: self.claude_history_emission.clone(),
        };
        for key in &safe_keys {
            match self.terminal_jsonl_dispositions.get(key) {
                Some(disposition) => {
                    result
                        .terminal_jsonl_dispositions
                        .insert(key.clone(), disposition.clone());
                }
                None => {
                    result.terminal_jsonl_dispositions.remove(key);
                }
            }
        }
        for (key, working) in &self.files {
            // `get_mut` deep-copies an entry still shared with `self` or
            // `previous`, so take it only for an entry a carry changes.
            if !result.files.get(key).is_some_and(|retained| {
                (working.source_file_fingerprint.is_empty()
                    && !retained.source_file_fingerprint.is_empty())
                    || retained.carry_sampled_audit_changes(working)
            }) {
                continue;
            }
            let Some(retained) = result.files.get_mut(key) else {
                continue;
            };
            // A cleared source witness is outstanding reparse work, not a new
            // accepted body. Reverting an unsettled entry must keep that debt;
            // otherwise a partial save can undo a census/fence correction.
            if working.source_file_fingerprint.is_empty() {
                retained.source_file_fingerprint.clear();
            }
            retained.carry_sampled_audit(working);
        }
        result.restore_claude_empty_map_advances(empty_advances);
        result.retain_quarantined_fingerprints(&retained_quarantine);
        result.reconcile_codex_recovery_settlement(previous, &accepted);
        result
    }
}
