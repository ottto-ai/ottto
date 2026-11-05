//! Historical replay and legacy settlement reconciliation for the scan index.

use crate::snapshots::*;

impl ScanIndex {
    pub(crate) fn legacy_settlement_ledger_needs_migration(&self) -> bool {
        self.accepted_snapshot_fingerprint_ledger_version != SNAPSHOT_ACCEPTED_LEDGER_VERSION
    }

    /// True while the accepted ledger carries no settlement proof this daemon
    /// has observed, so `current - accepted` is not evidence and no seal may be
    /// taken from it. This is the single predicate both seal sites share:
    /// `prepare_legacy_settlement_reconciliation` (through the re-open) at the
    /// top of a cycle, and `finish_legacy_settlement_reconciliation` at its end.
    /// Guarding only the second one delays an unproven seal by one cycle rather
    /// than preventing it, because `prepare_*` seals the identical shape first.
    ///
    /// Two shapes qualify:
    ///
    /// - `SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION`: written by the first
    ///   legacy-settlement migration, whose fast path inferred acceptance from
    ///   index cleanliness.
    /// - `SNAPSHOT_ACCEPTED_LEDGER_PRE_LEDGER_VERSION` with a non-empty accepted
    ///   set and no sweep cursor: a pre-ledger index that has never armed a
    ///   page. Its pending set can already be empty, and sealing on that
    ///   observation retires the migration without the forced re-parse that is
    ///   the only thing that recovers a revision the retry-loss dropped from the
    ///   index. The cursor is what scopes this to never-armed ledgers: any
    ///   `legacy_settlement_reconcile_after_fingerprint` means the bounded sweep
    ///   is already proving this set, so it is neither unproven nor re-openable.
    ///   An empty accepted set is likewise not unproven - there is nothing to
    ///   re-open, and the ordinary sweep already re-offers every current
    ///   revision.
    ///
    /// The unproven state is left by `reopen_unproven_accepted_snapshot_ledger`,
    /// which clears the accepted set, and by `prepare_historical_replay`, which
    /// promotes straight to `SNAPSHOT_ACCEPTED_LEDGER_VERSION` after clearing
    /// the whole index and re-offering everything it re-parses.
    pub(crate) fn legacy_settlement_ledger_is_unproven(&self) -> bool {
        self.accepted_snapshot_fingerprint_ledger_version
            == SNAPSHOT_ACCEPTED_LEDGER_UNPROVEN_VERSION
            || (self.accepted_snapshot_fingerprint_ledger_version
                == SNAPSHOT_ACCEPTED_LEDGER_PRE_LEDGER_VERSION
                && !self.accepted_snapshot_fingerprints.is_empty()
                && self.legacy_settlement_reconcile_after_fingerprint.is_none())
    }

    /// Discard an accepted-revision ledger this daemon cannot re-prove, so the
    /// bounded sweep re-offers every currently indexed revision exactly once.
    ///
    /// `legacy_settlement_ledger_is_unproven` selects the shapes: the ledger the
    /// first migration marked migrated without per-revision settlement evidence,
    /// and a pre-ledger ledger that has never armed a page. The second one
    /// matters because its pending set can already be empty, in which case no
    /// page is ever armed and the forced re-parse that recovers a dropped
    /// revision never runs.
    ///
    /// Clearing the whole v1 set is the conservative reading, and it is forced:
    /// the on-disk ledger carries no per-revision provenance and no witness of
    /// which migration path wrote it, so a v1 entry proved by a real entity ACK
    /// is byte-identical to one sealed by the unsound fast path. The re-offer
    /// costs one bounded pass — the server answers each revision it already
    /// holds as an unchanged no-op and re-records it as accepted — while a
    /// wrongly retained entry would suppress the lost revision forever.
    ///
    /// Dropping the version back to the pre-ledger value, rather than holding a
    /// separate "re-opened" bit, is what makes this idempotent: the next call
    /// sees a plain unmigrated ledger and resumes the sweep instead of clearing
    /// the acceptances the sweep has since re-earned.
    fn reopen_unproven_accepted_snapshot_ledger(&mut self, source: SnapshotSource) {
        if !self.legacy_settlement_ledger_is_unproven() {
            return;
        }
        let reopened = self.accepted_snapshot_fingerprints.len();
        self.accepted_snapshot_fingerprints.clear();
        self.legacy_settlement_reconcile_after_fingerprint = None;
        self.accepted_snapshot_fingerprint_ledger_version = 0;
        eprintln!(
            "ottto-service: re-opened the legacy snapshot settlement ledger for {}; {} revision(s) \
             were recorded as accepted by a ledger this daemon cannot re-prove and are \
             re-offered through the existing entity-ACK contract in bounded pages",
            source.api_slug(),
            reopened
        );
    }

    /// True when this call reset the index (a new generation); false for the
    /// generation it already holds (row 36's ledger mirror follows only a
    /// reset).
    pub fn prepare_historical_replay(&mut self, generation: String) -> bool {
        if self.historical_replay_generation.as_ref() == Some(&generation) {
            return false;
        }
        self.historical_replay_generation = Some(generation);
        for (_, entry) in self.files.slots_mut() {
            if entry.upload_context_receipt.is_some() {
                entry.make_mut().upload_context_receipt = None;
            }
        }
        self.upload_context_proof.entity_stamps.clear();
        // Replay resets delivery authority, not file-owned recovery evidence.
        // Otherwise a missing member or expired trace can silently shrink or
        // reprice a previously joined contribution during ordinary replay.
        self.files
            .retain(|_, entry| entry.retain_history_evidence());
        // Retired entries' ACK evidence resets with the entries it outlived.
        self.codex_counting_tombstones.clear();
        self.codex_counting_evicted_legacy = Default::default();
        let active = self.active_effective_upload_body_witness_revision;
        for (_, entry) in self.files.slots_mut() {
            let entry = entry.make_mut();
            if entry.has_unverified_source() {
                let due = entry.unverified_deadline().unwrap_or(0);
                entry.set_unverified_deadline(due);
            }
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
            claude_history_upgrade::re_owe(
                &mut entry.effective_upload_body_witness_revision,
                0,
                active,
            );
            if !entry.has_unverified_source() {
                entry.scan_identity_version = None;
            }
        }
        self.terminal_jsonl_dispositions.clear();
        self.resume_after_path = None;
        self.resume_upper_bound_path = None;
        self.resume_census_window_end = None;
        self.bounded_sweep_had_unsettled_upload = false;
        self.bounded_sweep_unsettled_causes = 0;
        self.traversal = None;
        self.scan_residue_witness = None;
        self.confirmed_empty_files.clear();
        self.file_snapshot_fingerprints.clear();
        let retained = self
            .file_snapshot_fingerprints
            .values()
            .flat_map(|set| set.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        self.snapshot_activity_at
            .retain(|fp, _| retained.contains(fp.as_str()));
        self.accepted_snapshot_fingerprints
            .retain(|fp| retained.contains(fp.as_str()));
        self.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
        self.accepted_incidence_pending_census = false;
        self.accepted_rebuild_incidence.clear();
        self.accepted_rebuild_pending_since_unix_seconds = None;
        self.accepted_rebuild_last_alarm_unix_seconds = None;
        self.legacy_settlement_reconcile_after_fingerprint = None;
        // A replay re-enters terminal entities that are still present because
        // delivery checkpoints above must be rebuilt. Keep the terminal
        // record until that scan proves a replacement ACK or re-quarantine.
        // If its source is absent, retaining it is the only replay-safe way to
        // preserve the explicit disclosure and counter.
        self.quarantined_snapshot_fingerprints.retain(|_, record| {
            matches!(
                record.disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
                    | SnapshotQuarantineDisposition::SupersededTerminal
            )
        });
        true
    }

    /// Arm at most `limit` ambiguous pre-ledger identities for re-entry through
    /// the already-deployed snapshot entity-ACK upload contract. The cursor and
    /// each armed quarantine record are persisted before scanning, so a restart
    /// resumes instead of rebuilding one unbounded request.
    ///
    /// A revision leaves this migration only through positive settlement
    /// evidence: an exact entity ACK recorded in `accepted_snapshot_fingerprints`,
    /// or an explicit terminal quarantine disposition that discloses it. There
    /// is deliberately no shortcut that infers acceptance from the shape of the
    /// local index, because a clean index is exactly what the silent
    /// retry-loss path leaves behind, and inferring from it seals the lost
    /// revision as accepted with no re-offer and no disclosure.
    pub(crate) fn prepare_legacy_settlement_reconciliation(
        &mut self,
        source: SnapshotSource,
        limit: usize,
    ) -> (BTreeSet<String>, bool) {
        if self.accepted_snapshot_fingerprint_ledger_version == SNAPSHOT_ACCEPTED_LEDGER_VERSION {
            return (BTreeSet::new(), false);
        }
        // Opaque incidence cannot prove the migration complete, nor justify
        // clearing intact ACKs while reopening an old ledger.
        if self.decode_has_opaque_file_incidence() {
            return (BTreeSet::new(), false);
        }
        self.reopen_unproven_accepted_snapshot_ledger(source);

        let pending = self.legacy_settlement_reconciliation_pending_fingerprints();
        // This is the seal that actually runs first: `prepare_*` is called at the
        // top of every ordinary cycle and `finish_*` only at its end, so the same
        // guard has to hold here or a guard in `finish_*` alone merely delays an
        // unproven seal by one cycle. The re-open above has already cleared every
        // unproven accepted set, so the predicate is false by construction here;
        // it is repeated as a fail-safe, and it fails toward leaving the ledger
        // open rather than sealing it without proof.
        if pending.is_empty() && !self.legacy_settlement_ledger_is_unproven() {
            self.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
            self.legacy_settlement_reconcile_after_fingerprint = None;
            return (BTreeSet::new(), true);
        }
        let unarmed = self
            .eligible_snapshot_fingerprint_refs()
            .filter(|fingerprint| {
                pending.contains(*fingerprint)
                    && !self.decode_holds_entity(fingerprint)
                    && !self
                        .quarantined_snapshot_fingerprints
                        .contains_key(*fingerprint)
            })
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if unarmed.is_empty() || limit == 0 {
            return (BTreeSet::new(), false);
        }
        let after = self
            .legacy_settlement_reconcile_after_fingerprint
            .as_deref();
        let selected =
            unarmed
                .iter()
                .filter(|fingerprint| after.map_or(true, |cursor| fingerprint.as_str() > cursor))
                .chain(unarmed.iter().filter(|fingerprint| {
                    after.is_some_and(|cursor| fingerprint.as_str() <= cursor)
                }))
                .take(limit)
                .cloned()
                .collect::<BTreeSet<_>>();
        let mut witness = snapshot_quarantine_witness(source);
        witness.contract = SNAPSHOT_UNPROVEN_RETRY_CONTRACT_VERSION.to_string();
        for fingerprint in &selected {
            self.quarantined_snapshot_fingerprints.insert(
                fingerprint.clone(),
                SnapshotQuarantineRecord {
                    contract_retry_claims: None,
                    reconstruction_contract:
                        crate::snapshots::terminal_contract_retry::current_contract(),
                    witness: witness.clone(),
                    retry_after_unix_seconds: 0,
                    upload_body_witness: None,
                    failed_reconstruction_count: 0,
                    disposition: SnapshotQuarantineDisposition::RetryPending,
                },
            );
        }
        // The lost-obligation production shape has an empty terminal-unhealthy
        // traversal whose independent retry is not due. Reset only traversal
        // discovery; existing file/entity checkpoints remain the source of the
        // forced reparse decisions above.
        if !selected.is_empty() {
            self.legacy_settlement_reconcile_after_fingerprint = selected.last().cloned();
            // Reset only a traversal that is already terminal-unhealthy. The
            // predicate is the production `terminal_unhealthy` definition:
            // discovery done (both pending queues empty) and errors recorded.
            // That is the one persisted shape `ensure_bounded_traversal` refuses
            // to rebuild while its independent retry is not due, which is why the
            // reset existed; every other shape it either rebuilds or advances on
            // its own. Scoping it here is what stops a machine from paying a full
            // re-discovery for each armed page of the sweep.
            //
            // Accepted delta: a traversal that is mid-walk with errors already
            // recorded, or discovery-complete and healthy but held open by an
            // unfinished state/sidecar census or reconciliation, is no longer
            // reset. The armed page then waits for the current traversal
            // generation to finish before it is re-parsed and re-offered. That is
            // bounded added latency, not a stall - the traversal is still advanced
            // by `ensure_bounded_traversal` - and the ledger stays open meanwhile,
            // which is the safe state.
            let traversal_is_terminal_unhealthy = self.traversal.as_ref().is_some_and(|t| {
                t.pending_directories.is_empty()
                    && t.pending_candidates.is_empty()
                    && t.counts.has_errors()
            });
            if traversal_is_terminal_unhealthy {
                self.traversal = None;
            }
            self.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::LegacyReconcile);
        }
        (selected, true)
    }

    pub(crate) fn legacy_settlement_reconciliation_pending_fingerprints(&self) -> BTreeSet<String> {
        if self.accepted_snapshot_fingerprint_ledger_version == SNAPSHOT_ACCEPTED_LEDGER_VERSION {
            return BTreeSet::new();
        }
        self.current_snapshot_fingerprints()
            .difference(&self.accepted_snapshot_fingerprints)
            .filter(|fingerprint| {
                self.quarantined_snapshot_fingerprints
                    .get(*fingerprint)
                    .map_or(true, |record| {
                        record.disposition == SnapshotQuarantineDisposition::RetryPending
                    })
            })
            .cloned()
            .collect()
    }

    pub(crate) fn finish_legacy_settlement_reconciliation(&mut self) {
        // An unproven ledger's accepted set has not been re-proved by this
        // daemon, so its pending set is not yet meaningful and a cycle that
        // skipped arming could observe a stale empty pending set and seal it.
        // `legacy_settlement_ledger_is_unproven` carries the exact scope,
        // including the cursor condition that limits the pre-ledger leg to
        // never-armed ledgers, and the two ways the state is left.
        if self.decode_has_opaque_file_incidence() || self.legacy_settlement_ledger_is_unproven() {
            return;
        }
        if self
            .legacy_settlement_reconciliation_pending_fingerprints()
            .is_empty()
        {
            self.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
            self.legacy_settlement_reconcile_after_fingerprint = None;
        }
    }

    pub(crate) fn snapshot_unproven_terminal_count(&self) -> usize {
        self.quarantined_snapshot_fingerprints
            .values()
            .filter(|record| record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal)
            .count()
    }

    pub(crate) fn snapshot_superseded_terminal_count(&self) -> usize {
        self.quarantined_snapshot_fingerprints
            .values()
            .filter(|record| {
                record.disposition == SnapshotQuarantineDisposition::SupersededTerminal
            })
            .count()
    }

    pub(crate) fn record_accepted_snapshot_fingerprints(&mut self, accepted: &BTreeSet<String>) {
        for fingerprint in accepted {
            if !self.decode_holds_entity(fingerprint) {
                self.accepted_snapshot_fingerprints
                    .insert(fingerprint.clone());
            }
        }
        let current = self.current_snapshot_fingerprints();
        let opaque_incidence = self.decode_has_opaque_file_incidence();
        let carried = self.carried_ack_fingerprints();
        let mut retained = std::mem::take(&mut self.accepted_snapshot_fingerprints);
        retained.retain(|fingerprint| {
            (opaque_incidence || carried.contains(fingerprint) || current.contains(fingerprint))
                && !self
                    .quarantined_snapshot_fingerprints
                    .contains_key(fingerprint)
        });
        self.accepted_snapshot_fingerprints = retained;
    }

    #[cfg(test)]
    pub(crate) fn install_terminal_unhealthy_traversal_for_retry_test(
        &mut self,
        source: SnapshotSource,
        roots: &[PathBuf],
        backfill_window_days: u64,
        retry_not_before_unix_seconds: u64,
    ) {
        self.traversal = Some(ScanTraversalCheckpoint {
            context_fingerprint: scan_traversal_context_fingerprint(
                source,
                roots,
                backfill_window_days,
            ),
            census_window_end: "2026-09-01T03:27:03Z".to_string(),
            scan_roots: Vec::new(),
            pending_directories: VecDeque::new(),
            pending_candidates: VecDeque::new(),
            observed_index_keys: Default::default(),

            oversized_discovery: Default::default(),

            codex_rollout_paths: BTreeSet::new(),
            codex_join_directory_census: None,
            reconciliation_upper_bound: None,
            reconciliation_after: None,
            reconciliation_started: false,
            watcher_hint_seen: false,
            codex_freshness_yield: false,
            retired_codex_parent_resolution_retry_required: serde::de::IgnoredAny,
            unhealthy_retry_attempt: 1,
            unhealthy_retry_not_before_unix_seconds: Some(retry_not_before_unix_seconds),
            counts: ScanTraversalCounts {
                disappeared_file_count: 1,
                ..ScanTraversalCounts::default()
            },
            residue: ScanTraversalResidue::default(),
            listing_started_unix_seconds: None,
            listing_owed_requeued_unix_seconds: Default::default(),
        });
    }

    pub(crate) fn historical_replay_generation_matches(&self, generation: &str) -> bool {
        self.historical_replay_generation.as_deref() == Some(generation)
    }
}
