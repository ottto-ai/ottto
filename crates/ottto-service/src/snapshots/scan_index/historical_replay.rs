//! Historical replay for the scan index.

use crate::snapshots::*;

impl ScanIndex {
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
        // reprice a previously joined contribution during ordinary replay. A
        // sealed-prefix tag is such evidence: the entry and its tag stay.
        self.files
            .retain(|_, entry| entry.retain_history_evidence() || entry.has_prefix_provenance());
        // Retired entries' ACK evidence resets with the entries it outlived.
        let active = self.active_effective_upload_body_witness_revision;
        for (_, entry) in self.files.slots_mut() {
            let entry = entry.make_mut();
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
            claude_history_upgrade::re_owe(
                &mut entry.effective_upload_body_witness_revision,
                0,
                active,
            );
            if !entry.has_sampled_tag() {
                entry.scan_identity_version = None;
            }
        }
        self.terminal_jsonl_dispositions.clear();
        self.resume_after_path = None;
        self.resume_upper_bound_path = None;
        self.resume_census_window_end = None;
        // Owed identity-503 custody survives the replay, as at a walk start.
        self.bounded_sweep_unsettled_causes =
            self.unsettled_cause_bits() & UnsettledUploadCause::Isolated503.bit();
        self.bounded_sweep_had_unsettled_upload = self.bounded_sweep_unsettled_causes != 0;
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
            rewalk_owed: false,
        });
    }

    pub(crate) fn historical_replay_generation_matches(&self, generation: &str) -> bool {
        self.historical_replay_generation.as_deref() == Some(generation)
    }
}
