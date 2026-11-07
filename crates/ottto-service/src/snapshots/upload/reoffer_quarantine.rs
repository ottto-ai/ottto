//! Upload-side retry state of the scan index: the effective upload body
//! witness stamps, admission and reason re-offers, quarantine witnesses,
//! terminal-contract and head-conflict retries, and the quarantine records a
//! committed index keeps.

use crate::snapshots::*;

impl ScanIndex {
    /// The one writer of a settled file's `effective_upload_body_witness_revision`.
    /// Claude never downgrades (`max(stored, allowed_active)`); Codex and Pi
    /// keep the exact stamp. Refuses a zero revision, a file excluded for a
    /// local hold, a file the history gate holds, a literal-denied file, and
    /// under a row that denies the literal any listed family or, while the
    /// list is paused, any file: a protected root never stamps to a new
    /// revision. Request-owned money routes
    /// its covering-ACK, below-floor and confirmed-empty settlements here.
    /// The only other writer is `re_owe_effective_upload_body_witness_revision`.
    pub(crate) fn stamp_effective_upload_body_witness_revision(
        &mut self,
        index_key: &str,
        source_file_fingerprint: &str,
        allowed_active: u64,
    ) -> bool {
        if allowed_active == 0
            || self
                .effective_upload_body_witness_revision_excluded_source_files
                .contains(source_file_fingerprint)
            || self
                .claude_history_emission_held(source_file_fingerprint)
                .is_some()
            || self
                .claude_history_emission
                .literal_denied(source_file_fingerprint)
        {
            return false;
        }
        // A revision whose row denies the request-owned
        // literal never stamps a listed family, or any file while the list is
        // paused, whatever this cycle decided (a covering ACK, below-floor or
        // confirmed-empty settlement of a file that was not a candidate).
        // The pause holds adoption only: a file that uploads `e2` under it
        // keeps its stamp and is owed again once the list is back.
        if claude_history_upgrade::denies_request_owned_literal(allowed_active)
            && (self.claude_reemission_exclusions.pauses_adoption()
                || self.claude_family_listed(index_key))
        {
            return false;
        }
        let monotone = self.active_effective_upload_body_witness_revision_monotone;
        // No Claude file is stamped above the last revision the
        // history gate is complete for.
        if monotone && allowed_active > claude_history_upgrade::max_gated_claude_revision() {
            return false;
        }
        let Some(entry) = self.files.get_mut(index_key) else {
            return false;
        };
        entry.effective_upload_body_witness_revision = if monotone {
            entry
                .effective_upload_body_witness_revision
                .max(allowed_active)
        } else {
            allowed_active
        };
        true
    }

    /// The only way to lower a file's `effective_upload_body_witness_revision`
    /// (owner B): only downward, and only below the active revision (before
    /// any activation, below the highest revision with a policy row), so the
    /// file is owed again and goes back through the history gate. Counts
    /// `history_reowed`. Returns false and writes nothing otherwise. MONEY's
    /// census 3 -> 2 path calls it.
    pub(crate) fn re_owe_effective_upload_body_witness_revision(
        &mut self,
        index_key: &str,
        to: u64,
    ) -> bool {
        let active = self.active_effective_upload_body_witness_revision;
        self.files.get_mut(index_key).is_some_and(|entry| {
            claude_history_upgrade::re_owe(
                &mut entry.effective_upload_body_witness_revision,
                to,
                active,
            )
        })
    }

    /// Reuse the existing quarantine retry page after a reviewed admission
    /// increase. Legacy records have no rejection reason: re-offer current
    /// refusals, preserving accepted marks and absent/superseded disclosures.
    pub(crate) fn prepare_snapshot_admission_reoffer(&mut self, limit: usize) -> bool {
        let current = self
            .eligible_snapshot_fingerprint_refs()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let selected = self
            .quarantined_snapshot_fingerprints
            .iter()
            .filter(|(fingerprint, record)| {
                current.contains(*fingerprint)
                    && !self.accepted_snapshot_fingerprints.contains(*fingerprint)
                    && record.witness.item_wire_byte_limit < MAX_SNAPSHOT_ITEM_WIRE_BYTES
                    && record.disposition != SnapshotQuarantineDisposition::SupersededTerminal
            })
            .take(limit)
            .map(|(fingerprint, _)| fingerprint.clone())
            .collect::<Vec<_>>();
        for fingerprint in &selected {
            let record = self
                .quarantined_snapshot_fingerprints
                .get_mut(fingerprint)
                .unwrap();
            record.witness.item_wire_byte_limit = MAX_SNAPSHOT_ITEM_WIRE_BYTES;
            record.retry_after_unix_seconds = 0;
            record.failed_reconstruction_count = 0;
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
        }
        if !selected.is_empty() {
            // Match legacy settlement recovery: only a completed unhealthy
            // traversal needs discovery re-opened. Never restart a live page.
            if self.traversal.as_ref().is_some_and(|t| {
                t.pending_directories.is_empty()
                    && t.pending_candidates.is_empty()
                    && t.counts.has_errors()
            }) {
                self.traversal = None;
            }
            self.mark_bounded_sweep_unsettled_by(UnsettledUploadCause::AdmissionReoffer);
        }
        !selected.is_empty()
    }

    pub(crate) fn snapshot_admission_reoffer_pending(&self) -> bool {
        self.quarantined_snapshot_fingerprints
            .values()
            .any(|record| {
                record.witness.item_wire_byte_limit == MAX_SNAPSHOT_ITEM_WIRE_BYTES
                    && record.disposition == SnapshotQuarantineDisposition::RetryPending
            })
    }

    /// Q-W: every current-limit pending retry uses the same outside/unknown
    /// incidence rule, regardless of which operation created or armed it.
    pub(crate) fn snapshot_admission_reoffer_pending_for_scan(
        &self,
        source: SnapshotSource,
        window_days: u64,
    ) -> bool {
        if source != SnapshotSource::ClaudeCode {
            return self.snapshot_admission_reoffer_pending();
        }
        let Some(now) = unix_seconds(SystemTime::now()) else {
            return self.snapshot_admission_reoffer_pending();
        };
        let (mut outside, mut inside) = (0, 0);
        for (fingerprint, record) in &self.quarantined_snapshot_fingerprints {
            if record.witness.item_wire_byte_limit != MAX_SNAPSHOT_ITEM_WIRE_BYTES
                || record.disposition != SnapshotQuarantineDisposition::RetryPending
            {
                continue;
            }
            // A retry can age out after its refusal. Use the scanner's mtime
            // cutoff on current metadata: committed mtimes can be stale after
            // a restore/copy. Unknown incidence or metadata stays wide.
            let mut found = false;
            let outside_window = self
                .file_snapshot_fingerprints
                .iter()
                .any(|(key, entities)| {
                    if !entities.contains(fingerprint) {
                        return false;
                    }
                    found = true;
                    fs::symlink_metadata(key)
                        .ok()
                        .filter(|metadata| metadata.is_file())
                        .and_then(|metadata| metadata.modified().ok())
                        .and_then(unix_seconds)
                        .map_or(true, |modified| {
                            !is_recent_enough_at(modified, now, window_days)
                        })
                });
            if outside_window || !found {
                outside += 1;
            } else {
                inside += 1;
            }
        }
        if outside + inside > 0 {
            eprintln!(
                "ottto-service: Claude admission scan window: outside_or_unknown={outside} inside={inside}"
            );
        }
        outside > 0
    }

    pub(in crate::snapshots) fn activate_quarantine_witness(&mut self, source: SnapshotSource) {
        self.active_quarantine_witness = Some(
            self.active_upload_context_fingerprint
                .as_deref()
                .filter(|_| self.file_upload_context_enabled())
                .map_or_else(
                    || snapshot_quarantine_witness(source),
                    |context| snapshot_quarantine_witness_for_context(source, context),
                ),
        );
    }

    #[cfg(test)]
    pub(crate) fn activate_quarantine_witness_for_test(&mut self, source: SnapshotSource) {
        self.activate_quarantine_witness(source);
    }

    pub(in crate::snapshots) fn quarantine_requires_retry(&self, fingerprint: &str) -> bool {
        if self.decode_holds_entity(fingerprint) {
            return false;
        }
        if self.reason_reoffer_retries.contains_key(fingerprint) {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        self.quarantined_snapshot_fingerprints
            .get(fingerprint)
            .zip(self.active_quarantine_witness.as_ref())
            .is_some_and(|(persisted, active)| {
                if persisted.contract_retry_claims.is_some() {
                    return self.terminal_contract_retries.contains_key(fingerprint);
                }
                persisted.disposition == SnapshotQuarantineDisposition::RetryPending
                    && (self.terminal_contract_retries.contains_key(fingerprint)
                        || !persisted.witness.same_retry_contract_any_context(active)
                        || persisted.retry_after_unix_seconds <= now)
            })
    }

    /// Merge the already saved upload claims before source acquisition. The caller
    /// saves changes before activating these runtime-only leases or reading files.
    pub(crate) fn merge_terminal_contract_claims(
        &mut self,
        records: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) -> bool {
        terminal_contract_retry::merge_maps(&mut self.quarantined_snapshot_fingerprints, records)
    }

    pub(crate) fn activate_terminal_contract_retries(
        &mut self,
        leases: BTreeSet<String>,
    ) -> Vec<PathBuf> {
        self.terminal_contract_retries.clear();
        // A fingerprint can have more than one indexed incidence. One claim
        // selects one owning file, never every duplicate incidence.
        for (key, fingerprints) in &self.file_snapshot_fingerprints {
            for fingerprint in fingerprints.intersection(&leases) {
                self.terminal_contract_retries
                    .entry(fingerprint.clone())
                    .or_insert_with(|| key.clone());
            }
        }
        // Use the same revalidated candidate admission as exact refusal re-offers.
        // Distinct entities in one file and duplicate incidences own one hint.
        self.terminal_contract_retries
            .values()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Mirror the upload ledger's open head-CAS challenge sessions that hold a
    /// saved base, the only ones whose upload can carry the answer.
    pub(crate) fn activate_head_conflict_sessions(&mut self, sessions: BTreeSet<String>) {
        self.head_conflict_sessions = sessions;
    }

    /// The hashed session key owes a head-CAS answer this cycle.
    pub(crate) fn head_conflict_owed(&self, session_key: &str) -> bool {
        self.head_conflict_sessions.contains(session_key)
    }

    /// A leased file still queued for a bounded page has not reached a hold.
    pub(crate) fn quarantine_retry_is_queued(&self, fingerprint: &str) -> bool {
        self.terminal_contract_retries
            .get(fingerprint)
            .is_some_and(|key| {
                self.traversal
                    .iter()
                    .flat_map(|traversal| traversal.pending_candidates.iter())
                    .any(|pending| pending.path == Path::new(key))
            })
    }

    /// Arm this cycle's exact refusal re-offer leases and return the indexed
    /// files that hold them, for the bounded watcher-hint queue. Paths come
    /// only from the committed file/entity incidence table; the scan
    /// revalidates each one like any other hint. Family/account holds keep
    /// their own earlier gates in `candidate_decision`.
    pub(crate) fn activate_reason_reoffer_retries(
        &mut self,
        leases: BTreeMap<String, String>,
    ) -> Vec<PathBuf> {
        self.reason_reoffer_retries = leases;
        if self.reason_reoffer_retries.is_empty() {
            return Vec::new();
        }
        self.file_snapshot_fingerprints
            .keys()
            .filter(|key| self.reason_reoffer_leased(key))
            .map(PathBuf::from)
            .collect()
    }

    /// This cycle leased the file's snapshot for a reason re-offer.
    pub(in crate::snapshots) fn reason_reoffer_leased(&self, key: &str) -> bool {
        !self.reason_reoffer_retries.is_empty()
            && self
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|fingerprints| {
                    fingerprints
                        .iter()
                        .any(|fingerprint| self.reason_reoffer_retries.contains_key(fingerprint))
                })
    }

    pub(in crate::snapshots) fn quarantine_requires_retry_body(
        &self,
        fingerprint: &str,
        body_witness: &str,
    ) -> bool {
        if self.decode_holds_entity(fingerprint) {
            return false;
        }
        self.quarantined_snapshot_fingerprints
            .get(fingerprint)
            .is_some_and(|record| {
                record.upload_body_witness.as_deref() != Some(body_witness)
                    || self.quarantine_requires_retry(fingerprint)
            })
    }

    /// Arm this cycle's exact-body cooldown view (fingerprint -> refused
    /// body witness), read from the prepared upload ledger after its leases
    /// and any clock re-clamp. Replaces the previous view and its counts.
    pub(crate) fn activate_reason_reoffer_cooldowns<T: Into<ReasonReofferCooldown>>(
        &mut self,
        cooldowns: BTreeMap<String, T>,
    ) {
        self.reason_reoffer_cooldowns = cooldowns
            .into_iter()
            .map(|(fp, cooldown)| (fp, cooldown.into()))
            .collect();
    }

    /// True when this entity's ordinary retry is only the retained conflict
    /// of its exact refused body, which no lease lets through this cycle:
    /// re-reading the unchanged file cannot send it. A lease, an acceptance,
    /// another body or a changed quarantine witness keeps the retry.
    fn reason_reoffer_cooldown_defers(&self, fingerprint: &str) -> bool {
        if self
            .reason_reoffer_cooldowns
            .get(fingerprint)
            .is_some_and(|c| c.input_change_only)
        {
            return true;
        }
        !self.reason_reoffer_retries.contains_key(fingerprint)
            && !self.accepted_snapshot_fingerprint_recorded(fingerprint)
            && self
                .reason_reoffer_cooldowns
                .get(fingerprint)
                .zip(self.quarantined_snapshot_fingerprints.get(fingerprint))
                .is_some_and(|(body_witness, record)| {
                    record.disposition == SnapshotQuarantineDisposition::RetryPending
                        && record.upload_body_witness.as_deref()
                            == Some(body_witness.body_witness.as_str())
                        && self
                            .active_quarantine_witness
                            .as_ref()
                            .is_some_and(|active| {
                                record.witness.same_retry_contract_any_context(active)
                            })
                })
    }

    /// The ordinary retry gate of candidate selection, without the retry an
    /// exact-body cooldown defers.
    pub(in crate::snapshots) fn quarantine_retry_selects_file(
        &self,
        fingerprint: &str,
        key: &str,
    ) -> bool {
        self.quarantine_requires_retry(fingerprint)
            && self
                .terminal_contract_retries
                .get(fingerprint)
                .map_or(true, |owner| owner == key)
            && !self.reason_reoffer_cooldown_defers(fingerprint)
    }

    /// Revoke this cycle's bound if any mapped candidate is selected or
    /// changed. Not-yet-visited entities remain provisional cooldown debt:
    /// only the ordinary complete, clean traversal can settle them. Requiring
    /// a page-local seen set would make multi-page quiet walks block forever.
    pub(in crate::snapshots) fn note_reason_reoffer_cooldown_candidate(
        &mut self,
        candidate: &CandidateFile,
        skipped: bool,
    ) {
        if self.reason_reoffer_cooldowns.is_empty() {
            return;
        }
        let key = local_index_key(&candidate.path);
        let unchanged = skipped
            && self.files.get(&key).is_some_and(|entry| {
                entry.size_bytes == candidate.size_bytes
                    && entry.modified_unix_seconds == candidate.modified_unix_seconds
                    && entry.modified_unix_nanos == Some(candidate.modified_unix_nanos)
                    && entry.source_file_fingerprint == candidate.source_file_fingerprint
                    && entry.scan_identity_version.as_deref()
                        == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            });
        if !unchanged {
            if let Some(fingerprints) = self.file_snapshot_fingerprints.get(&key) {
                for fingerprint in fingerprints {
                    if !skipped
                        || !self
                            .reason_reoffer_cooldowns
                            .get(fingerprint)
                            .is_some_and(|c| c.input_change_only)
                    {
                        self.reason_reoffer_cooldowns.remove(fingerprint);
                    }
                }
            }
        }
    }

    /// This exact runtime bound makes the retained conflict non-blocking for
    /// this page. It never certifies a traversal or changes its prior causes;
    /// every candidate still has to pass the normal clean census boundary.
    pub(crate) fn reason_reoffer_conflict_is_deferred(
        &self,
        fingerprint: &str,
        body: &str,
    ) -> bool {
        self.reason_reoffer_cooldowns
            .get(fingerprint)
            .is_some_and(|cooldown| cooldown.body_witness == body)
            && self.reason_reoffer_cooldown_defers(fingerprint)
    }

    /// Current, distinct cooldown entities, including debt not visited on
    /// this bounded page or whose ordinary timer has not expired. The set is
    /// bounded by the refusal view, never by the whole source corpus.
    pub(crate) fn reason_reoffer_cooldown_deferred_count(&self) -> usize {
        if self.reason_reoffer_cooldowns.is_empty() {
            return 0;
        }
        self.current_snapshot_fingerprint_refs()
            .filter(|fingerprint| self.reason_reoffer_cooldown_defers(fingerprint))
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn retain_quarantined_fingerprints(
        &mut self,
        quarantined: &BTreeMap<String, SnapshotQuarantineRecord>,
    ) {
        let current = self
            .file_snapshot_fingerprints
            .values()
            .flat_map(BTreeSet::iter)
            .collect::<BTreeSet<_>>();
        let replay_safe_absent_terminals = self
            .quarantined_snapshot_fingerprints
            .iter()
            .filter(|(fingerprint, record)| {
                !current.contains(*fingerprint)
                    && matches!(
                        record.disposition,
                        SnapshotQuarantineDisposition::UnprovenTerminal
                            | SnapshotQuarantineDisposition::SupersededTerminal
                    )
            })
            .map(|(fingerprint, record)| (fingerprint.clone(), record.clone()))
            .collect::<BTreeMap<_, _>>();
        let previous_claims = self
            .quarantined_snapshot_fingerprints
            .iter()
            .filter(|(_, record)| record.contract_retry_claims.is_some())
            .map(|(fp, record)| (fp.clone(), record.clone()))
            .collect();
        self.quarantined_snapshot_fingerprints = quarantined
            .iter()
            .filter(|(fingerprint, record)| {
                current.contains(*fingerprint)
                    || record.disposition == SnapshotQuarantineDisposition::SupersededTerminal
            })
            .map(|(fingerprint, witness)| (fingerprint.clone(), witness.clone()))
            .collect();
        for (fingerprint, record) in replay_safe_absent_terminals {
            self.quarantined_snapshot_fingerprints
                .entry(fingerprint)
                .or_insert(record);
        }
        terminal_contract_retry::merge_maps(
            &mut self.quarantined_snapshot_fingerprints,
            &previous_claims,
        );
        let opaque_incidence = self.decode_has_opaque_file_incidence();
        let carried = self.carried_ack_fingerprints();
        self.accepted_snapshot_fingerprints.retain(|fingerprint| {
            (opaque_incidence || carried.contains(fingerprint) || current.contains(fingerprint))
                && !self
                    .quarantined_snapshot_fingerprints
                    .contains_key(fingerprint)
        });
    }
}
