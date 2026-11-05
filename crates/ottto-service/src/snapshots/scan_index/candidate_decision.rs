//! Scan-index candidate decisions and recorded parse outcomes.

use crate::snapshots::*;

impl ScanIndex {
    pub(in crate::snapshots) fn candidate_decision(
        &self,
        candidate: &CandidateFile,
    ) -> CandidateDecision {
        self.candidate_decision_with_reason(candidate).0
    }

    pub(in crate::snapshots) fn candidate_decision_with_reason(
        &self,
        candidate: &CandidateFile,
    ) -> (CandidateDecision, Option<CandidateParseReason>) {
        self.candidate_decision_with_reason_at(candidate, sampled_scan::now_seconds())
    }

    pub(in crate::snapshots) fn candidate_decision_in_window(
        &self,
        candidate: &CandidateFile,
        audit_now: u64,
        source_change: &mut Option<change_reason::SourceChange>,
    ) -> (CandidateDecision, Option<CandidateParseReason>) {
        self.candidate_decision_refined(candidate, audit_now, true, source_change)
    }

    #[cfg(test)]
    pub(in crate::snapshots) fn candidate_decision_at(
        &self,
        candidate: &CandidateFile,
        now: u64,
    ) -> CandidateDecision {
        self.candidate_decision_with_reason_at(candidate, now).0
    }

    pub(in crate::snapshots) fn candidate_decision_with_reason_at(
        &self,
        candidate: &CandidateFile,
        now: u64,
    ) -> (CandidateDecision, Option<CandidateParseReason>) {
        self.candidate_decision_with_reason_gated(candidate, now, true)
    }

    /// True when only the body-witness revision selects this candidate: the
    /// same decision without that gate skips the file.
    pub(in crate::snapshots) fn candidate_requires_only_body_witness_adoption(
        &self,
        candidate: &CandidateFile,
        now: u64,
    ) -> bool {
        self.effective_upload_body_witness_revision_requires_adoption(&local_index_key(
            &candidate.path,
        )) && self
            .candidate_decision_with_reason_gated(candidate, now, false)
            .0
            == CandidateDecision::Skip
    }

    /// Whether an unindexed member's family holds an authority record (a held
    /// body the committed index does not keep) whose gate would skip it as an
    /// indexed member: its revision unchanged, its witness binding unmoved,
    /// its retry not due and no correction owing it.
    fn claude_unindexed_member_waits_for_authority(&self, candidate: &CandidateFile) -> bool {
        let Some((root_session_id, member)) = claude_index_path_family_member(&candidate.path)
        else {
            return false;
        };
        self.claude_usage_authority_quarantine
            .get(&root_session_id)
            .is_some_and(|record| {
                !record
                    .proof_correction
                    .as_ref()
                    .is_some_and(|correction| correction.owed_member_ids.contains(&member))
                    && self
                        .claude_usage_authority_candidate_requires_family_reparse(candidate)
                        .is_none()
            })
    }

    /// The candidate decision plus, for `Parse`, the first gate that selected
    /// the file. The reason is a count-only diagnostic; only the adoption
    /// page budget reads it. `body_witness_adoption: false` evaluates the
    /// same gates without the body-witness revision.
    ///
    /// Scoped history admission can ignore revision and proven mode-context
    /// debt while checking every independent local refresh reason.
    pub(in crate::snapshots) fn candidate_decision_with_reason_gated(
        &self,
        candidate: &CandidateFile,
        now: u64,
        body_witness_adoption: bool,
    ) -> (CandidateDecision, Option<CandidateParseReason>) {
        self.candidate_decision_refined(candidate, now, body_witness_adoption, &mut None)
    }

    /// The gated decision; `source_change` names the `SourceChanged` arm that
    /// selected the file, for the change-reason counts only.
    fn candidate_decision_refined(
        &self,
        candidate: &CandidateFile,
        now: u64,
        body_witness_adoption: bool,
        source_change: &mut Option<change_reason::SourceChange>,
    ) -> (CandidateDecision, Option<CandidateParseReason>) {
        let key = local_index_key(&candidate.path);
        if self.decode_holds_file(&key) {
            return (CandidateDecision::Skip, None);
        }
        if self.stale_refusal_holds_unchanged_input(candidate) {
            return (CandidateDecision::Skip, None);
        }
        if self
            .terminal_jsonl_dispositions
            .get(&key)
            .is_some_and(|disposition| {
                disposition.source_file_fingerprint != candidate.source_file_fingerprint
                    || disposition.parser_generation != JSONL_TERMINAL_DISPOSITION_GENERATION
            })
        {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::TerminalDisposition),
            );
        }
        let Some(entry) = self.files.get(&key) else {
            if self.claude_unindexed_member_waits_for_authority(candidate)
                || self.withheld_account_unchanged(&key, candidate)
            {
                return (CandidateDecision::Skip, None);
            }
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::NewFile),
            );
        };
        if let Some((root_session_id, member)) = claude_index_path_family_member(&candidate.path) {
            if self
                .claude_usage_authority_quarantine
                .contains_key(&root_session_id)
            {
                if self
                    .claude_usage_authority_candidate_requires_family_reparse(candidate)
                    .is_some()
                    || self
                        .claude_usage_authority_quarantine
                        .get(&root_session_id)
                        .and_then(|record| record.proof_correction.as_ref())
                        .is_some_and(|correction| correction.owed_member_ids.contains(&member))
                {
                    return (
                        CandidateDecision::Parse,
                        Some(CandidateParseReason::AuthorityQuarantine),
                    );
                }
                return (CandidateDecision::Skip, None);
            }
        }
        let withheld_unchanged = !entry.source_file_fingerprint.is_empty()
            && self.withheld_account_unchanged(&key, candidate);
        // A withheld key's audit debt (carried onto its reverted entry) cannot
        // settle while held; an unchanged one defers it to its next counted
        // re-parse, usually the binding read, instead of a Full every pass.
        // A prefix-only hold must survive settlement of the file's own turns.
        // Its persisted attempt counter expires on the third decision pass.
        if self
            .claude_copy_removals
            .pending(claude_money_birth_store::location_key(&key))
        {
            *source_change = Some(change_reason::SourceChange::CopyRemoval);
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::SourceChanged),
            );
        }
        let audit_due = entry.audit_requires_full(now) && !withheld_unchanged;
        if audit_due {
            return (CandidateDecision::Parse, Some(CandidateParseReason::Audit));
        }
        // A locally held Claude family above keeps its existing bounded retry
        // gate. Otherwise a projection change selects even an unchanged v2
        // file under an already admitted context, independently of parser age.
        // Completed restores the old revision while account-held. Its memo is
        // scoped to the active revision/context, so repeating that adoption
        // cannot settle it; a new activation still selects a counted parse.
        if body_witness_adoption
            && !withheld_unchanged
            && self.effective_upload_body_witness_revision_requires_adoption(&key)
        {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::BodyWitnessAdoption),
            );
        }
        // A settings or capability change never selects a read: it applies
        // from the file's next ordinary read on, for every source.
        if self
            .file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|fingerprints| {
                fingerprints.iter().any(|fingerprint| {
                    // Missing activity on the restored tuple cannot settle an
                    // account hold either. An actual quarantine retry remains
                    // independent authority to re-read, even with CONTENT.
                    (!withheld_unchanged
                        && !self
                            .snapshot_activity_at
                            .get(fingerprint)
                            .is_some_and(valid_snapshot_activity))
                        || self.quarantine_retry_selects_file(fingerprint, &key)
                })
            })
        {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::ActivityOrQuarantineRetry),
            );
        }
        // A withheld key keeps its old committed revision; unless re-armed it
        // re-parses only once per process or on a stamp/evidence change.
        if withheld_unchanged {
            return (CandidateDecision::Skip, None);
        }
        let known_fragment = entry.codex_fragment.as_ref().is_some_and(|fragment| {
            fragment.matches(
                entry.size_bytes,
                candidate.size_bytes,
                codex_fragment::Stamp::candidate(candidate),
            ) && entry.source_file_fingerprint == candidate.source_file_fingerprint
        });
        let transcript_changed = !known_fragment
            && (entry.size_bytes != candidate.size_bytes
                || entry.modified_unix_seconds != candidate.modified_unix_seconds
                || entry
                    .modified_unix_nanos
                    .is_some_and(|value| value != candidate.modified_unix_nanos));
        if transcript_changed {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::TranscriptChanged),
            );
        }
        if entry.codex_captured_uncommitted
            || entry.codex_captured_tier_receipt_required
            || entry.codex_captured_joined_member_set.is_some()
        {
            // The independent native quarantine owns its existing retry gate;
            // selector capture never constitutes acceptance or creates a skip.
            let quarantine_holds = entry.source_file_fingerprint
                == candidate.source_file_fingerprint
                && self
                    .file_snapshot_fingerprints
                    .get(&key)
                    .is_some_and(|fingerprints| {
                        !fingerprints.is_empty()
                            && fingerprints.iter().all(|fingerprint| {
                                self.quarantined_snapshot_fingerprints
                                    .get(fingerprint)
                                    .is_some_and(|record| {
                                        self.active_quarantine_witness.as_ref().is_some_and(
                                            |active| {
                                                record
                                                    .witness
                                                    .same_retry_contract_any_context(active)
                                            },
                                        ) && !self.quarantine_retry_selects_file(fingerprint, &key)
                                    })
                            })
                    });
            return if quarantine_holds {
                (CandidateDecision::Skip, None)
            } else {
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::CodexCapture),
                )
            };
        }
        if entry.last_snapshot_fingerprint.is_none() && !self.confirmed_empty_files.contains(&key) {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::UnknownOutcome),
            );
        }
        if !self.file_snapshot_fingerprints.contains_key(&key)
            && entry
                .last_snapshot_fingerprint
                .as_ref()
                .is_some_and(|fingerprint| {
                    !self
                        .snapshot_activity_at
                        .get(fingerprint)
                        .is_some_and(valid_snapshot_activity)
                })
        {
            return (
                CandidateDecision::Parse,
                Some(CandidateParseReason::LegacyActivity),
            );
        }
        if entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            && !entry.has_unverified_source()
        {
            // An owed revision is not observed: it parses, never migrates.
            return if entry.source_file_fingerprint.as_str()
                == candidate.legacy_source_file_fingerprint
            {
                if candidate.legacy_config_reconciliation_required {
                    (CandidateDecision::ReconcileLegacy, None)
                } else {
                    (CandidateDecision::Migrate, None)
                }
            } else {
                // The legacy source-wide sidecar identity changed while this
                // entry was not observed. We cannot prove which session was
                // affected from the irreversible old digest, so correctness
                // requires a one-time parse instead of silently absorbing it.
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::LegacyIdentity),
                )
            };
        }
        if entry.source_file_fingerprint != candidate.source_file_fingerprint {
            let reason = if entry.source_file_fingerprint.is_empty() {
                CandidateParseReason::Rearmed
            } else {
                *source_change = Some(change_reason::SourceChange::Fingerprint);
                CandidateParseReason::SourceChanged
            };
            (CandidateDecision::Parse, Some(reason))
        } else if self.claude_account_deferred_holds.contains_key(&key) {
            // Equality of the committed fingerprint cannot settle an account
            // retry. Only the validated CONTENT memo above grants that Skip;
            // missing/refused/poisoned/unstamped advisory state must recover
            // through the existing counted parse, without clearing the tuple.
            // Memo-miss recovery, NOT a source change: SourceChanged is the
            // legacy selector bucket; withheld_reparse{start} names this read.
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::SourceChanged),
            )
        } else {
            (CandidateDecision::Skip, None)
        }
    }

    /// This file is a family member an owed proof correction names.
    pub(in crate::snapshots) fn claude_authority_correction_owed(&self, path: &Path) -> bool {
        claude_index_path_family_member(path).is_some_and(|(root, member)| {
            self.claude_usage_authority_quarantine
                .get(&root)
                .and_then(|record| record.proof_correction.as_ref())
                .is_some_and(|correction| correction.owed_member_ids.contains(&member))
        })
    }

    /// This member is selected only because its family owes
    /// a proof correction (no witness change and no due retry).
    pub(in crate::snapshots) fn claude_authority_correction_only(
        &self,
        candidate: &CandidateFile,
    ) -> bool {
        self.claude_authority_correction_owed(&candidate.path)
            && self
                .claude_usage_authority_candidate_requires_family_reparse(candidate)
                .is_none()
    }

    /// Whether an owed proof correction still blocks a fully
    /// settled upload, and how many owed members wait for the history gate
    /// instead. A member whose indexed file still owes the history upgrade is
    /// held by the gate: its correction settles once the gate permits it, so
    /// it is deferred (disclosed), not blocking. A member with no indexed file
    /// blocks.
    pub(crate) fn claude_authority_proof_correction_blocking(&self) -> (bool, usize) {
        let owed = self
            .claude_usage_authority_quarantine
            .values()
            .filter_map(|record| record.proof_correction.as_ref())
            .map(|correction| correction.owed_member_ids.len())
            .sum::<usize>();
        if owed == 0 {
            return (false, 0);
        }
        // By family member identity, not source fingerprint: a re-armed
        // entry keeps its member path with a cleared fingerprint.
        let mut found = 0;
        let mut deferred = 0;
        for key in self.files.keys() {
            let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            let owes = self
                .claude_usage_authority_quarantine
                .get(&root)
                .and_then(|record| record.proof_correction.as_ref())
                .is_some_and(|correction| correction.owed_member_ids.contains(&member));
            if owes {
                found += 1;
                if self.effective_upload_body_witness_revision_requires_adoption(key) {
                    deferred += 1;
                }
            }
        }
        (found < owed || deferred < found, deferred)
    }

    pub(in crate::snapshots) fn claude_usage_authority_candidate_requires_family_reparse(
        &self,
        candidate: &CandidateFile,
    ) -> Option<String> {
        let (root_session_id, source_session_id) =
            claude_index_path_family_member(&candidate.path)?;
        let record = self
            .claude_usage_authority_quarantine
            .get(&root_session_id)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let witness_matches = self
            .claude_usage_family_witnesses
            .get(&root_session_id)
            .is_some_and(|witness| {
                claude_usage_family_witness_fingerprint(witness)
                    == record.proven_witness_fingerprint
            });
        let revision_matches = record
            .member_source_file_fingerprints
            .get(&source_session_id)
            == Some(&candidate.source_file_fingerprint);
        let retry_due = record.disposition
            == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
            && record.retry_after_unix_seconds <= now
            || claude_terminal_predates_e2(record);
        (!witness_matches || !revision_matches || retry_due).then_some(root_session_id)
    }

    pub(in crate::snapshots) fn last_snapshot_fingerprint(
        &self,
        candidate: &CandidateFile,
    ) -> Option<String> {
        self.files
            .get(&local_index_key(&candidate.path))
            .and_then(|entry| entry.last_snapshot_fingerprint.clone())
    }

    pub(in crate::snapshots) fn last_upload_body_witness(
        &self,
        candidate: &CandidateFile,
    ) -> Option<String> {
        self.files
            .get(&local_index_key(&candidate.path))
            .and_then(|entry| entry.last_upload_body_witness.clone())
    }

    /// A fresh entry for `candidate` that carries `key`'s upload witness,
    /// counting state and upload-context receipt from the entry it replaces.
    /// Callers decide the snapshot fingerprint and identity version.
    fn carried(
        &self,
        key: &str,
        candidate: CandidateFile,
        last_snapshot_fingerprint: Option<String>,
        scan_identity_version: String,
    ) -> ScanIndexEntry {
        let old = self.files.get(key);
        ScanIndexEntry {
            codex_fragment: None,
            size_bytes: candidate.size_bytes,
            modified_unix_seconds: candidate.modified_unix_seconds,
            modified_unix_nanos: Some(candidate.modified_unix_nanos),
            source_file_fingerprint: candidate.source_file_fingerprint,
            last_snapshot_fingerprint,
            last_upload_body_witness: old.and_then(|entry| entry.last_upload_body_witness.clone()),
            effective_upload_body_witness_revision: old
                .map_or(0, |entry| entry.effective_upload_body_witness_revision),
            scan_identity_version: Some(scan_identity_version),
            codex_joined_member_set: None,
            codex_captured_joined_member_set: None,
            codex_protected_owner: None,
            codex_applied_tier_receipt: None,
            codex_applied_tier_receipt_required: false,
            codex_captured_tier_receipt: None,
            codex_captured_tier_receipt_required: false,
            codex_captured_uncommitted: false,
            codex_counting_v2: old.is_some_and(|entry| entry.codex_counting_v2),
            codex_counting_owner: old.and_then(|entry| entry.codex_counting_owner.clone()),
            opened_changed_nanos: candidate.fingerprint_changed_nanos,
            opened_birth_nanos: candidate.fingerprint_birth_nanos,
            upload_context_receipt: old.and_then(|entry| entry.upload_context_receipt.clone()),
        }
    }

    pub(in crate::snapshots) fn migrate(&mut self, candidate: CandidateFile) {
        let key = local_index_key(&candidate.path);
        rearm_cause::reproven(&key);
        let old = self.files.get(&key);
        let last_snapshot_fingerprint =
            old.and_then(|entry| entry.last_snapshot_fingerprint.clone());
        let entry = self.carried(
            &key,
            candidate,
            last_snapshot_fingerprint,
            LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string(),
        );
        self.files.insert(key, entry);
    }

    pub(in crate::snapshots) fn record(
        &mut self,
        candidate: CandidateFile,
        last_snapshot_fingerprint: Option<String>,
        parse_outcome: ScanParseOutcome,
    ) {
        let key = local_index_key(&candidate.path);
        rearm_cause::reproven(&key);
        let scan_identity_version = self
            .files
            .get(&key)
            .map(ScanIndexEntry::carried_audit_version)
            .unwrap_or_else(|| LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        // The body witness and `codex_counting_v2` are carried; a configured
        // singleton parse then sets the latter to that parse's decided version.
        let entry = self.carried(
            &key,
            candidate,
            last_snapshot_fingerprint,
            scan_identity_version,
        );
        self.files.insert(key.clone(), entry);
        match parse_outcome {
            ScanParseOutcome::ConfirmedEmpty | ScanParseOutcome::PolicySuppressed => {
                self.claude_copy_removals
                    .clear_hold(claude_money_birth_store::location_key(&key));
                self.note_empty_file_upload_context(&key);
                self.confirmed_empty_files.insert(key);
            }
            ScanParseOutcome::Snapshot | ScanParseOutcome::Unknown => {
                self.clear_empty_file_upload_context(&key);
                self.confirmed_empty_files.remove(&key);
            }
        }
    }

    pub(in crate::snapshots) fn record_terminal_jsonl_disposition(
        &mut self,
        candidate: &CandidateFile,
        loss: Option<TerminalJsonlLoss>,
    ) {
        let key = local_index_key(&candidate.path);
        match loss {
            Some(loss) => {
                self.terminal_jsonl_dispositions.insert(
                    key,
                    TerminalJsonlDisposition {
                        source_file_fingerprint: candidate.source_file_fingerprint.clone(),
                        parser_generation: JSONL_TERMINAL_DISPOSITION_GENERATION.to_string(),
                        loss,
                    },
                );
            }
            None => {
                self.terminal_jsonl_dispositions.remove(&key);
            }
        }
    }

    pub(in crate::snapshots) fn terminal_jsonl_loss(
        &self,
        candidate: &CandidateFile,
    ) -> Option<&TerminalJsonlLoss> {
        self.terminal_jsonl_dispositions
            .get(&local_index_key(&candidate.path))
            .filter(|disposition| {
                disposition.source_file_fingerprint == candidate.source_file_fingerprint
                    && disposition.parser_generation == JSONL_TERMINAL_DISPOSITION_GENERATION
            })
            .map(|disposition| &disposition.loss)
    }
}
