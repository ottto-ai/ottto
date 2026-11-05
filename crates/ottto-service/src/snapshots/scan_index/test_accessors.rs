//! Scan-index inspection and retained-authority fixture accessors.

use crate::snapshots::*;

impl ScanIndex {
    #[cfg(test)]
    pub(crate) fn bounded_sweep_had_unsettled_upload(&self) -> bool {
        self.bounded_sweep_had_unsettled_upload
    }

    #[cfg(test)]
    pub(crate) fn bounded_sweep_unsettled_cause_names(&self) -> Vec<&'static str> {
        UnsettledUploadCause::names(self.unsettled_cause_bits())
    }

    #[cfg(test)]
    pub(crate) fn accepted_snapshot_fingerprints_for_test(&self) -> &BTreeSet<String> {
        &self.accepted_snapshot_fingerprints
    }

    pub(crate) fn accepted_snapshot_fingerprint_recorded(&self, fingerprint: &str) -> bool {
        !self.decode_holds_entity(fingerprint)
            && self.accepted_snapshot_fingerprints.contains(fingerprint)
    }

    /// A well-formed RetryPending family quarantine bound to a retained
    /// synthetic witness whose only member is the root itself.
    #[cfg(test)]
    pub(crate) fn insert_retry_pending_claude_authority_for_test(&mut self, root_session_id: &str) {
        self.insert_claude_authority_for_test(
            root_session_id,
            &"1".repeat(64),
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
        );
    }

    /// A well-formed RetryPending family quarantine bound to a retained
    /// synthetic witness whose only member is the root itself, recording
    /// `revision` as that member's held source revision.
    #[cfg(test)]
    pub(crate) fn insert_retry_pending_claude_authority_at_revision_for_test(
        &mut self,
        root_session_id: &str,
        revision: &str,
    ) {
        self.insert_claude_authority_for_test(
            root_session_id,
            revision,
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
        );
    }

    /// Installs the family witness an older build stored for
    /// `root_session_id`: an upgraded store's state. No build mints a new
    /// witness; the fold only rebuilds stored ones. Built from the family's
    /// parsed member items and the root's paired telemetry with the same
    /// fingerprints the rebuild checks (no legacy exclusion). Returns false,
    /// installing nothing, when the rows do not reduce or a member has no
    /// assigned requests.
    #[cfg(test)]
    pub(crate) fn install_stored_claude_family_witness_for_test<'a>(
        &mut self,
        root_session_id: &str,
        items: impl IntoIterator<Item = &'a SnapshotItem>,
        api_report: &crate::claude_local_otel::ClaudeLocalOtelLoadReport,
        trace_report: &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    ) -> bool {
        let members = items
            .into_iter()
            .filter(|item| claude_snapshot_family_root_ref(item) == root_session_id)
            .map(|item| (item.source_session_id.clone(), item))
            .collect::<BTreeMap<_, _>>();
        let (Some(api_rows), Some(trace_rows)) = (
            api_report.evidence.get(root_session_id),
            trace_report.evidence.get(root_session_id),
        ) else {
            return false;
        };
        let member_ids = members.keys().cloned().collect::<BTreeSet<_>>();
        let Some(reduced) = reduce_claude_usage_ledger_with_rows(
            root_session_id,
            &member_ids,
            api_rows,
            trace_rows,
            Clone::clone,
        ) else {
            return false;
        };
        let mut member_request_id_fingerprints = BTreeMap::new();
        let mut member_occurrence_fingerprints = BTreeMap::new();
        for (member, item) in &members {
            let request_hashes = item
                .claude_usage_request_ids
                .iter()
                .map(|request_id| format!("{:x}", Sha256::digest(request_id.as_bytes())))
                .collect::<BTreeSet<_>>();
            let Some(assigned) = reduced.assigned_request_id_hashes.get(member) else {
                return false;
            };
            if !request_hashes.is_subset(assigned) {
                return false;
            }
            let occurrences = item
                .claude_usage_occurrences
                .iter()
                .map(|(request_id, occurrence)| {
                    (
                        format!("{:x}", Sha256::digest(request_id.as_bytes())),
                        ClaudeTranscriptUsageOccurrenceWitness::from(occurrence),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            member_request_id_fingerprints.insert(
                member.clone(),
                claude_request_id_set_fingerprint(&request_hashes),
            );
            member_occurrence_fingerprints.insert(
                member.clone(),
                claude_occurrence_map_fingerprint(&occurrences),
            );
        }
        let assigned_request_id_fingerprints = reduced
            .assigned_request_id_hashes
            .iter()
            .map(|(member, hashes)| (member.clone(), claude_request_id_set_fingerprint(hashes)))
            .collect();
        self.claude_usage_family_witnesses.insert(
            root_session_id.to_string(),
            ClaudeUsageFamilyWitness {
                evidence_fingerprint: reduced.evidence_fingerprint,
                member_request_id_fingerprints,
                member_occurrence_fingerprints,
                assigned_request_id_fingerprints,
                legacy_excluded_request_id_hashes: BTreeMap::new(),
                legacy_exclusion_evidence_fingerprint: None,
                legacy_owner_roots: BTreeSet::new(),
            },
        );
        true
    }

    /// [`Self::install_stored_claude_family_witness_for_test`] with the
    /// root's telemetry read from `support_dir`.
    #[cfg(test)]
    pub(crate) fn install_stored_claude_family_witness_from_support_for_test<'a>(
        &mut self,
        root_session_id: &str,
        items: impl IntoIterator<Item = &'a SnapshotItem>,
        support_dir: &Path,
    ) -> bool {
        let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
            support_dir,
            [root_session_id.to_owned()],
        );
        let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
            support_dir,
            [root_session_id.to_owned()],
        );
        self.install_stored_claude_family_witness_for_test(root_session_id, items, &api, &trace)
    }

    /// The owed correction an older build persisted for a family,
    /// built from the persisted types (unchanged since 0.1.203): its terminal
    /// record bound to the retained witness, owing every indexed member at its
    /// held or indexed revision, as an older build granted it. The
    /// members are re-armed, so the next pass reads every owed member.
    #[cfg(test)]
    pub(crate) fn bind_pre_flip_claude_correction_for_test(&mut self, root_session_id: &str) {
        // A held record already names the revisions its read saw; the
        // correction keeps them.
        let held = self
            .claude_usage_authority_quarantine
            .get(root_session_id)
            .map(|record| record.member_source_file_fingerprints.clone())
            .unwrap_or_default();
        let mut members = BTreeMap::new();
        for (index_key, entry) in &mut self.files {
            let Some((root, member)) = claude_index_path_family_member(Path::new(index_key)) else {
                continue;
            };
            if root == root_session_id {
                let revision = std::mem::take(&mut entry.source_file_fingerprint);
                // A re-armed entry has no revision; any well-formed one pairs it.
                let revision = held
                    .get(&member)
                    .cloned()
                    .unwrap_or(if revision.is_empty() {
                        "5".repeat(64)
                    } else {
                        revision
                    });
                members.insert(member, revision);
            }
        }
        self.bind_claude_authority_for_test(
            root_session_id,
            members,
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
        );
        self.seed_census_correction_for_test(root_session_id);
    }

    #[cfg(test)]
    fn bind_claude_authority_for_test(
        &mut self,
        root_session_id: &str,
        members: BTreeMap<String, String>,
        disposition: ClaudeUsageAuthorityQuarantineDisposition,
    ) {
        let failed_reconstruction_count = match disposition {
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending => 1,
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => {
                MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            }
        };
        let witness = self
            .claude_usage_family_witnesses
            .get(root_session_id)
            .expect("the family retains a witness");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let record = ClaudeUsageAuthorityQuarantineRecord {
            proof_correction: None,
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(witness),
            member_source_file_fingerprints: members,
            failed_reconstruction_count,
            disposition,
            retry_after_unix_seconds: now.saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS),
        };
        assert!(claude_usage_authority_preserves_pending(&record, witness));
        self.claude_usage_authority_quarantine
            .insert(root_session_id.to_string(), record);
    }

    /// A well-formed UnprovenTerminal family quarantine bound to a retained
    /// synthetic witness whose only member is the root itself, recording
    /// `revision` as that member's held source revision.
    #[cfg(test)]
    pub(crate) fn insert_unproven_terminal_claude_authority_for_test(
        &mut self,
        root_session_id: &str,
        revision: &str,
    ) {
        self.insert_claude_authority_for_test(
            root_session_id,
            revision,
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
        );
    }

    /// The root member revision recorded by a terminal quarantine that is
    /// still bound to the family's retained witness.
    #[cfg(test)]
    pub(crate) fn bound_terminal_claude_authority_revision_for_test(
        &self,
        root_session_id: &str,
    ) -> Option<String> {
        let record = self
            .claude_usage_authority_quarantine
            .get(root_session_id)?;
        let witness = self.claude_usage_family_witnesses.get(root_session_id)?;
        if record.disposition != ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
            || !claude_usage_authority_preserves_pending(record, witness)
        {
            return None;
        }
        record
            .member_source_file_fingerprints
            .get(root_session_id)
            .cloned()
    }

    /// The content-free digest of the family's retained usage witness.
    #[cfg(test)]
    pub(crate) fn claude_usage_family_witness_digest_for_test(
        &self,
        root_session_id: &str,
    ) -> Option<String> {
        self.claude_usage_family_witnesses
            .get(root_session_id)
            .map(claude_usage_family_witness_fingerprint)
    }

    /// Whether a bounded traversal is still in progress.
    #[cfg(test)]
    pub(crate) fn scan_traversal_in_progress_for_test(&self) -> bool {
        self.traversal.is_some()
    }

    #[cfg(test)]
    pub(crate) fn initialize_current_claude_contract_for_test(&mut self) {
        assert!(self.files.is_empty() && self.traversal.is_none());
        assert!(self.claude_request_identity_contract.is_none());
        // Controlled already-current reader INPUT, not clearing real upgrade
        // debt. Use before the fixture's first transcript is indexed only.
        self.claude_request_identity_contract =
            Some(claude_request_identity::cycle_contract(true).into());
    }

    #[cfg(test)]
    pub(crate) fn claude_request_identity_contract_for_test(&self) -> Option<&str> {
        self.claude_request_identity_contract.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn claude_authority_record_for_test(
        &self,
        root_session_id: &str,
    ) -> Option<ClaudeAuthorityRecordForTest> {
        let record = self
            .claude_usage_authority_quarantine
            .get(root_session_id)?;
        Some(ClaudeAuthorityRecordForTest {
            contract: record.contract.clone(),
            proven_witness_fingerprint: record.proven_witness_fingerprint.clone(),
            member_source_file_fingerprints: record.member_source_file_fingerprints.clone(),
            failed_reconstruction_count: record.failed_reconstruction_count,
            terminal: record.disposition
                == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: record.retry_after_unix_seconds,
            correction: record.proof_correction.as_ref().map(|correction| {
                (
                    correction.proof_witness_fingerprint.clone(),
                    correction.owed_member_ids.clone(),
                )
            }),
            bound_to_retained_witness: self
                .claude_usage_family_witnesses
                .get(root_session_id)
                .is_some_and(|witness| claude_usage_authority_preserves_pending(record, witness)),
        })
    }

    #[cfg(test)]
    fn insert_claude_authority_for_test(
        &mut self,
        root_session_id: &str,
        revision: &str,
        disposition: ClaudeUsageAuthorityQuarantineDisposition,
    ) {
        let witness = ClaudeUsageFamilyWitness {
            evidence_fingerprint: "e".repeat(64),
            member_request_id_fingerprints: BTreeMap::from([(
                root_session_id.to_string(),
                "f".repeat(64),
            )]),
            member_occurrence_fingerprints: BTreeMap::new(),
            assigned_request_id_fingerprints: BTreeMap::new(),
            legacy_excluded_request_id_hashes: BTreeMap::new(),
            legacy_exclusion_evidence_fingerprint: None,
            legacy_owner_roots: BTreeSet::new(),
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let failed_reconstruction_count = match disposition {
            ClaudeUsageAuthorityQuarantineDisposition::RetryPending => 1,
            ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => {
                MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
            }
        };
        let record = ClaudeUsageAuthorityQuarantineRecord {
            proof_correction: None,
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
            member_source_file_fingerprints: BTreeMap::from([(
                root_session_id.to_string(),
                revision.to_string(),
            )]),
            failed_reconstruction_count,
            disposition,
            retry_after_unix_seconds: now.saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS),
        };
        assert!(claude_usage_authority_preserves_pending(&record, &witness));
        self.claude_usage_family_witnesses
            .insert(root_session_id.to_string(), witness);
        self.claude_usage_authority_quarantine
            .insert(root_session_id.to_string(), record);
    }
}
