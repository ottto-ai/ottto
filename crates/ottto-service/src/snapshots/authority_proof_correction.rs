#[derive(Debug)]
struct ClaudeEmptyMapAdvance {
    root: String,
    member: String,
    key: String,
    revision: String,
    previous: Option<String>,
}

// A positive-proof correction is local checkpoint bookkeeping. It never
// authorizes collection, ownership, or acceptance of an unacknowledged body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClaudeAuthorityProofCorrection {
    proof_witness_fingerprint: String,
    owed_member_ids: BTreeSet<String>,
}

// Page-scoped evidence captured after policy/account filtering, before no-op
// suppression. This is not persisted and contains no new provider evidence.
#[derive(Debug, Clone)]
pub(crate) struct ClaudeProofCorrectionCandidate {
    index_key: String,
    root: String,
    member: String,
    proof: String,
    revision: String,
    fingerprint: String,
    body_witness: String,
}

#[cfg(test)]
impl ClaudeProofCorrectionCandidate {
    pub(crate) fn member_for_test(&self) -> &str {
        &self.member
    }

    pub(crate) fn revision_for_test(&self) -> &str {
        &self.revision
    }
}

fn claude_authority_record_contract_is_valid(
    record: &ClaudeUsageAuthorityQuarantineRecord,
) -> bool {
    match (&record.proof_correction, record.contract.as_str()) {
        (None, CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION) => true,
        (Some(correction), CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION) => {
            record.disposition == ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
                && correction.proof_witness_fingerprint == record.proven_witness_fingerprint
                && !correction.owed_member_ids.is_empty()
                && correction
                    .owed_member_ids
                    .iter()
                    .all(|member| record.member_source_file_fingerprints.contains_key(member))
        }
        _ => false,
    }
}

impl ScanIndex {
    pub(crate) fn claude_authority_proof_correction_pending(&self) -> bool {
        self.claude_usage_authority_quarantine
            .values()
            .any(|record| record.proof_correction.is_some())
    }

    fn rebind_claude_authority_proof(&mut self, root: &str, new: &ClaudeUsageFamilyWitness) {
        let Some(old) = self.claude_usage_family_witnesses.get(root) else {
            return;
        };
        let Some(record) = self.claude_usage_authority_quarantine.get(root) else {
            return;
        };
        let proof = claude_usage_family_witness_fingerprint(new);
        if record.disposition != ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal
            || !claude_usage_authority_preserves_pending(record, old)
            || proof == record.proven_witness_fingerprint
        {
            return;
        }
        // Conservative R5 fallback: a changed provider proof can alter a body
        // without changing transcript bytes. Until body equivalence is proved,
        // every member owes a correction under each genuinely new proof.
        let record = self
            .claude_usage_authority_quarantine
            .get_mut(root)
            .unwrap();
        record.contract = CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_string();
        record.proven_witness_fingerprint = proof.clone();
        record.proof_correction = Some(ClaudeAuthorityProofCorrection {
            proof_witness_fingerprint: proof,
            owed_member_ids: record
                .member_source_file_fingerprints
                .keys()
                .cloned()
                .collect(),
        });
    }

    // M1: only the existing complete healthy census can retire absent grants.
    fn retire_absent_claude_proof_corrections(
        &mut self,
        complete: &BTreeMap<String, BTreeSet<String>>,
    ) {
        let mut resolved = Vec::new();
        for (root, record) in &mut self.claude_usage_authority_quarantine {
            let Some(correction) = &mut record.proof_correction else {
                continue;
            };
            let Some(members) = complete.get(root) else {
                resolved.push(root.clone());
                continue;
            };
            if !record
                .member_source_file_fingerprints
                .keys()
                .any(|member| members.contains(member))
            {
                // Only whole-family authoritative absence may clear an empty
                // map. Keep malformed partial-family bookkeeping fail-closed.
                eprintln!("local snapshot sync: claude proof correction reason=member_map_absence_mismatch owed_members={}", correction.owed_member_ids.len());
                continue;
            }
            correction
                .owed_member_ids
                .retain(|member| members.contains(member));
            record
                .member_source_file_fingerprints
                .retain(|member, _| members.contains(member));
            if correction.owed_member_ids.is_empty() {
                resolved.push(root.clone());
            }
        }
        for root in resolved {
            self.claude_usage_authority_quarantine.remove(&root);
            self.claude_usage_family_pending.remove(&root);
        }
    }

    // A1: exact completed zero-entity parse advances only its revision pairing.
    // The owed set and all acceptance/debt fields are unchanged.
    pub(crate) fn advance_empty_claude_proof_corrections(&mut self, result: &SourceScanResult) {
        if !self.claude_authority_proof_correction_pending() {
            return;
        }
        for pending in &result.pending_finalization {
            if !pending.parse_complete
                || pending.parsed_snapshot_count != 0
                || !self.confirmed_empty_files.contains(&pending.index_key)
            {
                continue;
            }
            let Some(entry) = self.files.get(&pending.index_key) else {
                continue;
            };
            if entry.source_file_fingerprint != pending.source_file_fingerprint
                || entry.last_snapshot_fingerprint.is_some()
                || self
                    .file_snapshot_fingerprints
                    .get(&pending.index_key)
                    .is_some_and(|fingerprints| !fingerprints.is_empty())
            {
                continue;
            }
            let Some((root, member)) =
                claude_index_path_family_member(Path::new(&pending.index_key))
            else {
                continue;
            };
            let Some(record) = self.claude_usage_authority_quarantine.get_mut(&root) else {
                continue;
            };
            if record
                .proof_correction
                .as_ref()
                .is_some_and(|correction| correction.owed_member_ids.contains(&member))
            {
                record
                    .member_source_file_fingerprints
                    .insert(member, pending.source_file_fingerprint.clone());
            }
        }
    }

    // Capture only changed no-body pairs, not an index clone. Used by every
    // restoration seam so a carried map revision cannot certify reverted facts.
    fn claude_empty_map_advances(&self, previous: &ScanIndex) -> Vec<ClaudeEmptyMapAdvance> {
        if !self.claude_authority_proof_correction_pending() {
            return Vec::new();
        }
        let mut advances = Vec::new();
        for key in &self.confirmed_empty_files {
            let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            let Some(record) = self.claude_usage_authority_quarantine.get(&root) else {
                continue;
            };
            if record.proof_correction.is_none() {
                continue;
            }
            let Some(revision) = record.member_source_file_fingerprints.get(&member) else {
                continue;
            };
            if !self.files.get(key).is_some_and(|entry| {
                entry.source_file_fingerprint == *revision
                    && entry.last_snapshot_fingerprint.is_none()
            }) || self
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|fps| !fps.is_empty())
            {
                continue;
            }
            let old = previous
                .claude_usage_authority_quarantine
                .get(&root)
                .and_then(|record| record.member_source_file_fingerprints.get(&member));
            if old == Some(revision) {
                continue;
            }
            advances.push(ClaudeEmptyMapAdvance {
                root,
                member,
                key: key.clone(),
                revision: revision.clone(),
                previous: old.cloned(),
            });
        }
        advances
    }

    fn restore_claude_empty_map_advances(&mut self, advances: Vec<ClaudeEmptyMapAdvance>) {
        for advance in advances {
            let carried = self.confirmed_empty_files.contains(&advance.key)
                && self.files.get(&advance.key).is_some_and(|entry| {
                    entry.source_file_fingerprint == advance.revision
                        && entry.last_snapshot_fingerprint.is_none()
                })
                && !self
                    .file_snapshot_fingerprints
                    .get(&advance.key)
                    .is_some_and(|fps| !fps.is_empty());
            if carried {
                continue;
            }
            let Some(record) = self
                .claude_usage_authority_quarantine
                .get_mut(&advance.root)
            else {
                continue;
            };
            match advance.previous {
                Some(previous) => {
                    record
                        .member_source_file_fingerprints
                        .insert(advance.member, previous);
                }
                None => {
                    record
                        .member_source_file_fingerprints
                        .remove(&advance.member);
                }
            }
        }
    }

    // Earlier-page A1 pairs must drain before the generic proof re-arm clears
    // source fingerprints. This is local no-body completion, not entity deletion.
    fn settle_known_empty_claude_proof_corrections(
        &mut self,
        current_files: &BTreeSet<String>,
        snapshots: &[SnapshotItem],
    ) {
        if !self.claude_authority_proof_correction_pending() {
            return;
        }
        let pairs = self
            .confirmed_empty_files
            .iter()
            .filter_map(|key| {
                let (root, member) = claude_index_path_family_member(Path::new(key))?;
                if current_files.contains(key)
                    || snapshots.iter().any(|snapshot| {
                        snapshot.source_session_id == member
                            && claude_snapshot_family_root(snapshot) == root
                    })
                {
                    return None;
                }
                let record = self.claude_usage_authority_quarantine.get(&root)?;
                let correction = record.proof_correction.as_ref()?;
                let entry = self.files.get(key)?;
                (correction.owed_member_ids.contains(&member)
                    && !entry.source_file_fingerprint.is_empty()
                    && record.member_source_file_fingerprints.get(&member)
                        == Some(&entry.source_file_fingerprint)
                    && entry.last_snapshot_fingerprint.is_none()
                    && !self
                        .file_snapshot_fingerprints
                        .get(key)
                        .is_some_and(|fps| !fps.is_empty()))
                .then_some((root, member))
            })
            .collect::<Vec<_>>();
        for (root, member) in pairs {
            let record = self
                .claude_usage_authority_quarantine
                .get_mut(&root)
                .unwrap();
            record
                .proof_correction
                .as_mut()
                .unwrap()
                .owed_member_ids
                .remove(&member);
            if record
                .proof_correction
                .as_ref()
                .unwrap()
                .owed_member_ids
                .is_empty()
            {
                self.claude_usage_authority_quarantine.remove(&root);
                self.claude_usage_family_pending.remove(&root);
            }
        }
    }

    // M2 drains only local authority correction bookkeeping, never old entity
    // or manifest debt. Partial checkpoint keeps its existing prior-entity rule.
    pub(crate) fn settle_empty_claude_proof_corrections(&mut self, result: &SourceScanResult) {
        if !result.census_complete || !self.claude_authority_proof_correction_pending() {
            return;
        }
        let mut empty = Vec::new();
        for key in &self.confirmed_empty_files {
            let Some((root, member)) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            let Some(record) = self.claude_usage_authority_quarantine.get(&root) else {
                continue;
            };
            if !record
                .proof_correction
                .as_ref()
                .is_some_and(|correction| correction.owed_member_ids.contains(&member))
            {
                continue;
            }
            let Some(entry) = self.files.get(key) else {
                continue;
            };
            let known_current = record.member_source_file_fingerprints.get(&member)
                == Some(&entry.source_file_fingerprint);
            if !known_current
                || entry.source_file_fingerprint.is_empty()
                || self
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|fingerprints| !fingerprints.is_empty())
                || entry.last_snapshot_fingerprint.is_some()
                || result.pending_finalization.iter().any(|pending| {
                    pending.index_key == *key
                        && (!pending.parse_complete
                            || pending.source_file_fingerprint != entry.source_file_fingerprint)
                })
            {
                continue;
            }
            empty.push((root, member, entry.source_file_fingerprint.clone()));
        }
        for (root, member, revision) in empty {
            let record = self
                .claude_usage_authority_quarantine
                .get_mut(&root)
                .unwrap();
            record
                .member_source_file_fingerprints
                .insert(member.clone(), revision);
            let correction = record.proof_correction.as_mut().unwrap();
            correction.owed_member_ids.remove(&member);
            if correction.owed_member_ids.is_empty() {
                self.claude_usage_authority_quarantine.remove(&root);
                self.claude_usage_family_pending.remove(&root);
            }
        }
    }

    pub(crate) fn log_claude_proof_correction_debt(&self) {
        for record in self.claude_usage_authority_quarantine.values() {
            if let Some(correction) = &record.proof_correction {
                eprintln!("local snapshot sync: claude proof correction reason=awaiting_exact_settlement owed_members={}", correction.owed_member_ids.len());
            }
        }
    }

    pub(crate) fn capture_claude_proof_corrections(
        &self,
        result: &mut SourceScanResult,
        disposition: &ClaudeUsageAuthorityDisposition,
        body_witness: impl Fn(&SnapshotItem) -> String,
    ) -> Vec<ClaudeProofCorrectionCandidate> {
        if !self
            .claude_usage_authority_quarantine
            .values()
            .any(|record| record.proof_correction.is_some())
        {
            return Vec::new();
        }
        let keys = result
            .pending_finalization
            .iter()
            .filter(|pending| pending.parse_complete)
            .filter_map(|pending| {
                let (_, member) = claude_index_path_family_member(Path::new(&pending.index_key))?;
                Some((
                    (pending.source_file_fingerprint.as_str(), member),
                    pending.index_key.as_str(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let mut candidates = Vec::new();
        for snapshot in &mut result.snapshots {
            if snapshot.usage_accounting_contract.as_deref()
                != Some("session_exclusive_reported_usage:v1")
                || disposition
                    .quarantined_source_session_ids
                    .contains(&snapshot.source_session_id)
            {
                continue;
            }
            let root = claude_snapshot_family_root(snapshot);
            let Some(record) = self.claude_usage_authority_quarantine.get(&root) else {
                continue;
            };
            let Some(correction) = &record.proof_correction else {
                continue;
            };
            if !correction
                .owed_member_ids
                .contains(&snapshot.source_session_id)
            {
                continue;
            }
            let Some(witness) = self.claude_usage_family_witnesses.get(&root) else {
                continue;
            };
            if !claude_usage_authority_preserves_pending(record, witness) {
                continue;
            }
            let Some(revision) = snapshot.source_file_fingerprint.as_deref() else {
                continue;
            };
            let Some(key) = keys.get(&(revision, snapshot.source_session_id.clone())) else {
                continue;
            };
            // The finalizer performs this exact recomputation before body hashing.
            snapshot.snapshot_fingerprint =
                snapshot_fingerprint(SnapshotSource::ClaudeCode, snapshot);
            candidates.push(ClaudeProofCorrectionCandidate {
                index_key: (*key).to_string(),
                root,
                member: snapshot.source_session_id.clone(),
                proof: correction.proof_witness_fingerprint.clone(),
                revision: revision.to_string(),
                fingerprint: snapshot.snapshot_fingerprint.clone(),
                body_witness: body_witness(snapshot),
            });
        }
        candidates
    }

    /// Called only at an index settlement boundary. A following save either
    /// commits both exact body state and owed progress, or commits neither.
    pub(crate) fn settle_claude_proof_corrections(
        &mut self,
        previous: &ScanIndex,
        candidates: &[ClaudeProofCorrectionCandidate],
        accepted: &BTreeSet<String>,
        accepted_bodies: &BTreeMap<String, String>,
    ) {
        let mut by_file = BTreeMap::<&str, Vec<&ClaudeProofCorrectionCandidate>>::new();
        for candidate in candidates {
            by_file
                .entry(&candidate.index_key)
                .or_default()
                .push(candidate);
        }
        for (key, group) in by_file {
            let candidate = group[0];
            let Some(record) = self.claude_usage_authority_quarantine.get(&candidate.root) else {
                continue;
            };
            let Some(correction) = &record.proof_correction else {
                continue;
            };
            if correction.proof_witness_fingerprint != candidate.proof
                || !correction.owed_member_ids.contains(&candidate.member)
                || !self
                    .claude_usage_family_witnesses
                    .get(&candidate.root)
                    .is_some_and(|witness| {
                        claude_usage_authority_preserves_pending(record, witness)
                    })
                || group.iter().any(|item| {
                    item.member != candidate.member
                        || item.root != candidate.root
                        || item.proof != candidate.proof
                        || item.revision != candidate.revision
                })
                || !self
                    .files
                    .get(key)
                    .is_some_and(|entry| entry.source_file_fingerprint == candidate.revision)
            {
                continue;
            }
            let fingerprints = group
                .iter()
                .map(|item| item.fingerprint.clone())
                .collect::<BTreeSet<_>>();
            if self.file_snapshot_fingerprints.get(key) != Some(&fingerprints) {
                continue;
            }
            let bodies = group
                .iter()
                .map(|item| item.body_witness.as_str())
                .collect::<BTreeSet<_>>();
            let mut digest = Sha256::new();
            update_length_prefixed(&mut digest, b"snapshot_file_upload_body_set:v1");
            for body in &bodies {
                update_length_prefixed(&mut digest, body.as_bytes());
            }
            let body_set = format!("{:x}", digest.finalize());
            if self
                .files
                .get(key)
                .and_then(|entry| entry.last_upload_body_witness.as_deref())
                != Some(body_set.as_str())
            {
                continue;
            }
            let acked = group.iter().all(|item| {
                accepted.contains(&item.fingerprint)
                    && accepted_bodies.get(&item.fingerprint) == Some(&item.body_witness)
            });
            let noop = previous.accepted_snapshot_fingerprint_ledger_version
                == SNAPSHOT_ACCEPTED_LEDGER_VERSION
                && previous.file_snapshot_fingerprints.get(key) == Some(&fingerprints)
                && previous
                    .files
                    .get(key)
                    .and_then(|entry| entry.last_upload_body_witness.as_deref())
                    == Some(body_set.as_str())
                && fingerprints.iter().all(|fp| {
                    previous.accepted_snapshot_fingerprints.contains(fp)
                        && !previous.quarantined_snapshot_fingerprints.contains_key(fp)
                });
            if !acked && !noop {
                continue;
            }
            let record = self
                .claude_usage_authority_quarantine
                .get_mut(&candidate.root)
                .unwrap();
            record
                .member_source_file_fingerprints
                .insert(candidate.member.clone(), candidate.revision.clone());
            let correction = record.proof_correction.as_mut().unwrap();
            correction.owed_member_ids.remove(&candidate.member);
            if correction.owed_member_ids.is_empty() {
                self.claude_usage_authority_quarantine
                    .remove(&candidate.root);
                self.claude_usage_family_pending.remove(&candidate.root);
            }
        }
    }
}
