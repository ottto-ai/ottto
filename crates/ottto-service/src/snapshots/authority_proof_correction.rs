#[derive(Debug)]
struct ClaudeEmptyMapAdvance {
    root: String,
    member: String,
    key: String,
    revision: String,
    previous: Option<String>,
}

#[derive(Debug)]
struct ClaudeProofBodyDrain {
    root: String,
    member: String,
    key: String,
    proof: String,
    revision: String,
    fingerprints: BTreeSet<String>,
    previous: Option<String>,
}

/// Exact-ACK and proven no-op drains settled on the working index before save
/// selection, with each drained family's pre-drain record and pending proof.
/// Not persisted.
#[derive(Debug, Default)]
pub(crate) struct ClaudeProofBodyDrains {
    drains: Vec<ClaudeProofBodyDrain>,
    families: BTreeMap<
        String,
        (
            ClaudeUsageAuthorityQuarantineRecord,
            Option<ClaudeUsageFamilyPending>,
        ),
    >,
}

impl ClaudeProofBodyDrains {
    /// Adds a later settlement's drains. A family keeps its earliest
    /// pre-drain record and pending proof.
    pub(crate) fn append(&mut self, later: Self) {
        self.drains.extend(later.drains);
        for (root, family) in later.families {
            self.families.entry(root).or_insert(family);
        }
    }
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

#[derive(Debug)]
pub(crate) struct ClaudeCutoffCorrectionCandidate {
    index_key: String,
    root: String,
    member: String,
    proof: String,
    revision: String,
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

/// Content-free counts of unbound Claude authority records dropped on load or
/// save, of the indexed family members re-armed with them, and of demotions
/// that found no current witness and so formed no record (SOURCE U3).
static CLAUDE_AUTHORITY_DROPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static CLAUDE_AUTHORITY_DROP_REARMED_FILES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static CLAUDE_AUTHORITY_UNWITNESSED_DEMOTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const CLAUDE_AUTHORITY_DROP_LOGGED_REFS: usize = 4;

#[cfg(test)]
thread_local! {
    static CLAUDE_AUTHORITY_DROPS_FOR_TEST: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
    static CLAUDE_AUTHORITY_UNWITNESSED_DEMOTIONS_FOR_TEST: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// This thread's dropped records and re-armed files.
#[cfg(test)]
pub(crate) fn claude_authority_drops_for_test() -> (usize, usize) {
    CLAUDE_AUTHORITY_DROPS_FOR_TEST.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn claude_authority_unwitnessed_demotions_for_test() -> usize {
    CLAUDE_AUTHORITY_UNWITNESSED_DEMOTIONS_FOR_TEST.with(std::cell::Cell::get)
}

fn count_claude_authority_unwitnessed_demotion() {
    CLAUDE_AUTHORITY_UNWITNESSED_DEMOTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    CLAUDE_AUTHORITY_UNWITNESSED_DEMOTIONS_FOR_TEST.with(|cell| cell.set(cell.get() + 1));
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

    // RetryPending members were held, never uploaded under the old proof.
    // Reproof changes only their binding; no correction grant or retry reset.
    fn rebind_retry_pending_claude_authority(&mut self, root: &str) {
        let Some(witness) = self.claude_usage_family_witnesses.get(root) else {
            return;
        };
        let Some(record) = self.claude_usage_authority_quarantine.get_mut(root) else {
            return;
        };
        if record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
            && claude_usage_authority_deadline_is_bounded(record)
        {
            record.proven_witness_fingerprint = claude_usage_family_witness_fingerprint(witness);
        }
    }

    // SOURCE ruling: an unbound or ill-formed record fails closed alone, on
    // load and on save, with its pending proof state. Terminal refusals and
    // the upload ledger stay. Its indexed members are re-armed, bounded by
    // family size, so the next pass re-reads the family and re-forms the
    // record against the current witness, or leaves unproven residue.
    fn drop_unbound_claude_authority_records(&mut self, stage: &str) {
        let witnesses = &self.claude_usage_family_witnesses;
        let unbound = self
            .claude_usage_authority_quarantine
            .iter()
            .filter(|(root, record)| {
                !self.decode_holds_family(root)
                    && !witnesses.get(*root).is_some_and(|witness| {
                        claude_usage_authority_preserves_pending(record, witness)
                    })
            })
            .map(|(root, _)| root.clone())
            .collect::<BTreeSet<_>>();
        if unbound.is_empty() {
            return;
        }
        for root in &unbound {
            self.claude_usage_authority_quarantine.remove(root);
            self.claude_usage_family_pending.remove(root);
        }
        let mut rearmed = 0_usize;
        for (index_key, entry) in &mut self.files {
            if claude_index_path_member_ref(Path::new(index_key))
                .is_some_and(|member| unbound.contains(member.root))
                && !entry.source_file_fingerprint.is_empty()
            {
                entry.source_file_fingerprint.clear();
                rearmed += 1;
            }
        }
        // A pure CAS reread discards this normalized graph. Only the load or
        // working save applies a rearm, so do not count that same action twice.
        if stage == "cas" {
            return;
        }
        crate::local_resource_diagnostics::claude_reread::authority_normalization(rearmed as u64);
        CLAUDE_AUTHORITY_DROPS.fetch_add(unbound.len(), std::sync::atomic::Ordering::Relaxed);
        CLAUDE_AUTHORITY_DROP_REARMED_FILES
            .fetch_add(rearmed, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        CLAUDE_AUTHORITY_DROPS_FOR_TEST.with(|cell| {
            let (drops, files) = cell.get();
            cell.set((drops + unbound.len(), files + rearmed));
        });
        let family_refs = unbound
            .iter()
            .take(CLAUDE_AUTHORITY_DROP_LOGGED_REFS)
            .map(|root| {
                sha256_hex(&["claude_authority_drop_family_ref:v1", root.as_str()])[..12]
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join(",");
        eprintln!(
            "local snapshot scan index {stage} dropped {} unbound Claude usage authority record(s) \
             [family_ref_sha256 {family_refs}{}]; authority_drop_rearmed_files={rearmed}; those \
             families re-prove or stay unproven residue on the next pass",
            unbound.len(),
            if unbound.len() > CLAUDE_AUTHORITY_DROP_LOGGED_REFS {
                ",..."
            } else {
                ""
            }
        );
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
            if entry.observed_fingerprint() != pending.source_file_fingerprint
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
                entry.observed_fingerprint() == *revision
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
                    entry.observed_fingerprint() == advance.revision
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
                    if record.proof_correction.as_ref().is_some_and(|correction| {
                        correction.owed_member_ids.contains(&advance.member)
                    }) {
                        // No prior pair exists to restore. Preserve the debt
                        // with a domain-separated nonmatching revision: the
                        // reverted empty facts cannot certify completion.
                        record.member_source_file_fingerprints.insert(
                            advance.member,
                            sha256_hex(&[
                                "claude_empty_map_restore_missing_previous:v1",
                                &advance.revision,
                            ]),
                        );
                    } else {
                        record
                            .member_source_file_fingerprints
                            .remove(&advance.member);
                    }
                }
            }
        }
    }

    // R2, the body-drain analogue of the A2 restore above: a drain certifies
    // only the revision and entity set the selected save keeps. Any other
    // selected entry leaves the member owed under the same proof with its
    // pre-drain pair. A record its last drain removed is re-bound with its
    // pending proof. Returns whether any member owes again.
    pub(crate) fn restore_unselected_claude_proof_body_drains(
        &mut self,
        drains: ClaudeProofBodyDrains,
    ) -> bool {
        let ClaudeProofBodyDrains {
            drains,
            mut families,
        } = drains;
        let (carried, reverted): (Vec<_>, Vec<_>) = drains.into_iter().partition(|drain| {
            self.files
                .get(&drain.key)
                .is_some_and(|entry| entry.observed_fingerprint() == drain.revision)
                && self.file_snapshot_fingerprints.get(&drain.key) == Some(&drain.fingerprints)
        });
        for drain in &reverted {
            if self
                .claude_usage_authority_quarantine
                .contains_key(&drain.root)
            {
                continue;
            }
            let Some((mut record, pending)) = families.remove(&drain.root) else {
                continue;
            };
            if !self
                .claude_usage_family_witnesses
                .get(&drain.root)
                .is_some_and(|witness| claude_usage_authority_preserves_pending(&record, witness))
            {
                continue;
            }
            let Some(correction) = record
                .proof_correction
                .as_mut()
                .filter(|correction| correction.proof_witness_fingerprint == drain.proof)
            else {
                continue;
            };
            // Every member still owed when the record was removed has drained
            // on this page; only reverted ones owe again, added below.
            correction.owed_member_ids.clear();
            for kept in carried.iter().filter(|kept| kept.root == drain.root) {
                record
                    .member_source_file_fingerprints
                    .insert(kept.member.clone(), kept.revision.clone());
            }
            self.claude_usage_authority_quarantine
                .insert(drain.root.clone(), record);
            if let Some(pending) = pending {
                self.claude_usage_family_pending
                    .entry(drain.root.clone())
                    .or_insert(pending);
            }
        }
        let mut owed_again = false;
        for drain in reverted {
            let Some(record) = self.claude_usage_authority_quarantine.get_mut(&drain.root) else {
                continue;
            };
            let Some(correction) = record.proof_correction.as_mut() else {
                continue;
            };
            if correction.proof_witness_fingerprint != drain.proof
                || !correction.owed_member_ids.insert(drain.member.clone())
            {
                continue;
            }
            owed_again = true;
            let previous = drain.previous.unwrap_or_else(|| {
                // A valid record pairs every owed member; keep the debt with a
                // domain-separated nonmatching revision, as A2 does.
                sha256_hex(&[
                    "claude_proof_body_drain_restore_missing_previous:v1",
                    &drain.revision,
                ])
            });
            record
                .member_source_file_fingerprints
                .insert(drain.member, previous);
        }
        owed_again
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
                    && !entry.rearmed()
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
                || entry.rearmed()
                || self
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|fingerprints| !fingerprints.is_empty())
                || entry.last_snapshot_fingerprint.is_some()
                || result.pending_finalization.iter().any(|pending| {
                    pending.index_key == *key
                        && (!pending.parse_complete
                            || pending.parsed_snapshot_count != 0
                            || pending.source_file_fingerprint != entry.observed_fingerprint())
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
            // E2 (gate on): an owed member's request-owned literal settles
            // its correction on the same exact ACK as a reported body.
            let settles = snapshot.usage_accounting_contract.as_deref()
                == Some("session_exclusive_reported_usage:v1")
                || claude_history_upgrade::is_request_owned_literal(snapshot);
            if !settles
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

    // Capture before the cutoff alone removes snapshots. Every item produced
    // by the completed parse must still be present, reported and unheld.
    pub(crate) fn capture_claude_cutoff_corrections(
        &self,
        result: &SourceScanResult,
        disposition: &ClaudeUsageAuthorityDisposition,
    ) -> Vec<ClaudeCutoffCorrectionCandidate> {
        if !self.claude_authority_proof_correction_pending() {
            return Vec::new();
        }
        let mut candidates = Vec::new();
        for pending in &result.pending_finalization {
            if !pending.parse_complete || pending.parsed_snapshot_count == 0 {
                continue;
            }
            let Some((root, member)) =
                claude_index_path_family_member(Path::new(&pending.index_key))
            else {
                continue;
            };
            let Some(record) = self.claude_usage_authority_quarantine.get(&root) else {
                continue;
            };
            let Some(correction) = &record.proof_correction else {
                continue;
            };
            if !correction.owed_member_ids.contains(&member)
                || !self
                    .claude_usage_family_witnesses
                    .get(&root)
                    .is_some_and(|witness| {
                        claude_usage_authority_preserves_pending(record, witness)
                    })
            {
                continue;
            }
            let mut items = result.snapshots.iter().filter(|snapshot| {
                snapshot.source_file_fingerprint.as_deref()
                    == Some(pending.source_file_fingerprint.as_str())
            });
            if items.clone().count() != pending.parsed_snapshot_count
                || !items.all(|snapshot| {
                    snapshot.source_session_id == member
                        && claude_snapshot_family_root(snapshot) == root
                        && snapshot.usage_accounting_contract.as_deref()
                            == Some("session_exclusive_reported_usage:v1")
                        && !disposition.quarantined_source_session_ids.contains(&member)
                })
            {
                continue;
            }
            candidates.push(ClaudeCutoffCorrectionCandidate {
                index_key: pending.index_key.clone(),
                root,
                member,
                proof: correction.proof_witness_fingerprint.clone(),
                revision: pending.source_file_fingerprint.clone(),
            });
        }
        candidates
    }

    pub(crate) fn retain_fully_cutoff_corrections(
        candidates: &mut Vec<ClaudeCutoffCorrectionCandidate>,
        remaining: &[SnapshotItem],
    ) {
        candidates.retain(|candidate| {
            !remaining.iter().any(|snapshot| {
                snapshot.source_file_fingerprint.as_deref() == Some(candidate.revision.as_str())
            })
        });
    }

    // D2: apply only after final file selection. Restoring a prior entity or
    // revision invalidates the current-page no-body evidence and keeps debt.
    pub(crate) fn settle_cutoff_claude_proof_corrections(
        &mut self,
        candidates: &[ClaudeCutoffCorrectionCandidate],
    ) {
        for candidate in candidates {
            let Some(record) = self.claude_usage_authority_quarantine.get(&candidate.root) else {
                continue;
            };
            if !record.proof_correction.as_ref().is_some_and(|correction| {
                correction.proof_witness_fingerprint == candidate.proof
                    && correction.owed_member_ids.contains(&candidate.member)
            }) || !self
                .claude_usage_family_witnesses
                .get(&candidate.root)
                .is_some_and(|witness| claude_usage_authority_preserves_pending(record, witness))
                || !self.files.get(&candidate.index_key).is_some_and(|entry| {
                    entry.observed_fingerprint() == candidate.revision
                        && entry.last_snapshot_fingerprint.is_none()
                })
                || !self.confirmed_empty_files.contains(&candidate.index_key)
                || self
                    .file_snapshot_fingerprints
                    .get(&candidate.index_key)
                    .is_some_and(|items| !items.is_empty())
            {
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
            eprintln!("local snapshot sync: claude proof correction reason=backfill_cutoff drained_members=1");
        }
    }

    /// Called only at an index settlement boundary. A following save either
    /// commits both exact body state and owed progress, or commits neither.
    /// Pass the returned drains to `restore_unselected_claude_proof_body_drains`
    /// after the last selection and the account-audit release.
    pub(crate) fn settle_claude_proof_corrections(
        &mut self,
        previous: &ScanIndex,
        candidates: &[ClaudeProofCorrectionCandidate],
        accepted: &BTreeSet<String>,
        accepted_bodies: &BTreeMap<String, String>,
    ) -> ClaudeProofBodyDrains {
        self.settle_claude_proof_corrections_with_permanent(
            previous,
            candidates,
            accepted,
            accepted_bodies,
            |_, _| false,
        )
    }

    pub(crate) fn settle_claude_proof_corrections_with_permanent(
        &mut self,
        previous: &ScanIndex,
        candidates: &[ClaudeProofCorrectionCandidate],
        accepted: &BTreeSet<String>,
        accepted_bodies: &BTreeMap<String, String>,
        permanent: impl Fn(&str, &str) -> bool,
    ) -> ClaudeProofBodyDrains {
        let mut drains = ClaudeProofBodyDrains::default();
        if !self.claude_authority_proof_correction_pending() {
            return drains;
        }
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
                    .is_some_and(|entry| entry.observed_fingerprint() == candidate.revision)
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
            let body_set = snapshot_file_upload_body_set_hex(bodies);
            if self
                .files
                .get(key)
                .and_then(|entry| entry.last_upload_body_witness.as_deref())
                != Some(body_set.as_str())
            {
                continue;
            }
            let rejected = |item: &ClaudeProofCorrectionCandidate| {
                permanent(&item.fingerprint, &item.body_witness)
                    && self
                        .quarantined_snapshot_fingerprints
                        .get(&item.fingerprint)
                        .is_some_and(|record| {
                            record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
                                && record.upload_body_witness.as_ref() == Some(&item.body_witness)
                        })
            };
            let acked_or_rejected = group.iter().all(|item| {
                (accepted.contains(&item.fingerprint)
                    && accepted_bodies.get(&item.fingerprint) == Some(&item.body_witness))
                    || rejected(item)
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
            if !acked_or_rejected && !noop {
                continue;
            }
            for item in group.iter().filter(|item| rejected(item)) {
                eprintln!("local snapshot sync: claude proof correction reason=permanent_rejection drained_members=1 body_witness={}", item.body_witness);
            }
            drains
                .families
                .entry(candidate.root.clone())
                .or_insert_with(|| {
                    (
                        record.clone(),
                        self.claude_usage_family_pending
                            .get(&candidate.root)
                            .cloned(),
                    )
                });
            let record = self
                .claude_usage_authority_quarantine
                .get_mut(&candidate.root)
                .unwrap();
            let previous = record
                .member_source_file_fingerprints
                .insert(candidate.member.clone(), candidate.revision.clone());
            let correction = record.proof_correction.as_mut().unwrap();
            correction.owed_member_ids.remove(&candidate.member);
            if correction.owed_member_ids.is_empty() {
                self.claude_usage_authority_quarantine
                    .remove(&candidate.root);
                self.claude_usage_family_pending.remove(&candidate.root);
            }
            drains.drains.push(ClaudeProofBodyDrain {
                root: candidate.root.clone(),
                member: candidate.member.clone(),
                key: key.to_string(),
                proof: candidate.proof.clone(),
                revision: candidate.revision.clone(),
                fingerprints,
                previous,
            });
        }
        drains
    }
}
