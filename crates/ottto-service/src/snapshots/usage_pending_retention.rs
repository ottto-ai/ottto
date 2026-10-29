//! Selected-checkpoint eligibility, never census or acceptance credit.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Refusal {
    Scratch,
    Invalid,
    DecodeHold,
    Quarantine,
    IdentityOrContext,
    Membership,
    HeldMember,
    DuplicateOwner,
    HistoryOrReplay,
    AuditOrCorrection,
    Unaccepted,
    UsageProof,
    ReceiptB1,
    RetryCarryB3,
}

pub(super) enum Settlement<'a> {
    Settled(&'a ClaudeUsageFamilyWitness),
    Refused(Refusal),
}

#[derive(Clone, Copy)]
struct MemberFile<'a> {
    key: &'a str,
    entry: &'a ScanIndexEntry,
    duplicate: bool,
    history_hold: bool,
}
type Members<'a> = BTreeMap<ClaudeIndexPathMemberRef<'a>, MemberFile<'a>>;
type Inventory<'a> = BTreeMap<&'a str, Members<'a>>;

// One borrowed node per indexed file, plus at most one node per file's root.
// Refuse before allocation if the optional diagnostic scratch is not bounded.
fn inventory(index: &ScanIndex) -> Option<Inventory<'_>> {
    use crate::heap_layout_bound::{tree_nodes, Counter};
    if !crate::heap_layout_bound::layout_supported() {
        return None;
    }
    let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
    tree_nodes::<&str, Members<'_>>(index.files.len(), &mut cost)?;
    tree_nodes::<ClaudeIndexPathMemberRef<'_>, MemberFile<'_>>(index.files.len(), &mut cost)?;
    let mut inventory: Inventory<'_> = BTreeMap::new();
    for (key, entry) in &index.files {
        let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
            continue;
        };
        if !index.claude_usage_family_pending.contains_key(member.root) {
            continue;
        }
        inventory
            .entry(member.root)
            .or_default()
            .entry(member)
            .and_modify(|file| file.duplicate = true)
            .or_insert(MemberFile {
                key,
                entry,
                duplicate: false,
                history_hold: false,
            });
    }
    for held in index
        .claude_history_emission
        .files
        .values()
        .filter(|held| held.held.is_some() || held.literal_denied)
    {
        if let Some(member) = claude_index_path_member_ref(Path::new(&held.index_key)) {
            if let Some(file) = inventory
                .get_mut(member.root)
                .and_then(|files| files.get_mut(&member))
            {
                file.history_hold = true;
            }
        }
    }
    Some(inventory)
}

fn known_refusal(
    index: &ScanIndex,
    root: &str,
    pending: &ClaudeUsageFamilyPending,
    files: Option<&Members<'_>>,
) -> Option<Refusal> {
    if pending.invalid {
        return Some(Refusal::Invalid);
    }
    if index.decode_holds_family(root) || index.decode_has_opaque_file_incidence() {
        return Some(Refusal::DecodeHold);
    }
    if index.claude_usage_authority_quarantine.contains_key(root) {
        return Some(Refusal::Quarantine);
    }
    if index.claude_request_identity_contract_changed
        || index.claude_request_identity_contract.is_none()
        || index.upload_context_fingerprint.is_none()
        || index.upload_context_fingerprint != index.active_upload_context_fingerprint
        || !claude_accepted_ledger_is_current(index)
    {
        return Some(Refusal::IdentityOrContext);
    }
    let Some(files) = files else {
        return Some(Refusal::Membership);
    };
    if pending.membership().is_empty()
        || files.len() != pending.membership().keys().count()
        || !files.contains_key(&ClaudeIndexPathMemberRef {
            root,
            subagent_stem: None,
        })
        || pending.membership().keys().any(|name| {
            ClaudeIndexPathMemberRef::of_family_member(root, name)
                .and_then(|member| files.get(&member))
                .map_or(true, |file| file.duplicate)
        })
    {
        return Some(Refusal::Membership);
    }
    if files.values().any(|file| {
        index.decode_holds_file(file.key)
            || index.claude_account_deferred_holds.contains_key(file.key)
            || file.entry.source_file_fingerprint.is_empty()
    }) {
        return Some(Refusal::HeldMember);
    }
    if pending
        .membership()
        .values()
        .flat_map(|hashes| hashes.iter())
        .any(|hash| index.claude_duplicate_request_owners.contains_key(hash))
    {
        return Some(Refusal::DuplicateOwner);
    }
    if index.claude_reemission_exclusions.pauses_adoption()
        || index.bounded_sweep_had_unsettled_upload
        || files.values().any(|file| {
            index.claude_family_listed(file.key)
                || index.effective_upload_body_witness_revision_requires_adoption(file.key)
                || file.history_hold
                || index
                    .claude_reemission_exclusions
                    .holds_without_list_before(
                        index
                            .claude_request_census
                            .get(file.key)
                            .and_then(|record| record.birth())
                            .map(|birth| birth.unix_seconds),
                        claude_reemission_exclusions::NO_LIST_HOLD_BEFORE_UNIX_SECONDS,
                    )
        })
    {
        return Some(Refusal::HistoryOrReplay);
    }
    if files.values().any(|file| {
        file.entry.has_unverified_source()
            || index
                .held_audit_progress
                .as_ref()
                .is_some_and(|held| held.key == file.key)
    }) || pending
        .membership()
        .keys()
        .any(|name| index.claude_owned_start_census.contains_key(name))
    {
        return Some(Refusal::AuditOrCorrection);
    }
    if files
        .values()
        .any(|file| !claude_stale_member_independently_accepted(index, file.key, file.entry))
    {
        return Some(Refusal::Unaccepted);
    }
    let Some(witness) = index.claude_usage_family_witnesses.get(root) else {
        return Some(Refusal::UsageProof);
    };
    if !claude_usage_family_witness_legacy_free(witness)
        || !witness
            .member_request_id_fingerprints
            .keys()
            .eq(pending.membership().keys())
        || !witness
            .member_occurrence_fingerprints
            .keys()
            .eq(pending.membership().keys())
        || !pending
            .member_occurrences
            .keys()
            .eq(pending.membership().keys())
        || pending.membership().iter().any(|(name, hashes)| {
            witness.member_request_id_fingerprints.get(name)
                != Some(&claude_request_hashes_fingerprint(hashes.iter()))
                || pending
                    .member_occurrences
                    .get(name)
                    .map_or(true, |occurrences| {
                        !hashes.iter().eq(occurrences.keys())
                            || witness.member_occurrence_fingerprints.get(name)
                                != Some(&claude_occurrence_map_fingerprint(occurrences))
                    })
        })
    {
        return Some(Refusal::UsageProof);
    }
    None
}

fn accepted_usage_receipt<'a>(
    _index: &'a ScanIndex,
    _root: &str,
) -> Result<&'a ClaudeUsageFamilyWitness, Refusal> {
    // TODO(E7 B1): Is #901's per-file receipt the exact accepted usage evidence,
    // binding all member/native/context/account/destination/body/correction revisions?
    // ACKed NULL, stale or refused bodies must never authorize this transition.
    Err(Refusal::ReceiptB1)
}

fn retry_carry_replacement(_index: &ScanIndex, _root: &str) -> Result<(), Refusal> {
    // TODO(E7 B3): Which bound commitment and overlap/debt carrier replace
    // stale-window token comparisons without granting a reconstruction read?
    Err(Refusal::RetryCarryB3)
}

fn settlement<'a>(
    index: &'a ScanIndex,
    root: &str,
    pending: &ClaudeUsageFamilyPending,
    files: Option<&Members<'_>>,
) -> Settlement<'a> {
    if let Some(reason) = known_refusal(index, root, pending, files) {
        return Settlement::Refused(reason);
    }
    match accepted_usage_receipt(index, root).and_then(|commitment| {
        retry_carry_replacement(index, root)?;
        Ok(commitment)
    }) {
        Ok(commitment) => Settlement::Settled(commitment),
        Err(reason) => Settlement::Refused(reason),
    }
}

#[derive(Default, Serialize)]
pub(super) struct Weight {
    pub(super) families: u64,
    pub(super) pending_value_bytes: u64,
}
impl Weight {
    fn add(&mut self, bytes: u64) {
        self.families = self.families.saturating_add(1);
        self.pending_value_bytes = self.pending_value_bytes.saturating_add(bytes);
    }
}
#[derive(Default, Serialize)]
pub(super) struct Counts {
    pub(super) considered: Weight,
    pub(super) settled: Weight,
    pub(super) refused: BTreeMap<Refusal, Weight>,
    // Independent gate observations overlap the primary refusals. B1 must not
    // hide the B3 backlog. They are never added to the disjoint totals above.
    pub(super) owner_gates: BTreeMap<Refusal, Weight>,
    pub(super) byte_measurement_failed: u64,
}

fn pending_bytes(pending: &ClaudeUsageFamilyPending) -> Option<u64> {
    struct Counter(u64);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("diagnostic byte count overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, pending).ok()?;
    Some(counter.0)
}

impl ScanIndex {
    // Per selected save attempt after CAS checks, before publication; not a
    // cumulative count, successful-save receipt or frozen-copy measurement.
    pub(super) fn measure_claude_usage_pending_settlement(&self) -> Counts {
        let mut counts = Counts::default();
        if self.claude_usage_family_pending.is_empty() {
            return counts;
        }
        let inventory = inventory(self);
        for (root, pending) in &self.claude_usage_family_pending {
            let bytes = pending_bytes(pending).unwrap_or_else(|| {
                counts.byte_measurement_failed += 1;
                0
            });
            counts.considered.add(bytes);
            if let Err(reason) = accepted_usage_receipt(self, root) {
                counts.owner_gates.entry(reason).or_default().add(bytes);
            }
            if let Err(reason) = retry_carry_replacement(self, root) {
                counts.owner_gates.entry(reason).or_default().add(bytes);
            }
            let result = match &inventory {
                Some(inventory) => settlement(self, root, pending, inventory.get(root.as_str())),
                None => Settlement::Refused(Refusal::Scratch),
            };
            match result {
                Settlement::Settled(commitment) => {
                    // H commitment exists only when the exact receipt gate earns it.
                    let _ = commitment;
                    counts.settled.add(bytes);
                }
                Settlement::Refused(reason) => counts.refused.entry(reason).or_default().add(bytes),
            }
        }
        crate::local_resource_diagnostics::traversal_point(
            "claude_usage_pending_settlement_attempt",
            "claude",
            &counts,
        );
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: &str = "a1111111-1111-4111-8111-111111111111";
    const KEY: &str = "/synthetic/a1111111-1111-4111-8111-111111111111.jsonl";

    fn fixture() -> ScanIndex {
        let mut index = ScanIndex::default();
        index.upload_context_fingerprint = Some("context".into());
        index.active_upload_context_fingerprint = index.upload_context_fingerprint.clone();
        index.claude_request_identity_contract = Some("contract".into());
        index.claude_request_identity_contract_changed = false;
        index.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
        index.claude_reemission_exclusions =
            ReemissionExclusions::with_state(claude_reemission_exclusions::ListState::Installed);
        let hashes = BTreeSet::from(["a".repeat(64)]);
        let occurrences = BTreeMap::from([(
            "a".repeat(64),
            ClaudeTranscriptUsageOccurrenceWitness {
                sequence: 4,
                input_tokens: 11,
                output_tokens: 13,
                cache_read_tokens: 2,
                cache_creation_5m_tokens: 3,
                cache_creation_1h_tokens: 5,
                reasoning_output_tokens: 7,
                model: Some("synthetic-model".into()),
                speed_mode: None,
                reasoning_effort: None,
            },
        )]);
        index.claude_usage_family_witnesses.insert(
            ROOT.into(),
            ClaudeUsageFamilyWitness {
                evidence_fingerprint: "e".repeat(64),
                member_request_id_fingerprints: BTreeMap::from([(
                    ROOT.into(),
                    claude_request_id_set_fingerprint(&hashes),
                )]),
                member_occurrence_fingerprints: BTreeMap::from([(
                    ROOT.into(),
                    claude_occurrence_map_fingerprint(&occurrences),
                )]),
                assigned_request_id_fingerprints: BTreeMap::from([(
                    ROOT.into(),
                    claude_request_id_set_fingerprint(&hashes),
                )]),
                legacy_excluded_request_id_hashes: BTreeMap::new(),
                legacy_owner_roots: BTreeSet::new(),
                legacy_exclusion_evidence_fingerprint: None,
            },
        );
        index.claude_usage_family_pending.insert(
            ROOT.into(),
            ClaudeUsageFamilyPending {
                census_window_end: "2026-10-01T00:00:00Z".into(),
                member_request_id_hashes: BTreeMap::from([(ROOT.into(), hashes)]),
                member_occurrences: BTreeMap::from([(ROOT.into(), occurrences)]),
                invalid: false,
                idless_revision: None,
                derived_request_members: BTreeSet::new(),
            },
        );
        let entities = BTreeSet::from(["entity-1".into(), "entity-2".into()]);
        let mut entry = crate::snapshots::tests::manifest_index_entry(Some(&codex_digest_hex(
            &snapshot_file_entity_set_digest(&entities),
        )));
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        entry.last_upload_body_witness = Some("accepted-body".into());
        index.files.insert(KEY.into(), entry);
        index.accepted_snapshot_fingerprints = entities.clone();
        index
            .file_snapshot_fingerprints
            .insert(KEY.into(), entities);
        index
    }
    fn decision(index: &ScanIndex) -> Settlement<'_> {
        // The pure predicate needs no heap-layout admission or host I/O.
        let files = BTreeMap::from([(
            ClaudeIndexPathMemberRef {
                root: ROOT,
                subagent_stem: None,
            },
            MemberFile {
                key: KEY,
                entry: &index.files[KEY],
                duplicate: false,
                history_hold: false,
            },
        )]);
        settlement(
            index,
            ROOT,
            &index.claude_usage_family_pending[ROOT],
            Some(&files),
        )
    }
    fn refused(index: &ScanIndex, expected: Refusal) {
        match decision(index) {
            Settlement::Refused(actual) => assert_eq!(actual, expected),
            Settlement::Settled(_) => panic!("unexpected settlement"),
        }
    }
    #[test]
    fn exact_partial_lost_and_acked_null_never_substitute_for_usage_acceptance() {
        let index = fixture();
        assert!(claude_stale_member_independently_accepted(
            &index,
            KEY,
            &index.files[KEY]
        ));
        refused(&index, Refusal::ReceiptB1);
        for accepted in [BTreeSet::from(["entity-1".into()]), BTreeSet::new()] {
            let mut changed = index.clone();
            changed.accepted_snapshot_fingerprints = accepted;
            refused(&changed, Refusal::Unaccepted);
        }
        let mut null = index.clone();
        null.files.get_mut(KEY).unwrap().last_upload_body_witness = Some("acked-NULL-body".into());
        assert!(claude_index_file_body_accepted(
            &null,
            KEY,
            &null.files[KEY]
        ));
        refused(&null, Refusal::ReceiptB1);
        let mut old = index.clone();
        old.files.get_mut(KEY).unwrap().last_snapshot_fingerprint = Some("stale-head".into());
        refused(&old, Refusal::Unaccepted);
        assert!(matches!(
            retry_carry_replacement(&index, ROOT),
            Err(Refusal::RetryCarryB3)
        ));
    }
    #[test]
    fn holds_duplicates_quarantine_and_missing_member_are_classified_before_owner_gates() {
        let mut index = fixture();
        index
            .claude_account_deferred_holds
            .insert(KEY.into(), "hold".into());
        refused(&index, Refusal::HeldMember);
        index.claude_account_deferred_holds.clear();
        index.claude_duplicate_request_owners.insert(
            "a".repeat(64),
            BTreeSet::from([claude_duplicate_request_owner(ROOT, ROOT)]),
        );
        refused(&index, Refusal::DuplicateOwner);
        index.claude_duplicate_request_owners.clear();
        index.claude_usage_authority_quarantine.insert(
            ROOT.into(),
            ClaudeUsageAuthorityQuarantineRecord {
                contract: "contract".into(),
                proven_witness_fingerprint: "proof".into(),
                member_source_file_fingerprints: BTreeMap::new(),
                failed_reconstruction_count: 1,
                disposition: ClaudeUsageAuthorityQuarantineDisposition::default(),
                retry_after_unix_seconds: 1,
                proof_correction: None,
            },
        );
        refused(&index, Refusal::Quarantine);
        index.claude_usage_authority_quarantine.clear();
        index
            .claude_usage_family_pending
            .get_mut(ROOT)
            .unwrap()
            .member_request_id_hashes
            .insert(format!("{ROOT}_missing"), BTreeSet::new());
        refused(&index, Refusal::Membership);
    }
    #[test]
    fn byte_counter_uses_existing_wire_bytes_and_both_gates_are_visible() {
        let index = fixture();
        let counts = index.measure_claude_usage_pending_settlement();
        let bytes = serde_json::to_vec(&index.claude_usage_family_pending[ROOT])
            .unwrap()
            .len() as u64;
        assert_eq!(counts.considered.families, 1);
        assert_eq!(counts.considered.pending_value_bytes, bytes);
        assert_eq!(counts.settled.families, 0);
        assert_eq!(
            counts
                .refused
                .values()
                .map(|weight| weight.families)
                .sum::<u64>(),
            1
        );
        assert_eq!(
            counts.owner_gates[&Refusal::ReceiptB1].pending_value_bytes,
            bytes
        );
        assert_eq!(
            counts.owner_gates[&Refusal::RetryCarryB3].pending_value_bytes,
            bytes
        );
        assert_eq!(counts.byte_measurement_failed, 0);
    }
}
