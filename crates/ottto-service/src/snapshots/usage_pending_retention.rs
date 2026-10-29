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
    AccountDebt,
    Unaccepted,
    UsageProof,
    ReceiptB1,
    RetryCarryB3,
    CarrierS4,
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
}
type Members<'a> = BTreeMap<ClaudeIndexPathMemberRef<'a>, MemberFile<'a>>;
#[derive(Default)]
struct FamilyFiles<'a> {
    members: Members<'a>,
    held: bool,
}
type Inventory<'a> = BTreeMap<&'a str, FamilyFiles<'a>>;

// One borrowed node per indexed file, plus at most one node per file's root.
// Refuse before allocation if the optional diagnostic scratch is not bounded.
fn inventory(index: &ScanIndex) -> Option<Inventory<'_>> {
    use crate::heap_layout_bound::{tree_nodes, Counter};
    if !crate::heap_layout_bound::layout_supported() {
        return None;
    }
    let mut cost = Counter::new(crate::source_rotation::PARKED_BUDGET);
    tree_nodes::<&str, FamilyFiles<'_>>(index.claude_usage_family_pending.len(), &mut cost)?;
    tree_nodes::<ClaudeIndexPathMemberRef<'_>, MemberFile<'_>>(index.files.len(), &mut cost)?;
    Some(build_inventory(index))
}

// The production caller admits this borrowed graph before allocation. Small
// synthetic fixtures can exercise family semantics on non-native CI layouts.
fn build_inventory(index: &ScanIndex) -> Inventory<'_> {
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
            .members
            .entry(member)
            .and_modify(|file| file.duplicate = true)
            .or_insert(MemberFile {
                key,
                entry,
                duplicate: false,
            });
    }
    // Holds may name a sibling omitted from the selected files map. They
    // still hold the entire family; absence here cannot erase that debt.
    for key in index
        .claude_account_deferred_holds
        .keys()
        .map(String::as_str)
        .chain(
            index
                .claude_history_emission
                .files
                .values()
                .filter(|held| held.held.is_some() || held.literal_denied)
                .map(|held| held.index_key.as_str()),
        )
    {
        if let Some(member) = claude_index_path_member_ref(Path::new(key)) {
            if index.claude_usage_family_pending.contains_key(member.root) {
                inventory.entry(member.root).or_default().held = true;
            }
        }
    }
    inventory
}

fn known_refusal(
    index: &ScanIndex,
    root: &str,
    pending: &ClaudeUsageFamilyPending,
    files: Option<&FamilyFiles<'_>>,
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
    if index.claude_account_family_pending.contains_key(root) {
        return Some(Refusal::AccountDebt);
    }
    if files.is_some_and(|family| family.held) {
        return Some(Refusal::HeldMember);
    }
    if index.claude_request_identity_contract_changed
        || index.claude_request_identity_contract.is_none()
        || index.upload_context_fingerprint.is_none()
        || index.upload_context_fingerprint != index.active_upload_context_fingerprint
        || !claude_accepted_ledger_is_current(index)
    {
        return Some(Refusal::IdentityOrContext);
    }
    let Some(family) = files else {
        return Some(Refusal::Membership);
    };
    let files = &family.members;
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
    files: Option<&FamilyFiles<'_>>,
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

fn negative_scheduling_carrier_durable(_index: &ScanIndex, _root: &str) -> bool {
    // TODO(E7 S4-carrier): Where is the durable L carrier preserving this
    // family's negative scheduling fence and overlap/debt effects after removal?
    // A usage/body digest (H) and first-seen status (N) cannot replace it.
    false
}

fn may_retire(index: &ScanIndex, root: &str, result: &Settlement<'_>) -> bool {
    matches!(result, Settlement::Settled(_)) && negative_scheduling_carrier_durable(index, root)
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
    pub(super) compacted: Weight,
    pub(super) compaction_scratch_refused: Weight,
    pub(super) retirement_carrier_refused: Weight,
    pub(super) retired: Weight,
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

// Per selected save attempt after CAS checks, before publication; not a
// cumulative count, successful-save receipt or frozen-copy measurement.
fn classify_index(
    index: &ScanIndex,
    mut settled: impl FnMut(&str, &ClaudeUsageFamilyWitness, u64, bool),
) -> Counts {
    let mut counts = Counts::default();
    if index.claude_usage_family_pending.is_empty() {
        return counts;
    }
    let inventory = inventory(index);
    for (root, pending) in &index.claude_usage_family_pending {
        let bytes = pending_bytes(pending).unwrap_or_else(|| {
            counts.byte_measurement_failed += 1;
            0
        });
        counts.considered.add(bytes);
        if let Err(reason) = accepted_usage_receipt(index, root) {
            counts.owner_gates.entry(reason).or_default().add(bytes);
        }
        if let Err(reason) = retry_carry_replacement(index, root) {
            counts.owner_gates.entry(reason).or_default().add(bytes);
        }
        if !negative_scheduling_carrier_durable(index, root) {
            counts
                .owner_gates
                .entry(Refusal::CarrierS4)
                .or_default()
                .add(bytes);
        }
        let result = match &inventory {
            Some(inventory) => settlement(index, root, pending, inventory.get(root.as_str())),
            None => Settlement::Refused(Refusal::Scratch),
        };
        let retire = may_retire(index, root, &result);
        match result {
            Settlement::Settled(commitment) => {
                // H commitment exists only when the exact receipt gate earns it.
                settled(root, commitment, bytes, retire);
                counts.settled.add(bytes);
                if !retire {
                    counts.retirement_carrier_refused.add(bytes);
                }
            }
            Settlement::Refused(reason) => counts.refused.entry(reason).or_default().add(bytes),
        }
    }
    counts
}

// Own predecessors until the existing atomic index publication succeeds. No
// token graphs are cloned; a failed save restores the same pending records.
pub(super) struct Prepared {
    previous: Vec<(String, ClaudeUsageFamilyPending)>,
}
impl Prepared {
    fn compact(&mut self, index: &mut ScanIndex, root: String, retire: bool) -> u64 {
        if retire {
            let previous = index
                .claude_usage_family_pending
                .remove(&root)
                .expect("classified root");
            let bytes = pending_bytes(&previous).unwrap_or(0);
            self.previous.push((root, previous));
            return bytes;
        }
        let pending = index
            .claude_usage_family_pending
            .get_mut(&root)
            .expect("classified root");
        let bytes = pending_bytes(pending).unwrap_or(0);
        let skeleton = compacted_skeleton(pending);
        let previous = std::mem::replace(pending, skeleton);
        self.previous.push((root, previous));
        bytes
    }
    pub(super) fn finish(self, index: &mut ScanIndex, published: bool) {
        if !published {
            for (root, pending) in self.previous {
                index.claude_usage_family_pending.insert(root, pending);
            }
        }
    }
}

fn compacted_skeleton(pending: &ClaudeUsageFamilyPending) -> ClaudeUsageFamilyPending {
    ClaudeUsageFamilyPending {
        census_window_end: pending.census_window_end.clone(),
        member_request_id_hashes: pending
            .membership()
            .iter()
            .map(|(member, hashes)| (member.clone(), hashes.iter().cloned().collect()))
            .collect(),
        member_occurrences: BTreeMap::new(),
        invalid: pending.invalid,
        idless_revision: pending.idless_revision,
        derived_request_members: BTreeSet::new(),
    }
}

// Price the new exact keys and candidate/rollback slots before cloning. The
// old occurrences move into Prepared until publication; no second token copy.
fn price_compaction(
    root: &str,
    pending: &ClaudeUsageFamilyPending,
    cost: &mut crate::heap_layout_bound::Counter,
) -> Option<()> {
    use crate::heap_layout_bound::tree_nodes;
    cost.add(root.len().checked_mul(2)?)?;
    cost.add(pending.census_window_end.len())?;
    cost.add(std::mem::size_of::<(String, ClaudeUsageFamilyPending)>().checked_mul(4)?)?;
    tree_nodes::<String, BTreeSet<String>>(pending.membership().keys().count(), cost)?;
    for (member, hashes) in pending.membership().iter() {
        cost.add(member.len())?;
        tree_nodes::<String, ()>(hashes.len(), cost)?;
        for hash in hashes.iter() {
            cost.add(hash.len())?;
        }
    }
    Some(())
}

impl ScanIndex {
    pub(super) fn prepare_claude_usage_pending_settlement(&mut self) -> Prepared {
        let mut candidates = Vec::new();
        let mut scratch_refused = Weight::default();
        let mut cost =
            crate::heap_layout_bound::Counter::new(crate::source_rotation::PARKED_BUDGET);
        let mut counts = classify_index(self, |root, _commitment, bytes, retire| {
            let pending = &self.claude_usage_family_pending[root];
            if price_compaction(root, pending, &mut cost).is_none()
                || candidates.try_reserve(1).is_err()
            {
                scratch_refused.add(bytes);
            } else {
                candidates.push((root.to_owned(), retire));
            }
        });
        counts.compaction_scratch_refused = scratch_refused;
        let mut prepared = Prepared {
            previous: Vec::new(),
        };
        // Reserve before mutation; allocation refusal keeps every occurrence.
        if prepared
            .previous
            .try_reserve_exact(candidates.len())
            .is_ok()
        {
            for (root, retire) in candidates {
                let bytes = prepared.compact(self, root, retire);
                if retire {
                    counts.retired.add(bytes);
                } else {
                    counts.compacted.add(bytes);
                }
            }
        } else {
            for (root, _) in candidates {
                counts
                    .compaction_scratch_refused
                    .add(pending_bytes(&self.claude_usage_family_pending[&root]).unwrap_or(0));
            }
        }
        if counts.considered.families != 0 {
            crate::local_resource_diagnostics::traversal_point(
                "claude_usage_pending_settlement_attempt",
                SnapshotSource::ClaudeCode.api_slug(),
                &counts,
            );
        }
        prepared
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
        let entities = BTreeSet::from(["1".repeat(64), "2".repeat(64)]);
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
            },
        )]);
        let family = FamilyFiles {
            members: files,
            held: false,
        };
        settlement(
            index,
            ROOT,
            &index.claude_usage_family_pending[ROOT],
            Some(&family),
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
        assert!(!negative_scheduling_carrier_durable(&index, ROOT));
        assert!(!may_retire(&index, ROOT, &decision(&index)));
        assert!(!may_retire(
            &index,
            ROOT,
            &Settlement::Settled(&index.claude_usage_family_witnesses[ROOT])
        ));
        for accepted in [BTreeSet::from(["1".repeat(64)]), BTreeSet::new()] {
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
        let counts = classify_index(&index, |_, _, _, _| {});
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
        assert_eq!(
            counts.owner_gates[&Refusal::CarrierS4].pending_value_bytes,
            bytes
        );
        assert_eq!(counts.retired.families, 0);
        assert_eq!(counts.byte_measurement_failed, 0);
    }
    #[test]
    fn compacted_keys_and_commitment_survive_two_wire_restarts_and_failure_restores_values() {
        let mut index = fixture();
        let original = index.claude_usage_family_pending[ROOT].clone();
        let witness = index.claude_usage_family_witnesses[ROOT].clone();
        let mut prepared = Prepared {
            previous: Vec::with_capacity(1),
        };
        prepared.compact(&mut index, ROOT.into(), false);
        let compacted = &index.claude_usage_family_pending[ROOT];
        assert!(compacted.member_occurrences.is_empty());
        assert_eq!(
            serde_json::to_value(compacted.membership()).unwrap(),
            serde_json::to_value(original.membership()).unwrap()
        );
        assert_eq!(index.claude_usage_family_witnesses[ROOT], witness);
        // Exercise the actual rollback used for any failed publication.
        prepared.finish(&mut index, false);
        assert_eq!(index.claude_usage_family_pending[ROOT], original);
        let mut committed = Prepared {
            previous: Vec::with_capacity(1),
        };
        committed.compact(&mut index, ROOT.into(), false);
        committed.finish(&mut index, true);
        let mut skeleton = index.claude_usage_family_pending[ROOT].clone();
        for _ in 0..2 {
            skeleton = serde_json::from_slice(&serde_json::to_vec(&skeleton).unwrap()).unwrap();
            assert!(skeleton.member_occurrences.is_empty());
            assert_eq!(
                serde_json::to_value(skeleton.membership()).unwrap(),
                serde_json::to_value(original.membership()).unwrap()
            );
        }
    }

    #[test]
    fn production_owner_gates_preserve_pending_and_accepted_state_across_two_restarts() {
        let mut index = fixture();
        let pending = index.claude_usage_family_pending[ROOT].clone();
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let file_heads = serde_json::to_value(&index.files).unwrap();
        for _ in 0..2 {
            let prepared = index.prepare_claude_usage_pending_settlement();
            assert!(prepared.previous.is_empty());
            prepared.finish(&mut index, true);
            assert_eq!(index.claude_usage_family_pending[ROOT], pending);
            assert_eq!(index.accepted_snapshot_fingerprints, accepted);
            assert_eq!(serde_json::to_value(&index.files).unwrap(), file_heads);
            let restored = serde_json::from_slice(
                &serde_json::to_vec(&index.claude_usage_family_pending[ROOT]).unwrap(),
            )
            .unwrap();
            index
                .claude_usage_family_pending
                .insert(ROOT.into(), restored);
        }
    }
    #[test]
    fn carrier_crash_before_publication_preserves_pending_on_disk() {
        const CHILD_DIR: &str = "OTTTO_E7_USAGE_CRASH_FIXTURE_DIR";
        if let Some(directory) = std::env::var_os(CHILD_DIR) {
            let directory = PathBuf::from(directory);
            let mut index = ScanIndex::load(&directory.join("index.json")).unwrap();
            assert!(index.claude_usage_family_pending.contains_key(ROOT));
            let prepared = index.prepare_claude_usage_pending_settlement();
            assert!(
                prepared.previous.is_empty(),
                "closed gates preserve the predecessor"
            );
            assert!(!negative_scheduling_carrier_durable(&index, ROOT));
            fs::write(directory.join("reached-before-publication"), b"reached").unwrap();
            // Abrupt process death skips Prepared::finish and all destructors.
            std::process::exit(73);
        }
        struct FixtureDir(PathBuf);
        impl Drop for FixtureDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let directory = FixtureDir(std::env::temp_dir().join(format!(
                "ottto-usage-carrier-crash-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        fs::create_dir_all(&directory.0).unwrap();
        let path = directory.0.join("index.json");
        let mut index = fixture();
        index.save(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let original = index.claude_usage_family_pending[ROOT].clone();
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let file_heads = serde_json::to_value(&index.files).unwrap();
        let test_name = format!(
            "{}::carrier_crash_before_publication_preserves_pending_on_disk",
            module_path!().split_once("::").unwrap().1
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD_DIR, &directory.0)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "child did not reach crash edge: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(directory.0.join("reached-before-publication").exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        for _ in 0..2 {
            let restored = ScanIndex::load(&path).unwrap();
            assert!(restored.persistence_available());
            assert_eq!(restored.claude_usage_family_pending[ROOT], original);
            assert_eq!(restored.accepted_snapshot_fingerprints, accepted);
            assert_eq!(serde_json::to_value(&restored.files).unwrap(), file_heads);
            assert!(!negative_scheduling_carrier_durable(&restored, ROOT));
        }
    }
    #[test]
    fn remaining_account_debt_and_omitted_held_siblings_refuse_settlement() {
        let mut index = fixture();
        index.claude_account_family_pending.insert(ROOT.into(), serde_json::from_value(json!({
            "census_window_end":"2026-10-01T00:00:00Z", "account_identifier_hash":"account", "evidence_request_count":1, "invalid":false
        })).unwrap());
        refused(&index, Refusal::AccountDebt);
        for kind in ["deferred", "history"] {
            let mut index = fixture();
            let child = format!("/synthetic/{ROOT}/subagents/agent-hidden.jsonl");
            assert!(!index.files.contains_key(&child));
            if kind == "deferred" {
                index
                    .claude_account_deferred_holds
                    .insert(child, "hold".into());
            } else {
                index.claude_history_emission.files.insert(
                    "held-revision".into(),
                    claude_history_upgrade::GatedHistory {
                        index_key: child,
                        held: Some(claude_history_upgrade::HistoryHold::TelemetryUnread),
                        ..Default::default()
                    },
                );
            }
            let inventory = build_inventory(&index);
            assert!(inventory[ROOT].held);
            assert!(matches!(
                settlement(
                    &index,
                    ROOT,
                    &index.claude_usage_family_pending[ROOT],
                    inventory.get(ROOT)
                ),
                Settlement::Refused(Refusal::HeldMember)
            ));
        }
    }

    #[test]
    fn production_measurement_emits_claude_code_source_and_attempt_counts() {
        let mut index = fixture();
        let (prepared, records) = crate::local_resource_diagnostics::capture(|| {
            index.prepare_claude_usage_pending_settlement()
        });
        prepared.finish(&mut index, true);
        let records = records
            .iter()
            .filter(|record| record["stage"] == "claude_usage_pending_settlement_attempt")
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["source"], "claude_code");
    }
}
