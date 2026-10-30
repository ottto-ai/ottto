// Characterization only: these rejected record transitions are not used by
// production and do not prove a correction-through-ACK lifecycle.
use super::*;

const ROOT: &str = "d1111111-1111-4111-8111-111111111111";

fn fixture() -> (ScanIndex, [CandidateFile; 2]) {
    let keys = [
        format!("/synthetic/binding/{ROOT}.jsonl"),
        format!("/synthetic/binding/{ROOT}/subagents/agent-correction.jsonl"),
    ];
    let members = [ROOT.to_string(), format!("{ROOT}_agent-correction")];
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..ScanIndex::default()
    };
    let revisions = [hex64('a'), hex64('b')];
    for (slot, key) in keys.iter().enumerate() {
        let body = if slot == 0 { hex64('c') } else { hex64('d') };
        index_file(&mut index, key, &revisions[slot], &body, WINDOW);
        index.accepted_snapshot_fingerprints.insert(body);
        index
            .files
            .get_mut(key)
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    let witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: hex64('e'),
        member_request_id_fingerprints: members.iter().map(|m| (m.clone(), hex64('1'))).collect(),
        member_occurrence_fingerprints: members.iter().map(|m| (m.clone(), hex64('2'))).collect(),
        assigned_request_id_fingerprints: members.iter().map(|m| (m.clone(), hex64('3'))).collect(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    index.claude_usage_authority_quarantine.insert(
        ROOT.to_string(),
        ClaudeUsageAuthorityQuarantineRecord {
            proof_correction: None,
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
            member_source_file_fingerprints: members.into_iter().zip(revisions.clone()).collect(),
            failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: 0,
        },
    );
    index
        .claude_usage_family_witnesses
        .insert(ROOT.to_string(), witness);
    let candidates = std::array::from_fn(|slot| {
        let mut candidate = matching_candidate(&index, &keys[slot]);
        candidate.source_file_fingerprint = revisions[slot].clone();
        candidate
    });
    (index, candidates)
}

// Model a genuinely different witness, not a changed-file-only budget reset.
// This fixture does not claim to prove that witness from provider evidence.
fn bind_different_witness(index: &mut ScanIndex) {
    let witness = index.claude_usage_family_witnesses.get_mut(ROOT).unwrap();
    witness.evidence_fingerprint = hex64('f');
    let digest = claude_usage_family_witness_fingerprint(witness);
    index
        .claude_usage_authority_quarantine
        .get_mut(ROOT)
        .unwrap()
        .proven_witness_fingerprint = digest;
}

fn save_reload(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    index.save(path).expect("save prototype state");
    let loaded = ScanIndex::load(path).expect("reload prototype state");
    assert_eq!(
        serde_json::to_vec(&loaded).unwrap(),
        serde_json::to_vec(index).unwrap(),
        "valid binding reloads exactly without index rebuild"
    );
    loaded
}

#[test]
fn binding_only_terminal_prototype_skips_outstanding_correction_debt_after_reload() {
    let (mut index, candidates) = fixture();
    let accepted = index.accepted_snapshot_fingerprints.clone();
    bind_different_witness(&mut index);
    let scratch = crate::test_scratch::ScratchDir::new("binding-terminal-prototype");
    let loaded = save_reload(&mut index, &scratch.join("index.json"));
    assert_eq!(loaded.accepted_snapshot_fingerprints, accepted);
    for candidate in &candidates {
        assert!(loaded.files[&local_index_key(&candidate.path)]
            .source_file_fingerprint
            .is_empty());
        assert_eq!(
            loaded.candidate_decision(candidate),
            CandidateDecision::Skip,
            "digest-only rebind is not a correction attempt"
        );
    }
    assert_eq!(
        loaded.claude_usage_authority_quarantine[ROOT].failed_reconstruction_count,
        MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
    );
}
