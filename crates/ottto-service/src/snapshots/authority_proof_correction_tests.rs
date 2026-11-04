// Positive-proof correction of a terminal Claude family authority record:
// the persisted all-member grant, the candidate gate, strict load validation, record-contract compatibility with
// the source-pinned pre-change decoder, partial-checkpoint carriage,
// no-body completion, the empty map
// advance with its restoration seams, the accepted-body no-op, and
// correction custody. All fixtures are synthetic and
// content-free. The state-machine section is CONTROLLED: it seeds a granted
// index, then runs the production seams in production order. The lifecycle
// through real pages, uploads and reloads lives in
// `snapshot_sync/authority_proof_correction_pipeline_tests.rs`.
use super::*;

const APC_ROOT: &str = "e1111111-1111-4111-8111-111111111111";
const APC_WINDOW: &str = "2026-08-02T07:10:00Z";

fn apc_hex(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn apc_members() -> [String; 2] {
    [APC_ROOT.to_string(), format!("{APC_ROOT}_agent-proof")]
}

fn apc_keys() -> [String; 2] {
    [
        format!("/synthetic/proof-correction/{APC_ROOT}.jsonl"),
        format!("/synthetic/proof-correction/{APC_ROOT}/subagents/agent-proof.jsonl"),
    ]
}

/// A retained family witness; `evidence` distinguishes proofs.
fn apc_witness(evidence: char) -> ClaudeUsageFamilyWitness {
    let members = apc_members();
    ClaudeUsageFamilyWitness {
        evidence_fingerprint: apc_hex(evidence),
        member_request_id_fingerprints: members.iter().map(|m| (m.clone(), apc_hex('1'))).collect(),
        member_occurrence_fingerprints: members.iter().map(|m| (m.clone(), apc_hex('2'))).collect(),
        assigned_request_id_fingerprints: members
            .iter()
            .map(|m| (m.clone(), apc_hex('3')))
            .collect(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    }
}

fn apc_entry(source: &str, fingerprint: &str) -> ScanIndexEntry {
    let mut entry = manifest_index_entry(Some(fingerprint));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    entry.source_file_fingerprint = source.to_string();
    entry
}

fn apc_revisions() -> [String; 2] {
    [apc_hex('a'), apc_hex('b')]
}

/// Two committed, accepted family members and a bounded terminal record bound
/// to the retained witness W0, as exhausted reconstruction leaves them.
fn apc_terminal_fixture() -> ScanIndex {
    let mut index = ScanIndex {
        accepted_snapshot_fingerprint_ledger_version: SNAPSHOT_ACCEPTED_LEDGER_VERSION,
        ..ScanIndex::default()
    };
    let revisions = apc_revisions();
    for (slot, key) in apc_keys().iter().enumerate() {
        let body = if slot == 0 {
            apc_hex('c')
        } else {
            apc_hex('d')
        };
        index
            .files
            .insert(key.clone(), apc_entry(&revisions[slot], &body));
        index
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([body.clone()]));
        index
            .snapshot_activity_at
            .insert(body.clone(), Some(APC_WINDOW.to_string()));
        index.accepted_snapshot_fingerprints.insert(body);
    }
    let witness = apc_witness('e');
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    index.claude_usage_authority_quarantine.insert(
        APC_ROOT.to_string(),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
            member_source_file_fingerprints: apc_members().into_iter().zip(revisions).collect(),
            failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: now + CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS,
            proof_correction: None,
        },
    );
    index
        .claude_usage_family_witnesses
        .insert(APC_ROOT.to_string(), witness);
    index
}

/// The owed correction an older build persisted for a new proof of the
/// family: the terminal record declares contract v2, binds to that proof and
/// owes every recorded member; the retained witness becomes the new proof.
fn apc_prove(index: &mut ScanIndex, witness: &ClaudeUsageFamilyWitness) {
    let proof = claude_usage_family_witness_fingerprint(witness);
    let record = index
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
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
    index
        .claude_usage_family_witnesses
        .insert(APC_ROOT.to_string(), witness.clone());
}

fn apc_candidate(index: &ScanIndex, slot: usize) -> CandidateFile {
    let key = &apc_keys()[slot];
    let entry = &index.files[key];
    let mut candidate = test_candidate(PathBuf::from(key));
    candidate.size_bytes = entry.size_bytes;
    candidate.modified_unix_seconds = entry.modified_unix_seconds;
    candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap_or_default();
    candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
    candidate
}

fn apc_decision(
    index: &ScanIndex,
    candidate: &CandidateFile,
) -> (CandidateDecision, Option<CandidateParseReason>) {
    let decided = index.candidate_decision_with_reason_at(candidate, 0);
    assert_eq!(decided.0, index.candidate_decision_at(candidate, 0));
    decided
}

fn apc_record(index: &ScanIndex) -> &ClaudeUsageAuthorityQuarantineRecord {
    &index.claude_usage_authority_quarantine[APC_ROOT]
}

fn apc_owed(index: &ScanIndex) -> Option<BTreeSet<String>> {
    index
        .claude_usage_authority_quarantine
        .get(APC_ROOT)
        .and_then(|record| record.proof_correction.as_ref())
        .map(|correction| correction.owed_member_ids.clone())
}

fn apc_save_reload(index: &mut ScanIndex, path: &Path) -> ScanIndex {
    index.save(path).expect("save correction state");
    let loaded = ScanIndex::load(path).expect("reload correction state");
    assert_eq!(
        serde_json::to_vec(&loaded).unwrap(),
        serde_json::to_vec(index).unwrap(),
        "a valid record reloads exactly without an index rebuild"
    );
    loaded
}

const PARSE_FOR_AUTHORITY: (CandidateDecision, Option<CandidateParseReason>) = (
    CandidateDecision::Parse,
    Some(CandidateParseReason::AuthorityQuarantine),
);

/// [regress] An unindexed member of a family with an authority record (a
/// held body the committed index does not keep) waits like an indexed member
/// instead of a new-file read every pass; a changed or owed member, or one
/// whose family has no record, is still read as a new file.
#[test]
fn an_unchanged_unindexed_member_waits_for_its_family_authority() {
    const NEW_FILE: (CandidateDecision, Option<CandidateParseReason>) = (
        CandidateDecision::Parse,
        Some(CandidateParseReason::NewFile),
    );
    let mut index = apc_terminal_fixture();
    let candidates = [0, 1].map(|slot| apc_candidate(&index, slot));
    for key in apc_keys() {
        index.files.remove(&key);
    }
    for candidate in &candidates {
        assert_eq!(
            apc_decision(&index, candidate),
            (CandidateDecision::Skip, None),
            "an unchanged held member waits for its record"
        );
    }
    let mut changed = candidates[0].clone();
    changed.source_file_fingerprint = apc_hex('9');
    assert_eq!(apc_decision(&index, &changed), NEW_FILE);
    apc_prove(&mut index, &apc_witness('f'));
    assert_eq!(apc_decision(&index, &candidates[1]), NEW_FILE, "owed");
    index.claude_usage_authority_quarantine.remove(APC_ROOT);
    assert_eq!(apc_decision(&index, &candidates[0]), NEW_FILE, "no record");
}

/// A persisted grant over a bounded terminal record is a valid v2 record:
/// every owed member bypasses the terminal gate, and the grant survives a
/// save and reload.
#[test]
fn a_persisted_grant_owes_every_member_past_the_terminal_gate() {
    let mut index = apc_terminal_fixture();
    for slot in 0..2 {
        assert_eq!(
            apc_decision(&index, &apc_candidate(&index, slot)),
            (CandidateDecision::Skip, None),
            "the bound terminal record skips an unchanged member"
        );
    }
    apc_prove(&mut index, &apc_witness('f'));
    let record = apc_record(&index);
    assert!(claude_authority_record_contract_is_valid(record));
    assert!(index.claude_authority_proof_correction_pending());
    for slot in 0..2 {
        assert_eq!(
            apc_decision(&index, &apc_candidate(&index, slot)),
            PARSE_FOR_AUTHORITY,
            "an owed member parses even with its recorded revision"
        );
    }
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-grant");
    let loaded = apc_save_reload(&mut index, &scratch.join("index.json"));
    assert_eq!(apc_owed(&loaded), apc_owed(&index));
}

/// A changed member revision still parses through the existing path, and a
/// record whose correction failed (v1, terminal, no correction, rebound to
/// the proof) skips unchanged members again until the next changed proof.
#[test]
fn only_owed_or_changed_members_bypass_the_terminal_gate() {
    let mut index = apc_terminal_fixture();
    apc_prove(&mut index, &apc_witness('f'));
    let mut changed = apc_candidate(&index, 0);
    changed.source_file_fingerprint = apc_hex('5');
    assert_eq!(apc_decision(&index, &changed), PARSE_FOR_AUTHORITY);
    // The R3 failure shape the demotion path writes.
    let record = index
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
        .unwrap();
    record.proof_correction = None;
    record.contract = CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string();
    assert!(!index.claude_authority_proof_correction_pending());
    for slot in 0..2 {
        assert_eq!(
            apc_decision(&index, &apc_candidate(&index, slot)),
            (CandidateDecision::Skip, None)
        );
    }
    assert_eq!(apc_decision(&index, &changed), PARSE_FOR_AUTHORITY);
}

/// Write one mutated saved index and load it. Returns the loaded index and
/// whether the loader quarantined the file for a rebuild.
fn apc_load_value(scratch: &Path, name: &str, value: &Value) -> (ScanIndex, bool) {
    let path = scratch.join(format!("{name}.json"));
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&path).expect("load or quarantine");
    let quarantined = !path.exists()
        && fs::read_dir(scratch)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                let name_on_disk = entry.file_name().to_string_lossy().to_string();
                name_on_disk.starts_with(name) && name_on_disk.contains(".corrupt.")
            });
    (loaded, quarantined)
}

/// T5/R7 strict load: the proof, record digest and retained witness are one
/// binding; owed is non-empty and a subset of the recorded members; contract
/// v2 exactly when a correction is present, on a terminal record. Every other
/// shape drops only the authority record.
#[test]
fn invalid_correction_states_drop_only_the_affected_authority_record() {
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-load");
    let mut index = apc_terminal_fixture();
    apc_prove(&mut index, &apc_witness('f'));
    index.save(&scratch.join("valid-source.json")).unwrap();
    let valid: Value =
        serde_json::from_slice(&fs::read(scratch.join("valid-source.json")).unwrap()).unwrap();
    let (loaded, quarantined) = apc_load_value(&scratch, "valid", &valid);
    assert!(!quarantined);
    assert_eq!(serde_json::to_value(&loaded).unwrap(), valid);
    // The dropped record's members re-arm so the next pass re-reads them.
    let mut rearmed = index.files.clone();
    for key in apc_keys() {
        rearmed
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
    }

    let old_digest = claude_usage_family_witness_fingerprint(&apc_witness('e'));
    type RecordMutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, RecordMutation)> = vec![
        (
            "proof-not-record",
            Box::new(|record: &mut Value| {
                record["proof_correction"]["proof_witness_fingerprint"] = json!(apc_hex('9'));
            }),
        ),
        (
            "record-not-witness",
            Box::new(move |record: &mut Value| {
                record["proven_witness_fingerprint"] = json!(old_digest);
                record["proof_correction"]["proof_witness_fingerprint"] = json!(old_digest);
            }),
        ),
        (
            "owed-empty",
            Box::new(|record: &mut Value| {
                record["proof_correction"]["owed_member_ids"] = json!([]);
            }),
        ),
        (
            "owed-not-member",
            Box::new(|record: &mut Value| {
                record["proof_correction"]["owed_member_ids"] =
                    json!([APC_ROOT, format!("{APC_ROOT}_agent-unrecorded")]);
            }),
        ),
        (
            "v1-with-correction",
            Box::new(|record: &mut Value| {
                record["contract"] = json!(CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION);
            }),
        ),
        (
            "v2-without-correction",
            Box::new(|record: &mut Value| {
                record.as_object_mut().unwrap().remove("proof_correction");
            }),
        ),
        (
            "v2-null-correction",
            Box::new(|record: &mut Value| {
                record["proof_correction"] = Value::Null;
            }),
        ),
        (
            "v2-retry-pending",
            Box::new(|record: &mut Value| {
                record["disposition"] = json!("retry_pending");
                record["failed_reconstruction_count"] = json!(1);
            }),
        ),
        (
            "unknown-contract",
            Box::new(|record: &mut Value| {
                record["contract"] = json!("claude_usage_authority_quarantine:v3");
            }),
        ),
        (
            // Only the whole-family vanish rule may empty a member map.
            "member-map-emptied",
            Box::new(|record: &mut Value| {
                record["member_source_file_fingerprints"] = json!({});
            }),
        ),
    ];
    for (name, mutate) in cases {
        let mut value = valid.clone();
        mutate(&mut value["claude_usage_authority_quarantine"][APC_ROOT]);
        let (loaded, quarantined) = apc_load_value(&scratch, name, &value);
        assert!(!quarantined, "{name}: the rest of the index survives");
        assert_eq!(loaded.generation, index.generation, "{name}");
        assert_eq!(
            serde_json::to_value(&loaded.files).unwrap(),
            serde_json::to_value(&rearmed).unwrap(),
            "{name}"
        );
        assert!(
            loaded.claude_usage_authority_quarantine.is_empty(),
            "{name}"
        );
    }
}

/// A new reader treats an old-contract record exactly as before: no field is
/// written, the encoded record is byte-for-byte the pre-change shape, and it
/// reloads identically. The source-pinned pre-change decoder reads the same
/// bytes back unchanged.
#[test]
fn new_reader_keeps_old_contract_records_byte_identical() {
    let mut index = apc_terminal_fixture();
    let record = apc_record(&index).clone();
    let [root, agent] = apc_members();
    let [root_revision, agent_revision] = apc_revisions();
    let expected = format!(
        "{{\"contract\":\"claude_usage_authority_quarantine:v1\",\"proven_witness_fingerprint\":\"{}\",\"member_source_file_fingerprints\":{{\"{root}\":\"{root_revision}\",\"{agent}\":\"{agent_revision}\"}},\"failed_reconstruction_count\":4,\"disposition\":\"unproven_terminal\",\"retry_after_unix_seconds\":{}}}",
        record.proven_witness_fingerprint, record.retry_after_unix_seconds
    );
    assert_eq!(serde_json::to_string(&record).unwrap(), expected);
    assert_eq!(
        previous_release_0_1_173::reencode(&expected),
        expected,
        "the pre-change decoder reads and writes the same record"
    );
    let decoded: ClaudeUsageAuthorityQuarantineRecord = serde_json::from_str(&expected).unwrap();
    assert_eq!(decoded, record);
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-old-record");
    let path = scratch.join("index.json");
    let loaded = apc_save_reload(&mut index, &path);
    assert!(!String::from_utf8(fs::read(&path).unwrap())
        .unwrap()
        .contains("proof_correction"));
    assert_eq!(apc_record(&loaded), &record);
    assert_eq!(
        apc_decision(&loaded, &apc_candidate(&loaded, 0)),
        (CandidateDecision::Skip, None)
    );
}

/// R7 against the actual pre-change decoder source. The pinned base has no
/// `deny_unknown_fields` on the record, so a v2 record still decodes and the
/// field is dropped; its record predicate then rejects the v2 contract, so the
/// old loader takes its invalid-index branch: whole-index quarantine and a
/// rebuild from a fresh index. The same decoder silently accepts a v1 record
/// carrying the field, which is why the field may only appear under v2 (and
/// the new reader rejects v1 with the field). This characterizes the pinned
/// source; it is not an execution of an older binary.
#[test]
fn pre_change_decoder_rejects_the_declared_v2_contract_and_rebuilds() {
    let mut index = apc_terminal_fixture();
    apc_prove(&mut index, &apc_witness('f'));
    let saved = serde_json::to_value(&index).unwrap();
    let records = &saved["claude_usage_authority_quarantine"];
    assert!(records[APC_ROOT].get("proof_correction").is_some());
    let accepted = previous_release_0_1_173::loader_accepts_authority_records(
        records,
        &index.claude_usage_family_witnesses,
    )
    .expect("no deny_unknown_fields: the old serde decode itself succeeds");
    assert!(!accepted, "the old predicate rejects contract v2");

    let mut stranded = records.clone();
    stranded[APC_ROOT]["contract"] = json!(CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION);
    assert!(
        previous_release_0_1_173::loader_accepts_authority_records(
            &stranded,
            &index.claude_usage_family_witnesses,
        )
        .unwrap(),
        "an undeclared field would be silently dropped by the old reader"
    );
    let dropped: Value = serde_json::from_str(&previous_release_0_1_173::reencode(
        &stranded[APC_ROOT].to_string(),
    ))
    .unwrap();
    assert!(dropped.get("proof_correction").is_none());

    // The old loader's invalid branch used this shared quarantine helper.
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-old-reader");
    let path = scratch.join("index.json");
    index.save(&path).unwrap();
    let encoded_index_bytes = fs::metadata(&path).unwrap().len();
    let files = index.files.len();
    let accepted_entities = index.accepted_snapshot_fingerprints.len();
    let rebuilt =
        quarantine_invalid_scan_index(&path, "decode", None, None, None, SystemTime::now())
            .unwrap();
    assert!(!path.exists());
    assert!(rebuilt.files.is_empty());
    for slot in 0..2 {
        assert_eq!(
            apc_decision(&rebuilt, &apc_candidate(&index, slot)),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::NewFile)
            ),
            "the rebuild reparses every discovered file"
        );
    }
    apc_emit(json!({
        "receipt": "claude_authority_correction_old_reader:v1",
        "decoder": "source_pinned_0_1_173_896b98f6_record_and_predicate",
        "release_version": "0.1.173",
        "release_source_commit": "896b98f6b7347251b35c2d13cd462b132cd99d84",
        "old_binary_executed": false,
        "synthetic_encoded_index_bytes": encoded_index_bytes,
        "v2_record_serde_decode_ok": true,
        "v2_record_old_predicate_accepts": accepted,
        "rebuild_reparsed_file_count": files,
        "rebuild_lost_accepted_entity_count": accepted_entities,
    }));
}

/// Partial checkpoint (shed): the committable subset keeps the correction
/// with every member whose corrected body is not durably settled, binds it to
/// the retained proof, and reloads intact while the unACKed file reverts.
#[test]
fn partial_checkpoint_subset_keeps_every_unsettled_owed_member() {
    let previous = apc_terminal_fixture();
    let mut current = previous.clone();
    apc_prove(&mut current, &apc_witness('f'));
    let [root_key, agent_key] = apc_keys();
    // The root's corrected body was ACKed and its drain recorded; the agent's
    // corrected body was offered and shed.
    let root_body = apc_hex('6');
    let agent_body = apc_hex('8');
    for (key, body) in [(&root_key, &root_body), (&agent_key, &agent_body)] {
        current
            .files
            .get_mut(key)
            .unwrap()
            .last_snapshot_fingerprint = Some(body.clone());
        current
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([body.clone()]));
        current
            .snapshot_activity_at
            .insert(body.clone(), Some(APC_WINDOW.to_string()));
    }
    current
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
        .unwrap()
        .proof_correction
        .as_mut()
        .unwrap()
        .owed_member_ids
        .remove(APC_ROOT);
    let subset = current.committable_subset(
        &previous,
        &BTreeSet::from([root_body.clone()]),
        &BTreeMap::new(),
    );
    assert_eq!(
        apc_owed(&subset),
        Some(BTreeSet::from([apc_members()[1].clone()])),
        "the shed member stays owed"
    );
    assert_eq!(apc_record(&subset), apc_record(&current));
    assert_eq!(
        subset.file_snapshot_fingerprints[&agent_key],
        previous.file_snapshot_fingerprints[&agent_key],
        "the unACKed body is not committed"
    );
    assert_eq!(
        subset.file_snapshot_fingerprints[&root_key],
        BTreeSet::from([root_body])
    );
    let mut subset = subset;
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-subset");
    let loaded = apc_save_reload(&mut subset, &scratch.join("index.json"));
    assert_eq!(
        apc_decision(&loaded, &apc_candidate(&loaded, 1)),
        PARSE_FOR_AUTHORITY,
        "the shed member is parsed again after restart"
    );
}

// ---------------------------------------------------------------------------
// No-body completion, the empty map advance with its
// restoration seams, and the accepted-body no-op as CONTROLLED
// state-machine tests: the granted record and each page's file facts are
// seeded, so none of these is a natural pipeline run. Every transition under
// test is made by production code, in `finish_sync_source` order: a page's
// parse goes through `ScanIndex::record` and the real finalizer, then the map
// advance; a completed page, or a later page of a complete census, through
// the current-page no-body drain; a shed through partial-checkpoint selection, which is
// `committable_subset` followed by the no-body drain exactly as the locked
// checkpoint orders them, or through borrowed and consuming held
// restoration; a restart through a save and a strict reload. The real locked
// checkpoint and natural pages run in the pipeline tests.

/// Rebound state: every recorded member owes a correction under proof F.
fn apc_granted() -> ScanIndex {
    let mut index = apc_terminal_fixture();
    apc_prove(&mut index, &apc_witness('f'));
    index
}

/// An earlier exact settlement of `member`, leaving another member owed.
fn apc_settled(index: &mut ScanIndex, member: &str) {
    let correction = index
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
        .unwrap()
        .proof_correction
        .as_mut()
        .unwrap();
    assert!(correction.owed_member_ids.remove(member));
    assert!(!correction.owed_member_ids.is_empty());
}

fn apc_map(index: &ScanIndex) -> BTreeMap<String, String> {
    apc_record(index).member_source_file_fingerprints.clone()
}

/// The record without its member map and owed set: contract, proof, counter,
/// disposition, deadline and correction proof.
fn apc_frame(
    index: &ScanIndex,
) -> (
    String,
    String,
    u8,
    ClaudeUsageAuthorityQuarantineDisposition,
    u64,
    Option<String>,
) {
    let record = apc_record(index);
    (
        record.contract.clone(),
        record.proven_witness_fingerprint.clone(),
        record.failed_reconstruction_count,
        record.disposition,
        record.retry_after_unix_seconds,
        record
            .proof_correction
            .as_ref()
            .map(|correction| correction.proof_witness_fingerprint.clone()),
    )
}

/// The whole saved index except the authority records.
fn apc_outside(index: &ScanIndex) -> Value {
    let mut value = serde_json::to_value(index).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("claude_usage_authority_quarantine");
    value
}

/// Accepted bodies, their ledger, quarantined bodies, every file's current
/// entities and the retained proof: the debt no correction seam may touch.
fn apc_debts(index: &ScanIndex) -> Value {
    json!({
        "accepted": index.accepted_snapshot_fingerprints,
        "ledger": index.accepted_snapshot_fingerprint_ledger_version,
        "quarantined": index.quarantined_snapshot_fingerprints,
        "entities": index.file_snapshot_fingerprints,
        "witnesses": index.claude_usage_family_witnesses,
    })
}

/// A real Claude scan result (of an empty directory) carrying exactly this
/// page's census flag and per-file finalization facts.
fn apc_scan(census_complete: bool, pending: Vec<PendingIndexFinalization>) -> SourceScanResult {
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-page");
    let mut unrelated = ScanIndex::default();
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &mut unrelated,
        APC_WINDOW,
        365,
        10,
    )
    .expect("empty synthetic scan");
    scan.snapshots.clear();
    scan.census_complete = census_complete;
    scan.pending_finalization = pending;
    scan
}

fn apc_pending(
    slot: usize,
    revision: &str,
    parse_complete: bool,
    parsed_snapshot_count: usize,
) -> PendingIndexFinalization {
    PendingIndexFinalization {
        withheld_content: None,
        sampled_audit_verified: false,
        codex_pending_recovery: false,
        index_key: apc_keys()[slot].clone(),
        source_file_fingerprint: revision.to_string(),
        previous_snapshot_fingerprint: None,
        previous_upload_body_witness: None,
        parse_complete,
        diagnostic_reason: if parse_complete {
            FileReason::Complete
        } else {
            FileReason::ReadOrLineLoss
        },
        parsed_snapshot_count,
        effective_upload_body_witness_revision: 0,
    }
}

/// One page whose only parse is member `slot` at `revision`, complete and
/// valid with no entity: the scanner's index record, the real finalizer, then
/// the A1 advance.
fn apc_empty_page(
    index: &mut ScanIndex,
    slot: usize,
    revision: &str,
    census_complete: bool,
) -> SourceScanResult {
    let mut candidate = apc_candidate(index, slot);
    candidate.source_file_fingerprint = revision.to_string();
    index.record(candidate, None, ScanParseOutcome::ConfirmedEmpty);
    let mut scan = apc_scan(census_complete, vec![apc_pending(slot, revision, true, 0)]);
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        index,
        snapshot_upload_body_witness,
    );
    assert!(scan.snapshots.is_empty(), "an empty parse offers no body");
    index.advance_empty_claude_proof_corrections(&scan);
    scan
}

/// A later page that parses no family member: its no-body drain settles the
/// saved empty pairs only when the census is complete.
fn apc_later_page(index: &mut ScanIndex, census_complete: bool) {
    index.settle_empty_claude_proof_corrections(&apc_scan(census_complete, Vec::new()));
}

fn apc_quarantine_bytes(index: &ScanIndex) -> Vec<u8> {
    serde_json::to_vec(&index.claude_usage_authority_quarantine).unwrap()
}

/// No-body completion. A member whose current recorded revision
/// parses complete, valid and empty drains as a no-body completion only when
/// the census is complete, offering nothing to upload; only the correction
/// changes. At an incomplete census the paired facts persist, and a later page
/// of a complete census drains them after restart.
#[test]
fn m2_current_revision_empty_member_drains_without_a_body_only_at_a_complete_census() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let current = apc_revisions()[0].clone();
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-m2");
    for complete in [true, false] {
        let mut index = apc_granted();
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let scan = apc_empty_page(&mut index, 0, &current, complete);
        assert!(index.confirmed_empty_files.contains(&root_key));
        assert_eq!(apc_map(&index)[&root], current);
        let outside = apc_outside(&index);
        let frame = apc_frame(&index);
        index.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(apc_outside(&index), outside, "M2 changes only the grant");
        assert_eq!(apc_frame(&index), frame);
        assert_eq!(index.accepted_snapshot_fingerprints, accepted);
        let expected = if complete {
            BTreeSet::from([agent.clone()])
        } else {
            BTreeSet::from([root.clone(), agent.clone()])
        };
        assert_eq!(apc_owed(&index), Some(expected), "complete={complete}");
        let mut loaded = apc_save_reload(&mut index, &scratch.join(format!("{complete}.json")));
        if !complete {
            apc_later_page(&mut loaded, true);
            assert_eq!(apc_owed(&loaded), Some(BTreeSet::from([agent.clone()])));
            assert_eq!(apc_frame(&loaded), frame);
            assert_eq!(loaded.accepted_snapshot_fingerprints, accepted);
        }
    }
}

/// No-body completion and restoration refusals (unsafe combinations).
/// Confirmation at an older revision, a legacy entry with no
/// snapshot and no confirmation, a failed read at the recorded revision, an
/// incomplete census, a map advanced past a restored entry, and an empty
/// entry and mark the map never advanced to: each stays owed through the
/// advance, the current-page drain and a later page of a complete census
/// (an incomplete one where the read failed), and reloads intact. The last
/// shape then advances on its own same-pass empty parse and drains.
#[test]
fn m2_older_legacy_failed_partial_and_unpaired_empty_facts_stay_owed() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let current = apc_revisions()[0].clone();
    let older = apc_hex('0');
    let advanced = apc_hex('4');
    let both = BTreeSet::from([root.clone(), agent.clone()]);
    let empty_entry = |index: &mut ScanIndex, revision: &str, confirmed: bool| {
        let entry = index.files.get_mut(&root_key).unwrap();
        entry.source_file_fingerprint = revision.to_string();
        entry.last_snapshot_fingerprint = None;
        entry.last_upload_body_witness = None;
        index.file_snapshot_fingerprints.remove(&root_key);
        if confirmed {
            index.confirmed_empty_files.insert(root_key.clone());
        }
    };
    let set_map = |index: &mut ScanIndex, revision: &str| {
        index
            .claude_usage_authority_quarantine
            .get_mut(APC_ROOT)
            .unwrap()
            .member_source_file_fingerprints
            .insert(root.clone(), revision.to_string());
    };
    type Shape<'a> = Box<dyn Fn(&mut ScanIndex) + 'a>;
    let cases: Vec<(&str, Shape, bool, Vec<PendingIndexFinalization>, bool)> = vec![
        (
            "older-revision",
            Box::new(|index: &mut ScanIndex| empty_entry(index, &older, true)),
            true,
            Vec::new(),
            true,
        ),
        (
            "legacy-none",
            Box::new(|index: &mut ScanIndex| empty_entry(index, &current, false)),
            true,
            Vec::new(),
            true,
        ),
        (
            "failed-read",
            Box::new(|index: &mut ScanIndex| empty_entry(index, &current, true)),
            true,
            vec![apc_pending(0, &current, false, 0)],
            false,
        ),
        (
            "partial-census",
            Box::new(|index: &mut ScanIndex| empty_entry(index, &current, true)),
            false,
            vec![apc_pending(0, &current, true, 0)],
            false,
        ),
        (
            "map-advanced-entry-restored",
            Box::new(|index: &mut ScanIndex| set_map(index, &advanced)),
            true,
            Vec::new(),
            true,
        ),
        (
            "entry-and-mark-without-map",
            Box::new(|index: &mut ScanIndex| empty_entry(index, &advanced, true)),
            true,
            Vec::new(),
            true,
        ),
    ];
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-m2-refusals");
    for (case, shape, scan_complete, pending, apply_complete) in cases {
        let mut index = apc_granted();
        shape(&mut index);
        let before = apc_quarantine_bytes(&index);
        let scan = apc_scan(scan_complete, pending);
        index.advance_empty_claude_proof_corrections(&scan);
        index.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(apc_quarantine_bytes(&index), before, "{case}: page seams");
        let mut loaded = apc_save_reload(&mut index, &scratch.join(format!("{case}.json")));
        apc_later_page(&mut loaded, apply_complete);
        assert_eq!(apc_owed(&loaded), Some(both.clone()), "{case}: stays owed");
        assert_eq!(apc_frame(&loaded), apc_frame(&index), "{case}");
        if case == "entry-and-mark-without-map" {
            // The next same-pass empty parse pairs the map, then drains.
            apc_empty_page(&mut loaded, 0, &advanced, false);
            assert_eq!(apc_map(&loaded)[&root], advanced);
            apc_later_page(&mut loaded, true);
            assert_eq!(apc_owed(&loaded), Some(BTreeSet::from([agent.clone()])));
        }
    }
}

/// A saved empty pair is not this page's current result when the same file
/// has an unsettled read. Exercise the production scan-aware authority seam,
/// including a failed newer revision that produced no snapshot at all.
#[test]
fn current_page_reads_defer_a_previously_durable_empty_pair_until_settlement() {
    let [root, agent] = apc_members();
    let current = apc_revisions()[0].clone();
    let newer = apc_hex('4');
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-current-empty");
    for (case, revision, complete, count) in [
        ("same-failed", current.as_str(), false, 0),
        ("newer-failed", newer.as_str(), false, 0),
        ("newer-nonempty", newer.as_str(), true, 1),
    ] {
        let mut index = apc_granted();
        apc_empty_page(&mut index, 0, &current, false);
        let path = scratch.join(format!("{case}.json"));
        let mut index = apc_save_reload(&mut index, &path);
        let before = apc_quarantine_bytes(&index);
        let mut scan = apc_scan(true, vec![apc_pending(0, revision, complete, count)]);
        let _ = apply_claude_reported_usage_to_scan_with_identity(
            &mut scan,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            &mut index,
            None,
        );
        assert_eq!(
            apc_quarantine_bytes(&index),
            before,
            "{case}: no early drain"
        );
        index.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(
            apc_owed(&index),
            Some(BTreeSet::from([root.clone(), agent.clone()]))
        );
        let loaded = apc_save_reload(&mut index, &path);
        assert_eq!(apc_quarantine_bytes(&loaded), before, "{case}: restart");
    }
}

/// A1 then A3 (Addendum 4 acceptance 1 and 5). A new empty revision parsed on
/// an earlier partial page advances only the member's map revision, with the
/// owed set, counter, deadline, proof and every acceptance and entity debt
/// byte-identical; the three facts persist together through restart; the
/// next page of a complete census then drains the member with no upload.
#[test]
fn a1_earlier_partial_empty_page_advances_only_the_map_then_a_complete_census_drains() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let new = apc_hex('4');
    let mut index = apc_granted();
    let owed = apc_owed(&index);
    let frame = apc_frame(&index);
    let agent_revision = apc_map(&index)[&agent].clone();
    let mut candidate = apc_candidate(&index, 0);
    candidate.source_file_fingerprint = new.clone();
    index.record(candidate, None, ScanParseOutcome::ConfirmedEmpty);
    let mut scan = apc_scan(false, vec![apc_pending(0, &new, true, 0)]);
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        &mut index,
        snapshot_upload_body_witness,
    );
    let outside = apc_outside(&index);
    let debts = apc_debts(&index);
    index.advance_empty_claude_proof_corrections(&scan);
    assert_eq!(apc_outside(&index), outside, "A1 advances only the map");
    assert_eq!(apc_debts(&index), debts);
    assert_eq!(apc_frame(&index), frame);
    assert_eq!(apc_owed(&index), owed, "the advanced member stays owed");
    assert_eq!(apc_map(&index)[&root], new);
    assert_eq!(apc_map(&index)[&agent], agent_revision);
    index.settle_empty_claude_proof_corrections(&scan);
    assert_eq!(
        apc_owed(&index),
        owed,
        "an incomplete census drains nothing"
    );

    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-a1");
    let mut loaded = apc_save_reload(&mut index, &scratch.join("advanced.json"));
    assert!(loaded.confirmed_empty_files.contains(&root_key));
    assert_eq!(loaded.files[&root_key].source_file_fingerprint, new);
    assert_eq!(apc_map(&loaded)[&root], new);
    assert_eq!(
        apc_decision(&loaded, &apc_candidate(&loaded, 0)),
        PARSE_FOR_AUTHORITY,
        "an owed member is still re-read until it drains"
    );
    apc_later_page(&mut loaded, true);
    assert_eq!(apc_owed(&loaded), Some(BTreeSet::from([agent])));
    assert_eq!(apc_frame(&loaded), frame);
    assert_eq!(apc_debts(&loaded), debts);
    apc_save_reload(&mut loaded, &scratch.join("advanced.json"));
}

/// A3 control (Addendum 4 acceptance 2 and 5). The committed state holds an
/// older empty entry while the record holds a newer revision; this page
/// parses that newer revision to a body a hold keeps from the upload. Neither
/// the non-empty parse nor borrowed or consuming held restoration of the old
/// empty entry advances the map, and neither the current-page drain nor a
/// later page of a complete census after restart drains the member.
#[test]
fn a3_held_restoration_of_an_older_empty_entry_never_advances_or_drains() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let older = apc_hex('0');
    let held_revision = apc_hex('5');
    let held_body = apc_hex('8');
    let mut previous = apc_granted();
    {
        let entry = previous.files.get_mut(&root_key).unwrap();
        entry.source_file_fingerprint = older.clone();
        entry.last_snapshot_fingerprint = None;
        entry.last_upload_body_witness = None;
    }
    previous.file_snapshot_fingerprints.remove(&root_key);
    previous.confirmed_empty_files.insert(root_key.clone());
    previous
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
        .unwrap()
        .member_source_file_fingerprints
        .insert(root.clone(), held_revision.clone());

    let mut current = previous.clone();
    let mut candidate = apc_candidate(&current, 0);
    candidate.source_file_fingerprint = held_revision.clone();
    current.record(
        candidate,
        Some(held_body.clone()),
        ScanParseOutcome::Snapshot,
    );
    // The finalizer's record of the parsed entity.
    current
        .file_snapshot_fingerprints
        .insert(root_key.clone(), BTreeSet::from([held_body.clone()]));
    let scan = apc_scan(true, vec![apc_pending(0, &held_revision, true, 1)]);
    current.advance_empty_claude_proof_corrections(&scan);
    assert_eq!(apc_map(&current)[&root], held_revision);

    let held = BTreeSet::from([held_body]);
    let mut restored = current.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    assert_eq!(restored.files[&root_key].source_file_fingerprint, older);
    assert!(restored.confirmed_empty_files.contains(&root_key));
    assert_eq!(apc_map(&restored)[&root], held_revision);
    let before = apc_quarantine_bytes(&restored);
    restored.settle_empty_claude_proof_corrections(&scan);
    assert_eq!(apc_quarantine_bytes(&restored), before);
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-a3-stale");
    let mut loaded = apc_save_reload(&mut restored, &scratch.join("index.json"));
    apc_later_page(&mut loaded, true);
    assert_eq!(
        apc_owed(&loaded),
        Some(BTreeSet::from([root, agent])),
        "a stale empty entry never completes a newer revision"
    );
}

/// Restoration and the settlement-order regression: the
/// LAST owed member has an accepted non-empty prior entity, and its new empty
/// revision advances the map on a page that is then shed. The checkpoint's
/// selection restores the prior entry and empty mark, so the map rolls back
/// with them, at an incomplete and at a complete census; the record, its last
/// owed member and the prior entity, acceptance and ACK debt all stay, through
/// restart and a later complete census. Held restoration of an unrelated held
/// body carries the paired advance intact.
#[test]
fn a2_shed_after_an_empty_advance_rolls_the_map_back_and_keeps_the_last_owed_member() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let new = apc_hex('4');
    let mut committed = apc_granted();
    apc_settled(&mut committed, &agent);
    let committed_entry = serde_json::to_value(&committed.files[&root_key]).unwrap();
    let committed_revision = apc_map(&committed)[&root].clone();
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-a2-rollback");
    for complete in [false, true] {
        let mut index = committed.clone();
        let scan = apc_empty_page(&mut index, 0, &new, complete);
        assert_eq!(
            apc_map(&index)[&root],
            new,
            "A1 advanced with the empty facts"
        );
        let mut subset = index.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
        subset.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(
            serde_json::to_value(&subset.files[&root_key]).unwrap(),
            committed_entry,
            "complete={complete}: the prior entity's entry is restored"
        );
        assert!(!subset.confirmed_empty_files.contains(&root_key));
        assert_eq!(
            apc_map(&subset)[&root],
            committed_revision,
            "complete={complete}: the map rolls back with the entry"
        );
        assert_eq!(
            apc_owed(&subset),
            Some(BTreeSet::from([root.clone()])),
            "complete={complete}: the last owed member stays owed"
        );
        assert_eq!(apc_frame(&subset), apc_frame(&committed));
        assert_eq!(apc_debts(&subset), apc_debts(&committed));
        let mut loaded =
            apc_save_reload(&mut subset, &scratch.join(format!("shed-{complete}.json")));
        apc_later_page(&mut loaded, true);
        assert_eq!(apc_owed(&loaded), Some(BTreeSet::from([root.clone()])));
        assert_eq!(apc_debts(&loaded), apc_debts(&committed));
        assert_eq!(
            apc_decision(&loaded, &apc_candidate(&loaded, 0)),
            PARSE_FOR_AUTHORITY
        );
    }

    let mut index = committed.clone();
    apc_empty_page(&mut index, 0, &new, false);
    let held = BTreeSet::from([apc_hex('d')]);
    let borrowed = index.with_locally_held_keys_reverted(&committed, &held, &BTreeSet::new());
    assert_eq!(borrowed.files[&root_key].source_file_fingerprint, new);
    assert!(borrowed.confirmed_empty_files.contains(&root_key));
    assert_eq!(
        apc_map(&borrowed)[&root],
        new,
        "the paired advance is carried"
    );
}

/// Restoration carriage: the LAST owed member has
/// no prior entity (a delivery-free entry). Its empty advance on a shed page
/// is carried by the checkpoint selection together with the file entry and
/// empty mark, persists through restart, and a later page of a complete census
/// drains it and clears the record.
#[test]
fn a2_partial_save_without_a_prior_entity_carries_the_pair_and_drains_at_a_complete_census() {
    let [root, agent] = apc_members();
    let [_, agent_key] = apc_keys();
    let new = apc_hex('4');
    let mut committed = apc_granted();
    apc_settled(&mut committed, &root);
    {
        let entry = committed.files.get_mut(&agent_key).unwrap();
        entry.last_snapshot_fingerprint = None;
        entry.last_upload_body_witness = None;
    }
    // This member starts delivery-free. Do not seed an orphan accepted
    // entity: ordinary checkpoint reconciliation correctly prunes one.
    if let Some(entities) = committed.file_snapshot_fingerprints.remove(&agent_key) {
        for fingerprint in entities {
            committed
                .accepted_snapshot_fingerprints
                .remove(&fingerprint);
            committed.snapshot_activity_at.remove(&fingerprint);
        }
    }
    let mut index = committed.clone();
    let scan = apc_empty_page(&mut index, 1, &new, false);
    let mut subset = index.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
    subset.settle_empty_claude_proof_corrections(&scan);
    assert_eq!(subset.files[&agent_key].source_file_fingerprint, new);
    assert!(subset.confirmed_empty_files.contains(&agent_key));
    assert_eq!(apc_map(&subset)[&agent], new);
    assert_eq!(apc_owed(&subset), Some(BTreeSet::from([agent])));
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-a2-carry");
    let mut loaded = apc_save_reload(&mut subset, &scratch.join("shed.json"));
    apc_later_page(&mut loaded, true);
    assert!(
        !loaded
            .claude_usage_authority_quarantine
            .contains_key(APC_ROOT),
        "the last owed member's no-body completion clears the record"
    );
    assert_eq!(
        loaded.accepted_snapshot_fingerprints,
        committed.accepted_snapshot_fingerprints
    );
    apc_save_reload(&mut loaded, &scratch.join("shed.json"));
}

/// A3 (Addendum 4 acceptance 4 and 5): a complete non-empty parse at a new
/// revision never advances the map at any census; the changed revision takes
/// the existing R4 path, and the member stays owed through restart.
#[test]
fn a3_a_non_empty_parse_never_advances_the_map() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let changed = apc_hex('6');
    let body = apc_hex('9');
    let mut index = apc_granted();
    let before = apc_quarantine_bytes(&index);
    let mut candidate = apc_candidate(&index, 0);
    candidate.source_file_fingerprint = changed.clone();
    index.record(
        candidate.clone(),
        Some(body.clone()),
        ScanParseOutcome::Snapshot,
    );
    index
        .file_snapshot_fingerprints
        .insert(root_key.clone(), BTreeSet::from([body]));
    for complete in [false, true] {
        let scan = apc_scan(complete, vec![apc_pending(0, &changed, true, 1)]);
        index.advance_empty_claude_proof_corrections(&scan);
        index.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(apc_quarantine_bytes(&index), before, "complete={complete}");
    }
    assert_eq!(apc_decision(&index, &candidate), PARSE_FOR_AUTHORITY);
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-a3-nonempty");
    let mut loaded = apc_save_reload(&mut index, &scratch.join("index.json"));
    apc_later_page(&mut loaded, true);
    assert_eq!(apc_owed(&loaded), Some(BTreeSet::from([root, agent])));
}

/// The accepted-body no-op, distinct from an ACK, at the real settlement seam: a member whose
/// captured current-proof body is already accepted with the same file body set
/// drains with no upload and no acknowledgement. Without that prior
/// acceptance it drains only on its exact ACK; an ACK of another body, or a
/// changed body set, drains nothing.
#[test]
fn an_accepted_unchanged_body_drains_as_a_no_op_without_an_upload() {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let fingerprint = apc_hex('c');
    let body = apc_hex('7');
    let body_set = |witness: &str| {
        let mut digest = Sha256::new();
        update_length_prefixed(&mut digest, b"snapshot_file_upload_body_set:v1");
        update_length_prefixed(&mut digest, witness.as_bytes());
        format!("{:x}", digest.finalize())
    };
    let mut accepted = apc_granted();
    accepted
        .files
        .get_mut(&root_key)
        .unwrap()
        .last_upload_body_witness = Some(body_set(&body));
    let candidate = ClaudeProofCorrectionCandidate {
        index_key: root_key.clone(),
        root: APC_ROOT.to_string(),
        member: root.clone(),
        proof: apc_record(&accepted).proven_witness_fingerprint.clone(),
        revision: apc_revisions()[0].clone(),
        fingerprint: fingerprint.clone(),
        body_witness: body.clone(),
    };
    let settle = |previous: &ScanIndex, acks: &[(&str, &str)]| {
        let mut index = previous.clone();
        index.settle_claude_proof_corrections(
            previous,
            std::slice::from_ref(&candidate),
            &acks
                .iter()
                .map(|(fp, _)| fp.to_string())
                .collect::<BTreeSet<_>>(),
            &acks
                .iter()
                .map(|(fp, witness)| (fp.to_string(), witness.to_string()))
                .collect::<BTreeMap<_, _>>(),
        );
        apc_owed(&index)
    };
    let remaining = Some(BTreeSet::from([agent.clone()]));
    let both = Some(BTreeSet::from([root, agent]));
    assert_eq!(settle(&accepted, &[]), remaining, "no POST, no ACK: no-op");
    let mut unaccepted = accepted.clone();
    unaccepted
        .accepted_snapshot_fingerprints
        .remove(&fingerprint);
    assert_eq!(settle(&unaccepted, &[]), both, "an unaccepted body owes");
    assert_eq!(
        settle(&unaccepted, &[(fingerprint.as_str(), body.as_str())]),
        remaining,
        "the exact ACK drains it"
    );
    assert_eq!(
        settle(
            &unaccepted,
            &[(fingerprint.as_str(), apc_hex('2').as_str())]
        ),
        both,
        "an ACK of another body drains nothing"
    );
    let mut changed = accepted.clone();
    changed
        .files
        .get_mut(&root_key)
        .unwrap()
        .last_upload_body_witness = Some(body_set(&apc_hex('3')));
    assert_eq!(
        settle(&changed, &[]),
        both,
        "a changed body set is not a no-op"
    );
}

#[test]
fn terminal_refusal_requires_current_proof_revision_body_and_nonpartial_outcome() {
    let [root, agent] = apc_members();
    let key = apc_keys()[0].clone();
    let fp = apc_hex('c');
    let body = apc_hex('7');
    let mut base = apc_granted();
    base.accepted_snapshot_fingerprints.remove(&fp);
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, b"snapshot_file_upload_body_set:v1");
    update_length_prefixed(&mut digest, body.as_bytes());
    base.files.get_mut(&key).unwrap().last_upload_body_witness =
        Some(format!("{:x}", digest.finalize()));
    base.quarantined_snapshot_fingerprints.insert(
        fp.clone(),
        SnapshotQuarantineRecord {
            contract_retry_claims: None,
            reconstruction_contract: crate::snapshots::terminal_contract_retry::current_contract(),
            witness: snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            retry_after_unix_seconds: 0,
            upload_body_witness: Some(body.clone()),
            failed_reconstruction_count: MAX_SNAPSHOT_RECONSTRUCTION_FAILURES,
            disposition: SnapshotQuarantineDisposition::UnprovenTerminal,
        },
    );
    let candidate = ClaudeProofCorrectionCandidate {
        index_key: key.clone(),
        root: APC_ROOT.to_string(),
        member: root.clone(),
        proof: apc_record(&base).proven_witness_fingerprint.clone(),
        revision: apc_revisions()[0].clone(),
        fingerprint: fp.clone(),
        body_witness: body.clone(),
    };
    let scratch = crate::test_scratch::ScratchDir::new("apc-terminal-refusal");
    let path = scratch.join("before-settlement.json");
    let mut before = base.clone();
    let before = apc_save_reload(&mut before, &path);
    assert_eq!(
        apc_owed(&before),
        Some(BTreeSet::from([root.clone(), agent.clone()])),
        "restart before settlement keeps debt"
    );
    for case in [
        "permanent",
        "retryable",
        "superseded",
        "other-proof",
        "other-body",
        "partial",
    ] {
        let mut index = base.clone();
        let frame = apc_frame(&index);
        let mut item = candidate.clone();
        match case {
            "retryable" => {
                let quarantine = index
                    .quarantined_snapshot_fingerprints
                    .get_mut(&fp)
                    .unwrap();
                quarantine.disposition = SnapshotQuarantineDisposition::RetryPending;
                quarantine.failed_reconstruction_count = 1;
            }
            "superseded" => {
                index.files.get_mut(&key).unwrap().source_file_fingerprint = apc_hex('8')
            }
            "other-proof" => item.proof = apc_hex('9'),
            "other-body" => {
                index
                    .quarantined_snapshot_fingerprints
                    .get_mut(&fp)
                    .unwrap()
                    .upload_body_witness = Some(apc_hex('a'))
            }
            _ => {}
        }
        let outside = apc_outside(&index);
        if case == "partial" {
            index.settle_claude_proof_corrections(
                &base,
                &[item],
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
        } else {
            index.settle_claude_proof_corrections_with_permanent(
                &base,
                &[item],
                &BTreeSet::new(),
                &BTreeMap::new(),
                |fingerprint, witness| fingerprint == fp && witness == body,
            );
        }
        assert_eq!(
            apc_frame(&index),
            frame,
            "{case}: counters/deadline unchanged"
        );
        assert_eq!(
            apc_outside(&index),
            outside,
            "{case}: accepted/refusal/debt state unchanged"
        );
        let loaded = apc_save_reload(&mut index, &scratch.join(format!("{case}.json")));
        assert_eq!(
            apc_owed(&loaded),
            Some(if case == "permanent" {
                BTreeSet::from([agent.clone()])
            } else {
                BTreeSet::from([root.clone(), agent.clone()])
            }),
            "{case}"
        );
    }
}

fn apc_cutoff_item(revision: &str, activity: &str) -> SnapshotItem {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.source_session_id = APC_ROOT.to_string();
    item.source_file_fingerprint = Some(revision.to_string());
    item.attribution_facts.clear();
    item.usage_accounting_contract = Some("session_exclusive_reported_usage:v1".to_string());
    item.source_started_at = Some(activity.to_string());
    item.source_ended_at = Some(activity.to_string());
    item.source_last_activity_at = Some(activity.to_string());
    item
}

#[test]
fn cutoff_only_completion_carries_its_selected_empty_facts_or_stays_owed() {
    let [root, agent] = apc_members();
    let key = apc_keys()[0].clone();
    let revision = apc_hex('6');
    let cutoff = crate::backfill::BackfillState {
        backfill_cutoff_at: Some("2026-09-30T08:00:00Z".to_string()),
        ..Default::default()
    };
    let cutoff_bytes = serde_json::to_vec(&cutoff).unwrap();
    for rollback in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("apc-cutoff-restart");
        let path = scratch.join("index.json");
        let mut durable_before = apc_granted();
        let before = apc_save_reload(&mut durable_before, &path);
        assert_eq!(
            apc_owed(&before),
            Some(BTreeSet::from([root.clone(), agent.clone()]))
        );
        let mut index = before.clone();
        index.files.get_mut(&key).unwrap().source_file_fingerprint = revision.clone();
        let mut scan = apc_scan(true, vec![apc_pending(0, &revision, true, 1)]);
        scan.snapshots
            .push(apc_cutoff_item(&revision, "2026-09-30T07:00:00Z"));
        let mut candidates = index
            .capture_claude_cutoff_corrections(&scan, &ClaudeUsageAuthorityDisposition::default());
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            crate::backfill::apply_backfill_cutoff(&mut scan.snapshots, &cutoff),
            1
        );
        ScanIndex::retain_fully_cutoff_corrections(&mut candidates, &scan.snapshots);
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut index,
            snapshot_upload_body_witness,
        );
        if rollback {
            index.files.insert(key.clone(), before.files[&key].clone());
            index
                .file_snapshot_fingerprints
                .insert(key.clone(), before.file_snapshot_fingerprints[&key].clone());
            index.confirmed_empty_files.remove(&key);
        }
        let frame = apc_frame(&index);
        let outside = apc_outside(&index);
        // Current-page non-empty parses cannot borrow the no-body empty path.
        index.settle_empty_claude_proof_corrections(&scan);
        assert_eq!(
            apc_owed(&index),
            Some(BTreeSet::from([root.clone(), agent.clone()]))
        );
        index.settle_cutoff_claude_proof_corrections(&candidates);
        assert_eq!(apc_outside(&index), outside);
        assert_eq!(apc_frame(&index), frame);
        let loaded = apc_save_reload(&mut index, &path);
        assert_eq!(
            apc_owed(&loaded),
            Some(if rollback {
                BTreeSet::from([root.clone(), agent.clone()])
            } else {
                BTreeSet::from([agent.clone()])
            })
        );
        if !rollback {
            assert_eq!(apc_map(&loaded)[&root], revision);
        }
    }
    assert_eq!(serde_json::to_vec(&cutoff).unwrap(), cutoff_bytes);
}

#[test]
fn partial_cutoff_keeps_the_remaining_body_on_the_exact_ack_path() {
    let revision = apc_revisions()[0].clone();
    let before = apc_granted();
    for (complete, held, parsed_count) in [
        (true, false, 2),
        (false, false, 2),
        (true, true, 2),
        (true, false, 3),
    ] {
        let mut index = before.clone();
        let mut scan = apc_scan(
            true,
            vec![apc_pending(0, &revision, complete, parsed_count)],
        );
        scan.snapshots = vec![
            apc_cutoff_item(&revision, "2026-09-30T07:00:00Z"),
            apc_cutoff_item(&revision, "2026-09-30T09:00:00Z"),
        ];
        let mut disposition = ClaudeUsageAuthorityDisposition::default();
        if held {
            disposition
                .quarantined_source_session_ids
                .insert(APC_ROOT.to_string());
        }
        let mut cutoff_candidates = index.capture_claude_cutoff_corrections(&scan, &disposition);
        assert_eq!(
            cutoff_candidates.len(),
            usize::from(complete && !held && parsed_count == 2)
        );
        let cutoff = crate::backfill::BackfillState {
            backfill_cutoff_at: Some("2026-09-30T08:00:00Z".to_string()),
            ..Default::default()
        };
        assert_eq!(
            crate::backfill::apply_backfill_cutoff(&mut scan.snapshots, &cutoff),
            1
        );
        ScanIndex::retain_fully_cutoff_corrections(&mut cutoff_candidates, &scan.snapshots);
        assert!(
            cutoff_candidates.is_empty(),
            "one capturable item forbids a policy drain"
        );
        if !complete || held || parsed_count != 2 {
            continue;
        }
        let candidates = index.capture_claude_proof_corrections(
            &mut scan,
            &disposition,
            snapshot_upload_body_witness,
        );
        assert_eq!(candidates.len(), 1);
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut index,
            snapshot_upload_body_witness,
        );
        index.settle_cutoff_claude_proof_corrections(&cutoff_candidates);
        index.settle_claude_proof_corrections(
            &before,
            &candidates,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(apc_owed(&index), apc_owed(&before));
        let candidate = &candidates[0];
        index.settle_claude_proof_corrections(
            &before,
            &candidates,
            &BTreeSet::from([candidate.fingerprint.clone()]),
            &BTreeMap::from([(
                candidate.fingerprint.clone(),
                candidate.body_witness.clone(),
            )]),
        );
        assert_eq!(
            apc_owed(&index),
            Some(BTreeSet::from([apc_members()[1].clone()]))
        );
    }
}

fn apc_emit(line: Value) {
    use std::io::Write as _;
    std::io::stderr()
        .write_all(format!("{line}\n").as_bytes())
        .expect("allocation receipt");
}

/// Source-pinned pre-change decoder. The record type and its predicate are
/// copied (with rustfmt line wrapping) from `crates/ottto-service/src/snapshots.rs` at release source
/// 896b98f6b7347251b35c2d13cd462b132cd99d84 (release 0.1.173; blob 00ffefd4574e), lines
/// 2350-2370 and 2570-2595; they use the unchanged shared helpers, constants
/// and disposition enum. Only the authority conjuncts of that base's
/// `ScanIndex::load` guard (lines 22481-22495) are restated as a function.
/// This is source characterization, not an older binary.
mod previous_release_0_1_173 {
    use super::*;

    // BEGIN SOURCE-PINNED 0.1.173 896b98f6 snapshots.rs 2350-2370
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ClaudeUsageAuthorityQuarantineRecord {
        contract: String,
        /// Exact content-free digest of the last proven family witness. The
        /// witness itself remains in `claude_usage_family_witnesses`; this binding
        /// prevents a stale quarantine from being paired with a different proof.
        proven_witness_fingerprint: String,
        /// Exact scan fingerprints for every currently known family member. These
        /// contain no transcript content and let a changed revision bypass the
        /// timer while unchanged failures observe bounded retry cadence.
        member_source_file_fingerprints: BTreeMap<String, String>,
        /// Consecutive complete-family reconstruction failures for this retained
        /// witness. Older v1 records predate the field but already represent the
        /// initial failure, so deserialize them as one rather than granting an
        /// unbounded fresh budget after upgrade.
        #[serde(default = "initial_claude_usage_authority_failure_count")]
        failed_reconstruction_count: u8,
        #[serde(default)]
        disposition: ClaudeUsageAuthorityQuarantineDisposition,
        retry_after_unix_seconds: u64,
    }
    // END SOURCE-PINNED

    // BEGIN SOURCE-PINNED 0.1.173 896b98f6 snapshots.rs 2570-2595
    fn claude_usage_authority_deadline_is_bounded(
        record: &ClaudeUsageAuthorityQuarantineRecord,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        record.contract == CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION
            && sha256_hex_is_well_formed(&record.proven_witness_fingerprint)
            && !record.member_source_file_fingerprints.is_empty()
            && (1..=MAX_CLAUDE_USAGE_AUTHORITY_FAILURES)
                .contains(&record.failed_reconstruction_count)
            && match record.disposition {
                ClaudeUsageAuthorityQuarantineDisposition::RetryPending => {
                    record.failed_reconstruction_count < MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
                }
                ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal => {
                    record.failed_reconstruction_count == MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
                }
            }
            && record
                .member_source_file_fingerprints
                .values()
                .all(|fingerprint| sha256_hex_is_well_formed(fingerprint))
            && record.retry_after_unix_seconds
                <= now.saturating_add(CLAUDE_USAGE_AUTHORITY_RETRY_SECONDS.saturating_mul(2))
    }
    // END SOURCE-PINNED

    /// The base loader's authority conjuncts over the saved
    /// `claude_usage_authority_quarantine` map, decoded with the base record
    /// type exactly as the base `ScanIndex` field decodes it.
    pub(super) fn loader_accepts_authority_records(
        records: &Value,
        witnesses: &SharedMap<String, ClaudeUsageFamilyWitness>,
    ) -> serde_json::Result<bool> {
        let records: BTreeMap<String, ClaudeUsageAuthorityQuarantineRecord> =
            serde_json::from_value(records.clone())?;
        Ok(records
            .values()
            .all(claude_usage_authority_deadline_is_bounded)
            && records.iter().all(|(root_session_id, quarantine)| {
                witnesses.get(root_session_id).is_some_and(|witness| {
                    claude_usage_family_witness_fingerprint(witness)
                        == quarantine.proven_witness_fingerprint
                })
            }))
    }

    /// Decode one record with the base type and encode it again.
    pub(super) fn reencode(record: &str) -> String {
        let decoded: ClaudeUsageAuthorityQuarantineRecord =
            serde_json::from_str(record).expect("the base record decodes");
        serde_json::to_string(&decoded).unwrap()
    }
}

/// An index whose authority record is unbound: unbound on load or on save.
fn apc_unbound_fixture() -> ScanIndex {
    let mut index = apc_terminal_fixture();
    index.generation = 29;
    let record = index
        .claude_usage_authority_quarantine
        .get_mut(APC_ROOT)
        .unwrap();
    record.disposition = ClaudeUsageAuthorityQuarantineDisposition::RetryPending;
    record.failed_reconstruction_count = 1;
    record.proven_witness_fingerprint = apc_hex('9');
    let mut refusal = snapshot_quarantine_record(SnapshotSource::ClaudeCode);
    refusal.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
    refusal.retry_after_unix_seconds = 0;
    refusal.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    index
        .quarantined_snapshot_fingerprints
        .insert(apc_hex('7'), refusal.clone());
    refusal.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
    index
        .quarantined_snapshot_fingerprints
        .insert(apc_hex('8'), refusal);
    // An unrelated indexed file that must keep its revision.
    index.files.insert(
        "/synthetic/proof-correction/f2222222-2222-4222-8222-222222222222.jsonl".to_string(),
        apc_entry(&apc_hex('6'), &apc_hex('5')),
    );
    index
}

/// The fail-closed shape of `index`: only the authority record goes, and only
/// that family's indexed members are re-armed.
fn apc_without_unbound_record(index: &ScanIndex) -> Value {
    let mut expected = index.clone();
    expected.claude_usage_authority_quarantine.remove(APC_ROOT);
    for key in apc_keys() {
        expected
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    // Empty maps are omitted by ScanIndex's persisted representation.
    serde_json::to_value(expected).unwrap()
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn load_drops_unbound_authority_record_and_keeps_index() {
    let scratch = crate::test_scratch::ScratchDir::new("authority-load-containment");
    let index = apc_unbound_fixture();
    let expected = apc_without_unbound_record(&index);
    let (drops, rearmed) = claude_authority_drops_for_test();
    let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    let (loaded, quarantined) =
        apc_load_value(&scratch, "unbound", &serde_json::to_value(&index).unwrap());
    assert_eq!(
        diagnostics
            .finish()
            .claude_reread
            .authority_normalization_cleared,
        apc_keys().len() as u64
    );
    assert!(
        !quarantined,
        "one unbound record cannot quarantine the whole index"
    );
    assert_eq!(
        claude_authority_drops_for_test(),
        (drops + 1, rearmed + apc_keys().len()),
        "one record dropped; only its family's members re-armed"
    );
    assert_eq!(loaded.generation, 29);
    assert_eq!(loaded.snapshot_unproven_terminal_count(), 1);
    assert_eq!(loaded.snapshot_superseded_terminal_count(), 1);
    assert_eq!(serde_json::to_value(loaded).unwrap(), expected);
}

#[test]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn contained_unbound_authority_record_does_not_latch_claude_reemission_stop() {
    let scratch = crate::test_scratch::ScratchDir::new("authority-load-no-rebuild-stop");
    let index = apc_unbound_fixture();
    let path = scratch.join("index.json");
    fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
    let marker = ReemissionExclusions::seen_marker_path(&scratch);
    fs::create_dir_all(marker.parent().unwrap()).unwrap();
    fs::write(marker, "").unwrap();
    let loaded =
        ScanIndex::load_for_snapshot_source(&path, SnapshotSource::ClaudeCode, &scratch).unwrap();
    assert!(path.exists(), "the index was kept, not quarantined");
    assert_eq!(loaded.generation, 29);
    assert_eq!(
        serde_json::to_value(loaded).unwrap(),
        apc_without_unbound_record(&index)
    );
    assert!(!claude_reemission_stop_latched());
    assert_eq!(claude_reemission_stop_reason(), "none");
}

/// An existing orphan fails closed for its one record at save, in
/// debug and release alike; the save succeeds and the result loads as is.
#[test]
fn save_drops_existing_orphan_authority_record_and_succeeds() {
    let scratch = crate::test_scratch::ScratchDir::new("authority-save-containment");
    let path = scratch.join("index.json");
    let mut index = apc_unbound_fixture();
    index.generation = 0;
    let mut expected = apc_without_unbound_record(&index);
    expected["generation"] = json!(1);
    let (drops, rearmed) = claude_authority_drops_for_test();
    let diagnostics = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
    index
        .save(&path)
        .expect("an orphan record never fails the save");
    assert_eq!(
        diagnostics
            .finish()
            .claude_reread
            .authority_normalization_cleared,
        apc_keys().len() as u64
    );
    assert_eq!(
        claude_authority_drops_for_test(),
        (drops + 1, rearmed + apc_keys().len())
    );
    assert_eq!(serde_json::to_value(&index).unwrap(), expected);
    let (loaded, quarantined) = apc_load_value(
        &scratch,
        "saved",
        &serde_json::from_slice(&fs::read(&path).unwrap()).unwrap(),
    );
    assert!(!quarantined, "load accepts the saved result");
    assert_eq!(
        claude_authority_drops_for_test(),
        (drops + 1, rearmed + apc_keys().len()),
        "nothing is left to drop on load"
    );
    assert_eq!(serde_json::to_value(loaded).unwrap(), expected);
}

#[test]
fn empty_map_restore_never_removes_owed_member() {
    let scratch = crate::test_scratch::ScratchDir::new("authority-empty-restore");
    let mut index = apc_granted();
    let member = apc_members()[1].clone();
    let revision = apc_record(&index).member_source_file_fingerprints[&member].clone();
    index.restore_claude_empty_map_advances(vec![ClaudeEmptyMapAdvance {
        root: APC_ROOT.to_string(),
        member: member.clone(),
        key: apc_keys()[1].clone(),
        revision: revision.clone(),
        previous: None,
    }]);
    assert!(
        claude_authority_record_contract_is_valid(apc_record(&index)),
        "rollback keeps the owed member represented"
    );
    assert!(apc_owed(&index).unwrap().contains(&member));
    assert_ne!(
        apc_record(&index).member_source_file_fingerprints[&member],
        revision,
        "rolled-back empty facts cannot certify a revision"
    );
    apc_save_reload(&mut index, &scratch.join("index.json"));
}

/// R2 page, CONTROLLED: the committed grant owes the root (with the agent too,
/// unless `last_owed`), and the root's body is accepted. This page sees the
/// root at `revision` with the same entity and body set, as a family sidecar
/// touch leaves it, and its captured current-proof body no-op-drains on the
/// working index before save selection, as `finish_sync_source` orders it.
fn apc_r2_page(last_owed: bool, revision: &str) -> (ScanIndex, ScanIndex, ClaudeProofBodyDrains) {
    let [root, agent] = apc_members();
    let [root_key, _] = apc_keys();
    let fingerprint = apc_hex('c');
    let body = apc_hex('7');
    let mut committed = apc_granted();
    committed
        .files
        .get_mut(&root_key)
        .unwrap()
        .last_upload_body_witness = Some(snapshot_file_upload_body_set_hex([body.as_str()]));
    if last_owed {
        apc_settled(&mut committed, &agent);
    }
    let mut working = committed.clone();
    working
        .files
        .get_mut(&root_key)
        .unwrap()
        .source_file_fingerprint = revision.to_string();
    let candidate = ClaudeProofCorrectionCandidate {
        index_key: root_key.clone(),
        root: APC_ROOT.to_string(),
        member: root.clone(),
        proof: apc_record(&committed).proven_witness_fingerprint.clone(),
        revision: revision.to_string(),
        fingerprint,
        body_witness: body,
    };
    let drains = working.settle_claude_proof_corrections(
        &committed,
        std::slice::from_ref(&candidate),
        &BTreeSet::new(),
        &BTreeMap::new(),
    );
    assert!(
        !apc_owed(&working).is_some_and(|owed| owed.contains(&root)),
        "the no-op drains in memory, with no upload"
    );
    if last_owed {
        assert!(
            !working
                .claude_usage_authority_quarantine
                .contains_key(APC_ROOT),
            "the last owed member's drain clears the record"
        );
    } else {
        assert_eq!(apc_map(&working)[&root], revision);
    }
    (committed, working, drains)
}

/// R2 (main, production default): a no-op drain at a revision the partial
/// save does not select is reverted. The shed page restores the committed
/// entry, so the member stays owed with its pre-drain pair: the saved record
/// names the saved file's revision. Proof, counter, deadline and every
/// accepted body are unchanged, and the restarted index parses the
/// member again for its correction.
#[test]
fn r2_a_no_op_drain_whose_revision_the_partial_save_does_not_select_stays_owed() {
    let [root, _] = apc_members();
    let [root_key, _] = apc_keys();
    let moved = apc_hex('5');
    let scratch = crate::test_scratch::ScratchDir::new("proof-correction-r2-revert");
    for last_owed in [false, true] {
        let label = format!("last owed {last_owed}");
        let (committed, working, drains) = apc_r2_page(last_owed, &moved);
        let committed_revision = committed.files[&root_key].source_file_fingerprint.clone();
        assert_ne!(committed_revision, moved, "{label}: the revision moved");
        let mut subset = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            subset.files[&root_key].source_file_fingerprint, committed_revision,
            "{label}: nothing settled, so the save keeps the committed entry"
        );
        assert!(
            subset.restore_unselected_claude_proof_body_drains(drains),
            "{label}: the member owes again"
        );
        assert!(apc_owed(&subset).unwrap().contains(&root), "{label}");
        assert_eq!(
            apc_record(&subset),
            apc_record(&committed),
            "{label}: the pre-drain record: pair, owed set, proof, counter, deadline"
        );
        assert_eq!(
            apc_map(&subset)[&root],
            subset.files[&root_key].source_file_fingerprint,
            "{label}: the saved record names the saved file's revision"
        );
        assert_eq!(apc_debts(&subset), apc_debts(&committed), "{label}");
        let drops = claude_authority_drops_for_test();
        let loaded = apc_save_reload(&mut subset, &scratch.join(format!("shed-{last_owed}.json")));
        assert_eq!(
            claude_authority_drops_for_test(),
            drops,
            "{label}: the re-bound record is valid and bound; nothing is dropped"
        );
        assert_eq!(
            apc_decision(&loaded, &apc_candidate(&loaded, 0)),
            PARSE_FOR_AUTHORITY,
            "{label}: the owed member is parsed again after restart"
        );
    }
}

/// R2 controls. A drain whose revision the save does select is kept exactly
/// as before: with an unmoved revision the committed entry is that revision,
/// and with a moved one a save that carries the working entry (a page with
/// no holds) carries it. The restore changes nothing in either case.
#[test]
fn r2_a_drain_at_the_selected_revision_settles_exactly_as_before() {
    let [root, _] = apc_members();
    let [root_key, _] = apc_keys();
    let unmoved = apc_revisions()[0].clone();
    for last_owed in [false, true] {
        let label = format!("last owed {last_owed}");
        let (committed, working, drains) = apc_r2_page(last_owed, &unmoved);
        let mut subset = working.committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new());
        let selected = serde_json::to_vec(&subset).unwrap();
        assert!(
            !subset.restore_unselected_claude_proof_body_drains(drains),
            "{label}: an unmoved revision is selected"
        );
        assert_eq!(serde_json::to_vec(&subset).unwrap(), selected, "{label}");

        let (_, mut working, drains) = apc_r2_page(last_owed, &apc_hex('5'));
        let carried = serde_json::to_vec(&working).unwrap();
        assert!(
            !working.restore_unselected_claude_proof_body_drains(drains),
            "{label}: the carried working entry is the drained revision"
        );
        assert_eq!(serde_json::to_vec(&working).unwrap(), carried, "{label}");
        if !last_owed {
            assert_eq!(
                apc_map(&working)[&root],
                working.files[&root_key].source_file_fingerprint
            );
        }
    }
}
