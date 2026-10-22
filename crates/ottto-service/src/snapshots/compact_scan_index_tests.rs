// The scan index is written as compact JSON. Only the whitespace changes:
// values, generation fencing, CAS and every reader stay the same, and a
// legacy pretty file (all releases before this change) still loads. All
// fixtures are synthetic.
use super::*;
use crate::snapshots::claude_request_census::{
    decode_bounded_index, decode_index, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};

const HELD_ROOT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CENSUS_KEY: &str = "/census/projects/census-a.jsonl";
/// Quotes, backslashes, control characters and non-ASCII text, which both
/// formatters must escape identically.
const ESCAPED: &str = "caf\u{e9} \"quoted\" back\\slash \u{1F600} tab\t nl\n bell\u{7}";

fn hex(seed: char) -> String {
    seed.to_string().repeat(64)
}

/// One index carrying every proof-bearing section: a held Claude family
/// (bound authority record, usage witness and pending proof), account family
/// witness and pending proof, a request census record and its shadow, a
/// snapshot quarantine, accepted and body fingerprints, a live traversal and
/// escaped strings in keys and values. Returns the held family's transcript
/// candidate, which an unchanged index skips.
fn rich_index(root: &Path) -> (ScanIndex, CandidateFile) {
    let transcript = root.join(format!("{HELD_ROOT}.jsonl"));
    let key = local_index_key(&transcript);
    let escaped_key = format!("/synthetic/{ESCAPED}/rollout.jsonl");
    let revision = hex('a');
    let mut candidate = test_candidate(transcript);
    candidate.source_file_fingerprint = revision.clone();
    let mut index = ScanIndex::default();

    let mut entry = manifest_index_entry(Some(&hex('b')));
    entry.size_bytes = candidate.size_bytes;
    entry.modified_unix_seconds = candidate.modified_unix_seconds;
    entry.modified_unix_nanos = Some(candidate.modified_unix_nanos);
    entry.source_file_fingerprint = revision.clone();
    entry.last_upload_body_witness = Some(hex('9'));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    index.files.insert(key.clone(), entry);
    let mut escaped_entry = manifest_index_entry(Some(&hex('7')));
    escaped_entry.last_upload_body_witness = Some(hex('8'));
    index.files.insert(escaped_key.clone(), escaped_entry);
    let mut census_entry = manifest_index_entry(None);
    census_entry.source_file_fingerprint = hex('a');
    index.files.insert(CENSUS_KEY.to_string(), census_entry);
    index
        .file_snapshot_fingerprints
        .insert(escaped_key.clone(), BTreeSet::from([hex('7')]));
    index.snapshot_activity_at = BTreeMap::from([
        (hex('b'), Some("2026-08-01T10:00:00Z".to_string())),
        (hex('7'), Some("2026-08-02T10:00:00Z".to_string())),
        (hex('6'), None),
    ]);
    index.accepted_snapshot_fingerprints = BTreeSet::from([hex('b'), hex('7')]);
    index.accepted_snapshot_fingerprint_ledger_version = SNAPSHOT_ACCEPTED_LEDGER_VERSION;
    let mut quarantine = snapshot_quarantine_record(SnapshotSource::ClaudeCode);
    quarantine.upload_body_witness = Some(hex('5'));
    index
        .quarantined_snapshot_fingerprints
        .insert(hex('6'), quarantine);
    index
        .confirmed_empty_files
        .insert(format!("/synthetic/{ESCAPED}/empty.jsonl"));
    index
        .known_configured_scan_roots
        .insert(format!("/synthetic/{ESCAPED}"));
    index.resume_after_path = Some(format!("/synthetic/{ESCAPED}/resume"));

    let witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: format!("provider-evidence {ESCAPED}"),
        member_request_id_fingerprints: BTreeMap::from([(HELD_ROOT.to_string(), hex('1'))]),
        member_occurrence_fingerprints: BTreeMap::from([(HELD_ROOT.to_string(), hex('2'))]),
        assigned_request_id_fingerprints: BTreeMap::from([(HELD_ROOT.to_string(), hex('3'))]),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    let witness_fingerprint = claude_usage_family_witness_fingerprint(&witness);
    index
        .claude_usage_family_witnesses
        .insert(HELD_ROOT.to_string(), witness);
    index.claude_usage_authority_quarantine.insert(
        HELD_ROOT.to_string(),
        ClaudeUsageAuthorityQuarantineRecord {
            proof_correction: None,
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: witness_fingerprint.clone(),
            member_source_file_fingerprints: BTreeMap::from([(HELD_ROOT.to_string(), revision)]),
            failed_reconstruction_count: 1,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
            retry_after_unix_seconds: claude_usage_authority_retry_deadline(
                HELD_ROOT,
                &witness_fingerprint,
            ),
        },
    );
    let request_hashes =
        BTreeMap::from([(HELD_ROOT.to_string(), BTreeSet::from([hex('c'), hex('d')]))]);
    index.claude_usage_family_pending.insert(
        HELD_ROOT.to_string(),
        ClaudeUsageFamilyPending {
            census_window_end: "2026-08-01T00:00:00Z".to_string(),
            member_request_id_hashes: request_hashes.clone(),
            member_occurrences: BTreeMap::new(),
            invalid: false,
        },
    );
    index.claude_account_family_witnesses.insert(
        HELD_ROOT.to_string(),
        ClaudeAccountFamilyWitness {
            account_identifier_hash: hex('e'),
            evidence_request_count: 2,
            members: BTreeMap::from([(HELD_ROOT.to_string(), 2)]),
            member_request_id_fingerprints: BTreeMap::from([(HELD_ROOT.to_string(), hex('f'))]),
        },
    );
    index.claude_account_family_pending.insert(
        HELD_ROOT.to_string(),
        ClaudeAccountFamilyPending {
            census_window_end: "2026-08-01T00:00:00Z".to_string(),
            account_identifier_hash: hex('e'),
            evidence_request_count: 2,
            members: BTreeMap::from([(HELD_ROOT.to_string(), 2)]),
            member_request_id_hashes: request_hashes,
            invalid: false,
        },
    );
    index.claude_request_census_mut_for_test().insert_for_test(
        CENSUS_KEY,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &hex('a'),
            7,
            ClaudeRequestCensusShape::Exact,
            vec![1, u64::MAX],
        ),
    );
    index.claude_request_census_shadow =
        serde_json::from_value(serde_json::json!({"o": true, "f": 3, "d": 2}))
            .expect("census shadow");
    index.traversal = Some(ScanTraversalCheckpoint {
        context_fingerprint: hex('4'),
        census_window_end: "2026-08-01T00:00:00Z".to_string(),
        scan_roots: vec![root.to_path_buf()],
        pending_directories: VecDeque::new(),
        pending_candidates: VecDeque::new(),
        observed_index_keys: BTreeSet::from([key, escaped_key]),
        codex_rollout_paths: BTreeSet::new(),
        codex_join_directory_census: None,
        reconciliation_upper_bound: Some(format!("/synthetic/{ESCAPED}/upper")),
        reconciliation_after: None,
        reconciliation_started: true,
        watcher_hint_seen: false,
        codex_parent_resolution_retry_required: false,
        unhealthy_retry_attempt: 0,
        unhealthy_retry_not_before_unix_seconds: None,
        counts: ScanTraversalCounts::default(),
        residue: ScanTraversalResidue::default(),
    });
    (index, candidate)
}

/// The proof-bearing sections, compared field by field (ScanIndex itself has
/// no PartialEq), in addition to whole-value serialized equality.
fn assert_same_proof_state(actual: &ScanIndex, expected: &ScanIndex, name: &str) {
    assert_eq!(actual.generation, expected.generation, "{name}");
    assert_eq!(
        actual.claude_usage_family_pending, expected.claude_usage_family_pending,
        "{name}"
    );
    assert_eq!(
        actual.claude_usage_family_witnesses, expected.claude_usage_family_witnesses,
        "{name}"
    );
    assert_eq!(
        actual.claude_usage_authority_quarantine, expected.claude_usage_authority_quarantine,
        "{name}"
    );
    assert_eq!(
        actual.claude_account_family_pending, expected.claude_account_family_pending,
        "{name}"
    );
    assert_eq!(
        actual.claude_account_family_witnesses, expected.claude_account_family_witnesses,
        "{name}"
    );
    assert_eq!(
        actual.claude_request_census_for_test().get(CENSUS_KEY),
        expected.claude_request_census_for_test().get(CENSUS_KEY),
        "{name}"
    );
    assert!(actual
        .claude_request_census_for_test()
        .get(CENSUS_KEY)
        .is_some());
    assert_eq!(
        actual.claude_request_census_shadow, expected.claude_request_census_shadow,
        "{name}"
    );
    assert_eq!(
        actual.claude_request_census_shadow.would_open_for_test(),
        Some(true)
    );
    assert_eq!(
        actual.quarantined_snapshot_fingerprints, expected.quarantined_snapshot_fingerprints,
        "{name}"
    );
    assert_eq!(
        actual.accepted_snapshot_fingerprints, expected.accepted_snapshot_fingerprints,
        "{name}"
    );
    assert_eq!(
        actual.resume_after_path, expected.resume_after_path,
        "{name}"
    );
    assert!(actual
        .resume_after_path
        .as_deref()
        .is_some_and(|path| path.contains(ESCAPED)));
}

#[test]
fn compact_and_legacy_pretty_scan_index_decode_to_identical_state() {
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-decode");
    let (index, _) = rich_index(&scratch);
    let compact = serde_json::to_vec(&index).expect("compact index");
    let pretty = serde_json::to_vec_pretty(&index).expect("pretty index");
    assert!(compact.len() < pretty.len());
    // Compact output has no whitespace outside strings; escapes stay escapes.
    assert!(!compact.contains(&b'\n'));
    let compact_text = String::from_utf8(compact.clone()).expect("utf8");
    assert!(compact_text.contains(r#"\"quoted\" back\\slash"#));
    assert!(compact_text.contains(r"tab\t nl\n bell\u0007"));
    for (name, bytes) in [("compact", &compact), ("pretty", &pretty)] {
        // The streaming census reader (ScanIndex::load and the save CAS) and
        // the bounded reader (bounded retry CAS) both accept either layout.
        let streamed = decode_index(bytes.as_slice()).expect(name);
        let bounded = decode_bounded_index(bytes).expect(name);
        for (reader, decoded) in [("streamed", &streamed), ("bounded", &bounded)] {
            let label = format!("{name}/{reader}");
            assert_same_proof_state(decoded, &index, &label);
            assert_eq!(
                serde_json::to_vec(decoded).expect("re-encode"),
                compact,
                "{label}"
            );
            assert_eq!(
                serde_json::to_vec_pretty(decoded).expect("re-encode pretty"),
                pretty,
                "{label}"
            );
        }
    }
}

#[test]
fn legacy_pretty_scan_index_loads_and_next_save_is_compact_and_cas_fenced() {
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-switch");
    let path = scratch.join("claude_code-scan-index-v3.json");
    let (mut legacy, _) = rich_index(&scratch);
    // Generation 4 as last written by an older (pretty) daemon.
    legacy.generation = 4;
    let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("legacy bytes");
    fs::write(&path, &legacy_bytes).expect("write legacy pretty index");

    let mut current = ScanIndex::load(&path).expect("legacy pretty index loads");
    assert_same_proof_state(&current, &legacy, "legacy load");
    // Loading never migrates or rewrites the file.
    assert_eq!(fs::read(&path).expect("legacy file"), legacy_bytes);
    let mut stale = ScanIndex::load(&path).expect("second writer at generation 4");

    current.save(&path).expect("next ordinary save");
    assert_eq!(current.generation, 5);
    let saved = fs::read(&path).expect("compact file");
    assert_eq!(saved, serde_json::to_vec(&current).expect("compact bytes"));
    assert!(!saved.contains(&b'\n'));
    assert!(saved.len() < legacy_bytes.len());
    let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
    assert!(!temp_path.exists());

    // A writer still holding the pretty file's generation stays fenced after
    // the format switch, and its failed save leaves the compact file intact.
    stale.resume_after_path = Some("stale".to_string());
    stale
        .save(&path)
        .expect_err("stale generation must not clobber the compact winner");
    assert_eq!(stale.generation, 4);
    stale
        .save_with_read_limit(&path, crate::snapshot_retry::RESPONSE_BYTES)
        .expect_err("the bounded CAS reader fences it too");
    assert_eq!(stale.generation, 4);
    assert_eq!(fs::read(&path).expect("winner bytes"), saved);
    assert!(!temp_path.exists());

    let mut reloaded = ScanIndex::load(&path).expect("compact index loads");
    assert_same_proof_state(&reloaded, &current, "compact load");
    assert_eq!(reloaded.generation, 5);
    // The bounded CAS reader accepts the compact file and still advances.
    reloaded
        .save_with_read_limit(&path, crate::snapshot_retry::RESPONSE_BYTES)
        .expect("bounded save over the compact file");
    assert_eq!(reloaded.generation, 6);
    assert_eq!(
        fs::read(&path).expect("bounded save bytes"),
        serde_json::to_vec(&reloaded).expect("compact bytes")
    );
    current
        .save(&path)
        .expect_err("generation 5 is fenced by the bounded save");
    assert_eq!(current.generation, 5);
}

#[test]
fn released_serde_loaders_read_the_compact_scan_index() {
    // Every release before #664 loaded the index with serde_json::from_reader
    // (on the File, later through a BufReader); #664 onward use decode_index.
    // None of them depend on whitespace.
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-downgrade");
    let path = scratch.join("claude_code-scan-index-v3.json");
    let (mut index, _) = rich_index(&scratch);
    index.save(&path).expect("compact save");
    let bytes = fs::read(&path).expect("compact file");
    assert!(!bytes.contains(&b'\n'));
    let from_file: ScanIndex =
        serde_json::from_reader(File::open(&path).expect("open")).expect("from_reader(File)");
    let from_buffered: ScanIndex =
        serde_json::from_reader(BufReader::new(File::open(&path).expect("open")))
            .expect("from_reader(BufReader)");
    let from_slice: ScanIndex = serde_json::from_slice(&bytes).expect("from_slice");
    for (name, decoded) in [
        ("from_reader(File)", &from_file),
        ("from_reader(BufReader)", &from_buffered),
        ("from_slice", &from_slice),
    ] {
        assert_same_proof_state(decoded, &index, name);
        assert_eq!(
            serde_json::to_vec(decoded).expect("re-encode"),
            bytes,
            "{name}"
        );
    }
}

#[test]
fn compact_switch_keeps_manifest_witnesses_and_skip_decisions() {
    let scratch = crate::test_scratch::ScratchDir::new("compact-index-witnesses");
    let path = scratch.join("claude_code-scan-index-v3.json");
    let (mut legacy, candidate) = rich_index(&scratch);
    legacy.generation = 4;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy).expect("legacy bytes"),
    )
    .expect("write legacy pretty index");
    let observe = |index: &ScanIndex| {
        let manifest = index
            .manifest_for_window(
                SnapshotSource::ClaudeCode,
                "2026-01-01T00:00:00Z",
                "2027-01-01T00:00:00Z",
            )
            .expect("manifest");
        let witness = claude_usage_family_witness_fingerprint(
            &index.claude_usage_family_witnesses[HELD_ROOT],
        );
        let body_witnesses = index
            .files
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    entry.last_snapshot_fingerprint.clone(),
                    entry.last_upload_body_witness.clone(),
                )
            })
            .collect::<Vec<_>>();
        (
            manifest,
            witness,
            body_witnesses,
            index.accepted_snapshot_fingerprints.clone(),
            index.candidate_decision(&candidate),
        )
    };
    let before = ScanIndex::load(&path).expect("legacy pretty index loads");
    let pretty = observe(&before);
    // Both current entities are in the window; the quarantined fingerprint
    // is not a current entity.
    assert_eq!(pretty.0.entity_count, 2);
    // The unchanged held family member is not reparsed, so nothing re-uploads.
    assert_eq!(pretty.4, CandidateDecision::Skip);

    let mut switched = before;
    switched.save(&path).expect("compact save");
    assert!(!fs::read(&path).expect("compact file").contains(&b'\n'));
    let after = ScanIndex::load(&path).expect("compact index loads");
    assert_eq!(after.generation, 5);
    assert_eq!(observe(&after), pretty);
}
