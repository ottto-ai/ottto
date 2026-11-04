// Census P2 keeps these mechanisms: a locally held key reverts to its
// committed revision, and an observed but unindexed Codex file is read once
// after a restart. All fixtures are synthetic and content-free.
use super::*;

const WINDOW: &str = "2026-08-02T07:10:00Z";

fn hex64(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn committed_entry(source: &str, fingerprint: &str) -> ScanIndexEntry {
    let mut entry = manifest_index_entry(Some(fingerprint));
    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.to_string());
    entry.source_file_fingerprint = source.to_string();
    entry
}

fn index_file(index: &mut ScanIndex, key: &str, source: &str, fingerprint: &str, activity: &str) {
    index
        .files
        .insert(key.to_string(), committed_entry(source, fingerprint));
    index
        .file_snapshot_fingerprints
        .insert(key.to_string(), BTreeSet::from([fingerprint.to_string()]));
    index
        .snapshot_activity_at
        .insert(fingerprint.to_string(), Some(activity.to_string()));
}

fn matching_candidate(index: &ScanIndex, key: &str) -> CandidateFile {
    let entry = &index.files[key];
    let mut candidate = test_candidate(PathBuf::from(key));
    candidate.size_bytes = entry.size_bytes;
    candidate.modified_unix_seconds = entry.modified_unix_seconds;
    candidate.modified_unix_nanos = entry.modified_unix_nanos.unwrap_or_default();
    candidate.source_file_fingerprint = entry.source_file_fingerprint.clone();
    candidate
}

fn decision(
    index: &ScanIndex,
    candidate: &CandidateFile,
) -> (CandidateDecision, Option<CandidateParseReason>) {
    let decided = index.candidate_decision_with_reason_at(candidate, 0);
    // The reason is diagnostic only: it names a parse and never changes it.
    assert_eq!(decided.0, index.candidate_decision_at(candidate, 0));
    assert_eq!(decided.1.is_some(), decided.0 == CandidateDecision::Parse);
    decided
}

// A held key keeps its committed revision, its activity and accepted
// ledger, and reparse debt; every other key commits as scanned. A held key
// with no committed revision in a family with retained authority evidence is
// not restorable.
#[test]
fn locally_held_keys_revert_to_committed_revision_and_keep_manifest() {
    let activity = "2026-08-02T07:00:00Z";
    let held_key = "/opaque/held.jsonl";
    let sibling_key = "/opaque/sibling.jsonl";
    let fresh_held_key = "/opaque/fresh-held.jsonl";
    let fresh_key = "/opaque/fresh.jsonl";
    let mut previous = ScanIndex::default();
    index_file(
        &mut previous,
        held_key,
        "held-old-source",
        "held-old",
        activity,
    );
    index_file(
        &mut previous,
        sibling_key,
        "sibling-old-source",
        "sibling-old",
        activity,
    );
    previous
        .accepted_snapshot_fingerprints
        .extend(["held-old".to_string(), "sibling-old".to_string()]);

    let mut scanned = previous.clone();
    index_file(
        &mut scanned,
        held_key,
        "held-new-source",
        "held-new",
        activity,
    );
    index_file(
        &mut scanned,
        sibling_key,
        "sibling-new-source",
        "sibling-new",
        activity,
    );
    index_file(
        &mut scanned,
        fresh_held_key,
        "fresh-held-source",
        "fresh-held",
        activity,
    );
    index_file(&mut scanned, fresh_key, "fresh-source", "fresh", activity);
    for replaced in ["held-old", "sibling-old"] {
        scanned.snapshot_activity_at.remove(replaced);
    }
    scanned
        .accepted_snapshot_fingerprints
        .extend(["sibling-new".to_string(), "fresh".to_string()]);
    let held = BTreeSet::from(["held-new".to_string(), "fresh-held".to_string()]);

    let reverted = scanned.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    let saved: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&reverted).expect("encode index"))
            .expect("decode index");
    assert_eq!(
        saved.files[held_key].source_file_fingerprint,
        "held-old-source"
    );
    assert_eq!(
        saved.files[held_key].last_snapshot_fingerprint.as_deref(),
        Some("held-old")
    );
    assert_eq!(
        saved.file_snapshot_fingerprints[held_key],
        BTreeSet::from(["held-old".to_string()])
    );
    assert!(saved.snapshot_activity_at.contains_key("held-old"));
    assert!(!saved.snapshot_activity_at.contains_key("held-new"));
    assert!(saved.accepted_snapshot_fingerprints.contains("held-old"));
    assert!(!saved.accepted_snapshot_fingerprints.contains("held-new"));
    // A held key that was never committed stays absent.
    assert!(!saved.files.contains_key(fresh_held_key));
    assert!(!saved
        .file_snapshot_fingerprints
        .contains_key(fresh_held_key));
    assert!(!saved.snapshot_activity_at.contains_key("fresh-held"));
    // Every other key commits exactly as scanned.
    assert_eq!(
        saved.files[sibling_key].source_file_fingerprint,
        "sibling-new-source"
    );
    assert_eq!(
        saved.file_snapshot_fingerprints[sibling_key],
        BTreeSet::from(["sibling-new".to_string()])
    );
    assert!(saved.files.contains_key(fresh_key));

    // The manifest is the fold of the committed held revision with every
    // other scanned key.
    let mut expected = scanned.clone();
    index_file(
        &mut expected,
        held_key,
        "held-old-source",
        "held-old",
        activity,
    );
    expected.files.remove(fresh_held_key);
    expected.file_snapshot_fingerprints.remove(fresh_held_key);
    expected.snapshot_activity_at.remove("held-new");
    expected.snapshot_activity_at.remove("fresh-held");
    let window_start = "2026-08-01T00:00:00Z";
    let window_end = "2026-08-03T00:00:00Z";
    let manifest = saved
        .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
        .expect("held revert keeps a complete activity witness");
    assert_eq!(manifest.entity_count, 3);
    assert_eq!(
        manifest,
        expected
            .manifest_for_window(SnapshotSource::ClaudeCode, window_start, window_end)
            .expect("expected manifest")
    );

    // An unchanged held key is still skipped; reparse debt re-arms it.
    let candidate = matching_candidate(&previous, held_key);
    assert_eq!(
        decision(&saved, &candidate),
        (CandidateDecision::Skip, None)
    );
    let reparse = scanned.with_locally_held_keys_reverted(&previous, &held, &held);
    assert!(reparse.files[held_key].source_file_fingerprint.is_empty());
    assert_eq!(
        decision(&reparse, &candidate),
        (
            CandidateDecision::Parse,
            Some(CandidateParseReason::Rearmed)
        )
    );

    // An explicitly cleared source fingerprint on the scanned held key
    // (prior reparse debt) survives the revert.
    let mut rearmed = scanned.clone();
    rearmed
        .files
        .get_mut(held_key)
        .expect("held entry")
        .source_file_fingerprint
        .clear();
    let rearmed = rearmed.with_locally_held_keys_reverted(&previous, &held, &BTreeSet::new());
    assert!(rearmed.files[held_key].source_file_fingerprint.is_empty());
    assert_eq!(
        rearmed.files[held_key].last_snapshot_fingerprint.as_deref(),
        Some("held-old")
    );

    // Dropping a never-committed held key is settleable only while its family
    // carries no retained authority evidence; a committed held key restores.
    assert!(scanned.locally_held_keys_restorable(&previous, &held, &BTreeSet::new()));
    let mut fresh_family_evidence = scanned.clone();
    fresh_family_evidence
        .insert_unproven_terminal_claude_authority_for_test("fresh-held", &hex64('a'));
    assert!(!fresh_family_evidence.locally_held_keys_restorable(
        &previous,
        &held,
        &BTreeSet::new()
    ));
    let mut previous_family_evidence = previous.clone();
    previous_family_evidence
        .insert_unproven_terminal_claude_authority_for_test("fresh-held", &hex64('a'));
    assert!(!scanned.locally_held_keys_restorable(
        &previous_family_evidence,
        &held,
        &BTreeSet::new()
    ));
    let mut committed_family_evidence = scanned.clone();
    committed_family_evidence
        .insert_unproven_terminal_claude_authority_for_test("held", &hex64('a'));
    assert!(committed_family_evidence.locally_held_keys_restorable(
        &previous,
        &held,
        &BTreeSet::new()
    ));
}

/// A page read the file and the generation observed it, but the partial
/// checkpoint kept the traversal without the unacknowledged entry. After a
/// restart the file is read once, with the same usage a fresh scan counts, and
/// never again; a second load in the same process queues nothing.
#[test]
fn codex_observed_unindexed_file_is_read_once_after_restart() {
    let dir = temp_dir("f5-codex-observed-unindexed");
    let root = dir.join("home/.codex/sessions");
    fs::create_dir_all(&root).unwrap();
    let session = "019fa111-2222-7333-8444-555555555555";
    let path = root.join(format!("rollout-2026-10-29T10-00-00-{session}.jsonl"));
    fs::write(
        &path,
        [
            serde_json::json!({"type":"session_meta","payload":{"id":session}}),
            serde_json::json!({"timestamp":"2026-10-29T10:00:01Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":12,"output_tokens":4}}}}),
        ]
        .iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>(),
    )
    .unwrap();
    let key = local_index_key(&path);
    let roots = [root.clone()];
    let usage = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .filter(|item| item.source_session_id == session)
            .map(|item| {
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.reasoning_output_tokens,
                    item.request_count,
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = usage(
        &scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &roots,
            &mut ScanIndex::default(),
            "2026-10-29T12:00:00Z",
            BACKFILL_WINDOW_DAYS,
            10,
        )
        .unwrap(),
    );
    assert_eq!(expected.len(), 1);
    assert_eq!(expected[0].1, 4);

    let mut orphaned = ScanIndex::default();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &roots,
        &mut orphaned,
        "2026-10-29T12:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut orphaned,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    let traversal = orphaned.traversal.as_mut().unwrap();
    assert!(traversal.observed_index_keys.contains(&key));
    traversal.pending_candidates.clear();
    assert!(!orphaned.files.contains_key(&key));
    let index_path = dir.join("codex-index.json");
    orphaned.save(&index_path).unwrap();
    let support = dir.join("support");
    fs::create_dir_all(&support).unwrap();
    let load = || {
        ScanIndex::load_for_snapshot_source_with_origin(
            &index_path,
            SnapshotSource::Codex,
            &support,
        )
        .unwrap()
        .0
    };

    let mut index = load();
    assert!(
        load().traversal.unwrap().pending_candidates.is_empty(),
        "once per process: a later load of the same index queues nothing"
    );
    let mut read = Vec::new();
    for minute in 1..=3 {
        let mut scan = scan_source_roots_with_limit(
            SnapshotSource::Codex,
            &roots,
            &mut index,
            &format!("2026-10-29T12:0{minute}:00Z"),
            BACKFILL_WINDOW_DAYS,
            10,
        )
        .unwrap();
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        read.extend(usage(&scan));
    }
    assert_eq!(read, expected, "read once, with a fresh scan's usage");
    assert!(index.files.contains_key(&key));
    let _ = fs::remove_dir_all(&dir);
}

mod provider_envelope_experiment_tests {
    include!("provider_envelope_experiment_tests.rs");
}

mod witness_reconstruct_scope {
    include!("witness_reconstruct_scope_tests.rs");
}
