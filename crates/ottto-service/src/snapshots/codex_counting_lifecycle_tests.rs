//! Synthetic counting transitions at the selected local ACK boundary.
use super::codex_counting_version::{self, AckEvidence, CountingVersion};
use super::*;
use serde_json::json;

const SESSION: &str = "0199f7a0-0000-7000-8000-00000000c0de";
const POST: &str = "2026-10-01T10:00:00Z";
const CUTOVER: i64 = 1_790_000_000_000;

fn header(at: &str) -> Value {
    json!({"type":"session_meta","timestamp":at,
        "payload":{"id":SESSION,"timestamp":at,"source":"cli"}})
}

fn rows(input: u64) -> Vec<Value> {
    let usage = codex_file_join::tests::usage(input);
    vec![
        header(POST),
        json!({"type":"event_msg","timestamp":POST,
            "payload":{"type":"task_started","turn_id":"turn"}}),
        json!({"type":"turn_context","timestamp":POST,
            "payload":{"turn_id":"turn","model":"gpt-5.2"}}),
        json!({"type":"event_msg","timestamp":POST,"payload":{"type":"token_count",
            "info":{"last_token_usage":usage,"total_token_usage":usage}}}),
        json!({"type":"event_msg","timestamp":"2026-10-01T10:00:01Z","payload":{"type":"token_count",
            "info":{"last_token_usage":usage,"total_token_usage":usage}}}),
        json!({"type":"event_msg","timestamp":POST,
            "payload":{"type":"task_complete","turn_id":"turn"}}),
    ]
}

fn write(path: &Path, rows: &[Value]) {
    fs::write(
        path,
        rows.iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}

fn scan(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
    scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        &[root.join("sessions"), root.join("archived_sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
    )
    .unwrap()
}

/// One ACKed singleton at its original path, saved and reloaded.
struct Acked {
    root: PathBuf,
    original: PathBuf,
    index_path: PathBuf,
    previous: ScanIndex,
}

fn acked_original(v2: bool, old_binding: bool) -> Acked {
    let root = codex_file_join::tests::fixture().0;
    fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
    fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
    fs::create_dir_all(root.join("archived_sessions")).unwrap();
    let original = root
        .join("sessions")
        .join(format!("rollout-2026-10-01T10-00-00-{SESSION}.jsonl"));
    write(&original, &rows(100));
    let mut previous = ScanIndex::default();
    let mut result = if v2 {
        let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
        scan(&root, &mut previous)
    } else {
        scan(&root, &mut previous)
    };
    assert_eq!(result.snapshots.len(), 1);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut previous);
    let old_key = local_index_key(&original);
    let entry = &previous.files[&old_key];
    assert_eq!(entry.codex_counting_v2, v2);
    assert!(entry.last_snapshot_fingerprint.is_some());
    assert!(entry.last_upload_body_witness.is_some());
    assert!(!entry.codex_history_is_protected(), "an ordinary singleton");
    // This build binds even while inactive: the realistic Legacy move.
    assert_eq!(
        entry.codex_counting_owner,
        Some(codex_protected_owner(SESSION))
    );
    if !old_binding {
        previous
            .files
            .get_mut(&old_key)
            .unwrap()
            .codex_counting_owner = None;
    }
    let index_path = root.join("index.json");
    previous.save(&index_path).unwrap();
    let previous = ScanIndex::load(&index_path).unwrap();
    Acked {
        root,
        original,
        index_path,
        previous,
    }
}

/// Parse the archived path with a changed body under an active cutover.
fn parse_archived(acked: &Acked, previous: &ScanIndex, v2: bool) -> ScanIndex {
    let archived = acked
        .root
        .join("archived_sessions")
        .join(acked.original.file_name().unwrap());
    write(&archived, &rows(200));
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let mut working = previous.clone();
    let mut result = scan(&acked.root, &mut working);
    assert_eq!(result.snapshots.len(), 1, "archive is fully parsed");
    assert_eq!(result.scanned_file_count, 1);
    assert_eq!(result.snapshots[0].input_tokens, if v2 { 200 } else { 400 });
    let key = local_index_key(&archived);
    assert_eq!(working.files[&key].codex_counting_v2, v2);
    // Both fresh and cursor restore use the moved evidence prepared by inventory.
    assert_eq!(
        working.codex_counting_moved_evidence[&key],
        if v2 {
            AckEvidence::V2Marked
        } else {
            AckEvidence::LegacyAcked
        }
    );
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    working
        .committable_subset(previous, &accepted, &BTreeMap::new())
        .save(&acked.index_path)
        .unwrap();
    let loaded = ScanIndex::load(&acked.index_path).unwrap();
    assert_eq!(loaded.files[&key].codex_counting_v2, v2);
    assert_ne!(
        loaded.files[&key].last_upload_body_witness,
        acked.previous.files[&local_index_key(&acked.original)].last_upload_body_witness
    );
    loaded
}

fn moved_session(v2: bool, old_binding: bool) {
    let acked = acked_original(v2, old_binding);
    let archived = acked
        .root
        .join("archived_sessions")
        .join(acked.original.file_name().unwrap());
    fs::rename(&acked.original, &archived).unwrap();
    parse_archived(&acked, &acked.previous, v2);
    fs::remove_dir_all(&acked.root).unwrap();
}

/// B1 across pages: a page whose only hint is the old path's removal prunes
/// and saves the old entry before the archived file exists; a later page
/// parses the archived path with a changed body.
fn pruned_moved_session(v2: bool, old_binding: bool) {
    let acked = acked_original(v2, old_binding);
    let old_key = local_index_key(&acked.original);
    let outside = acked.root.join("in-flight");
    fs::create_dir_all(&outside).unwrap();
    let parked = outside.join(acked.original.file_name().unwrap());
    fs::rename(&acked.original, &parked).unwrap();
    // Inactive build: the tombstone is written whatever the cutover.
    let mut working = acked.previous.clone();
    let mut result = scan_source_roots_with_attribution_and_hints(
        SnapshotSource::Codex,
        &[
            acked.root.join("sessions"),
            acked.root.join("archived_sessions"),
        ],
        &mut working,
        "2026-10-06T23:00:00Z",
        7,
        false,
        None,
        std::slice::from_ref(&acked.original),
        false,
    )
    .unwrap();
    assert!(result.snapshots.is_empty());
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    assert!(!working.files.contains_key(&old_key), "old entry is pruned");
    let owner = codex_protected_owner(SESSION);
    let expected = if v2 && old_binding {
        AckEvidence::V2Marked
    } else {
        AckEvidence::LegacyAcked
    };
    assert_eq!(working.codex_counting_tombstones[&owner].evidence, expected);
    // The all-accepted save publishes the pruning.
    working.save(&acked.index_path).unwrap();
    let pruned = ScanIndex::load(&acked.index_path).unwrap();
    assert!(!pruned.files.contains_key(&old_key));
    assert_eq!(pruned.codex_counting_tombstones[&owner].evidence, expected);
    fs::rename(
        &parked,
        acked
            .root
            .join("archived_sessions")
            .join(acked.original.file_name().unwrap()),
    )
    .unwrap();
    let mut loaded = parse_archived(&acked, &pruned, v2);
    // The archived entry now carries the evidence itself: its proven owner
    // frees the slot at the next inventory, whatever the cutover.
    let archived_key = local_index_key(
        &acked
            .root
            .join("archived_sessions")
            .join(acked.original.file_name().unwrap()),
    );
    assert!(loaded.codex_counting_tombstones.contains_key(&owner));
    codex_counting_version::prepare_moved_evidence(
        &mut loaded,
        &BTreeMap::from([(archived_key, owner.clone())]),
        true,
    );
    assert!(!loaded.codex_counting_tombstones.contains_key(&owner));
    fs::remove_dir_all(&acked.root).unwrap();
}

#[test]
fn pruned_legacy_ack_survives_a_later_archive_page_and_reload() {
    pruned_moved_session(false, true);
}

#[test]
fn pruned_unbound_legacy_ack_survives_a_later_archive_page_and_reload() {
    pruned_moved_session(false, false);
}

#[test]
fn pruned_v2_ack_survives_a_later_archive_page_and_reload() {
    pruned_moved_session(true, true);
}

#[test]
fn moved_bound_legacy_ack_survives_archive_changed_body_and_reload() {
    moved_session(false, true);
}

#[test]
fn moved_legacy_ack_survives_archive_changed_body_and_reload() {
    moved_session(false, false);
}

#[test]
fn moved_v2_ack_survives_archive_changed_body_and_reload() {
    moved_session(true, true);
}

#[test]
fn cutover_equality_and_marked_pre_cutover_root() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    for evidence in [AckEvidence::None, AckEvidence::V2Marked] {
        assert_eq!(
            codex_counting_version::decide(
                &header("2026-09-21T14:13:20Z"),
                evidence,
                Some(CUTOVER)
            ),
            CountingVersion::V2
        );
        assert_eq!(
            codex_counting_version::decide(
                &header("2026-09-21T14:13:19.999Z"),
                evidence,
                Some(CUTOVER)
            ),
            CountingVersion::Legacy
        );
    }
}

#[test]
fn fork_marker_selection_is_separate_from_owned_header_admission() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let mut fork = header(POST);
    fork["payload"]["forked_from_id"] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    // The selector alone ignores forked_from_id; history_base is its explicit
    // continuation fence. Ownership must first admit a header to reach it.
    assert_eq!(
        codex_counting_version::decide(&fork, AckEvidence::None, Some(CUTOVER)),
        CountingVersion::V2
    );
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    codex_counting_version::configure(&mut accumulator, AckEvidence::None, Some(CUTOVER));
    apply_codex_line(&fork, &mut accumulator);
    assert!(
        !accumulator.codex_counting_v2(),
        "an unresolved fork header is withheld by ownership"
    );
    fork["payload"]["history_base"] = json!({"id":"parent"});
    assert_eq!(
        codex_counting_version::decide(&fork, AckEvidence::V2Marked, Some(CUTOVER)),
        CountingVersion::Legacy
    );
}

#[test]
fn moved_evidence_is_shared_by_group_cursor_and_retained_restore() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let path = PathBuf::from("/synthetic/archived_sessions/current.jsonl");
    let candidate = CandidateFile {
        scan_root: PathBuf::from("/synthetic/archived_sessions"),
        path: path.clone(),
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: "source".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    };
    let key = local_index_key(&path);
    let old_key = format!("/synthetic/sessions/rollout-2026-10-01T10-00-00-{SESSION}.jsonl");
    let owners = BTreeMap::from([(key, codex_protected_owner(SESSION))]);
    let mut index = ScanIndex::default();
    let mut old: ScanIndexEntry = serde_json::from_value(json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old",
        "last_snapshot_fingerprint":"old-ack","codex_counting_v2":true,
        "codex_counting_owner":codex_protected_owner("another-session")
    }))
    .unwrap();
    index.files.insert(old_key.clone(), old.clone());
    codex_counting_version::prepare_moved_evidence(&mut index, &owners, false);
    assert_eq!(
        codex_counting_version::members_evidence([&candidate], &index),
        AckEvidence::None,
        "a filename cannot transfer a different proven owner's mark"
    );
    // An unbound old mark cannot be attributed by filename. It is a
    // conservative Legacy hint, including when a V2 mark survives there.
    old.codex_counting_owner = None;
    index.files.insert(old_key.clone(), old.clone());
    codex_counting_version::prepare_moved_evidence(&mut index, &owners, false);
    let singleton = codex_counting_version::singleton_view(&candidate, &index);
    assert_eq!(
        singleton,
        codex_counting_version::group_view([&candidate], &index)
    );
    assert_eq!(
        singleton,
        codex_counting_version::view(AckEvidence::LegacyAcked, CUTOVER)
    );
    let mut restored = SnapshotAccumulator::new(SnapshotSource::Codex);
    codex_counting_version::configure(&mut restored, AckEvidence::None, Some(CUTOVER));
    apply_codex_line(&header(POST), &mut restored);
    assert!(restored.codex_counting_v2());
    assert!(!codex_counting_version::reusable_under_view(
        &restored, &singleton
    ));
    old.codex_counting_owner = Some(codex_protected_owner(SESSION));
    index.files.insert(old_key, old);
    codex_counting_version::prepare_moved_evidence(&mut index, &owners, false);
    let singleton = codex_counting_version::singleton_view(&candidate, &index);
    assert_eq!(
        singleton,
        codex_counting_version::group_view([&candidate], &index)
    );
    assert!(codex_counting_version::reusable_under_view(
        &restored, &singleton
    ));
    // A second, proven same-session Legacy ACK outranks the V2 mark.
    let mut legacy = index.files.values().next().unwrap().clone();
    legacy.codex_counting_v2 = false;
    index
        .files
        .insert("/synthetic/missing/member.jsonl".into(), legacy);
    codex_counting_version::prepare_moved_evidence(&mut index, &owners, false);
    assert_eq!(
        codex_counting_version::members_evidence([&candidate], &index),
        AckEvidence::LegacyAcked
    );
}

fn archived_candidate() -> CandidateFile {
    let path = PathBuf::from(format!(
        "/synthetic/archived_sessions/rollout-2026-10-01T10-00-00-{SESSION}.jsonl"
    ));
    CandidateFile {
        scan_root: PathBuf::from("/synthetic/archived_sessions"),
        path,
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: "source".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    }
}

fn acked_entry(v2: bool, owner: Option<String>) -> ScanIndexEntry {
    let mut entry: ScanIndexEntry = serde_json::from_value(json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old",
        "last_snapshot_fingerprint":"old-ack","codex_counting_v2":v2
    }))
    .unwrap();
    entry.codex_counting_owner = owner;
    entry
}

#[test]
fn pruned_old_entry_keeps_cursor_and_group_counting_views() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let candidate = archived_candidate();
    let owners = BTreeMap::from([(
        local_index_key(&candidate.path),
        codex_protected_owner(SESSION),
    )]);
    let old_key = format!("/synthetic/sessions/rollout-2026-10-01T10-00-00-{SESSION}.jsonl");
    for (v2, bound, expected) in [
        (false, true, AckEvidence::LegacyAcked),
        (false, false, AckEvidence::LegacyAcked),
        (true, true, AckEvidence::V2Marked),
    ] {
        let mut index = ScanIndex::default();
        let owner = bound.then(|| codex_protected_owner(SESSION));
        index.files.insert(old_key.clone(), acked_entry(v2, owner));
        codex_counting_version::prepare_moved_evidence(&mut index, &owners, true);
        let singleton = codex_counting_version::singleton_view(&candidate, &index);
        let group = codex_counting_version::group_view([&candidate], &index);
        assert_eq!(singleton, codex_counting_version::view(expected, CUTOVER));
        assert!(codex_counting_version::tombstone_before_retire(
            &mut index, &old_key
        ));
        index.remove_file_entry(&old_key);
        assert!(index.files.is_empty());
        // The paused job's next page sees the same view, so reuse holds.
        codex_counting_version::prepare_moved_evidence(&mut index, &owners, true);
        assert_eq!(
            codex_counting_version::singleton_view(&candidate, &index),
            singleton
        );
        assert_eq!(
            codex_counting_version::group_view([&candidate], &index),
            group
        );
    }
}

#[test]
fn counting_tombstones_are_bounded_and_never_evict_legacy_evidence() {
    // Written and collected whatever the cutover.
    let legacy = |n: usize| (format!("{n:064x}"), AckEvidence::LegacyAcked);
    let tombstone = |evidence| codex_counting_version::CountingTombstone {
        evidence,
        retired_in: "g1".into(),
    };
    let mut index = ScanIndex {
        traversal: Some(
            serde_json::from_value(json!({
                "context_fingerprint":"c","census_window_end":"g1","scan_roots":[],
                "pending_directories":[],"pending_candidates":[],"observed_index_keys":[],
                "reconciliation_upper_bound":null,"reconciliation_after":null,
                "reconciliation_started":false,"counts":{}
            }))
            .unwrap(),
        ),
        codex_counting_tombstones: (0..codex_counting_version::MAX_COUNTING_TOMBSTONES)
            .map(legacy)
            .map(|(owner, evidence)| (owner, tombstone(evidence)))
            .collect(),
        ..ScanIndex::default()
    };
    let owner = codex_protected_owner(SESSION);
    let key = format!("/synthetic/sessions/rollout-2026-10-01T10-00-00-{SESSION}.jsonl");
    // Full of Legacy evidence: the retirement is refused, the entry stays.
    index
        .files
        .insert(key.clone(), acked_entry(false, Some(owner.clone())));
    assert!(!codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    assert!(!index.codex_counting_tombstones.contains_key(&owner));
    // V2-only evidence retires without a slot; it never selects a version.
    index
        .files
        .insert(key.clone(), acked_entry(true, Some(owner.clone())));
    assert!(codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    assert!(!index.codex_counting_tombstones.contains_key(&owner));
    // A V2-only tombstone gives its slot to Legacy evidence.
    let v2_owner = legacy(0).0;
    index
        .codex_counting_tombstones
        .get_mut(&v2_owner)
        .unwrap()
        .evidence = AckEvidence::V2Marked;
    index
        .files
        .insert(key.clone(), acked_entry(false, Some(owner.clone())));
    assert!(codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    assert!(!index.codex_counting_tombstones.contains_key(&v2_owner));
    assert_eq!(
        index.codex_counting_tombstones[&owner].evidence,
        AckEvidence::LegacyAcked
    );
    assert_eq!(
        index.codex_counting_tombstones.len(),
        codex_counting_version::MAX_COUNTING_TOMBSTONES
    );
    // In a later generation, the oldest earlier-generation Legacy evidence
    // gives its slot; this generation's never does.
    index.traversal.as_mut().unwrap().census_window_end = "g2".into();
    let later_owner = legacy(9999).0;
    index
        .files
        .insert(key.clone(), acked_entry(false, Some(later_owner.clone())));
    assert!(codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    assert!(!index.codex_counting_tombstones.contains_key(&legacy(1).0));
    assert_eq!(
        index.codex_counting_tombstones[&later_owner].retired_in,
        "g2"
    );
    assert_eq!(
        index.codex_counting_tombstones.len(),
        codex_counting_version::MAX_COUNTING_TOMBSTONES
    );
    index.files.clear();

    // Absence frees a slot only in a complete inventory of a later traversal
    // generation than the retiring one.
    let present = BTreeMap::from([("/synthetic/p.jsonl".to_owned(), legacy(2).0)]);
    codex_counting_version::prepare_moved_evidence(&mut index, &present, false);
    assert_eq!(
        index.codex_counting_tombstones.len(),
        codex_counting_version::MAX_COUNTING_TOMBSTONES,
        "an incomplete inventory proves nothing absent"
    );
    codex_counting_version::prepare_moved_evidence(&mut index, &present, true);
    assert_eq!(
        index
            .codex_counting_tombstones
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([legacy(2).0, later_owner.clone()]),
        "the retiring generation's walk may have raced a rename"
    );
    // A live proven entry with at least the same evidence absorbs it.
    index
        .files
        .insert(key.clone(), acked_entry(true, Some(legacy(2).0)));
    codex_counting_version::prepare_moved_evidence(&mut index, &present, true);
    assert_eq!(
        index.codex_counting_tombstones.len(),
        2,
        "V2 never absorbs Legacy"
    );
    index
        .files
        .insert(key.clone(), acked_entry(false, Some(legacy(2).0)));
    index.files.insert(
        "/synthetic/l.jsonl".into(),
        acked_entry(false, Some(later_owner)),
    );
    codex_counting_version::prepare_moved_evidence(&mut index, &present, true);
    assert!(index.codex_counting_tombstones.is_empty());
    // Persisted beside the entries; absent when empty.
    index
        .codex_counting_tombstones
        .insert(owner.clone(), tombstone(AckEvidence::LegacyAcked));
    let bytes = serde_json::to_value(&index).unwrap();
    assert_eq!(
        bytes["codex_counting_tombstones"][&owner],
        json!({"evidence":"legacy_acked","retired_in":"g1"})
    );
}

#[test]
fn invalid_counting_binding_never_masks_a_valid_owner() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let candidate = archived_candidate();
    let owners = BTreeMap::from([(
        local_index_key(&candidate.path),
        codex_protected_owner(SESSION),
    )]);
    // A corrupt or future-format binding decodes as "" (invalid). The member
    // name carries no session id, so only the valid protected owner binds it.
    let mut member = acked_entry(false, Some(String::new()));
    member.codex_protected_owner = Some(codex_protected_owner(SESSION));
    let mut index = ScanIndex::default();
    index
        .files
        .insert("/synthetic/sessions/a.jsonl".into(), member);
    codex_counting_version::prepare_moved_evidence(&mut index, &owners, false);
    assert_eq!(
        codex_counting_version::members_evidence([&candidate], &index),
        AckEvidence::LegacyAcked
    );
}
