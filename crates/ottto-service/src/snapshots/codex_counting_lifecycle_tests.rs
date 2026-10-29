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
    scan_at(root, index, "2026-10-06T23:00:00Z")
}

fn scan_at(root: &Path, index: &mut ScanIndex, collected_at: &str) -> SourceScanResult {
    scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        &[root.join("sessions"), root.join("archived_sessions")],
        index,
        collected_at,
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
        Some(codex_protected_owner(SESSION).into_boxed_str())
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
    parse_archived_at(acked, previous, v2, "2026-10-06T23:00:00Z")
}

fn parse_archived_at(
    acked: &Acked,
    previous: &ScanIndex,
    v2: bool,
    collected_at: &str,
) -> ScanIndex {
    let archived = acked
        .root
        .join("archived_sessions")
        .join(acked.original.file_name().unwrap());
    write(&archived, &rows(200));
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let mut working = previous.clone();
    let mut result = scan_at(&acked.root, &mut working, collected_at);
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
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/archived_sessions"),
        path: path.clone(),
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: "source".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
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
    old.codex_counting_owner = Some(codex_protected_owner(SESSION).into_boxed_str());
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
        physical_identity: None,
        scan_root: PathBuf::from("/synthetic/archived_sessions"),
        path,
        size_bytes: 1,
        modified_unix_seconds: 1,
        modified_unix_nanos: 1,
        source_file_fingerprint: "source".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

fn acked_entry(v2: bool, owner: Option<String>) -> ScanIndexEntry {
    let mut entry: ScanIndexEntry = serde_json::from_value(json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old",
        "last_snapshot_fingerprint":"old-ack","codex_counting_v2":v2
    }))
    .unwrap();
    entry.codex_counting_owner = owner.map(String::into_boxed_str);
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
fn counting_tombstones_are_bounded_and_protect_current_generation_legacy_evidence() {
    // Written and collected whatever the cutover.
    let legacy = |n: usize| (format!("{n:064x}"), AckEvidence::LegacyAcked);
    let tombstone = |evidence| codex_counting_version::CountingTombstone {
        evidence,
        retired_in: "g1".into(),
        created_unix_ms: None,
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

#[test]
fn full_map_never_evicts_an_owner_the_retirement_rewrites() {
    let key = format!("/synthetic/sessions/rollout-2026-10-01T10-00-00-{SESSION}.jsonl");
    let ids = codex_session_id_candidates_from_path(Path::new(&key));
    assert_eq!(ids.len(), 2, "legacy and modern filename identities");
    let rewritten = codex_protected_owner(&ids[0]);
    let tombstone = |evidence| codex_counting_version::CountingTombstone {
        evidence,
        retired_in: String::new(),
        created_unix_ms: None,
    };
    let mut index = ScanIndex {
        codex_counting_tombstones: (1..codex_counting_version::MAX_COUNTING_TOMBSTONES)
            .map(|n| (format!("{n:064x}"), tombstone(AckEvidence::LegacyAcked)))
            .chain([(rewritten.clone(), tombstone(AckEvidence::V2Marked))])
            .collect(),
        ..ScanIndex::default()
    };
    // Unbound: both identities become Legacy hints and one needs a slot. The
    // only V2-only slot belongs to an identity being rewritten, so none frees.
    index.files.insert(key.clone(), acked_entry(false, None));
    assert!(!codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    assert_eq!(
        index.codex_counting_tombstones.len(),
        codex_counting_version::MAX_COUNTING_TOMBSTONES
    );
    assert_eq!(
        index.codex_counting_tombstones[&rewritten].evidence,
        AckEvidence::V2Marked
    );
}

fn retirement_generation(index: &mut ScanIndex, generation: &str) {
    index.traversal = Some(
        serde_json::from_value(json!({
            "context_fingerprint":"c", "census_window_end":generation, "scan_roots":[],
            "pending_directories":[], "pending_candidates":[], "observed_index_keys":[],
            "reconciliation_upper_bound":index.files.keys().next_back(),
            "reconciliation_after":null, "reconciliation_started":false, "counts":{}
        }))
        .unwrap(),
    );
}

#[test]
fn bounded_reconciliation_preserves_retired_counting_evidence_across_reload() {
    let acked = acked_original(false, true);
    let mut working = acked.previous.clone();
    let old_key = local_index_key(&acked.original);
    retirement_generation(&mut working, "2026-10-05T23:00:00Z");
    assert!(reconcile_missing_index_entries_with_limit(&mut working, 1));
    assert!(!working.files.contains_key(&old_key));
    working.save(&acked.index_path).unwrap();
    let loaded = ScanIndex::load(&acked.index_path).unwrap();
    assert!(!loaded.files.contains_key(&old_key));
    assert_eq!(
        loaded.codex_counting_tombstones[&codex_protected_owner(SESSION)].evidence,
        AckEvidence::LegacyAcked
    );
    fs::remove_dir_all(acked.root).unwrap();
}

/// The header roster in the available root can be complete even though root
/// resolution omitted a previously known root. Exercise the real inventory
/// caller and selected checkpoint, rather than passing GC a synthetic bool.
#[test]
fn unavailable_known_root_cannot_collect_retired_owner_before_archive_reload() {
    for v2 in [false, true] {
        let acked = acked_original(v2, true);
        let archived_root = acked.root.join("archived_sessions");
        let archived = archived_root.join(acked.original.file_name().unwrap());
        fs::rename(&acked.original, &archived).unwrap();
        let mut working = acked.previous.clone();
        retirement_generation(&mut working, "2026-10-05T23:00:00Z");
        assert!(reconcile_missing_index_entries_with_limit(&mut working, 1));
        working.save(&acked.index_path).unwrap();
        let retired = ScanIndex::load(&acked.index_path).unwrap();
        let owner = codex_protected_owner(SESSION);
        assert!(retired.codex_counting_tombstones.contains_key(&owner));
        assert!(retired
            .known_configured_scan_roots
            .contains(&local_index_key(&archived_root)));
        let hidden = acked.root.join("unavailable-archive");
        fs::rename(&archived_root, &hidden).unwrap();
        let control = acked.root.join("sessions/control.jsonl");
        let mut control_rows = rows(200);
        control_rows[0]["payload"]["id"] = json!("0199f7a0-0000-7000-8000-00000000beef");
        write(&control, &control_rows);
        let mut working = retired.clone();
        let mut result = {
            let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
            scan(&acked.root, &mut working)
        };
        assert_eq!(result.snapshots.len(), 1, "available-root inventory ran");
        assert_eq!(result.snapshots[0].input_tokens, 200, "fresh V2 control");
        assert!(result.disappeared_file_count > 0, "unresolved known root");
        assert!(working.codex_counting_tombstones.contains_key(&owner));
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        working
            .committable_subset(&retired, &accepted, &BTreeMap::new())
            .save(&acked.index_path)
            .unwrap();
        let checkpoint = ScanIndex::load(&acked.index_path).unwrap();
        assert!(checkpoint.codex_counting_tombstones.contains_key(&owner));
        fs::rename(&hidden, &archived_root).unwrap();
        parse_archived_at(&acked, &checkpoint, v2, "2026-10-07T23:00:00Z");
        fs::remove_dir_all(acked.root).unwrap();
    }
}

#[test]
fn tombstone_overflow_prefers_safe_classes_then_oldest_known_creation() {
    for cutover in [None, Some(CUTOVER)] {
        let _cutover = cutover.map(codex_counting_version::TestCutover::set);
        let mut index = ScanIndex::default();
        retirement_generation(&mut index, "g2");
        let owner_at = |n: usize| format!("{n:064x}");
        index.codex_counting_tombstones = (0..codex_counting_version::MAX_COUNTING_TOMBSTONES)
            .map(|n| {
                (
                    owner_at(n),
                    codex_counting_version::CountingTombstone {
                        evidence: AckEvidence::LegacyAcked,
                        retired_in: "g1".into(),
                        created_unix_ms: None,
                    },
                )
            })
            .collect();
        // Lexical order deliberately disagrees with the safety/creation order.
        let v2_owner = owner_at(900);
        index
            .codex_counting_tombstones
            .get_mut(&v2_owner)
            .unwrap()
            .evidence = AckEvidence::V2Marked;
        let pre_owner = owner_at(800);
        let pre = index.codex_counting_tombstones.get_mut(&pre_owner).unwrap();
        pre.created_unix_ms = Some(CUTOVER - 1);
        // Under an active cutover this is safe even in the current generation.
        // Inactive current-generation Legacy remains protected.
        pre.retired_in = if cutover.is_some() { "g2" } else { "g1" }.into();
        let post_owner = owner_at(700);
        index
            .codex_counting_tombstones
            .get_mut(&post_owner)
            .unwrap()
            .created_unix_ms = Some(CUTOVER);
        let key = "/synthetic/sessions/current.jsonl";
        for (n, evicted) in [(2000, v2_owner), (2001, pre_owner), (2002, post_owner)] {
            index
                .files
                .insert(key.into(), acked_entry(false, Some(owner_at(n))));
            assert!(codex_counting_version::tombstone_before_retire(
                &mut index, key
            ));
            assert!(!index.codex_counting_tombstones.contains_key(&evicted));
            assert_eq!(
                index.codex_counting_tombstones.len(),
                codex_counting_version::MAX_COUNTING_TOMBSTONES
            );
        }
        assert!(
            index.codex_counting_tombstones.contains_key(&owner_at(1)),
            "unknown creation most protected while inactive"
        );
        let receipts = codex_counting_version::take_local_receipts(&mut index, None).unwrap();
        assert_eq!(receipts.tombstone_evictions_v2_only, 1);
        assert_eq!(
            receipts.tombstone_evictions_pre_cutover_legacy,
            u64::from(cutover.is_some())
        );
        assert_eq!(
            receipts.tombstone_evictions_not_provably_pre_cutover_legacy,
            if cutover.is_some() { 1 } else { 2 }
        );
        assert_eq!(
            index.codex_counting_evictions, [0; 3],
            "drained once per scan"
        );
    }
}

#[test]
fn absence_collection_requires_healthy_scope_and_fresh_directory_witnesses() {
    let acked = acked_original(false, true);
    let mut index = acked.previous.clone();
    retirement_generation(&mut index, "g2");
    let traversal = index.traversal.as_mut().unwrap();
    traversal.scan_roots = vec![
        acked.root.join("sessions"),
        acked.root.join("archived_sessions"),
    ];
    let mut directories = codex_file_join::DirectoryCensus::new();
    for root in &traversal.scan_roots {
        directories.observe(root, &fs::symlink_metadata(root).unwrap());
    }
    let inventory = codex_file_join::HeaderInventory::new(
        &traversal.scan_roots,
        &BTreeSet::new(),
        Some(&directories),
    );
    assert!(codex_counting_version::absence_coverage_complete(
        &index, &inventory
    ));
    index
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .disappeared_file_count = 1;
    assert!(!codex_counting_version::absence_coverage_complete(
        &index, &inventory
    ));
    index
        .traversal
        .as_mut()
        .unwrap()
        .counts
        .disappeared_file_count = 0;
    index.traversal.as_mut().unwrap().watcher_hint_seen = true;
    assert!(!codex_counting_version::absence_coverage_complete(
        &index, &inventory
    ));
    index.traversal.as_mut().unwrap().watcher_hint_seen = false;
    fs::create_dir(acked.root.join("sessions/changed-membership")).unwrap();
    assert!(!codex_counting_version::absence_coverage_complete(
        &index, &inventory
    ));
    fs::remove_dir_all(acked.root).unwrap();
}

#[test]
fn inventory_creation_timestamp_survives_tombstone_reload() {
    let acked = acked_original(false, true);
    let mut index = acked.previous.clone();
    let key = local_index_key(&acked.original);
    assert!(codex_counting_version::tombstone_before_retire(
        &mut index, &key
    ));
    index.remove_file_entry(&key);
    let owner = codex_protected_owner(SESSION);
    assert_eq!(
        index.codex_counting_tombstones[&owner].created_unix_ms,
        None
    );
    let roots = vec![
        acked.root.join("sessions"),
        acked.root.join("archived_sessions"),
    ];
    let paths = BTreeSet::from([key]);
    let mut directories = codex_file_join::DirectoryCensus::new();
    for root in &roots {
        directories.observe(root, &fs::symlink_metadata(root).unwrap());
    }
    let mut inventory = codex_file_join::HeaderInventory::new(&roots, &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    codex_counting_version::note_inventory_created(&mut index, &inventory);
    index.save(&acked.index_path).unwrap();
    let loaded = ScanIndex::load(&acked.index_path).unwrap();
    assert_eq!(
        loaded.codex_counting_tombstones[&owner].created_unix_ms,
        Some(1_790_848_800_000)
    );
    fs::remove_dir_all(acked.root).unwrap();
}

/// Fill the cap while making only the selected owner eligible for eviction.
fn evict_counting_owner(index: &mut ScanIndex, owner: &str, created: Option<i64>) {
    retirement_generation(index, "g2");
    index.codex_counting_tombstones = (0..codex_counting_version::MAX_COUNTING_TOMBSTONES - 1)
        .map(|n| {
            (
                format!("{n:064x}"),
                codex_counting_version::CountingTombstone {
                    evidence: AckEvidence::LegacyAcked,
                    retired_in: "g2".into(),
                    created_unix_ms: None,
                },
            )
        })
        .collect();
    index.codex_counting_tombstones.insert(
        owner.into(),
        codex_counting_version::CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "g1".into(),
            created_unix_ms: created,
        },
    );
    let key = "/synthetic/sessions/new-retirement.jsonl";
    index
        .files
        .insert(key.into(), acked_entry(false, Some("f".repeat(64))));
    assert!(codex_counting_version::tombstone_before_retire(index, key));
    index.files.remove(key);
    assert!(!index.codex_counting_tombstones.contains_key(owner));
}

#[test]
fn cap_eviction_receipts_correlate_a_later_v2_selection_after_selected_reload() {
    for created in [
        None,
        Some(CUTOVER),
        Some(1_790_848_800_000),
        Some(CUTOVER - 1),
    ] {
        let acked = acked_original(false, true);
        let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
        let owner = codex_protected_owner(SESSION);
        let mut index = acked.previous.clone();
        index.files.clear();
        evict_counting_owner(&mut index, &owner, created);
        let pre_cutover = created.is_some_and(|created| created < CUTOVER);
        let receipts = codex_counting_version::take_local_receipts(&mut index, None).unwrap();
        assert_eq!(receipts.tombstone_evictions_v2_only, 0);
        assert_eq!(
            receipts.tombstone_evictions_pre_cutover_legacy,
            u64::from(pre_cutover)
        );
        assert_eq!(
            receipts.tombstone_evictions_not_provably_pre_cutover_legacy,
            u64::from(!pre_cutover)
        );
        assert_eq!(receipts.legacy_to_v2_after_tombstone_eviction, 0);
        assert_eq!(receipts.tombstone_count, 1024);
        assert_eq!(receipts.tombstone_cap, 1024);
        assert_eq!(index.codex_counting_evicted_legacy.is_empty(), pre_cutover);

        // Correlation follows the selected checkpoint even when no new file
        // ACK from this page is selected. The carrier's removal is already
        // committed by the prior page, before this cap eviction.
        let mut prior_page = acked.previous.clone();
        prior_page.files.clear();
        let mut checkpoint =
            index.committable_subset(&prior_page, &BTreeSet::new(), &BTreeMap::new());
        checkpoint.save(&acked.index_path).unwrap();
        let mut reloaded = ScanIndex::load(&acked.index_path).unwrap();
        assert_eq!(
            serde_json::to_value(&reloaded.codex_counting_evicted_legacy).unwrap(),
            serde_json::to_value(&index.codex_counting_evicted_legacy).unwrap()
        );
        let moved = acked.root.join("archived_sessions/moved.jsonl");
        fs::rename(&acked.original, &moved).unwrap();
        let mut changed = rows(200);
        if pre_cutover {
            changed[0] = header("2026-09-01T10:00:00Z");
        }
        write(&moved, &changed);
        let mut result = scan_at(&acked.root, &mut reloaded, "2026-10-07T23:00:00Z");
        let later = result.codex_counting_v2.as_deref().unwrap();
        assert_eq!(
            later.tombstone_evictions_not_provably_pre_cutover_legacy, 0,
            "eviction event counters do not persist across scans"
        );
        assert_eq!(
            later.legacy_to_v2_after_tombstone_eviction,
            u64::from(!pre_cutover)
        );
        assert_eq!(later.v2_sessions, u64::from(!pre_cutover));
        assert_eq!(
            reloaded.codex_counting_evicted_legacy.is_empty(),
            pre_cutover,
            "selection alone must not consume correlation"
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut reloaded);
        let owners = BTreeMap::from([(local_index_key(&moved), owner)]);
        codex_counting_version::prepare_moved_evidence(&mut reloaded, &owners, false);
        assert!(
            reloaded.codex_counting_evicted_legacy.is_empty(),
            "committed ACK absorbs correlation"
        );
        fs::remove_dir_all(acked.root).unwrap();
    }
}

#[test]
fn cap_eviction_with_a_live_legacy_carrier_does_not_report_a_flip() {
    for bound in [true, false] {
        let acked = acked_original(false, bound);
        let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
        let owner = codex_protected_owner(SESSION);
        let mut index = acked.previous.clone();
        evict_counting_owner(&mut index, &owner, None);
        assert_eq!(index.codex_counting_evictions, [0, 0, 1]);
        assert!(
            !index.codex_counting_evicted_legacy.is_empty(),
            "record loss without an index walk per eviction"
        );
        write(&acked.original, &rows(200));
        let result = scan_at(&acked.root, &mut index, "2026-10-07T23:00:00Z");
        let receipts = result.codex_counting_v2.as_deref().unwrap();
        assert_eq!(
            receipts.tombstone_evictions_not_provably_pre_cutover_legacy,
            1
        );
        assert_eq!(receipts.legacy_to_v2_after_tombstone_eviction, 0);
        assert_eq!(
            receipts.v2_sessions, 0,
            "the remaining carrier keeps Legacy"
        );
        if bound {
            assert!(
                index.codex_counting_evicted_legacy.is_empty(),
                "committed binding absorbs the record"
            );
        }
        fs::remove_dir_all(acked.root).unwrap();
    }
}

#[test]
fn evicted_legacy_diagnostic_history_is_bounded_lenient_and_charged() {
    let acked = acked_original(false, true);
    let limit = codex_counting_version::MAX_EVICTED_LEGACY_OWNERS;
    let mut owners = (0..limit + 10)
        .map(|n| format!("{n:064x}"))
        .collect::<Vec<_>>();
    owners.push("private-invalid-owner".into());
    owners.push(format!("{:064x}", limit + 9));
    let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
    value["codex_counting_evicted_legacy"] = json!(owners
        .iter()
        .map(|owner| json!({"owner":owner,"selected_v2":false}))
        .collect::<Vec<_>>());
    let derived: ScanIndex = serde_json::from_value(value.clone()).unwrap();
    let expected = (10..limit + 10)
        .map(|n| json!({"owner":format!("{n:064x}"),"selected_v2":false}))
        .collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_value(&derived.codex_counting_evicted_legacy).unwrap(),
        json!(expected)
    );
    if crate::heap_layout_bound::layout_supported() {
        assert!(
            crate::heap_layout_bound::bound(&derived.codex_counting_evicted_legacy, usize::MAX)
                .unwrap()
                > limit * 64
        );
    }
    fs::write(&acked.index_path, serde_json::to_vec(&value).unwrap()).unwrap();
    let loaded = ScanIndex::load(&acked.index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded.codex_counting_evicted_legacy).unwrap(),
        json!(expected)
    );
    for damaged in [json!(null), json!({"future":true}), json!([7])] {
        value["codex_counting_evicted_legacy"] = damaged;
        let derived: ScanIndex = serde_json::from_value(value.clone()).unwrap();
        assert!(derived.codex_counting_evicted_legacy.is_empty());
        fs::write(&acked.index_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(ScanIndex::load(&acked.index_path)
            .unwrap()
            .codex_counting_evicted_legacy
            .is_empty());
    }
    fs::remove_dir_all(acked.root).unwrap();
}

#[test]
fn restored_tombstone_absorbs_old_eviction_correlation_before_absence_gc() {
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let owner = codex_protected_owner(SESSION);
    let mut index = ScanIndex::default();
    evict_counting_owner(&mut index, &owner, None);
    assert!(!index.codex_counting_evicted_legacy.is_empty());
    // Another carrier was later retired successfully, restoring Legacy
    // evidence. A later healthy absence collection is a different loss cause.
    index.codex_counting_tombstones.pop_first();
    index.codex_counting_tombstones.insert(
        owner.clone(),
        codex_counting_version::CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "g1".into(),
            created_unix_ms: None,
        },
    );
    codex_counting_version::prepare_moved_evidence(&mut index, &BTreeMap::new(), true);
    assert!(
        !index.codex_counting_tombstones.contains_key(&owner),
        "absence GC ran"
    );
    assert!(
        index.codex_counting_evicted_legacy.is_empty(),
        "restored carrier absorbed old loss before GC"
    );
    let mut accumulator = SnapshotAccumulator::new(SnapshotSource::Codex);
    codex_counting_version::configure(&mut accumulator, AckEvidence::None, Some(CUTOVER));
    apply_codex_line(&header(POST), &mut accumulator);
    assert!(accumulator.codex_counting_v2());
    assert!(!codex_counting_version::evicted_legacy_selected_v2(
        &accumulator,
        &index
    ));
}

#[test]
fn preexisting_v2_ack_does_not_absorb_an_unobserved_legacy_eviction_flip() {
    let acked = acked_original(true, true);
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let owner = codex_protected_owner(SESSION);
    let mut index = acked.previous.clone();
    // A mixed owner view has a V2-marked live entry and a Legacy tombstone.
    // Removing the latter loses its LAST Legacy carrier, despite the V2 ACK.
    evict_counting_owner(&mut index, &owner, None);
    write(&acked.original, &rows(200));
    let result = scan_at(&acked.root, &mut index, "2026-10-07T23:00:00Z");
    let receipts = result.codex_counting_v2.as_deref().unwrap();
    assert_eq!(receipts.v2_sessions, 1);
    assert_eq!(receipts.legacy_to_v2_after_tombstone_eviction, 1);
    let record = serde_json::to_value(&index.codex_counting_evicted_legacy).unwrap();
    assert_eq!(record[0]["selected_v2"], true);
    // Persist the observation with a partial checkpoint retaining the old V2
    // ACK. Only after that observation may the old ACK absorb correlation.
    let mut checkpoint =
        index.committable_subset(&acked.previous, &BTreeSet::new(), &BTreeMap::new());
    checkpoint.save(&acked.index_path).unwrap();
    let mut loaded = ScanIndex::load(&acked.index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded.codex_counting_evicted_legacy).unwrap(),
        record
    );
    let owners = BTreeMap::from([(local_index_key(&acked.original), owner)]);
    codex_counting_version::prepare_moved_evidence(&mut loaded, &owners, false);
    assert!(loaded.codex_counting_evicted_legacy.is_empty());
    fs::remove_dir_all(acked.root).unwrap();
}
