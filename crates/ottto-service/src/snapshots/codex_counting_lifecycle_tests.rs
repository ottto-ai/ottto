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

fn moved_session(v2: bool, old_binding: bool) {
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
    assert_eq!(previous.files[&old_key].codex_counting_v2, v2);
    assert!(previous.files[&old_key].last_snapshot_fingerprint.is_some());
    assert!(previous.files[&old_key].last_upload_body_witness.is_some());
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
    let archived = root
        .join("archived_sessions")
        .join(original.file_name().unwrap());
    fs::rename(&original, &archived).unwrap();
    write(&archived, &rows(200));
    let _cutover = codex_counting_version::TestCutover::set(CUTOVER);
    let mut working = previous.clone();
    let mut result = scan(&root, &mut working);
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
        .committable_subset(&previous, &accepted, &BTreeMap::new())
        .save(&index_path)
        .unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(loaded.files[&key].codex_counting_v2, v2);
    assert_ne!(
        loaded.files[&key].last_upload_body_witness,
        previous.files[&old_key].last_upload_body_witness
    );
    fs::remove_dir_all(root).unwrap();
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
    codex_counting_version::prepare_moved_evidence(&mut index, &owners);
    assert_eq!(
        codex_counting_version::members_evidence([&candidate], &index),
        AckEvidence::None,
        "a filename cannot transfer a different proven owner's mark"
    );
    // An unbound old mark cannot be attributed by filename. It is a
    // conservative Legacy hint, including when a V2 mark survives there.
    old.codex_counting_owner = None;
    index.files.insert(old_key.clone(), old.clone());
    codex_counting_version::prepare_moved_evidence(&mut index, &owners);
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
    codex_counting_version::prepare_moved_evidence(&mut index, &owners);
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
    codex_counting_version::prepare_moved_evidence(&mut index, &owners);
    assert_eq!(
        codex_counting_version::members_evidence([&candidate], &index),
        AckEvidence::LegacyAcked
    );
}
