use super::*;
use crate::snapshots::*;
use serde_json::json;

const A: &str = "0b6b6c2e-0000-4000-8000-0000000000aa";
const B: &str = "0b6b6c2e-0000-4000-8000-0000000000bb";

fn native(session: &str, requests: &[&str]) -> SnapshotItem {
    let dir = std::env::temp_dir().join(format!(
        "ottto-copy-containment-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{session}.jsonl"));
    let mut file = File::create(&path).unwrap();
    for request in requests {
        let row = json!({"type":"assistant", "sessionId":session,
            "timestamp":"2026-10-07T10:00:00Z", "requestId":request,
            "message":{"id":format!("msg_{request}"), "model":"claude-fixture-model",
                "role":"assistant", "usage":{"input_tokens":10,"output_tokens":2}}});
        serde_json::to_writer(&mut file, &row).unwrap();
        file.write_all(b"\n").unwrap();
    }
    drop(file);
    let mut file = File::open(&path).unwrap();
    let identity = opened_object_identity(SnapshotSource::ClaudeCode, &mut file).unwrap();
    let parsed = parse_opened_jsonl_file(
        file,
        &identity,
        &path,
        "2026-10-08T00:00:00Z",
        "f".repeat(64),
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        None,
        None,
        None,
        true,
        None,
        true,
    )
    .unwrap();
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(parsed.snapshots.len(), 1);
    parsed.snapshots.into_iter().next().unwrap()
}

fn held(start: Option<u64>) -> HoldRevision {
    HoldRevision::new(
        HoldReason::CopiedOverlapUnproven,
        "a".repeat(64),
        "b".repeat(64),
        start,
    )
    .unwrap()
}

#[test]
fn copy_containment_observes_unmarked_rewritten_session_copy_without_mutating_usage() {
    let original = native(A, &["req_shared", "req_original"]);
    let copy = native(B, &["req_shared", "req_copy"]);
    let before = serde_json::to_vec(&copy).unwrap();
    assert_eq!(
        observe_native_pair(&copy, &original),
        NativePairObservation::Overlap { request_count: 1 }
    );
    assert_eq!(
        observe_native_pair(&original, &copy),
        NativePairObservation::Overlap { request_count: 1 }
    );
    assert_eq!(before, serde_json::to_vec(&copy).unwrap());
    assert_eq!(copy.request_count, 2);
    // This checkpoint observes the negative. It neither subtracts nor offers.
}

#[test]
fn copy_containment_equal_aggregate_body_does_not_establish_request_membership() {
    let left = native(A, &["req_left"]);
    let right = native(B, &["req_right"]);
    assert_eq!(left.request_count, right.request_count);
    assert_eq!(left.input_tokens, right.input_tokens);
    assert_eq!(left.output_tokens, right.output_tokens);
    assert_eq!(
        observe_native_pair(&left, &right),
        NativePairObservation::NoObservedOverlap
    );
    let copy = native(B, &["req_left"]);
    assert_eq!(copy.request_count, right.request_count);
    assert_eq!(copy.input_tokens, right.input_tokens);
    assert_eq!(copy.snapshot_fingerprint, right.snapshot_fingerprint);
    assert_eq!(
        serde_json::to_value(&copy).unwrap(),
        serde_json::to_value(&right).unwrap(),
        "the same session's two different native ID sets can have identical wire bodies"
    );
    assert_eq!(
        observe_native_pair(&left, &copy),
        NativePairObservation::Overlap { request_count: 1 }
    );
}

#[test]
fn copy_containment_same_session_in_two_slots_is_not_cross_session_overlap() {
    let left = native(A, &["req_shared"]);
    let right = native(A, &["req_shared"]);
    assert_eq!(
        observe_native_pair(&left, &right),
        NativePairObservation::SameSession
    );
}

#[test]
fn copy_containment_owner_bound_refusal_returns_no_partial_overlap_count() {
    let mut left = native(A, &["req_shared"]);
    let right = native(B, &["req_shared"]);
    left.claude_usage_request_ids = (0..=MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
        .map(|i| format!("req_{i}"))
        .collect();
    assert_eq!(
        observe_native_pair(&left, &right),
        NativePairObservation::Unavailable
    );
}

#[test]
fn copy_containment_hold_revision_change_never_resets_known_or_unknown_age() {
    let old = held(Some(100));
    let next = old.revise("c".repeat(64), "d".repeat(64)).unwrap();
    assert_eq!(next.known_observed_age_seconds(150), Some(50));
    assert_eq!(next.reason, old.reason);
    assert_eq!(
        held(None)
            .revise("c".repeat(64), "d".repeat(64))
            .unwrap()
            .known_observed_age_seconds(150),
        None
    );
    assert_eq!(old.known_observed_age_seconds(99), None);
}

#[test]
fn copy_containment_hold_roundtrip_is_content_free_and_rejects_unknown_contracts() {
    let record = held(Some(100));
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(HoldRevision::decode(&bytes), Some(record));
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    value["version"] = json!(2);
    assert!(HoldRevision::decode(&serde_json::to_vec(&value).unwrap()).is_none());
    value["version"] = json!(1);
    value["path"] = json!("must not accept arbitrary diagnostic text");
    assert!(HoldRevision::decode(&serde_json::to_vec(&value).unwrap()).is_none());
}

#[test]
fn copy_containment_hold_rejects_truncated_fingerprints_or_fabricated_epoch_age() {
    assert!(HoldRevision::new(
        HoldReason::CopiedOverlapUnproven,
        "a".repeat(8),
        "b".repeat(64),
        None
    )
    .is_none());
    assert!(HoldRevision::new(
        HoldReason::CopiedOverlapUnproven,
        "a".repeat(64),
        "b".repeat(64),
        Some(0)
    )
    .is_none());
    let record = held(None);
    assert!(record.revise("A".repeat(64), "b".repeat(64)).is_none());
}

#[test]
fn copy_containment_observation_borrows_ids_without_allocating_a_second_owner_graph() {
    let original = native(A, &["req_shared", "req_original"]);
    let copy = native(B, &["req_shared", "req_copy"]);
    let (observation, allocations) =
        crate::retry_allocation_probe::measure(|| observe_native_pair(&copy, &original));
    assert_eq!(
        observation,
        NativePairObservation::Overlap { request_count: 1 }
    );
    assert_eq!(allocations.allocations, 0);
    eprintln!("copy_containment_component: actual_native_pair=true overlap_ids=1 second_owner_graph_allocations={} upload_hold_wiring=false ack_membership=false", allocations.allocations);
}

#[test]
fn copy_containment_rearm_of_committed_entry_does_not_reset_revision_parking() {
    let record = held(None);
    let revision = "a".repeat(64);
    let context = "b".repeat(64);
    let path = PathBuf::from(format!("/synthetic/{A}.jsonl"));
    let key = local_index_key(&path);
    let candidate = CandidateFile {
        scan_root: PathBuf::from("/synthetic"),
        path,
        size_bytes: 1,
        modified_unix_seconds: 2,
        modified_unix_nanos: 3,
        source_file_fingerprint: revision.clone(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: "actual-opened-identity-fixture".to_string(),
    };
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(json!({
            "size_bytes":1,"modified_unix_seconds":2,"modified_unix_nanos":3,
            "source_file_fingerprint":revision,"last_snapshot_fingerprint":"entity",
            "scan_identity_version":LOCAL_SCAN_INDEX_IDENTITY_VERSION
        }))
        .unwrap(),
    );
    index
        .snapshot_activity_at
        .insert("entity".into(), Some("2026-10-07T10:00:00Z".into()));
    let mut base_parses = 0;
    for _ in 0..12 {
        // The real candidate gate observes the same invalidated fingerprint
        // produced by ordinary/proven/stale rearm. This does NOT execute those
        // rearm controllers or the upload/checkpoint lifecycle.
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        assert_eq!(
            index.candidate_decision_with_reason_at(&candidate, 100),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::Rearmed)
            )
        );
        base_parses += 1;
        assert_eq!(
            record.read_disposition(&candidate.source_file_fingerprint, &context),
            ReadDisposition::ParkUnchangedHeldRevision
        );
        assert_eq!(record.known_observed_age_seconds(100), None);
    }
    assert_eq!(base_parses, 12);
    assert_eq!(
        record.read_disposition(&"c".repeat(64), &context),
        ReadDisposition::ReadRevisionOrEvidenceChanged
    );
    assert_eq!(
        record.read_disposition(&candidate.source_file_fingerprint, &"d".repeat(64)),
        ReadDisposition::ReadRevisionOrEvidenceChanged
    );
    // No normal Skip/certificate, current native read or ACK was manufactured.
}

#[test]
fn copy_containment_hold_encoded_and_clone_requested_bytes_are_measured_separately() {
    let record = held(Some(100));
    let encoded = serde_json::to_vec(&record).unwrap();
    let (copy, allocations) = crate::retry_allocation_probe::measure(|| record.clone());
    assert_eq!(record, copy);
    assert!(allocations.requested_peak >= 128);
    let layout = crate::heap_layout_bound::bound(&copy, usize::MAX);
    eprintln!("copy_containment_hold_component: encoded_bytes={} clone_requested_peak_bytes={} clone_allocations={} requested_layout={layout:?} map_storage_unmeasured=true rss_unmeasured=true", encoded.len(), allocations.requested_peak, allocations.allocations);
}
