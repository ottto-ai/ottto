use super::*;
use serde_json::{json, Value};

fn progress() -> SnapshotUploadProgress {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    progress
}
fn body() -> Value {
    json!({"source_session_id":"synthetic-sticky-session", "snapshot_fingerprint":"b".repeat(64),
        "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
        "request_evidence":[{"identity_basis":"telemetry_login"}],
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[{"model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":"a".repeat(64)}]}]})
}
#[test]
fn acknowledged_bucket_keys_survive_progress_restart_and_older_decoder_drops_only_hint() {
    let mut progress = progress();
    progress.record_body(&"b".repeat(64), &"c".repeat(64));
    progress.record_cache_state(&body(), false).unwrap();
    let bytes = serde_json::to_vec(&progress).unwrap();
    let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    restored
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    assert_eq!(
        restored.accepted_identity_buckets,
        progress.accepted_identity_buckets
    );
    assert_eq!(
        restored
            .accepted_identity_buckets
            .get("synthetic-sticky-session")
            .unwrap()
            .len(),
        1
    );
    // An older progress decoder ignores the append-only L field. Re-encoding
    // it loses that hint; the new decoder defaults to unknown, preserving ACKs.
    #[derive(Serialize, Deserialize)]
    struct OlderProgress {
        schema_version: u16,
        generation: u64,
        destination_namespace_hash: String,
        accepted_fingerprints: BTreeSet<String>,
        accepted_body_witnesses: BTreeMap<String, String>,
    }
    let older: OlderProgress = serde_json::from_slice(&bytes).unwrap();
    let downgraded = serde_json::to_vec(&older).unwrap();
    assert!(!String::from_utf8_lossy(&downgraded).contains("accepted_identity_buckets"));
    let restored: SnapshotUploadProgress = serde_json::from_slice(&downgraded).unwrap();
    assert!(restored
        .accepted_identity_buckets
        .get("synthetic-sticky-session")
        .is_none());
    assert_eq!(
        restored.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
}
#[test]
fn only_a_stored_body_ack_records_bucket_keys() {
    let mut progress = progress();
    let items = [body()];
    let mut accepted = 0;
    for stored in [false, true] {
        attempt_snapshot_page(
            &items,
            &[0],
            "synthetic-sticky-ack",
            &mut progress,
            &mut accepted,
            &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
            &|_: &Value| "c".repeat(64),
            &|value: &Value| value["source_session_id"].as_str(),
            &mut |_| {
                let entity = crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: "synthetic-sticky-session".into(),
                    snapshot_fingerprint: "b".repeat(64),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: (!stored).then(|| "usage_identical".into()),
                };
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    accepted: u64::from(stored),
                    sessions_reconciled: 0,
                    session_ids: vec![],
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into(),
                    ),
                    accepted_entities: if stored { vec![entity.clone()] } else { vec![] },
                    unchanged_entities: if stored { vec![] } else { vec![entity] },
                    rejected_entities: vec![],
                    conflict_entities: vec![],
                })
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            progress
                .accepted_identity_buckets
                .get("synthetic-sticky-session")
                .is_some(),
            stored
        );
    }
}

#[test]
fn identity_budget_reserves_predecessor_retractions_without_mutating_local_patch() {
    use crate::snapshots::cache_observations::CacheObservations;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let observation = item.cache_observations_state.as_ref().unwrap()["observations"][0].clone();
    item.cache_observations = Some(CacheObservations {
        schema_version: 1,
        operations: vec![],
        coverage: "complete".into(),
        omitted_observation_count: Some(0),
    });
    let before = item.cache_observations.clone();
    let mut progress = progress();
    progress.accepted_cache_states.insert(
        cache_session_key(&item.source_session_id),
        json!({"observations":(0..32).map(|n| {
            let mut row = observation.clone();
            row["event_id"] = json!(format!("cache:{n:064x}"));
            row
        }).collect::<Vec<_>>()}),
    );
    let reserved = identity_cache_wire_reserve(&item, &progress);
    assert_eq!(item.cache_observations, before);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false, &BTreeSet::new());
    assert_eq!(
        projected
            .cache_observations
            .as_ref()
            .unwrap()
            .operations
            .len(),
        32,
        "reconciled patch: {:?}",
        projected.cache_observations,
    );
    assert!(reserved > 2_000, "reserved={reserved}");
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
    );
    // The upload owner attaches a known predecessor even with no cache patch.
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.cache_requests.clear();
    item.cache_base_head_etag = None;
    progress
        .accepted_cache_heads
        .insert(cache_session_key(&item.source_session_id), "a".repeat(64));
    let reserved = identity_cache_wire_reserve(&item, &progress);
    assert!(reserved > 64);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false, &BTreeSet::new());
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
    );
}

#[test]
fn maximum_accepted_ledger_progress_json_and_actual_load_peak_are_bounded() {
    let mut progress = progress();
    progress.accepted_identity_buckets =
        crate::snapshots::claude_request_identity::AcceptedBuckets::maximum_for_test();
    let bytes = serde_json::to_vec(&progress).unwrap();
    // Worst accepted-ledger caps in the real progress envelope; other ACK owners empty.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ottto-identity-load-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    std::fs::write(&path, &bytes).unwrap();
    let (restored, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
        SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap()
    });
    assert!(!restored.accepted_identity_buckets.is_empty());
    let json_bytes = bytes.len();
    let load_peak = allocation.requested_peak_with_overlap;
    eprintln!("E2_ACCEPTED_PROGRESS_JSON_BYTES={json_bytes} E2_ACCEPTED_PROGRESS_LOAD_PEAK_BYTES={load_peak}");
    assert!(json_bytes < 8 * 1024 * 1024, "json={json_bytes}");
    assert!(load_peak < 32 * 1024 * 1024, "peak={load_peak}");
    std::fs::remove_dir_all(root).unwrap();
}
