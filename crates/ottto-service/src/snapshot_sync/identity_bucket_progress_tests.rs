use super::*;
use serde_json::{json, Value};

fn progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
}
fn body() -> Value {
    json!({"source_session_id":"synthetic-sticky-session", "snapshot_fingerprint":"b".repeat(64),
        "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[{"evidence_ref":0}]}]})
}
#[test]
fn acknowledged_bucket_keys_survive_progress_restart_and_older_decoder_drops_only_hint() {
    let mut progress = progress();
    progress.record_body(&"b".repeat(64), &"c".repeat(64));
    progress.record_cache_state(&body(), false).unwrap();
    let bytes = serde_json::to_vec(&progress).unwrap();
    let restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
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
