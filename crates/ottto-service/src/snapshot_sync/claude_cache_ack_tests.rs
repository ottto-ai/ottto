//! Claude cache rows and the stored-body ACK. Synthetic, content-free bodies.
use super::*;
use serde_json::{json, Value};

const SESSION: &str = "synthetic-cache-session";

/// A Claude body with its session account evidence (a versioned witness
/// domain), and with cache rows when `cache` is set.
fn claude_body(cache: Option<&crate::snapshots::cache_observations::CacheObservations>) -> Value {
    let mut body = json!({"source_session_id":SESSION, "snapshot_fingerprint":"b".repeat(64),
        "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
        "session_account_evidence":{"identity_disposition":"missing"},
        "request_evidence":[{"identity_basis":"telemetry_login"}],
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[{"model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":"a".repeat(64)}]}]});
    if let Some(cache) = cache {
        body["cache_observations"] = serde_json::to_value(cache).unwrap();
    }
    body
}

/// [money] Cache rows on a Claude body leave its stored-body ACK as it was:
/// under a witnessed ACK the accepted identity buckets equal those of the
/// same body without rows, the accepted cache state is the patch's, and a
/// replayed ACK (lost before it was saved) changes nothing.
#[test]
fn claude_cache_rows_keep_the_stored_body_ack() {
    let patch = crate::snapshots::cache_adapter_tests::cache_fixture_item()
        .cache_observations
        .unwrap();
    let witness = "c".repeat(64);
    let entity = crate::snapshot_client::SnapshotEntityRef {
        source_session_id: SESSION.into(),
        snapshot_fingerprint: "b".repeat(64),
        occurrence_count: 1,
        body_witness_version: Some(
            crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_SESSION_ACCOUNT_VERSION,
        ),
        body_witness_digest: Some(witness.clone()),
        head_etag: None,
        head_challenge: None,
        unchanged_basis: None,
        retained_proof_missing: Vec::new(),
    };
    let ack = |progress: &mut SnapshotUploadProgress, body: &Value| {
        progress
            .record_stored_state(body, false, Some((&entity, witness.as_str())))
            .unwrap();
    };
    let progress = || {
        let mut progress = SnapshotUploadProgress::new(
            "a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        );
        progress
            .accepted_identity_buckets
            .bind_test_key(Some([0x42; 32]));
        progress
            .accepted_identity_buckets
            .set_retained_enabled(true);
        progress
    };
    let mut control = progress();
    ack(&mut control, &claude_body(None));
    let mut with_rows = progress();
    ack(&mut with_rows, &claude_body(Some(&patch)));
    assert!(control.accepted_identity_buckets.get(SESSION).is_some());
    assert_eq!(
        with_rows.accepted_identity_buckets,
        control.accepted_identity_buckets
    );
    let key = cache_session_key(SESSION);
    let state = crate::snapshots::cache_state_from_patch(None, &patch).unwrap();
    assert_eq!(with_rows.accepted_cache_states.get(&key), Some(&state));
    // The replay advances the ACK counter as it does for a body without rows.
    ack(&mut with_rows, &claude_body(Some(&patch)));
    ack(&mut control, &claude_body(None));
    assert_eq!(with_rows.accepted_cache_states.get(&key), Some(&state));
    assert_eq!(
        with_rows.accepted_identity_buckets,
        control.accepted_identity_buckets
    );
}
