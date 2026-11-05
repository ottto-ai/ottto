//! Canonical bytes and fingerprints of kept Claude telemetry rows, frozen from
//! the serializer before these rows shared repeated values in memory.
use super::usage_ledger::{
    claude_api_evidence_fingerprint_is_valid, claude_trace_evidence_fingerprint_is_valid,
};
use crate::claude_local_otel::{
    ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
    ClaudeLocalOtelEvidence, ClaudeRequestIdentityEvidence, ClaudeTraceOwnershipEvidence,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const H1: &str = "11111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const H2: &str = "22222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const V2_FINGERPRINT: &str =
    "sha256:b12084d4dd4d1f5bd8e1fc2590949d0c9022a251ba2be9046cde047fb0b23f6e";
const V2: &str = r#"{"capture_revision":"claude_api_request:v2","fingerprint":"sha256:b12084d4dd4d1f5bd8e1fc2590949d0c9022a251ba2be9046cde047fb0b23f6e","session_id":"golden-session","request_id":"req_golden01","client_request_id":"client-01","observed_at":"2026-11-05T00:00:00.000000000Z","model":"claude-golden-é\"","effort":"high","query_source":"repl_main_thread","speed":"fast","cost_usd_micros":4321,"event_sequence":7,"app_version":"2.1.99","input_tokens":11,"output_tokens":22,"cache_read_tokens":33,"cache_creation_tokens":44,"cache_creation_5m_tokens":5,"cache_creation_1h_tokens":6,"reasoning_output_tokens":7,"request_count":1,"account_identity_checked":true,"account_identifier_hash":"11111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_identity":{"identity_hash_scheme":"provider-sha256:v1","account":{"origin":"resource_and_log_record","disposition":"complete","resource_hash":"11111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","log_record_hash":"11111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"organization":{"origin":"log_record","disposition":"complete","log_record_hash":"22222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"disposition":"complete"}}"#;
const LEGACY_FINGERPRINT: &str =
    "sha256:7cf84595ff730079aa7d64cdfaf88e56e8b3c9ced3f68fe8a2ea3aba0133efbe";
// A row written before revisions, request ids and identity: defaults fill in.
const LEGACY_INPUT: &str = r#"{"fingerprint":"sha256:7cf84595ff730079aa7d64cdfaf88e56e8b3c9ced3f68fe8a2ea3aba0133efbe","session_id":"golden-session","observed_at":"2026-01-02T03:04:05Z","model":"claude-legacy","effort":"medium","input_tokens":1,"output_tokens":2,"cache_read_tokens":3,"cache_creation_5m_tokens":4,"cache_creation_1h_tokens":5,"reasoning_output_tokens":0,"request_count":1}"#;
const LEGACY: &str = r#"{"capture_revision":"","fingerprint":"sha256:7cf84595ff730079aa7d64cdfaf88e56e8b3c9ced3f68fe8a2ea3aba0133efbe","session_id":"golden-session","request_id":"","client_request_id":"","observed_at":"2026-01-02T03:04:05Z","model":"claude-legacy","effort":"medium","query_source":"","speed":"","cost_usd_micros":null,"event_sequence":null,"app_version":"","input_tokens":1,"output_tokens":2,"cache_read_tokens":3,"cache_creation_tokens":0,"cache_creation_5m_tokens":4,"cache_creation_1h_tokens":5,"reasoning_output_tokens":0,"request_count":1,"account_identity_checked":false}"#;
const TRACE_FINGERPRINT: &str =
    "sha256:ba4a66c4bd04182f187fec41580aebb3469f41f8f1e7269ec535b1b0ae4b6ce6";
const TRACE: &str = r#"{"capture_revision":"claude_llm_request_ownership:v1","fingerprint":"sha256:ba4a66c4bd04182f187fec41580aebb3469f41f8f1e7269ec535b1b0ae4b6ce6","session_id":"golden-session","request_id":"req_golden01","client_request_id":"client-01","agent_id":"agent-abc","parent_agent_id":"","workflow_run_id":"wf-1","observed_at":"2026-11-05T00:00:00.000000000Z"}"#;

fn identity() -> ClaudeRequestIdentityEvidence {
    use ClaudeIdentityDisposition::Complete;
    ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".into(),
        account: ClaudeIdentityAttributeEvidence {
            origin: ClaudeIdentityAttributeOrigin::ResourceAndLogRecord,
            disposition: Complete,
            resource_hash: Some(H1.into()),
            log_record_hash: Some(H1.into()),
        },
        organization: ClaudeIdentityAttributeEvidence {
            origin: ClaudeIdentityAttributeOrigin::LogRecord,
            disposition: Complete,
            resource_hash: None,
            log_record_hash: Some(H2.into()),
        },
        disposition: Complete,
    }
}

fn v2_row() -> ClaudeLocalOtelEvidence {
    ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        fingerprint: V2_FINGERPRINT.into(),
        session_id: "golden-session".into(),
        request_id: "req_golden01".into(),
        client_request_id: "client-01".into(),
        observed_at: "2026-11-05T00:00:00.000000000Z".into(),
        model: "claude-golden-é\"".into(),
        effort: "high".into(),
        query_source: "repl_main_thread".into(),
        speed: "fast".into(),
        cost_usd_micros: Some(4321),
        event_sequence: Some(7),
        app_version: "2.1.99".into(),
        input_tokens: 11,
        output_tokens: 22,
        cache_read_tokens: 33,
        cache_creation_tokens: 44,
        cache_creation_5m_tokens: 5,
        cache_creation_1h_tokens: 6,
        reasoning_output_tokens: 7,
        request_count: 1,
        account_identity_checked: true,
        account_identifier_hash: Some(H1.into()),
        request_identity: Some(Arc::new(identity())),
        ..Default::default()
    }
}

fn legacy_row() -> ClaudeLocalOtelEvidence {
    ClaudeLocalOtelEvidence {
        fingerprint: LEGACY_FINGERPRINT.into(),
        session_id: "golden-session".into(),
        observed_at: "2026-01-02T03:04:05Z".into(),
        model: "claude-legacy".into(),
        effort: "medium".into(),
        input_tokens: 1,
        output_tokens: 2,
        cache_read_tokens: 3,
        cache_creation_5m_tokens: 4,
        cache_creation_1h_tokens: 5,
        request_count: 1,
        ..Default::default()
    }
}

fn trace_row() -> ClaudeTraceOwnershipEvidence {
    ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        fingerprint: TRACE_FINGERPRINT.into(),
        session_id: "golden-session".into(),
        request_id: "req_golden01".into(),
        client_request_id: "client-01".into(),
        agent_id: "agent-abc".into(),
        parent_agent_id: String::new(),
        workflow_run_id: "wf-1".into(),
        observed_at: "2026-11-05T00:00:00.000000000Z".into(),
    }
}

fn digest(value: &impl serde::Serialize) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(value).unwrap())
    )
}

#[test]
fn kept_claude_rows_keep_frozen_canonical_bytes_and_fingerprints() {
    for (typed, input, canonical, fingerprint) in [
        (v2_row(), V2, V2, V2_FINGERPRINT),
        (legacy_row(), LEGACY_INPUT, LEGACY, LEGACY_FINGERPRINT),
    ] {
        let decoded: ClaudeLocalOtelEvidence = serde_json::from_str(input).unwrap();
        assert_eq!(decoded, typed);
        for row in [&typed, &decoded] {
            assert_eq!(serde_json::to_string(row).unwrap(), canonical);
            let mut cleared = row.clone();
            cleared.fingerprint.clear();
            assert_eq!(digest(&cleared), fingerprint);
            assert!(claude_api_evidence_fingerprint_is_valid(row));
        }
    }
    let typed = trace_row();
    let decoded: ClaudeTraceOwnershipEvidence = serde_json::from_str(TRACE).unwrap();
    assert_eq!(decoded, typed);
    for row in [&typed, &decoded] {
        assert_eq!(serde_json::to_string(row).unwrap(), TRACE);
        let mut cleared = row.clone();
        cleared.fingerprint.clear();
        assert_eq!(digest(&cleared), TRACE_FINGERPRINT);
        assert!(claude_trace_evidence_fingerprint_is_valid(row));
    }
}
