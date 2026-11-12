use super::*;
use serde_json::json;

fn hint() -> crate::snapshot_client::ActivityHintResponse {
    crate::snapshot_client::decode_activity_hint(json!({
        "source": "claude_code", "server_time": "2026-11-12T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 30,
        "recommended_scan_after": "2026-11-12T00:00:00Z",
        "snapshot_head_cas_required": true,
        "claude_otel_only_sessions_contract": CONTRACT,
        "claude_otel_only_pairing_floor": "2026-11-11T00:00:00Z"
    }))
    .unwrap()
}

/// [off=main] Missing/unknown capability never builds a window; each other
/// prerequisite independently closes it too. The base path stays available.
#[test]
fn off_main_capability_prerequisites() {
    assert!(advertised(&hint()).is_some());
    let mut variants = Vec::new();
    let mut value = hint();
    value.claude_otel_only_sessions_contract = None;
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_sessions_contract = Some("unknown".into());
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_floor = None;
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_floor = Some("invalid".into());
    variants.push(value);
    let mut value = hint();
    value.local_usage_reconciliation_enabled = false;
    variants.push(value);
    let mut value = hint();
    value.snapshot_head_cas_required = false;
    variants.push(value);
    let mut value = hint();
    value.source = "codex".into();
    variants.push(value);
    let mut value = hint();
    value.source = "pi".into();
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_ceiling = Some("invalid".into());
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_ceiling = value.claude_otel_only_pairing_floor.clone();
    variants.push(value);
    assert!(variants.iter().all(|value| advertised(value).is_none()));
}

/// [format] Tolerant optional hint decoding must not fail the ordinary response.
#[test]
fn malformed_optional_hints_stay_dark() {
    let mut value = serde_json::to_value(json!({
        "source": "claude_code", "server_time": "2026-11-12T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 30,
        "recommended_scan_after": "2026-11-12T00:00:00Z",
        "snapshot_head_cas_required": true,
        "claude_otel_only_sessions_contract": CONTRACT,
        "claude_otel_only_pairing_floor": "2026-11-11T00:00:00Z"
    }))
    .unwrap();
    for field in [
        "claude_otel_only_sessions_contract",
        "claude_otel_only_pairing_floor",
        "claude_otel_only_pairing_ceiling",
    ] {
        let before = value.clone();
        value[field] = json!({"unexpected": true});
        let decoded = crate::snapshot_client::decode_activity_hint(value.clone()).unwrap();
        assert!(advertised(&decoded).is_none());
        value = before;
    }
}

/// [behaviour] Fresh ids survive process restarts without a registry; ordinary
/// SDK sessions are not classified by query source or prompt.
#[test]
fn smoke_namespace_is_fresh_and_exact() {
    let a = crate::claude_spawn_gate::internal_session_id();
    let b = crate::claude_spawn_gate::internal_session_id();
    assert_ne!(a, b);
    assert!(crate::claude_spawn_gate::is_internal_session_id(&a));
    assert!(crate::claude_spawn_gate::is_internal_session_id(&b));
    assert!(!crate::claude_spawn_gate::is_internal_session_id(
        "c1153105-cc62-46fb-8020-611012351215"
    ));
    assert!(!crate::claude_spawn_gate::is_internal_session_id(&format!(
        "{a}0"
    )));
}

/// [format] The additive extension defaults absent on ordinary progress.
#[test]
fn additive_progress_hydrate_defaults_dark() {
    let old = json!({"schema_version": SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
        "destination_namespace_hash": "fixture-destination", "generation": 7});
    let progress: SnapshotUploadProgress = serde_json::from_value(old).unwrap();
    assert!(progress.telemetry_only.is_none());
}

/// [format] The pair's append-only order is API, trace. Old short sequences
/// pad with unknown; future tails are consumed without failing the ledger.
#[test]
fn generation_shapes_and_candidate_ledger_golden() {
    let api = json!({"device":1,"inode":2,"bytes":3,"modified":[4,5],"changed":[6,7]});
    let trace = json!({"device":8,"inode":9,"bytes":10,"modified":[11,12],"changed":[13,14]});
    for (input, expected) in [
        (json!([]), json!([null, null])),
        (json!([api]), json!([api, null])),
        (json!([api, trace]), json!([api, trace])),
        (json!([api,trace,{"future":"tail"}]), json!([api, trace])),
    ] {
        let raw = json!({"floor":1,"start":2,"candidates":{"root":{
            "built":{"fingerprint":"f","body":"b","generation":input,"context":"c"},"accepted":true
        }}});
        let ledger: Ledger = serde_json::from_value(raw.clone()).unwrap();
        let mut golden = raw;
        golden["candidates"]["root"]["built"]["generation"] = expected;
        assert_eq!(serde_json::to_value(ledger).unwrap(), golden);
    }
    assert!(serde_json::from_value::<Binding>(
        json!({"fingerprint":"f","body":"b","generation":[false]})
    )
    .is_err());
}

#[test]
fn delivery_requires_exact_accepted_body_context_and_destination() {
    let root = "candidate";
    let binding = json!({"fingerprint":"f","body":"b","generation":[null,null],"context":"c"});
    let mut value = json!({"schema_version":SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
        "destination_namespace_hash":"destination", "generation":1,
        "telemetry_only":{"floor":1,"start":2,"candidates":{root:{"built":binding,"accepted":false}}},
        "accepted_body_witnesses":{"f":"b"}, "accepted_body_contexts":{"f":"c"}});
    let mut progress: SnapshotUploadProgress = serde_json::from_value(value.clone()).unwrap();
    assert!(
        progress.telemetry_deliveries().is_empty(),
        "stored/unchanged ACK is not accepted-only proof"
    );
    progress.accept_telemetry(root, "other", "b");
    assert!(progress.telemetry_deliveries().is_empty());
    progress.accept_telemetry(root, "f", "different");
    assert!(progress.telemetry_deliveries().is_empty());
    progress.accept_telemetry(root, "f", "b");
    assert_eq!(progress.telemetry_deliveries().len(), 1);
    value = serde_json::to_value(&progress).unwrap();
    for (field, bad) in [
        ("accepted_body_witnesses", json!({"f":"changed"})),
        (
            "accepted_body_contexts",
            json!({"f":"different-destination"}),
        ),
    ] {
        let mut changed = value.clone();
        changed[field] = bad;
        let changed: SnapshotUploadProgress = serde_json::from_value(changed).unwrap();
        assert!(changed.telemetry_deliveries().is_empty());
    }
    progress.settle_telemetry_root(root);
    assert!(progress
        .telemetry_only
        .as_ref()
        .unwrap()
        .references()
        .next()
        .is_none());
}
