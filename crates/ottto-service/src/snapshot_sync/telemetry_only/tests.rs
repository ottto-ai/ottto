use super::*;
use serde_json::json;

/// [format] The additive extension defaults absent on ordinary progress.
#[test]
fn additive_progress_hydrate_defaults_dark() {
    let old = json!({"schema_version": SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
        "destination_namespace_hash": "fixture-destination", "generation": 7});
    let progress: SnapshotUploadProgress = serde_json::from_value(old).unwrap();
    assert!(progress.telemetry_only.is_none());
}

/// [format] API precedes trace in the named shape. Missing members default
/// unknown and future members are ignored without dropping the whole ledger.
#[test]
fn generation_shapes_and_candidate_ledger_golden() {
    let api = json!({"device":1,"inode":2,"bytes":3,"modified":[4,5],"changed":[6,7]});
    let trace = json!({"device":8,"inode":9,"bytes":10,"modified":[11,12],"changed":[13,14]});
    for (input, expected) in [
        (json!({}), json!({"api":null,"trace":null})),
        (json!({"api":api}), json!({"api":api,"trace":null})),
        (
            json!({"api":api,"trace":trace}),
            json!({"api":api,"trace":trace}),
        ),
        (
            json!({"api":api,"trace":trace,"future":{}}),
            json!({"api":api,"trace":trace}),
        ),
    ] {
        let raw = json!({"floor":1,"start":2,"candidates":{"root":{
            "built":{"fingerprint":"f","body":"b","generation":input}
        }}});
        let ledger: Ledger = serde_json::from_value(raw.clone()).unwrap();
        let mut golden = raw;
        golden["candidates"]["root"]["built"]["generation"] = expected;
        assert_eq!(serde_json::to_value(ledger).unwrap(), golden);
    }
    assert!(serde_json::from_value::<Built>(
        json!({"fingerprint":"f","body":"b","generation":{"api":false}})
    )
    .is_err());
}

/// Telemetry-only work only a walk takes up keeps an idle pass off: no ledger
/// at the advertised floor, or a pending append notice, owes a walk.
#[test]
fn pending_telemetry_notice_owes_a_walk() {
    let support = crate::test_scratch::ScratchDir::new("telemetry-owes-walk");
    let hint = crate::snapshot_client::decode_activity_hint(json!({
        "source":"claude_code", "server_time":"2026-11-18T00:00:00Z", "record_count_15m":0,
        "record_count_24h":0, "local_usage_reconciliation_enabled":true,
        "backfill_window_days":30, "recommended_scan_after":"2099-01-01T00:00:00Z",
        "snapshot_head_cas_enabled":true, "snapshot_head_cas_required":false,
        "claude_otel_only_sessions_contract":CONTRACT,
        "claude_otel_only_pairing_floor":"2026-08-02T06:00:00Z"
    }))
    .unwrap();
    let window = advertised(&hint).unwrap();
    let mut progress: SnapshotUploadProgress = serde_json::from_value(json!({
        "schema_version": SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
        "destination_namespace_hash": "fixture-destination", "generation": 7}))
    .unwrap();
    let index = ScanIndex::default();
    assert!(
        progress.telemetry_owes_walk(&support, &hint, &index),
        "no ledger"
    );
    progress.telemetry_only = Some(Box::new(Ledger {
        floor: window.floor,
        start: window.start,
        candidates: BTreeMap::new(),
    }));
    assert!(
        !progress.telemetry_owes_walk(&support, &hint, &index),
        "settled"
    );
    otel::telemetry_notices::configure(&support, true).unwrap();
    otel::telemetry_notices::appended_for_test(&support, "synthetic-root");
    assert!(
        progress.telemetry_owes_walk(&support, &hint, &index),
        "a pending notice walks"
    );
    otel::telemetry_notices::configure(&support, false).unwrap();
}
