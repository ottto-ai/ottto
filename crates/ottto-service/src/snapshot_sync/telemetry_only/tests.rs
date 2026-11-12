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
