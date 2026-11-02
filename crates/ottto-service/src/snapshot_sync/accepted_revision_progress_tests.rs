//! Accepted-head revision storage only; no recomposition consumer.
use super::*;
use crate::snapshot_client::SnapshotBatchResponse;
use serde_json::{json, Value};

fn progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

fn ack(item: &SnapshotItem, hash: Option<&str>, unchanged: bool, cas: bool) -> Value {
    let version = crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
    let mut reference = json!({
        "source_session_id": item.source_session_id,
        "snapshot_fingerprint": item.snapshot_fingerprint,
        "body_witness_version": version,
        "body_witness_digest": version.map(|_| snapshot_upload_body_witness(item)),
    });
    if cas {
        reference["head_etag"] = json!("e".repeat(64));
    }
    if let Some(hash) = hash {
        reference["accepted_revision_v2_hash"] = json!(hash);
    }
    let mut value = json!({
        "accepted": 1, "sessions_reconciled": 0, "session_ids": [],
        "disabled": false,
        "entity_ack_contract": crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities": [], "unchanged_entities": [],
    });
    value[if unchanged {
        "unchanged_entities"
    } else {
        "accepted_entities"
    }] = json!([reference]);
    value
}

fn settle(progress: &mut SnapshotUploadProgress, item: &SnapshotItem, value: Value, path: &Path) {
    let mut accepted = 0;
    attempt_snapshot_page(
        std::slice::from_ref(item),
        &[0],
        "accepted-revision-test",
        progress,
        &mut accepted,
        &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        &snapshot_upload_body_witness,
        &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
        &mut |items| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: None,
                snapshots: items,
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let response = SnapshotBatchResponse::decode_for_head_cas(value.clone(), true)?;
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        &mut |progress| progress.save(path),
    )
    .unwrap();
    assert_eq!(accepted, 1);
}

fn stored_hash(progress: &SnapshotUploadProgress, item: &SnapshotItem) -> Value {
    serde_json::to_value(progress).unwrap()["accepted_revision_v2_hashes"]
        [&item.snapshot_fingerprint]
        .clone()
}

/// [behaviour] Only head-CAS responses decode the optional 64-lowercase-hex hash.
#[test]
fn non_cas_ignores_revision_and_cas_validates_64_hex() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    for hash in [
        "b".repeat(64),
        "B".repeat(64),
        "b".repeat(63),
        "b".repeat(65),
        "g".repeat(64),
    ] {
        let legacy = SnapshotBatchResponse::decode_for_head_cas(
            ack(&item, Some(&hash), false, false),
            false,
        )
        .unwrap();
        assert!(legacy.accepted_entities[0]
            .accepted_revision_v2_hash
            .is_none());
        let cas =
            SnapshotBatchResponse::decode_for_head_cas(ack(&item, Some(&hash), false, true), true);
        assert_eq!(cas.is_ok(), hash == "b".repeat(64));
    }
    let without =
        SnapshotBatchResponse::decode_for_head_cas(ack(&item, None, false, true), true).unwrap();
    assert!(without.accepted_entities[0]
        .accepted_revision_v2_hash
        .is_none());
}

/// [behaviour] Store the canonical head even when local hashes differ; absent re-ACK keeps it.
#[test]
fn ack_replaces_hash_and_absent_settled_reack_keeps_it_across_restart() {
    let root = crate::test_scratch::ScratchDir::new("accepted-revision-ack");
    let path = root.join("progress.json");
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let mut progress = progress();
    for (hash, unchanged) in [
        (Some("b".repeat(64)), false),
        (Some("c".repeat(64)), true),
        (None, true),
    ] {
        if let Some(hash) = &hash {
            assert_ne!(*hash, snapshot_upload_body_witness(&item));
            assert_ne!(
                *hash,
                crate::snapshots::snapshot_semantic_envelope(
                    SnapshotSource::Codex,
                    &item,
                    SnapshotUploadPolicy::default()
                )
                .revision_v2_hash
            );
        }
        settle(
            &mut progress,
            &item,
            ack(&item, hash.as_deref(), unchanged, true),
            &path,
        );
        let expected = hash.unwrap_or_else(|| "c".repeat(64));
        progress = SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        assert_eq!(stored_hash(&progress, &item), json!(expected));
        assert!(!format!("{progress:?}").contains(&expected));
    }
    // Cache-head bootstrap must force a re-ACK without erasing the old proof.
    bootstrap_cache_heads(
        std::slice::from_ref(&item),
        "accepted-revision-test",
        &mut progress,
        false,
        |batch, cas| {
            assert!(cas);
            SnapshotBatchResponse::decode_for_head_cas(ack(&batch[0], None, true, true), cas)
        },
        |progress| progress.save(&path),
    )
    .unwrap();
    assert_eq!(stored_hash(&progress, &item), json!("c".repeat(64)));
    // An archived head without earlier proof stays absent, never locally inferred.
    let mut empty = self::progress();
    let empty_path = root.join("empty.json");
    settle(&mut empty, &item, ack(&item, None, true, true), &empty_path);
    assert!(empty.accepted_revision_v2_hashes.is_empty());
}

/// [format] Version 3 migrates at the existing CAS save; unknown future versions hold untouched.
#[test]
fn v3_migrates_and_future_progress_is_not_quarantined_or_overwritten() {
    let root = crate::test_scratch::ScratchDir::new("accepted-revision-upgrade");
    let path = root.join("progress.json");
    let entity = "d".repeat(64);
    let old = json!({"schema_version":3,"generation":7,"destination_namespace_hash":"a".repeat(64),
        "accepted_fingerprints":[entity],"accepted_body_witnesses":{&entity:"e".repeat(64)}});
    std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
    let load = || {
        SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
    };
    let mut migrated = load().unwrap();
    assert_eq!(migrated.schema_version, 4);
    assert!(migrated.accepted_revision_v2_hashes.is_empty());
    assert!(migrated.accepted_fingerprints.contains(&entity));
    migrated.save(&path).unwrap();
    assert_eq!(load().unwrap().generation, 8);
    let mut future = serde_json::to_value(&migrated).unwrap();
    future["schema_version"] = json!(5);
    let bytes = serde_json::to_vec(&future).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    assert!(load()
        .unwrap_err()
        .to_string()
        .contains("future schema hold"));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(migrated.save(&path).is_err());
    assert!(validate_state_v2_original_progress(&bytes, &"a".repeat(64)).is_err());
}

/// [format] Persisted values use the same strict hash shape and require an owning entity.
#[test]
fn persisted_hash_shape_and_entity_ownership_are_validated() {
    let root = crate::test_scratch::ScratchDir::new("accepted-revision-invalid");
    let path = root.join("progress.json");
    let entity = "d".repeat(64);
    let mut original = progress();
    original.record_body(&entity, &"e".repeat(64));
    for (hash, owner) in [
        ("b".repeat(64), true),
        ("B".repeat(64), true),
        ("b".repeat(63), true),
        ("g".repeat(64), true),
        ("b".repeat(64), false),
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        let key = if owner { entity.as_str() } else { "f" };
        value["accepted_revision_v2_hashes"] = json!({key:hash});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        assert_eq!(
            !loaded.accepted_revision_v2_hashes.is_empty(),
            owner && hash == "b".repeat(64)
        );
    }
}

/// [behaviour] A not-stored unchanged ACK cannot carry accepted-body revision proof.
#[test]
fn not_stored_ack_cannot_supply_a_revision() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let mut value = ack(&item, Some(&"b".repeat(64)), true, true);
    value["unchanged_entities"][0]["unchanged_basis"] = json!("usage_identical");
    let response = SnapshotBatchResponse::decode_for_head_cas(value, true).unwrap();
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "a".repeat(64),
        collector_version: None,
        snapshots: vec![item],
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    assert!(response
        .validate_entity_ack_with_head_cas(&request, true)
        .is_err());
}

/// [format] Retirement, replay reset and source-off remove the accepted digest with its entity.
#[test]
fn erase_revision_with_entity_and_source_scope() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let root = crate::test_scratch::ScratchDir::new("accepted-revision-erase");
        let stable = snapshot_index_path(&root, source);
        let index = snapshot_destination_scoped_index_path(&stable, &"a".repeat(64));
        let index = snapshot_v3_index_path(&index);
        let path = snapshot_upload_progress_path(&index);
        let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        let mut progress = self::progress();
        settle(
            &mut progress,
            &item,
            ack(&item, Some(&"b".repeat(64)), false, true),
            &path,
        );
        let mut retired = progress.clone();
        let saved = ScanIndex {
            generation: 1,
            ..Default::default()
        };
        retired.retire_acks_after_index_save(
            &saved,
            &BTreeSet::from([item.snapshot_fingerprint.clone()]),
            &BTreeSet::new(),
        );
        assert!(retired.accepted_revision_v2_hashes.is_empty());
        let mut replay = progress.clone();
        assert!(replay.prepare_historical_replay("new-generation"));
        assert!(replay.accepted_revision_v2_hashes.is_empty());
        let mut held = progress.clone();
        held.hold_unstored_body(
            &item.snapshot_fingerprint,
            &snapshot_upload_body_witness(&item),
        );
        assert!(held.accepted_revision_v2_hashes.is_empty());
        erase_source_files(&root, source, || Ok(())).unwrap();
        assert!(!path.exists());
        assert!(SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(source)
        )
        .unwrap()
        .accepted_revision_v2_hashes
        .is_empty());
    }
}
