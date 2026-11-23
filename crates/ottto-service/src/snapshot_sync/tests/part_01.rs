use super::*;
mod upload_borrowed_tests {
    include!("../upload_borrowed_tests.rs");
}
#[test]
fn owner_return_presence_uses_only_selected_source_custody() {
    let root = crate::test_scratch::ScratchDir::canonical("owner-return-presence");
    let ns = "a".repeat(64);
    let selected = root.join("snapshots/destinations").join(&ns);
    let other = root.join("snapshots/destinations").join("b".repeat(64));
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("codex-scan-index-v3.json"), b"{}").unwrap();
    assert!(!snapshot_namespace_has_store(&root, &ns).unwrap());
    std::fs::create_dir_all(&selected).unwrap();
    assert!(
        !snapshot_namespace_has_store(&root, &ns).unwrap(),
        "empty directory"
    );
    for (name, expected) in [
        ("codex-scan-index-v3.json", true),
        ("codex-scan-index-v3.json.v2.sqlite", true),
        ("codex-scan-index-v3.json.v2.sqlite.import", true),
        (
            "claude_code-scan-index-no-titles-attribution-epoch-v2.json",
            true,
        ),
        ("pi-scan-index.json", true),
        ("codex-scan-index-v3.corrupt.1.2.json", true),
        ("codex-scan-index-v3.json.v1-readonly", true),
        ("codex-scan-index-v3.json.v2-ack-receipt", true),
        ("codex-scan-index-v3-upload-progress.json", false),
        ("codex-scan-index-v3.json.lock", false),
        ("codex-scan-index-v3.json.tmp", false),
        ("codex-scan-index-v3.json.v2.sqlite.migration-backup", false),
    ] {
        let path = selected.join(name);
        std::fs::write(&path, b"{}").unwrap();
        assert_eq!(
            snapshot_namespace_has_store(&root, &ns).unwrap(),
            expected,
            "{name}"
        );
        std::fs::remove_file(path).unwrap();
    }
    let shards = selected.join("codex-scan-index-v3.json.shards");
    std::fs::create_dir(&shards).unwrap();
    assert!(
        snapshot_namespace_has_store(&root, &ns).unwrap(),
        "root-lost shards retain custody"
    );
    std::fs::remove_dir(shards).unwrap();
    std::fs::write(selected.join("pi-scan-index-v3.json"), b"{}").unwrap();
    assert!(
        snapshot_namespace_has_store(&root, &ns).unwrap(),
        "one surviving source is sufficient"
    );
    #[cfg(unix)]
    {
        let link = selected.join("codex-scan-index-v3.json");
        std::os::unix::fs::symlink(root.join("missing"), &link).unwrap();
        assert!(
            snapshot_namespace_has_store(&root, &ns).is_err(),
            "unknown sibling holds even with Pi present"
        );
    }
}

mod upload_error_tests {
    include!("../upload_error_tests.rs");
}
pub(super) mod codex_archive_tests {
    include!("../codex_archive_tests.rs");
}
mod terminal_contract_retry_tests {
    include!("../terminal_contract_retry_tests.rs");
}
mod ack_retention_tests {
    include!("../ack_retention_tests.rs");
}
use crate::snapshots::finalize_scan_after_policy;
/// [behaviour] Pinned: changing a history revision or replay string re-reads all history.
#[test]
fn history_revisions_are_pinned() {
    for (source, revision, replay) in [
        (
            SnapshotSource::ClaudeCode,
            3,
            "claude_reported_usage_union:v4",
        ),
        (SnapshotSource::Codex, 1, "codex_session_exclusive_usage:v7"),
        (SnapshotSource::Pi, 1, "pi_founder_backfill_leg_a:v1"),
    ] {
        assert_eq!(effective_upload_body_witness_revision(source), revision);
        assert_eq!(current_historical_replay(source).revision, replay);
    }
}
#[test]
fn machine_icon_cache_preserves_missing_null_and_blank_echoes() {
    let root = crate::test_scratch::ScratchDir::new("machine-icon-cache");
    let path = root.join("machine_icon.json");
    let cached =
        r#"{"machine_id":"otm_test","icon_url":"https://example.test/old.png","icon_version":7}"#;
    for echo in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("")),
        Some(serde_json::json!(" \t\n")),
    ] {
        let mut response = serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["codex"],"machine_icon_version":8});
        if let Some(echo) = echo {
            response["machine_icon_url"] = echo;
        }
        let response = serde_json::from_value(response).unwrap();
        persist_machine_icon_at(&path, &response);
        assert!(
            !path.exists(),
            "missing echoes must not create an unusable cache"
        );
        std::fs::write(&path, cached).unwrap();
        persist_machine_icon_at(&path, &response);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), cached);
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn machine_icon_cache_replaces_valid_echo_and_keeps_machine_identity() {
    let root = crate::test_scratch::ScratchDir::new("machine-icon-replacement");
    let path = root.join("machine_icon.json");
    std::fs::write(
        &path,
        r#"{"machine_id":"otm_test","icon_url":"https://example.test/old.png","icon_version":7}"#,
    )
    .unwrap();
    for machine_id in ["otm_test", "otm_other"] {
        let response = serde_json::from_value(serde_json::json!({
            "accepted":1,"machine_id":machine_id,"sources":["codex"],
            "machine_icon_url":"https://example.test/new.png","machine_icon_version":9
        }))
        .unwrap();
        persist_machine_icon_at(&path, &response);
        let cached: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            cached,
            serde_json::json!({"machine_id":machine_id,"icon_url":"https://example.test/new.png","icon_version":9})
        );
    }
    let cached = std::fs::read(&path).unwrap();
    let response = serde_json::from_value(
        serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["codex"]}),
    )
    .unwrap();
    persist_machine_icon_at(&path, &response);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        cached,
        "a missing echo must not relabel another machine's icon"
    );
}

pub(in crate::snapshot_sync) fn pending_head_index_item() -> (ScanIndex, SnapshotItem) {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let mut index = ScanIndex::default();
    index.files.insert(
        "synthetic/deferred.jsonl".into(),
        crate::snapshots::ScanIndexEntry {
            codex_fragment: None,
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: Some(1),
            source_file_fingerprint: item.source_file_fingerprint.clone().unwrap(),
            last_snapshot_fingerprint: Some("a".repeat(64)),
            last_upload_body_witness: Some("b".repeat(64)),
            scan_identity_version: None,
            codex_joined_member_set: None,
            codex_captured_joined_member_set: None,
            codex_protected_owner: None,
            codex_applied_tier_receipt: None,
            codex_applied_tier_receipt_required: false,
            codex_captured_tier_receipt: None,
            codex_captured_tier_receipt_required: false,
            codex_captured_uncommitted: false,
            codex_counting_v2: false,
            codex_counting_owner: None,
            effective_upload_body_witness_revision: 0,
            opened_changed_nanos: 0,
            opened_birth_nanos: 0,
            upload_context_receipt: None,
        },
    );
    index.file_snapshot_fingerprints.insert(
        "synthetic/deferred.jsonl".into(),
        BTreeSet::from([item.snapshot_fingerprint.clone()]),
    );
    (index, item)
}

#[test]
fn cache_pending_head_lifecycle_survives_finish_and_targets_only_accepted_head() {
    let (mut index, item) = pending_head_index_item();
    let mut other = index.files.values().next().unwrap().clone();
    other.source_file_fingerprint = "c".repeat(64);
    index
        .files
        .insert("synthetic/unrelated.jsonl".into(), other.clone());
    let mut progress = test_upload_progress();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("ottto-pending-head-{}", unique_poison_scope()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    progress
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap();
    progress.save_fixture(&path).unwrap();
    progress.finish_cycle_fixture(&path).unwrap();
    let namespace = progress.destination_namespace_hash.clone();
    let witness = progress.active_quarantine_witness.clone().unwrap();
    progress = SnapshotUploadProgress::load(&path, &namespace, witness).unwrap();
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "no-head obligation survives cycle cleanup/restart"
    );
    assert_eq!(progress.reselect_pending_cache_heads(&mut index, true), 0);
    assert!(progress.accepted_cache_heads.is_empty());
    let mut probe = item.clone();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    bootstrap_cache_heads(
        &[probe.clone()],
        &unique_poison_scope(),
        &mut progress,
        |items, enforce| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(1);
            response
                .unchanged_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: enforce.then(|| "e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        },
        |progress| progress.save_fixture(&path),
    )
    .unwrap();
    assert_eq!(
        progress.reselect_pending_cache_heads(&mut index, false),
        0,
        "disabled capability never arms a read"
    );
    assert_eq!(progress.reselect_pending_cache_heads(&mut index, true), 1);
    assert!(index.files["synthetic/deferred.jsonl"]
        .last_snapshot_fingerprint
        .is_none());
    assert_eq!(
        serde_json::to_value(&index.files["synthetic/unrelated.jsonl"]).unwrap(),
        serde_json::to_value(&other).unwrap()
    );
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "head acquisition and reselection cannot retire before enrichment/index save"
    );
    assert!(
        progress.accepted_cache_states.is_empty(),
        "ordinary head acquisition does not certify provisional cache state"
    );
    std::fs::remove_dir_all(&root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn cache_pending_head_retirement_requires_exact_cache_body_not_ordinary_ack() {
    let (index, item) = pending_head_index_item();
    let mut progress = test_upload_progress();
    progress
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap();
    progress
        .accepted_cache_heads
        .insert(cache_session_key(&item.source_session_id), "e".repeat(64));
    let mut ordinary = item.clone();
    ordinary.cache_observations = None;
    ordinary.cache_observations_state = None;
    progress.record_body(
        &ordinary.snapshot_fingerprint,
        &snapshot_upload_body_witness(&ordinary),
    );
    progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "ordinary settlement cannot fulfill cache enrichment"
    );
    progress.record_body(
        &item.snapshot_fingerprint,
        &snapshot_upload_body_witness(&item),
    );
    let mut wrong_file = item.clone();
    wrong_file.source_file_fingerprint = Some("d".repeat(64));
    progress.retire_pending_cache_heads(
        &index,
        &[wrong_file],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "same semantic entity from another file cannot retire this witness"
    );
    progress.retire_pending_cache_heads(
        &index,
        std::slice::from_ref(&item),
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert!(progress.pending_cache_heads.is_empty());
    progress
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap();
    progress.retire_pending_cache_heads(
        &index,
        &[],
        &BTreeSet::from([item.snapshot_fingerprint.clone()]),
        false,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "held absence cannot retire a prior obligation"
    );
    let mut old = serde_json::to_value(&progress).unwrap();
    old.as_object_mut().unwrap().remove("pending_cache_heads");
    let adopted: SnapshotUploadProgress = serde_json::from_value(old).unwrap();
    assert!(
        adopted.pending_cache_heads.is_empty(),
        "older progress adopts serde-default empty obligations"
    );
}

#[test]
fn cache_pending_head_two_files_multi_siblings_survive_partial_cache_settlement() {
    let (mut index, mut first) = pending_head_index_item();
    first.cache_base_head_etag = Some("e".repeat(64));
    let mut sibling = first.clone();
    sibling.snapshot_fingerprint = "9".repeat(64);
    let mut second = first.clone();
    second.source_file_fingerprint = Some("8".repeat(64));
    second.snapshot_fingerprint = "7".repeat(64);
    let mut entry = index.files.values().next().unwrap().clone();
    entry.source_file_fingerprint = second.source_file_fingerprint.clone().unwrap();
    entry.last_snapshot_fingerprint = Some("6".repeat(64));
    index.files.insert("synthetic/second.jsonl".into(), entry);
    index
        .file_snapshot_fingerprints
        .get_mut("synthetic/deferred.jsonl")
        .unwrap()
        .insert(sibling.snapshot_fingerprint.clone());
    index.file_snapshot_fingerprints.insert(
        "synthetic/second.jsonl".into(),
        BTreeSet::from([second.snapshot_fingerprint.clone()]),
    );
    let mut progress = test_upload_progress();
    for item in [&first, &sibling, &second] {
        progress
            .record_pending_cache_head(item, &cache_head_file_groups(&index), true)
            .unwrap();
    }
    assert_eq!(progress.pending_cache_heads.len(), 2);
    assert_eq!(
        progress
            .pending_cache_heads
            .values()
            .map(|pending| pending.entities.len())
            .sum::<usize>(),
        3
    );
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ottto-pending-siblings-{}-{}",
        unique_poison_scope(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let progress_path = root.join("progress.json");
    let index_path = root.join("index.json");
    progress.save_fixture(&progress_path).unwrap();
    // Ordinary body settlement followed by index commit may crash before
    // cycle cleanup. No cache/head authority is inferred from that ACK.
    let ordinary = [&first, &sibling, &second]
        .into_iter()
        .map(|item| {
            let mut item = item.clone();
            item.cache_observations = None;
            item.cache_observations_state = None;
            item.cache_base_head_etag = None;
            item
        })
        .collect::<Vec<_>>();
    let scope = unique_poison_scope();
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &ordinary,
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        claude_money_e2_pipeline_tests::ack,
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    index.save_fixture(&index_path).unwrap();
    let namespace = progress.destination_namespace_hash.clone();
    let witness = progress.active_quarantine_witness.clone().unwrap();
    progress = SnapshotUploadProgress::load(&progress_path, &namespace, witness.clone()).unwrap();
    assert!(progress.accepted_cache_heads.is_empty());
    assert_eq!(progress.pending_cache_heads.len(), 2);
    // Exact ordinary repeat acquires real ACK-owned head through bootstrap.
    bootstrap_cache_heads(
        &ordinary,
        &scope,
        &mut progress,
        |items, enforce| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(items.len() as u64);
            response.unchanged_entities = items
                .iter()
                .map(|item| crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: enforce.then(|| "e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                })
                .collect();
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        },
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    let mut selected = index.clone();
    assert_eq!(
        progress.reselect_pending_cache_heads(&mut selected, true),
        2,
        "one session selects both exact files"
    );
    let items = [first.clone(), sibling.clone(), second.clone()];
    let outcome = upload_resumable_batches_with_body_witness(
        &items,
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: batch.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(2);
            for item in batch {
                let reference = crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: Some(14),
                    body_witness_digest: Some(snapshot_upload_body_witness(item)),
                    head_etag: (item.snapshot_fingerprint != sibling.snapshot_fingerprint)
                        .then(|| "e".repeat(64)),
                    head_challenge: (item.snapshot_fingerprint == sibling.snapshot_fingerprint)
                        .then(|| "c".repeat(64)),
                    unchanged_basis: None,
                    cache_observations_state: None,
                };
                if item.snapshot_fingerprint == sibling.snapshot_fingerprint {
                    response.conflict_entities.push(reference);
                } else {
                    response.accepted_entities.push(reference);
                }
            }
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    assert_eq!(
        outcome,
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1,
            identity_503: 0
        }
    );
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index.save_fixture(&index_path).unwrap();
    progress.retire_pending_cache_heads(
        &index,
        &items,
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "failed sibling keeps its whole file group pending"
    );
    let pending = progress.pending_cache_heads.values().next().unwrap();
    assert_eq!(pending.entities.len(), 2);
    assert_eq!(
        pending.settled_entities,
        BTreeSet::from([first.snapshot_fingerprint.clone()])
    );
    progress.finish_cycle_fixture(&progress_path).unwrap();
    progress = SnapshotUploadProgress::load(&progress_path, &namespace, witness).unwrap();
    assert_eq!(
        progress.reselect_pending_cache_heads(&mut index.clone(), true),
        0,
        "same verified head does not force repeated file reads while quarantine waits"
    );
    let pending_bytes = serde_json::to_vec(&progress.pending_cache_heads)
        .unwrap()
        .len();
    println!("pending_head_resource files=1 entity_edges=2 serialized_bytes={pending_bytes}");
    assert!(
        pending_bytes <= 384 + 400 * 2,
        "fixed hash-only storage bound per tracked edge/file"
    );
    let mut rebound = progress.clone();
    rebound
        .accepted_cache_heads
        .insert(cache_session_key(&first.source_session_id), "d".repeat(64));
    assert_eq!(
        rebound.reselect_pending_cache_heads(&mut index.clone(), true),
        1,
        "different verified head targets only its pending file"
    );
    rebound.accepted_cache_heads.clear();
    assert_eq!(
        rebound.reselect_pending_cache_heads(&mut index.clone(), true),
        0
    );
    rebound.accepted_cache_heads = progress.accepted_cache_heads.clone();
    assert_eq!(
        rebound.reselect_pending_cache_heads(&mut index.clone(), true),
        1,
        "actual no-head then acquired head rearms exactly affected file"
    );
    let mut new_generation = progress.clone();
    assert!(new_generation.prepare_historical_replay("next-reviewed-generation"));
    assert!(new_generation
        .pending_cache_heads
        .values()
        .all(|pending| pending.settled_entities.is_empty() && pending.reselected_heads.is_empty()));
    let different_namespace_path = root.join("different_namespace_progress.json");
    std::fs::copy(&progress_path, &different_namespace_path).unwrap();
    let unrelated = SnapshotUploadProgress::load(
        &different_namespace_path,
        &"0".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert!(
        unrelated.pending_cache_heads.is_empty(),
        "destination namespace replacement never adopts obligations"
    );
    index
        .quarantined_snapshot_fingerprints
        .get_mut(&sibling.snapshot_fingerprint)
        .unwrap()
        .retry_after_unix_seconds = 0;
    progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
    upload_resumable_batches_with_body_witness(
        &[sibling.clone()],
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: batch.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(1);
            response
                .accepted_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: sibling.source_session_id.clone(),
                    snapshot_fingerprint: sibling.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: Some(14),
                    body_witness_digest: Some(snapshot_upload_body_witness(&sibling)),
                    head_etag: Some("e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    index.save_fixture(&index_path).unwrap();
    progress.retire_pending_cache_heads(
        &index,
        &[sibling],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert!(
        progress.pending_cache_heads.is_empty(),
        "final exact cache-bearing sibling ACK completes the group"
    );
    std::fs::remove_dir_all(&root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

fn cache_effective_wire_fixture_root() -> PathBuf {
    use serde_json::json;
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "ottto-cache-effective-wire-{}-{}",
        unique_poison_scope(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let id = "00000000-0000-7000-8000-000000000001";
    let path = root.join(format!("rollout-2026-09-30T10-00-00-{id}.jsonl"));
    let records = [
        json!({"type":"session_meta","timestamp":"2026-09-30T10:00:00Z","payload":{"id":id,"source":"cli","timestamp":"2026-09-30T10:00:00Z"}}),
        json!({"type":"turn_context","payload":{"model":"gpt-5.6-sol","effort":"high"}}),
        json!({"type":"token_usage_record","timestamp":"2026-09-30T10:00:01Z","payload":{"response_id":"resp_effective_wire","usage":{"input_tokens":100000,"cached_input_tokens":90000,"output_tokens":1}}}),
        json!({"type":"event_msg","timestamp":"2026-09-30T10:00:01Z","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100000,"cached_input_tokens":90000,"output_tokens":1},"last_token_usage":{"input_tokens":100000,"cached_input_tokens":90000,"output_tokens":1}}}}),
    ];
    std::fs::write(
        &path,
        records
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    root
}

#[test]
fn cache_pending_head_stamp_preserves_actual_quarantine_candidate_retry() {
    let root = cache_effective_wire_fixture_root();
    let scan = |index: &mut ScanIndex| {
        crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            index,
            "2026-09-30T10:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .unwrap()
    };
    let mut index = ScanIndex::default();
    let mut progress = test_upload_progress();
    // As the source pass: one context and quarantine witness bind the
    // index and the ledger, so the quarantined file's backoff holds.
    activate_source_upload_context(
        SnapshotSource::Codex,
        format!("{:x}", Sha256::digest(b"cache-on")),
        &mut index,
        &mut progress,
    );
    let mut first = scan(&mut index);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut first, &mut index);
    let mut item = first.snapshots.remove(0);
    progress
        .record_pending_cache_head(&item, &cache_head_file_groups(&index), true)
        .unwrap();
    let mut probe = item.clone();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    bootstrap_cache_heads(
        &[probe],
        &unique_poison_scope(),
        &mut progress,
        |items, enforce| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(1);
            response
                .unchanged_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: enforce.then(|| "e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    item.cache_base_head_etag = progress
        .accepted_cache_heads
        .get(&cache_session_key(&item.source_session_id))
        .cloned();
    crate::snapshots::prepare_cache_observations(&mut item, None);
    progress.quarantine_body(
        &item.snapshot_fingerprint,
        &snapshot_upload_body_witness(&item),
    );
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    let index_path = root.join("index.json");
    index.save_fixture(&index_path).unwrap();
    progress.retire_pending_cache_heads(
        &index,
        &[item.clone()],
        &BTreeSet::new(),
        true,
        &progress.pending_cache_head_file_witnesses(&index),
    );
    assert_eq!(progress.pending_cache_heads.len(), 1);
    assert_eq!(progress.reselect_pending_cache_heads(&mut index, true), 0);
    let waiting = scan(&mut index);
    assert!(
        waiting.snapshots.is_empty(),
        "same head waits for normal bounded quarantine without file reparse"
    );
    index
        .quarantined_snapshot_fingerprints
        .get_mut(&item.snapshot_fingerprint)
        .unwrap()
        .retry_after_unix_seconds = 0;
    let mut due = scan(&mut index);
    assert_eq!(
        due.snapshots.len(),
        1,
        "actual candidate predicate reparses when existing quarantine retry is due"
    );
    assert_eq!(progress.reselect_pending_cache_heads(&mut index, true), 0);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut due, &mut index);
    assert_eq!(
        due.snapshots.len(),
        1,
        "due retry also survives actual finalizer no-op selection"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cache_effective_wire_projection_matches_index_retractions_and_held_local_evidence() {
    let root = cache_effective_wire_fixture_root();
    let mut baseline = ScanIndex::default();
    baseline.activate_effective_upload_body_witness_revision(
        effective_upload_body_witness_revision(SnapshotSource::Codex),
    );
    let raw = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut baseline,
        "2026-09-30T10:05:00Z",
        crate::snapshots::BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
    )
    .unwrap();
    assert_eq!(raw.snapshots.len(), 1);
    let prior = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    assert_eq!(prior.source_session_id, raw.snapshots[0].source_session_id);
    let key = cache_session_key(&prior.source_session_id);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        std::slice::from_ref(&prior),
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let item = &request.snapshots[0];
            let mut response = entity_ack_response(1);
            response
                .accepted_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: Some(14),
                    body_witness_digest: Some(snapshot_upload_body_witness(item)),
                    head_etag: Some("e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        progress.accepted_cache_states[&key]["observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let accepted_prior = progress.accepted_cache_states.clone();
    for (enabled, held) in [(false, false), (true, true), (true, false)] {
        let mut disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
        if held {
            disposition.defer_sessions(BTreeSet::from([prior.source_session_id.clone()]));
        }
        let mut effective_scan = raw.clone();
        let mut effective_index = baseline.clone();
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut effective_scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        let mut wire_scan = effective_scan.clone();
        let mut wire_index = baseline.clone();
        if !held {
            for item in &mut wire_scan.snapshots {
                prepare_snapshot_cache_for_upload(item, &progress, enabled, true);
            }
        }
        finalize_scan_after_policy(SnapshotSource::Codex, &mut wire_scan, &mut wire_index);
        exclude_held_effective_body_witness_revision(
            &mut effective_index,
            &effective_scan.snapshots,
            &disposition,
        );
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::Codex,
            &mut effective_scan,
            &mut effective_index,
            |item| {
                effective_snapshot_upload_body_witness(item, &progress, enabled, true, &disposition)
            },
        );
        let effective = effective_index.files.values().next().unwrap();
        assert_eq!(
            effective.effective_upload_body_witness_revision,
            if held {
                0
            } else {
                effective_upload_body_witness_revision(SnapshotSource::Codex)
            },
            "caller excludes raw held file from effective adoption"
        );
        let expected = wire_index.files.values().next().unwrap();
        assert_eq!(
            effective.last_snapshot_fingerprint,
            expected.last_snapshot_fingerprint
        );
        assert_eq!(
            effective.last_upload_body_witness, expected.last_upload_body_witness,
            "actual prepared network projection and effective index witness fold must agree"
        );
        assert!(
            effective_scan.snapshots[0].cache_observations.is_some(),
            "local consumers retain authorized raw declaration"
        );
        assert!(
            effective_scan.snapshots[0]
                .cache_observations_state
                .is_none(),
            "local provisional source is distinct from ACK-owned accepted state"
        );
        assert_eq!(
            progress.accepted_cache_states, accepted_prior,
            "pure projection does not certify or change accepted state"
        );
        let mut uploadable = effective_scan.snapshots.clone();
        disposition.retain_uploadable(&mut uploadable);
        if held {
            assert!(uploadable.is_empty());
            let committed = effective_index.committable_subset(
                &ScanIndex::default(),
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert!(
                committed.files.is_empty(),
                "held group cannot enter index settlement from raw local witness"
            );
        } else if enabled {
            let projected = &wire_scan.snapshots[0];
            assert_eq!(projected.cache_base_head_etag, Some("e".repeat(64)));
            // The prior row's request is not in this read: kept, not
            // retracted, at the real preparation boundary.
            assert_eq!(
                projected.cache_observations_state.as_ref().unwrap()["observations"],
                accepted_prior[&key]["observations"]
            );
            assert!(projected
                .cache_observations
                .as_ref()
                .unwrap()
                .operations
                .is_empty());
        } else {
            assert!(wire_scan.snapshots[0].cache_observations.is_none());
        }
    }
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cache_effective_wire_mandatory_head_obligation_survives_finalizer_noop() {
    let root = cache_effective_wire_fixture_root();
    let scan = |index: &mut ScanIndex| {
        crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            index,
            "2026-09-30T10:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .unwrap()
    };
    let response = |items: &[&SnapshotItem], enforce: bool, head: Option<String>| {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".into(),
            machine_id: "a".repeat(64),
            collector_version: Some(collector_version()),
            snapshots: items.to_vec(),
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let item = &request.snapshots[0];
        let mut ack = entity_ack_response(1);
        ack.accepted_entities
            .push(crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: item.cache_observations.as_ref().map(|_| 14),
                body_witness_digest: item
                    .cache_observations
                    .as_ref()
                    .map(|_| snapshot_upload_body_witness(item)),
                head_etag: head,
                head_challenge: None,
                unchanged_basis: None,
                cache_observations_state: None,
            });
        ack.validate_entity_ack_with_head_cas(&request, enforce)?;
        Ok(ack)
    };
    let mut index = ScanIndex::default();
    index.activate_effective_upload_body_witness_revision(effective_upload_body_witness_revision(
        SnapshotSource::Codex,
    ));
    index.activate_upload_context("cache-off".into());
    let mut progress = test_upload_progress();
    let mut off = scan(&mut index);
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut off.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::Codex,
        &mut off,
        &mut index,
        |item| {
            effective_snapshot_upload_body_witness(
                item,
                &progress,
                false,
                false,
                &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
            )
        },
    );
    for item in &mut off.snapshots {
        prepare_snapshot_cache_for_upload(item, &progress, false, false);
    }
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &off.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| response(items, false, None),
        |_| Ok(()),
    )
    .unwrap();
    assert!(progress.accepted_cache_heads.is_empty());
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    index.save_fixture(&index_path).unwrap();
    progress.save_fixture(&progress_path).unwrap();
    progress.finish_cycle_fixture(&progress_path).unwrap();
    progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    index.activate_upload_context("cache-on-mandatory".into());
    // Forward-only: the capability change alone reads nothing, although
    // the accepted file holds no receipt under the new context.
    assert!(
        scan(&mut index.clone()).snapshots.is_empty(),
        "a capability change reads nothing"
    );
    // Its next ordinary read carries the capability; a re-arm stands in.
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let mut on = scan(&mut index);
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut on.snapshots,
        SnapshotUploadPolicy::default(),
    );
    let disposition = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    let identities = capture_deferred_cache_head_identities(
        SnapshotSource::Codex,
        &on.snapshots,
        &progress,
        true,
        true,
        &disposition,
    );
    assert_eq!(identities.len(), 1);
    assert!(capture_deferred_cache_head_identities(
        SnapshotSource::Codex,
        &on.snapshots,
        &progress,
        false,
        true,
        &disposition
    )
    .is_empty());
    let mut held = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    held.defer_sessions(BTreeSet::from([on.snapshots[0].source_session_id.clone()]));
    assert!(capture_deferred_cache_head_identities(
        SnapshotSource::Codex,
        &on.snapshots,
        &progress,
        true,
        true,
        &held
    )
    .is_empty());
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::Codex,
        &mut on,
        &mut index,
        |item| effective_snapshot_upload_body_witness(item, &progress, true, true, &disposition),
    );
    // The new context owes even an equal ordinary body once: finalization
    // keeps it for its exact ACK under that context, not as a no-op.
    assert_eq!(
        on.snapshots.len(),
        1,
        "the context change owes the unchanged accepted body once"
    );
    let groups = cache_head_file_groups(&index);
    for identity in &identities {
        assert!(progress
            .record_pending_cache_head_identity(
                identity.source_file_fingerprint.as_ref(),
                &identity.snapshot_fingerprint,
                &identity.session_key,
                &groups,
                true
            )
            .unwrap());
    }
    progress.save_fixture(&progress_path).unwrap(); // obligation before no-op index settlement
    index.save_fixture(&index_path).unwrap();
    progress.finish_cycle_fixture(&progress_path).unwrap();
    let mut loaded = ScanIndex::load(&index_path).unwrap();
    loaded.activate_upload_context("cache-on-mandatory".into());
    loaded.activate_effective_upload_body_witness_revision(effective_upload_body_witness_revision(
        SnapshotSource::Codex,
    ));
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert_eq!(progress.pending_cache_heads.len(), 1);
    assert_eq!(progress.reselect_pending_cache_heads(&mut loaded, true), 0);
    // Missing authority remains explicitly pending; the file stays owed
    // under the new context until its exact ACK.
    assert_eq!(
        crate::snapshots::e2_pipeline_scan_fixture::upload_context_unproven_files_for_test(&loaded),
        1
    );
    // Existing exact ordinary CAS transport supplies the actual prerequisite;
    // the marker itself neither schedules this probe nor invents head authority.
    bootstrap_cache_heads(
        &off.snapshots,
        &unique_poison_scope(),
        &mut progress,
        |items, enforce| response(items, enforce, enforce.then(|| "e".repeat(64))),
        |state| state.save_fixture(&progress_path),
    )
    .unwrap();
    assert_eq!(progress.reselect_pending_cache_heads(&mut loaded, true), 1);
    let mut enriched = scan(&mut loaded);
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut enriched.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::Codex,
        &mut enriched,
        &mut loaded,
        |item| effective_snapshot_upload_body_witness(item, &progress, true, true, &disposition),
    );
    assert_eq!(enriched.snapshots.len(), 1);
    let witnesses = progress.pending_cache_head_file_witnesses(&loaded);
    for item in &mut enriched.snapshots {
        prepare_snapshot_cache_for_upload(item, &progress, true, true);
    }
    upload_resumable_batches_with_body_witness(
        &enriched.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| response(items, true, Some("f".repeat(64))),
        |state| state.save_fixture(&progress_path),
    )
    .unwrap();
    assert_eq!(
        progress.pending_cache_heads.len(),
        1,
        "ACK alone never retires index obligation"
    );
    loaded.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
        &mut loaded,
        &enriched.snapshots,
        &progress.fresh_context_body_acks,
    );
    loaded.save_fixture(&index_path).unwrap();
    progress.retire_pending_cache_heads(
        &loaded,
        &enriched.snapshots,
        &BTreeSet::new(),
        true,
        &witnesses,
    );
    assert!(progress.pending_cache_heads.is_empty());
    progress.finish_cycle_fixture(&progress_path).unwrap();
    assert!(scan(&mut loaded).snapshots.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn cache_effective_wire_unchanged_capability_enable_reads_nothing() {
    let root = cache_effective_wire_fixture_root();
    let mut index = ScanIndex::default();
    index.activate_effective_upload_body_witness_revision(effective_upload_body_witness_revision(
        SnapshotSource::Codex,
    ));
    index.activate_upload_context("cache-off".into());
    let scan = |index: &mut ScanIndex| {
        crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            index,
            "2026-09-30T10:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .unwrap()
    };
    let mut off = scan(&mut index);
    assert_eq!(off.snapshots.len(), 1);
    assert!(off.snapshots[0].cache_observations.is_some());
    let mut progress = test_upload_progress();
    let held = crate::snapshots::ClaudeUsageAuthorityDisposition::default();
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut off.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::Codex,
        &mut off,
        &mut index,
        |item| effective_snapshot_upload_body_witness(item, &progress, false, false, &held),
    );
    assert!(
        off.snapshots[0].cache_observations.is_some(),
        "local consumers preserve authorized raw evidence"
    );
    for item in &mut off.snapshots {
        prepare_snapshot_cache_for_upload(item, &progress, false, false);
    }
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &off.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let item = &request.snapshots[0];
            let mut response = entity_ack_response(1);
            response
                .accepted_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack(&request)?;
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(accepted, 1);
    index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    index.activate_upload_context("cache-on".into());
    // Forward-only: the capability change alone reads nothing, although
    // the accepted file holds no receipt under the new context.
    assert!(
        scan(&mut index.clone()).snapshots.is_empty(),
        "a capability change reads nothing"
    );
    // Its next ordinary read carries the capability; a re-arm stands in.
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let mut on = scan(&mut index);
    assert_eq!(
        on.snapshots.len(),
        1,
        "the next ordinary read reparses the unchanged file"
    );
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut on.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::Codex,
        &mut on,
        &mut index,
        |item| effective_snapshot_upload_body_witness(item, &progress, true, false, &held),
    );
    assert_eq!(
        on.snapshots.len(),
        1,
        "effective cache enrichment must survive no-op selection"
    );
    let semantic = on.snapshots[0].snapshot_fingerprint.clone();
    let mut local_item = on.snapshots[0].clone();
    assert!(progress.accepted_cache_states.is_empty());
    prepare_snapshot_cache_for_upload(&mut local_item, &progress, true, false);
    let prepared_body = snapshot_upload_body_witness(&local_item);
    let mut probe = local_item.clone();
    probe.cache_observations = None;
    probe.cache_observations_state = None;
    let mut stages = Vec::new();
    bootstrap_cache_heads(
        &[probe],
        &unique_poison_scope(),
        &mut progress,
        |items, enforce| {
            stages.push(enforce);
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let item = &request.snapshots[0];
            let mut response = entity_ack_response(1);
            response
                .unchanged_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: enforce.then(|| "e".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(
        stages,
        [true],
        "already settled ordinary bytes still require their exact CAS repeat"
    );
    prepare_snapshot_cache_for_upload(&mut on.snapshots[0], &progress, true, false);
    assert_eq!(
        snapshot_upload_body_witness(&on.snapshots[0]),
        prepared_body,
        "opaque predecessor does not alter body identity"
    );
    upload_resumable_batches_with_body_witness(
        &on.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            let item = &request.snapshots[0];
            let mut response = entity_ack_response(1);
            response
                .accepted_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: Some(14),
                    body_witness_digest: Some(snapshot_upload_body_witness(item)),
                    head_etag: Some("f".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert!(progress
        .accepted_cache_states
        .contains_key(&cache_session_key(&local_item.source_session_id)));
    assert_eq!(on.snapshots[0].snapshot_fingerprint, semantic);
    // The service finish: the exact ACK earns the file's receipt.
    crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
        &mut index,
        &on.snapshots,
        &progress.fresh_context_body_acks,
    );
    assert!(
        scan(&mut index).snapshots.is_empty(),
        "next unchanged source is settled"
    );
    // A capability flip reads nothing on an unchanged file: it applies
    // from the next body on.
    index.activate_upload_context("cache-on-same-effective-projection".into());
    assert!(scan(&mut index).snapshots.is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cache_bootstrap_grown_existing_usage_settles_before_exact_head_probe() {
    let mut current = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    current.cache_observations = None;
    current.cache_observations_state = None;
    let mut old = current.clone();
    old.input_tokens -= 1;
    old.model_usage[0].input_tokens -= 1;
    let policy = SnapshotUploadPolicy::default();
    let revision = |item: &SnapshotItem| {
        crate::snapshots::snapshot_semantic_envelope(SnapshotSource::Codex, item, policy)
            .revision_v2_hash
    };
    let old_revision = revision(&old);
    let current_revision = revision(&current);
    assert_ne!(
        old_revision, current_revision,
        "existing accepted usage must differ before bootstrap"
    );
    let mut server_revision = old_revision.clone();
    let mut calls = Vec::new();
    let mut persisted_heads = Vec::new();
    let mut progress = test_upload_progress();
    bootstrap_cache_heads(
        &[current.clone()],
        &unique_poison_scope(),
        &mut progress,
        |items, enforce| {
            assert!(items[0].cache_observations.is_none());
            let incoming = revision(items[0]);
            calls.push(enforce);
            if enforce && incoming != server_revision {
                return Err(anyhow!(
                    "server CAS conflict: grown usage lacks predecessor token"
                ));
            }
            // Existing optional ordinary authority admits the grown body;
            // CAS can subsequently learn a head only for its exact repeat.
            server_revision = incoming;
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: policy,
                client_report: crate::client_report::ClientReport::empty(),
            };
            let mut response = entity_ack_response(1);
            let reference = crate::snapshot_client::SnapshotEntityRef {
                source_session_id: current.source_session_id.clone(),
                snapshot_fingerprint: current.snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: enforce.then(|| "e".repeat(64)),
                head_challenge: None,
                unchanged_basis: None,
                cache_observations_state: None,
            };
            if enforce {
                response.unchanged_entities.push(reference);
            } else {
                response.accepted_entities.push(reference);
            }
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        },
        |progress| {
            persisted_heads.push(progress.accepted_cache_heads.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls, [false, true]);
    assert!(
        persisted_heads[0].is_empty(),
        "ordinary delivery cannot mint producer head authority"
    );
    assert_eq!(
        persisted_heads[1][&cache_session_key(&current.source_session_id)],
        "e".repeat(64)
    );
    assert_eq!(server_revision, current_revision);
}

/// An `unchanged` ACK whose
/// `unchanged_basis` says the server did not store the body never marks
/// it emitted. The exact body is held, so it is offered once per change;
/// a plain `unchanged` ACK still settles as stored. Both server bases.
#[test]
fn unchanged_ack_with_usage_identical_does_not_mark_emitted() {
    for basis in [Some("usage_identical"), Some("dominated_by_head"), None] {
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        item.cache_observations = None;
        item.cache_observations_state = None;
        let fingerprint = item.snapshot_fingerprint.clone();
        let body = snapshot_upload_body_witness(&item);
        let mut response = entity_ack_response(1);
        response
            .unchanged_entities
            .push(crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: None,
                head_challenge: None,
                unchanged_basis: basis.map(str::to_string),
                cache_observations_state: None,
            });
        let mut progress = test_upload_progress();
        let mut requests = 0;
        for _ in 0..2 {
            let mut accepted = 0;
            let result = upload_resumable_batches_with_body_witness(
                &[item.clone()],
                &unique_poison_scope(),
                &mut progress,
                &mut accepted,
                |item| item.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness,
                |_| {
                    requests += 1;
                    Ok(response.clone())
                },
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(result, ResumableUploadResult::Completed, "{basis:?}");
        }
        assert_eq!(requests, 1, "{basis:?}: one body per change");
        assert!(progress.contains_body(&fingerprint, &body), "{basis:?}");
        assert!(progress.permanent_rejections.is_empty(), "{basis:?}");
        if basis.is_none() {
            assert!(progress.accepted_fingerprints.contains(&fingerprint));
            assert_eq!(progress.accepted_body_witnesses[&fingerprint], body);
            assert!(!progress.quarantined_fingerprints.contains_key(&fingerprint));
            continue;
        }
        assert!(
            !progress.accepted_fingerprints.contains(&fingerprint),
            "usage_identical is not stored: never marked emitted"
        );
        assert!(!progress.accepted_body_witnesses.contains_key(&fingerprint));
        let held = &progress.quarantined_fingerprints[&fingerprint];
        assert_eq!(
            held.disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal
        );
        assert_eq!(held.upload_body_witness.as_deref(), Some(body.as_str()));
        // The hold survives the cycle through the index, like a refusal.
        let mut next_cycle = test_upload_progress();
        next_cycle.prepare_quarantine_retries(&progress.quarantined_fingerprints);
        assert!(next_cycle.contains_body(&fingerprint, &body));
        assert!(!next_cycle.accepted_fingerprints.contains(&fingerprint));
    }
}

/// A held body (an `unchanged` ACK with a basis) never
/// blocks a later, different body of the same session. Unchanged ACK,
/// then local growth, then the grown body is offered and accepted, in the
/// same cycle and in the next one (hold carried through the index).
#[test]
fn held_unchanged_body_never_blocks_a_later_different_body() {
    for (basis, next_cycle) in [
        ("usage_identical", false),
        ("dominated_by_head", false),
        ("usage_identical", true),
        ("dominated_by_head", true),
    ] {
        let case = format!("{basis} next_cycle={next_cycle}");
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        item.cache_observations = None;
        item.cache_observations_state = None;
        let held = item.snapshot_fingerprint.clone();
        let mut grown = item.clone();
        grown.output_tokens += 1;
        grown.snapshot_fingerprint =
            crate::snapshots::snapshot_fingerprint(SnapshotSource::Codex, &grown);
        assert_ne!(grown.snapshot_fingerprint, held, "{case}");
        let grown_body = snapshot_upload_body_witness(&grown);
        let ack = |unchanged: bool, fingerprint: &str| {
            let mut response = entity_ack_response(1);
            let reference = crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: fingerprint.to_string(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: None,
                head_challenge: None,
                unchanged_basis: unchanged.then(|| basis.to_string()),
                cache_observations_state: None,
            };
            if unchanged {
                response.unchanged_entities.push(reference);
            } else {
                response.accepted_entities.push(reference);
            }
            response
        };
        let upload =
            |progress: &mut SnapshotUploadProgress,
             body: &SnapshotItem,
             response: crate::snapshot_client::SnapshotBatchResponse| {
                let mut offered = Vec::new();
                let mut accepted = 0;
                let result = upload_resumable_batches_with_body_witness(
                    std::slice::from_ref(body),
                    &unique_poison_scope(),
                    progress,
                    &mut accepted,
                    |item| item.snapshot_fingerprint.as_str(),
                    snapshot_upload_body_witness,
                    |items: &[&SnapshotItem]| {
                        offered.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                        Ok(response.clone())
                    },
                    |_| Ok(()),
                )
                .unwrap();
                assert_eq!(result, ResumableUploadResult::Completed, "{case}");
                offered
            };
        let mut progress = test_upload_progress();
        assert_eq!(
            upload(&mut progress, &item, ack(true, &held)),
            std::slice::from_ref(&held),
            "{case}"
        );
        assert!(
            progress.quarantined_fingerprints.contains_key(&held),
            "{case}"
        );
        if next_cycle {
            let mut carried = test_upload_progress();
            carried.prepare_quarantine_retries(&progress.quarantined_fingerprints);
            progress = carried;
        }
        // Local growth: a different body of the same session is offered
        // despite the hold, and the server's acceptance is recorded.
        assert_eq!(
            upload(
                &mut progress,
                &grown,
                ack(false, &grown.snapshot_fingerprint)
            ),
            std::slice::from_ref(&grown.snapshot_fingerprint),
            "{case}"
        );
        assert!(
            progress
                .accepted_fingerprints
                .contains(&grown.snapshot_fingerprint),
            "{case}"
        );
        assert_eq!(
            progress.accepted_body_witnesses[&grown.snapshot_fingerprint], grown_body,
            "{case}"
        );
        assert!(progress.permanent_rejections.is_empty(), "{case}");
        assert!(!progress.accepted_fingerprints.contains(&held), "{case}");
    }
}

#[test]
fn cache_capability_toggle_headless_settlement_recovers_current_predecessor() {
    for outcome in ["accepted", "unchanged"] {
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        item.cache_observations = None;
        item.cache_observations_state = None;
        let key = cache_session_key(&item.source_session_id);
        let mut progress = test_upload_progress();
        progress
            .accepted_cache_heads
            .insert(key.clone(), "1".repeat(64));
        let state = serde_json::json!({"schema_version":1,"observations":[],"coverage":"complete","omitted_observation_count":null});
        progress
            .accepted_cache_states
            .insert(key.clone(), state.clone());
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".into(),
            machine_id: "a".repeat(64),
            collector_version: Some(collector_version()),
            snapshots: vec![item.clone()],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let mut response = entity_ack_response(1);
        let reference = crate::snapshot_client::SnapshotEntityRef {
            source_session_id: item.source_session_id.clone(),
            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
            occurrence_count: 1,
            body_witness_version: None,
            body_witness_digest: None,
            head_etag: None,
            head_challenge: None,
            unchanged_basis: None,
            cache_observations_state: None,
        };
        if outcome == "accepted" {
            response.accepted_entities.push(reference);
        } else {
            response.unchanged_entities.push(reference);
        }
        response.validate_entity_ack(&request).unwrap();
        let mut accepted = 0;
        upload_resumable_batches_with_body_witness(
            &[item.clone()],
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |_| Ok(response.clone()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            progress.accepted_cache_states[&key], state,
            "disabled cache retains numeric evidence"
        );
        if outcome == "unchanged" {
            assert_eq!(progress.accepted_cache_heads[&key], "1".repeat(64));
            continue;
        }
        assert!(
            !progress.accepted_cache_heads.contains_key(&key),
            "{outcome}: head-changing ACK has no predecessor proof"
        );
        let mut stages = Vec::new();
        bootstrap_cache_heads(
            &[item.clone()],
            &unique_poison_scope(),
            &mut progress,
            |items, enforce| {
                stages.push(enforce);
                assert!(enforce, "ordinary exact bytes were already acknowledged");
                let mut response = entity_ack_response(1);
                response
                    .unchanged_entities
                    .push(crate::snapshot_client::SnapshotEntityRef {
                        source_session_id: item.source_session_id.clone(),
                        snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                        occurrence_count: 1,
                        body_witness_version: None,
                        body_witness_digest: None,
                        head_etag: Some("2".repeat(64)),
                        head_challenge: None,
                        unchanged_basis: None,
                        cache_observations_state: None,
                    });
                let request = SnapshotBatchRequest {
                    schema_version: request.schema_version,
                    source: request.source.clone(),
                    machine_id: request.machine_id.clone(),
                    collector_version: request.collector_version.clone(),
                    snapshots: items.to_vec(),
                    upload_policy: request.upload_policy,
                    client_report: request.client_report.clone(),
                };
                response.validate_entity_ack_with_head_cas(&request, enforce)?;
                Ok(response)
            },
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(stages, [true]);
        item.cache_base_head_etag = progress.accepted_cache_heads.get(&key).cloned();
        assert_eq!(
            item.cache_base_head_etag,
            Some("2".repeat(64)),
            "re-enable uses refreshed head"
        );
    }
}

#[test]
fn combined_revision_wire_uses_same_scan_index_and_ack_predecessor() {
    use serde_json::json;
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("ottto-combined-revision-{}", unique_poison_scope()));
    std::fs::create_dir_all(&root).unwrap();
    let id = "019e253c-3333-7000-9000-cccccccccccc";
    let path = root.join(format!("rollout-2026-09-30T10-00-00-{id}.jsonl"));
    let header = json!({"type":"session_meta","ordinal":0,"timestamp":"2026-09-30T10:00:00Z",
        "payload":{"id":id,"session_id":id,"source":"cli","timestamp":"2026-09-30T10:00:00Z",
            "creator_user_id":"synthetic-user","creator_account_id":"synthetic-workspace"}});
    let mut records = vec![
        header,
        json!({"type":"turn_context","payload":{"model":"gpt-5.6-sol","effort":"high"}}),
    ];
    let mut reads = 0;
    let mut index = ScanIndex::default();
    let mut progress = test_upload_progress();
    let progress_path = root.join("progress.json");
    let key = cache_session_key(id);
    let mut cases = Vec::new();
    let mut first_wire = serde_json::Value::Null;
    let mut first_state = serde_json::Value::Null;
    for (step, count) in [(0, 3), (1, 4)] {
        let start = if step == 0 { 0 } else { 3 };
        for request in start..count {
            let read = if request % 2 == 0 { 90_000 } else { 0 };
            reads += read;
            let timestamp = format!("2026-09-30T10:00:0{request}Z");
            records.push(json!({"type":"token_usage_record","timestamp":timestamp,"payload":{"response_id":format!("resp_revision_{request}"),"usage":{"input_tokens":100_000,"cached_input_tokens":read,"cache_write_input_tokens":0,"output_tokens":1}}}));
            records.push(json!({"type":"event_msg","timestamp":timestamp,"payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100_000*(request+1),"cached_input_tokens":reads,"output_tokens":request+1},"last_token_usage":{"input_tokens":100_000,"cached_input_tokens":read,"output_tokens":1}}}}));
        }
        std::fs::write(
            &path,
            records
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-09-30T10:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .unwrap();
        assert_eq!(scan.snapshots.len(), 1);
        assert!(scan.census_complete);
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        let mut item = scan.snapshots.remove(0);
        assert!(item.session_account_evidence.is_some());
        assert_eq!(
            (item.input_tokens, item.output_tokens),
            (100_000 * count, count)
        );
        // Identical to sync_source: predecessor and completed numeric state
        // are read from the acknowledged destination-scoped ledger.
        item.cache_base_head_etag = progress.accepted_cache_heads.get(&key).cloned();
        crate::snapshots::prepare_cache_observations(
            &mut item,
            progress.accepted_cache_states.get(&key),
        );
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".into(),
            machine_id: "a".repeat(64),
            collector_version: Some(collector_version()),
            snapshots: vec![item.clone()],
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        validate_snapshot_batch_request(&request).unwrap();
        let wire_bytes = serde_json::to_vec(&request).unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&wire_bytes).unwrap();
        let predecessor = wire["snapshots"][0]["semantic_envelope"].get("base_head_etag");
        if step == 0 {
            assert!(predecessor.is_none());
            first_wire = wire.clone();
            first_state = item.cache_observations_state.clone().unwrap();
        } else {
            assert_eq!(predecessor.unwrap(), &json!("65".repeat(32)));
            assert_ne!(
                wire["snapshots"][0]["snapshot_fingerprint"],
                first_wire["snapshots"][0]["snapshot_fingerprint"]
            );
            assert_ne!(
                wire["snapshots"][0]["semantic_envelope"]["revision_v2_hash"],
                first_wire["snapshots"][0]["semantic_envelope"]["revision_v2_hash"]
            );
            assert_eq!(
                item.cache_observations_state.as_ref().unwrap()["observations"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
        let mut response = entity_ack_response(1);
        response
            .accepted_entities
            .push(crate::snapshot_client::SnapshotEntityRef {
                source_session_id: id.into(),
                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: Some(14),
                body_witness_digest: Some(snapshot_upload_body_witness(&item)),
                head_etag: Some(if step == 0 {
                    "65".repeat(32)
                } else {
                    "66".repeat(32)
                }),
                head_challenge: None,
                unchanged_basis: None,
                cache_observations_state: None,
            });
        response.validate_entity_ack(&request).unwrap();
        let mut accepted = 0;
        upload_resumable_batches_with_body_witness(
            &[item.clone()],
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |_| Ok(response.clone()),
            |progress| progress.save_fixture(&progress_path),
        )
        .unwrap();
        let mut projection = json!({"session_account_evidence":wire["snapshots"][0]["session_account_evidence"],
            "cache_observations_state":item.cache_observations_state});
        for leaf in ["tool_usage", "tool_usage_truncated"] {
            if let Some(value) = wire["snapshots"][0].get(leaf) {
                projection[leaf] = value.clone();
            }
        }
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(crate::canonical_json::canonicalize(&projection).unwrap())
            ),
            snapshot_upload_body_witness(&item)
        );
        cases.push(json!({"admission":if step==0 {"first_admission"} else {"revision"},"capability":"combined",
            "provenance":"same physical source and ScanIndex; validated ACK and existing persisted progress ledger; normal SnapshotBatchRequest serializer",
            "wire":wire,"wire_body_utf8":String::from_utf8(wire_bytes).unwrap(),
            "internal_version":crate::snapshots::snapshot_upload_body_witness_version(&item),"released_ack_version":14,
            "digest":snapshot_upload_body_witness(&item),"cache_observations_state":item.cache_observations_state,
            "predecessor_wire":if step==0 {serde_json::Value::Null} else {first_wire.clone()},
            "predecessor_cache_observations_state":if step==0 {serde_json::Value::Null} else {first_state.clone()},
            "predecessor_head_etag":if step==0 {serde_json::Value::Null} else {json!("65".repeat(32))},
            "body_projection":projection,"accepted_head_etag":response.accepted_entities[0].head_etag}));
        progress.finish_cycle_fixture(&progress_path).unwrap();
        progress = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            progress.active_quarantine_witness.clone().unwrap(),
        )
        .unwrap();
    }
    if let Ok(output) = std::env::var("OTTTO_PAIRED_CREATOR_CACHE_REVISION_CORPUS_OUT") {
        std::fs::write(output, serde_json::to_vec_pretty(&json!({"contract_version":"paired_creator_cache_revision_corpus:v1","cases":cases})).unwrap()).unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn cache_overcap_byte_trim_witness_network_and_ack_use_identical_completion() {
    let (patch, prior) =
        crate::snapshots::cache_overcap_tests::large_prior_and_replacement_fixture();
    let mut raw = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    raw.cache_observations = Some(patch);
    raw.cache_observations_state = None;
    let key = cache_session_key(&raw.source_session_id);
    let mut progress = test_upload_progress();
    progress
        .accepted_cache_states
        .insert(key.clone(), prior.clone());
    progress
        .accepted_cache_heads
        .insert(key.clone(), "e".repeat(64));
    let witness = effective_snapshot_upload_body_witness(
        &raw,
        &progress,
        true,
        true,
        &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
    );
    let mut network = raw.clone();
    prepare_snapshot_cache_for_upload(&mut network, &progress, true, true);
    assert_eq!(witness, snapshot_upload_body_witness(&network));
    assert_eq!(
        progress.accepted_cache_states[&key], prior,
        "projection does not advance accepted state"
    );
    let wire = network.cache_observations.as_ref().unwrap();
    assert!(wire.validate());
    let expected = crate::snapshots::cache_state_from_patch(Some(&prior), wire).unwrap();
    assert_eq!(network.cache_observations_state.as_ref(), Some(&expected));
    assert!(
        crate::canonical_json::canonicalize(&expected)
            .unwrap()
            .len()
            <= crate::snapshots::cache_observations::MAX_STATE_BYTES
    );
    progress.record_cache_state(&network).unwrap();
    assert_eq!(
        progress.accepted_cache_states[&key], expected,
        "ACK completion applies the actual uploaded patch"
    );
    progress.record_cache_state(&network).unwrap();
    assert_eq!(
        progress.accepted_cache_states[&key], expected,
        "ACK retry is idempotent"
    );
    assert!(
        raw.cache_observations_state.is_none(),
        "local evidence is retained"
    );
}

/// [regress] The progress loader once capped accepted cache states at
/// 128 rows / 128 KiB, so a larger accepted state quarantined the whole
/// progress file on restart.
#[test]
fn accepted_cache_state_past_old_caps_survives_progress_restart() {
    let state = crate::snapshots::cache_overcap_tests::settled_state(200);
    assert_eq!(state["observations"].as_array().unwrap().len(), 200);
    assert!(serde_json::to_vec(&state).unwrap().len() > 128 * 1024);
    let mut progress = test_upload_progress();
    let key = cache_session_key("s");
    progress
        .accepted_cache_states
        .insert(key.clone(), state.clone());
    let root = test_dir("cache-state-restart");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    progress.save_fixture(&path).unwrap();
    let namespace = progress.destination_namespace_hash.clone();
    let witness = progress.active_quarantine_witness.clone().unwrap();
    let restored = SnapshotUploadProgress::load(&path, &namespace, witness).unwrap();
    assert_eq!(restored.accepted_cache_states.get(&key), Some(&state));
    let quarantined = std::fs::read_dir(&root)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("corrupt")
        })
        .count();
    assert_eq!(
        quarantined, 0,
        "nothing quarantined beside the progress file"
    );
    std::fs::remove_dir_all(root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}
