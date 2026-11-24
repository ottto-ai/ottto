#[test]
fn cache_event_ack_restart_correction_and_missing_proof() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "machine".into(),
        collector_version: None,
        snapshots: vec![item.clone()],
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let mut response = crate::snapshot_client::SnapshotBatchResponse {
        conflict_rescans: Default::default(),
        accepted: 1,
        sessions_reconciled: 1,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: vec![crate::snapshot_client::SnapshotEntityRef {
            source_session_id: item.source_session_id.clone(),
            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
            occurrence_count: 1,
            body_witness_version: Some(14),
            body_witness_digest: Some(snapshot_upload_body_witness(&item)),
            head_etag: Some("e".repeat(64)),
            head_challenge: None,
            unchanged_basis: None,
            cache_observations_state: None,
        }],
        unchanged_entities: Vec::new(),
        rejected_entities: Vec::new(),
        conflict_entities: Vec::new(),
    };
    response.validate_entity_ack(&request).unwrap();
    response.accepted_entities[0].body_witness_digest = None;
    assert!(response.validate_entity_ack(&request).is_err());
    response.accepted_entities[0].body_witness_digest = Some(snapshot_upload_body_witness(&item));
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        std::slice::from_ref(&item),
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| Ok(response.clone()),
        |_| Ok(()),
    )
    .unwrap();
    let statekey = cache_session_key(&item.source_session_id);
    assert_eq!(
        progress.accepted_cache_states[&statekey]["observations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(progress.accepted_cache_heads[&statekey], "e".repeat(64));
    let bytes = serde_json::to_vec(&progress).unwrap();
    let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    restored.active_quarantine_witness = progress.active_quarantine_witness.clone();
    upload_resumable_batches_with_body_witness(
        std::slice::from_ref(&item),
        &unique_poison_scope(),
        &mut restored,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| panic!("ACKed event replay should be skipped"),
        |_| Ok(()),
    )
    .unwrap();
    let directory = crate::test_scratch::canonical_private_dir("cache-progress");
    std::fs::create_dir_all(&directory).unwrap();
    let path = snapshot_upload_progress_path(&directory.join("index.json"));
    let _ = std::fs::remove_file(&path);
    let (mut settled_index, _) = pending_head_index_item();
    settled_index.record_accepted_snapshot_fingerprints(&restored.accepted_fingerprints);
    let mut digest = Sha256::new();
    for bytes in [
        b"snapshot_file_upload_body_set:v1".as_slice(),
        snapshot_upload_body_witness(&item).as_bytes(),
    ] {
        digest.update((bytes.len() as u32).to_be_bytes());
        digest.update(bytes);
    }
    settled_index
        .files
        .values_mut()
        .next()
        .unwrap()
        .last_upload_body_witness = Some(format!("{:x}", digest.finalize()));
    settled_index
        .save_fixture_for_source(&directory.join("index.json"), SnapshotSource::Codex)
        .unwrap();
    restored = route_fixture_progress(
        &settled_index,
        &directory.join("index.json"),
        &path,
        restored,
    );
    restored.save(&path).unwrap();
    restored.retire_acks_after_index_save(&settled_index, &BTreeSet::new(), &BTreeSet::new());
    restored.finish_cycle(&path).unwrap();
    let mut restored = SnapshotUploadProgress::load_for_index(
        &settled_index,
        &directory.join("index.json"),
        &path,
        &restored.destination_namespace_hash,
        restored.active_quarantine_witness.clone().unwrap(),
    )
    .unwrap();
    assert!(restored.accepted_fingerprints.is_empty());
    assert_eq!(restored.accepted_cache_heads[&statekey], "e".repeat(64));
    let prior = restored.accepted_cache_states[&statekey].clone();
    let mut corrected = item.clone();
    corrected.cache_base_head_etag = restored.accepted_cache_heads.get(&statekey).cloned();
    corrected.cache_observations = Some(crate::snapshots::cache_observations::CacheObservations {
        schema_version: 1,
        operations: Vec::new(),
        coverage: "complete".into(),
        omitted_observation_count: None,
        full_replacement: false,
    });
    crate::snapshots::prepare_cache_observations(&mut corrected, Some(&prior));
    assert_eq!(corrected.snapshot_fingerprint, item.snapshot_fingerprint);
    assert_ne!(
        snapshot_upload_body_witness(&corrected),
        snapshot_upload_body_witness(&item)
    );
    assert_eq!(
        corrected
            .cache_observations
            .as_ref()
            .unwrap()
            .operations
            .len(),
        1
    );
    let mut corrected_request = request.clone();
    corrected_request.snapshots = vec![corrected.clone()];
    let encoded = serde_json::to_value(&corrected_request).unwrap();
    assert_eq!(
        encoded["head_cas_contract"],
        crate::snapshots::SNAPSHOT_HEAD_CAS_CONTRACT
    );
    assert_eq!(
        encoded["snapshots"][0]["semantic_envelope"]["base_head_etag"],
        "e".repeat(64)
    );
    response.accepted_entities[0].body_witness_digest =
        Some(snapshot_upload_body_witness(&corrected));
    response.validate_entity_ack(&corrected_request).unwrap();
    upload_resumable_batches_with_body_witness(
        &[corrected],
        &unique_poison_scope(),
        &mut restored,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| Ok(response.clone()),
        |_| Ok(()),
    )
    .unwrap();
    assert!(restored.accepted_cache_states[&statekey]["observations"]
        .as_array()
        .unwrap()
        .is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn claude_account_switch_probe_fires_only_on_a_changed_account() {
    let mut probe = ClaudeAccountSwitchProbe::default();
    let start = Instant::now();
    let at = |seconds: u64| start + Duration::from_secs(seconds);
    let account = |uuid: &str| Some(format!("desktop={uuid};cli={uuid};org=org-1"));

    // The first reading is a baseline, never a switch.
    assert!(!probe.observe(at(0), || account("acct-a")));
    // Re-reads are throttled between checks.
    assert!(!probe.observe(at(5), || panic!("read inside the check interval")));
    assert!(!probe.observe(at(20), || account("acct-a")));
    // An unreadable fingerprint is not a switch and keeps the baseline.
    assert!(!probe.observe(at(40), || None));
    assert!(probe.observe(at(60), || account("acct-b")));
    assert!(!probe.observe(at(80), || account("acct-b")));
}
use crate::ControlToken;
use ottto_core::{
    FileDeviceStore, LocalConnectionBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_SECRET_FALLBACK_DIR_ENV, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
use ottto_protocol::{
    AgentAccountStatus, AgentLoginState, AgentStatusCollectionMethod, AgentStatusConfidence,
    AgentStatusState, MachineIdentity, OperatingSystem,
};
use serial_test::serial;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

struct SourceManifestTestGuard;

fn test_terminal_status_support_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-terminal-status-tests-{}",
            std::process::id()
        ))
    })
    .as_path()
}

impl SourceManifestTestGuard {
    fn new() -> Self {
        clear_source_manifests_for_test();
        let _ = std::fs::remove_dir_all(test_terminal_status_support_dir());
        Self
    }
}

impl Drop for SourceManifestTestGuard {
    fn drop(&mut self) {
        clear_source_manifests_for_test();
        let _ = std::fs::remove_dir_all(test_terminal_status_support_dir());
    }
}

fn test_fingerprints(count: usize) -> Vec<String> {
    (0..count).map(|index| format!("{index:064x}")).collect()
}

static TEST_POISON_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[test]
fn collision_suppressed_codex_rollout_is_not_upload_reachable() {
    let root = test_dir("collision-suppressed-codex-upload");
    let codex_dir = root.join(".codex");
    let sessions_dir = codex_dir.join("sessions");
    std::fs::create_dir_all(&sessions_dir).expect("create collision upload fixture");
    let session_id = "01a03e99-49cf-7460-9fd7-f7dbfd2f05e4";
    let alias = session_id.to_ascii_uppercase();
    let database = rusqlite::Connection::open(codex_dir.join("state_5.sqlite"))
        .expect("open collision upload state");
    database
        .execute_batch(
            "CREATE TABLE threads (\
                    id TEXT NOT NULL, title TEXT, tokens_used INTEGER NOT NULL,\
                    thread_source TEXT, first_user_message TEXT\
                );",
        )
        .expect("create collision upload table");
    for (id, title) in [(session_id, "Lower"), (alias.as_str(), "Upper")] {
        database
            .execute(
                "INSERT INTO threads VALUES (?1, ?2, 1, 'agent_created_thread', NULL)",
                rusqlite::params![id, title],
            )
            .expect("insert collision upload row");
    }
    drop(database);
    std::fs::write(
        sessions_dir.join(format!("rollout-{session_id}.jsonl")),
        format!(
            "{{\"timestamp\":\"2026-08-29T12:00:00Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session_id}\",\"session_id\":\"{session_id}\",\"history_mode\":\"paginated\",\"history_base\":{{\"cursor\":\"file-controlled\"}}}}}}\n\
                 {{\"timestamp\":\"2026-08-29T12:00:01Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"collision-turn\",\"model\":\"gpt-5.6-sol\"}}}}\n\
                 {{\"timestamp\":\"2026-08-29T12:00:02Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"token_count\",\"info\":{{\"total_token_usage\":{{\"input_tokens\":30,\"cached_input_tokens\":8,\"output_tokens\":12,\"reasoning_output_tokens\":1}},\"last_token_usage\":{{\"input_tokens\":30,\"cached_input_tokens\":8,\"output_tokens\":12,\"reasoning_output_tokens\":1}},\"model\":\"gpt-5.6-sol\"}}}}}}\n"
        ),
    )
    .expect("write collision upload rollout");

    let mut index = ScanIndex::default();
    let scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&sessions_dir),
        &mut index,
        "2026-08-29T12:30:00Z",
        183,
        10,
    )
    .expect("scan collision upload fixture");
    assert_eq!(scan.discovered_file_count, 1);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.scanned_session_count, 0);
    assert!(scan.snapshots.is_empty());
    assert_eq!(scan.recognized_usage_drop_count, 1);
    assert_eq!(scan.ownership_incomplete_file_count, 1);
    assert_eq!(scan.dropped_usage_record_count, 1);

    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut upload_calls = 0;
    let result = upload_resumable_batches(
        &scan.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        |batch| {
            upload_calls += 1;
            claude_money_e2_pipeline_tests::ack(batch)
        },
        |_| Ok(()),
    )
    .expect("empty suppressed workset settles without upload");
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(upload_calls, 0);
    assert_eq!(accepted, 0);
    let _ = std::fs::remove_dir_all(root);
}

/// A unique poison-ledger scope per call, so tests that run in parallel
/// cannot prune each other's ledgers.
fn unique_poison_scope() -> String {
    format!(
        "test-scope-{}",
        TEST_POISON_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

fn test_upload_progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
}

/// The real due-retry selection, with a held body's deadline reached.
fn lease_due_retry(progress: &mut SnapshotUploadProgress, fingerprint: &str) {
    if let Some(record) = progress.quarantined_fingerprints.get_mut(fingerprint) {
        record.retry_after_unix_seconds = 0;
        progress.prepare_quarantine_retries(&BTreeMap::new());
        assert!(progress.active_quarantine_retries.contains(fingerprint));
    }
}

/// [money] A lost ACK response leaves no checkpoint; only the exact
/// creator-domain proof (public v7) settles the retry, after which the
/// settled body is a no-op.
#[test]
fn account_ack_retry_checkpoints_released_witness_then_becomes_noop() {
    let root = test_dir("account-ack-retry-checkpoint");
    std::fs::create_dir_all(&root).expect("create snapshot fixture root");
    let path = root.join("account-session.jsonl");
    std::fs::write(
        &path,
        "{\"timestamp\":\"2026-08-30T12:00:00Z\",\"sessionId\":\"account-session\",\"requestId\":\"req-1\",\"message\":{\"id\":\"msg-1\",\"model\":\"claude-opus-4-8\",\"usage\":{\"input_tokens\":42,\"output_tokens\":1}}}\n",
    )
    .expect("write snapshot fixture");
    let mut index = ScanIndex::default();
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut index,
        "2026-08-30T12:05:00Z",
        183,
        10,
    )
    .expect("scan snapshot fixture");
    assert_eq!(scan.snapshots.len(), 1);
    let item = scan.snapshots.remove(0);
    // The session-account evidence alone selects the creator ACK domain;
    // a neighbouring released domain cannot settle it.
    assert_eq!(
        item.session_account_evidence
            .as_ref()
            .unwrap()
            .identity_disposition,
        Some("missing")
    );
    assert!(item.cache_observations.is_none());
    assert!(item.context_curve.is_none());
    assert_eq!(
        (item.input_tokens, item.output_tokens, item.request_count),
        (42, 1, 1)
    );
    let items = vec![item];
    let digest = snapshot_upload_body_witness(&items[0]);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let checked_response = |batch: &[&SnapshotItem], version, proof, unchanged| {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "claude_code".to_string(),
            machine_id: "machine".to_string(),
            collector_version: None,
            snapshots: batch.to_vec(),
            upload_policy: SnapshotUploadPolicy::default(),
            client_report: crate::client_report::ClientReport::empty(),
        };
        let uploaded = &request.snapshots[0];
        let reference = crate::snapshot_client::SnapshotEntityRef {
            source_session_id: uploaded.source_session_id.clone(),
            snapshot_fingerprint: uploaded.snapshot_fingerprint.clone(),
            occurrence_count: 1,
            body_witness_version: version,
            body_witness_digest: proof,
            head_etag: None,
            head_challenge: None,
            unchanged_basis: None,
            cache_observations_state: None,
        };
        let response = crate::snapshot_client::SnapshotBatchResponse {
            conflict_rescans: Default::default(),
            accepted: 1,
            sessions_reconciled: 0,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
            entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string()),
            accepted_entities: if unchanged {
                vec![]
            } else {
                vec![reference.clone()]
            },
            unchanged_entities: if unchanged { vec![reference] } else { vec![] },
            rejected_entities: Vec::new(),
            conflict_entities: Vec::new(),
        };
        response.validate_entity_ack(&request)?;
        Ok(response)
    };
    checked_response(
        &items.iter().collect::<Vec<_>>(),
        Some(7),
        Some(digest.clone()),
        false,
    )
    .expect("exact first-admission ACK validates in its declared domain");
    let first = upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| Err(anyhow!("response lost after durable remote write")),
        |_| Ok(()),
    );
    first.expect_err("lost response cannot advance local checkpoint");
    assert!(progress.accepted_fingerprints.is_empty());
    for unchanged in [false, true] {
        for (version, proof) in [
            (None, None),
            (Some(7), Some("0".repeat(64))),
            // The cache-declared neighbour domain cannot settle it.
            (Some(13), Some(digest.clone())),
        ] {
            lease_due_retry(&mut progress, &items[0].snapshot_fingerprint);
            let mut calls = 0;
            let outcome = upload_resumable_batches_with_body_witness(
                &items,
                &unique_poison_scope(),
                &mut progress,
                &mut accepted,
                |snapshot| snapshot.snapshot_fingerprint.as_str(),
                snapshot_upload_body_witness,
                |batch| {
                    calls += 1;
                    checked_response(batch, version, proof.clone(), unchanged)
                },
                |_| Ok(()),
            )
            .unwrap();
            // The refusal names the body: it is set aside, never settled.
            assert_eq!(
                (outcome, calls),
                (
                    ResumableUploadResult::Deferred {
                        count: 1,
                        isolated: 0,
                        identity_503: 0
                    },
                    1
                ),
                "missing/wrong proof or capability domain cannot settle retry"
            );
            assert_eq!(accepted, 0);
            assert!(progress.accepted_fingerprints.is_empty());
            assert!(!progress
                .accepted_body_witnesses
                .contains_key(&items[0].snapshot_fingerprint));
            assert_eq!(
                progress.quarantined_fingerprints[&items[0].snapshot_fingerprint].disposition,
                SnapshotQuarantineDisposition::RetryPending
            );
        }
    }
    lease_due_retry(&mut progress, &items[0].snapshot_fingerprint);
    let mut retry_calls = 0;
    upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            retry_calls += 1;
            checked_response(batch, Some(7), Some(digest.clone()), true)
        },
        |_| Ok(()),
    )
    .expect("exact unchanged ACK settles its declared checkpoint");
    assert_eq!(retry_calls, 1);
    assert_eq!(accepted, 1);
    assert!(progress.contains_body(&items[0].snapshot_fingerprint, &digest));
    let mut noop_calls = 0;
    upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| {
            noop_calls += 1;
            panic!("already accepted body must not be uploaded")
        },
        |_| Ok(()),
    )
    .expect("settled body is a durable no-op");
    assert_eq!(noop_calls, 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn replay_generation_reuploads_prior_acks_once_and_resumes_its_own_progress() {
    let poison_scope = &unique_poison_scope();
    let root = test_dir("snapshot-replay-generation-progress");
    let items = test_fingerprints(2);
    let destination = format!("{:064x}", 99);
    // The old ledger bytes sit beside an empty committed native graph.
    std::fs::create_dir_all(&root).expect("create progress fixture directory");
    let mut route = ScanIndex::default();
    let index_path = crate::snapshots::e2_pipeline_scan_fixture::bind_fixture_route(
        SnapshotSource::Codex,
        &mut route,
        &root,
        &destination,
    );
    route.save_fixture(&index_path).unwrap();
    let path = snapshot_upload_progress_path(&index_path);
    let old_generation = format!("codex:codex_session_exclusive_usage:v2:{destination}");
    let new_generation = format!("codex:codex_session_exclusive_usage:v3:{destination}");

    // Model the exact pre-change v3 file from the admission gap: it has no
    // replay-generation field, one current entity was ACKed, and another
    // was quarantined while both backend heads still need replacement.
    let mut progress = test_upload_progress();
    progress.record([items[0].as_str()]);
    progress.quarantine([items[1].as_str()]);
    let mut old_index = ScanIndex::default();
    old_index.prepare_historical_replay(old_generation);
    old_index.file_snapshot_fingerprints.insert(
        "old-generation.jsonl".to_string(),
        BTreeSet::from([items[1].clone()]),
    );
    old_index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    let mut current_v3 = serde_json::to_value(&progress).expect("serialize v3 progress");
    current_v3
        .as_object_mut()
        .expect("progress is an object")
        .remove("historical_replay_generation");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&current_v3).expect("serialize pre-change v3 progress"),
    )
    .expect("save pre-change v3 progress");

    // The route's first load imports the old bytes as its native rows.
    let mut rearmed = load_routed_progress(
        &route,
        &index_path,
        &destination,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    assert!(rearmed.historical_replay_generation.is_none());
    assert!(prepare_upload_progress_for_cycle(
        &mut rearmed,
        &old_index,
        &new_generation,
        true,
    ));
    assert!(rearmed.accepted_fingerprints.is_empty());
    assert!(rearmed.quarantined_fingerprints.is_empty());
    rearmed
        .save(&path)
        .expect("persist replay rearm before scan");

    let mut accepted = 0;
    let mut upload_calls = 0;
    let result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut rearmed,
        &mut accepted,
        String::as_str,
        |batch| {
            upload_calls += 1;
            assert_eq!(batch, items.iter().collect::<Vec<_>>());
            Ok(accept_fingerprints(batch))
        },
        |state| state.save_fixture(&path),
    )
    .expect("new replay uploads every prior old-generation entity");
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!((upload_calls, accepted), (1, 2));

    let mut resumed = load_routed_progress(
        &route,
        &index_path,
        &destination,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    assert!(!resumed.prepare_historical_replay(&new_generation));
    let mut resumed_accepted = 0;
    let mut resumed_upload_calls = 0;
    let resumed_result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut resumed,
        &mut resumed_accepted,
        String::as_str,
        |_| {
            resumed_upload_calls += 1;
            panic!("already accepted replay must not be uploaded")
        },
        |state| state.save_fixture(&path),
    )
    .expect("same replay generation resumes from its durable ACKs");
    assert_eq!(resumed_result, ResumableUploadResult::Completed);
    assert_eq!((resumed_upload_calls, resumed_accepted), (0, 0));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
#[serial(client_report)]
fn same_replay_generation_restores_cleared_conflict_progress_until_retry() {
    use crate::client_report::reset_for_test;

    reset_for_test();
    let poison_scope = unique_poison_scope();
    let root = test_dir("snapshot-replay-conflict-progress-restore");
    let index_path = root.join("codex-scan-index-v3.json");
    let progress_path = snapshot_upload_progress_path(&index_path);
    let destination = format!("{:064x}", 99);
    let replay_generation = format!("codex:codex_session_exclusive_usage:v3:{destination}");
    let conflicted_fingerprint = test_fingerprints(1).remove(0);

    let mut index = ScanIndex::default();
    index.prepare_historical_replay(replay_generation.clone());
    index.file_snapshot_fingerprints.insert(
        "conflicted.jsonl".to_string(),
        BTreeSet::from([conflicted_fingerprint.clone()]),
    );

    index.save_fixture(&index_path).unwrap();
    let mut progress =
        route_fixture_progress(&index, &index_path, &progress_path, test_upload_progress());
    assert!(progress.prepare_historical_replay(&replay_generation));
    let mut accepted = 0;
    let result = upload_resumable_batches(
        std::slice::from_ref(&conflicted_fingerprint),
        &poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| {
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: 0,
                sessions_reconciled: 0,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(
                    crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                ),
                accepted_entities: Vec::new(),
                unchanged_entities: Vec::new(),
                rejected_entities: Vec::new(),
                conflict_entities: vec![crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: "conflicted".to_string(),
                    snapshot_fingerprint: conflicted_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                }],
            })
        },
        |state| state.save_fixture(&progress_path),
    )
    .expect("conflict remains retryable");
    assert_eq!(
        result,
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1,
            identity_503: 0
        }
    );
    assert_eq!(accepted, 0);

    index.mark_bounded_sweep_unsettled();
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index
        .save_fixture(&index_path)
        .expect("persist conflicted index");
    clear_fixture_progress(&mut progress, &progress_path)
        .expect("completed conflict cycle clears disposable progress");

    let persisted_index = ScanIndex::load(&index_path).expect("reload conflicted index");
    let mut restored = SnapshotUploadProgress::load_for_index(
        &persisted_index,
        &index_path,
        &progress_path,
        &destination,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .expect("load cleared progress");
    assert!(prepare_upload_progress_for_cycle(
        &mut restored,
        &persisted_index,
        &replay_generation,
        true,
    ));
    assert!(
        restored
            .quarantined_fingerprints
            .contains_key(&conflicted_fingerprint),
        "same-generation historical preparation must restore index-owned conflict"
    );
    restored
        .save_fixture(&progress_path)
        .expect("persist restored same-generation conflict");
    clear_fixture_progress(&mut restored, &progress_path)
        .expect("model another completed follow-up cycle");

    let mut due_index = persisted_index;
    due_index
        .quarantined_snapshot_fingerprints
        .get_mut(&conflicted_fingerprint)
        .expect("conflict remains in index")
        .retry_after_unix_seconds = 0;
    due_index
        .save_fixture(&index_path)
        .expect("persist due conflict");

    let due_index = ScanIndex::load(&index_path).expect("reload due conflict index");
    let mut retry_progress = SnapshotUploadProgress::load_for_index(
        &due_index,
        &index_path,
        &progress_path,
        &destination,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .expect("load progress for due retry");
    assert!(prepare_upload_progress_for_cycle(
        &mut retry_progress,
        &due_index,
        &replay_generation,
        true,
    ));
    assert!(
        !retry_progress.contains(&conflicted_fingerprint),
        "due same-generation conflict must be released for upload retry"
    );

    let mut retry_accepted = 0;
    let mut retry_uploads = 0;
    let retry_result = upload_resumable_batches(
        std::slice::from_ref(&conflicted_fingerprint),
        &poison_scope,
        &mut retry_progress,
        &mut retry_accepted,
        String::as_str,
        |batch| {
            retry_uploads += 1;
            Ok(accept_fingerprints(batch))
        },
        |_| Ok(()),
    )
    .expect("due same-generation conflict is retried");
    assert_eq!(retry_result, ResumableUploadResult::Completed);
    assert_eq!((retry_uploads, retry_accepted), (1, 1));

    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
    reset_for_test();
}

#[derive(Clone, Serialize)]
struct BodyWitnessTestItem {
    snapshot_fingerprint: String,
    body_revision: String,
}

#[test]
fn resumable_progress_tracks_hash_neutral_body_corrections() {
    let fingerprint = format!("{:064x}", 42);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut uploads = Vec::new();
    let mut run =
        |body_revision: &str, progress: &mut SnapshotUploadProgress, accepted: &mut u64| {
            let item = BodyWitnessTestItem {
                snapshot_fingerprint: fingerprint.clone(),
                body_revision: body_revision.to_string(),
            };
            upload_resumable_batches_with_body_witness(
                &[item],
                &unique_poison_scope(),
                progress,
                accepted,
                |item| item.snapshot_fingerprint.as_str(),
                |item| format!("{:064x}", if item.body_revision == "a" { 10 } else { 11 }),
                |batch| {
                    uploads.push(batch[0].body_revision.clone());
                    Ok(accept_batch_with(batch, |item| {
                        item.snapshot_fingerprint.as_str()
                    }))
                },
                |_| Ok(()),
            )
            .expect("body-witness upload")
        };

    assert_eq!(
        run("a", &mut progress, &mut accepted),
        ResumableUploadResult::Completed
    );
    assert_eq!(
        run("a", &mut progress, &mut accepted),
        ResumableUploadResult::Completed
    );
    assert_eq!(
        run("b", &mut progress, &mut accepted),
        ResumableUploadResult::Completed
    );
    assert_eq!(
        run("a", &mut progress, &mut accepted),
        ResumableUploadResult::Completed
    );
    assert_eq!(uploads, ["a", "b", "a"]);
    assert_eq!(accepted, 3);
    assert_eq!(
        progress.accepted_fingerprints,
        BTreeSet::from([fingerprint])
    );

    let mut corrected_progress = test_upload_progress();
    let witness_a = format!("{:064x}", 10);
    let witness_b = format!("{:064x}", 11);
    corrected_progress.quarantine_body(&format!("{:064x}", 42), &witness_a);
    assert!(corrected_progress.contains_body(&format!("{:064x}", 42), &witness_a));
    assert!(
        !corrected_progress.contains_body(&format!("{:064x}", 42), &witness_b),
        "a corrected hash-neutral body bypasses the old body's quarantine"
    );
    let mut corrected_accepted = 0;
    let mut corrected_uploads = 0;
    let corrected_item = BodyWitnessTestItem {
        snapshot_fingerprint: format!("{:064x}", 42),
        body_revision: "b".to_string(),
    };
    upload_resumable_batches_with_body_witness(
        &[corrected_item],
        &unique_poison_scope(),
        &mut corrected_progress,
        &mut corrected_accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |_| witness_b.clone(),
        |batch| {
            corrected_uploads += 1;
            Ok(accept_batch_with(batch, |item| {
                item.snapshot_fingerprint.as_str()
            }))
        },
        |_| Ok(()),
    )
    .expect("corrected body bypasses quarantine");
    assert_eq!((corrected_uploads, corrected_accepted), (1, 1));
}

#[test]
fn resumable_progress_rejects_conflicting_bodies_for_one_semantic_entity() {
    let fingerprint = format!("{:064x}", 42);
    let items = [
        BodyWitnessTestItem {
            snapshot_fingerprint: fingerprint.clone(),
            body_revision: "a".to_string(),
        },
        BodyWitnessTestItem {
            snapshot_fingerprint: fingerprint,
            body_revision: "b".to_string(),
        },
    ];
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut uploads = 0;
    let error = upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        |item| format!("{:064x}", if item.body_revision == "a" { 10 } else { 11 }),
        |batch| {
            uploads += 1;
            Ok(accept_batch_with(batch, |item| {
                item.snapshot_fingerprint.as_str()
            }))
        },
        |_| Ok(()),
    )
    .expect_err("conflicting bodies fail before upload");
    assert!(error
        .to_string()
        .contains("resolve conflicting snapshot body witnesses"));
    assert_eq!((uploads, accepted), (0, 0));
    assert!(progress.accepted_fingerprints.is_empty());
}

/// [regress] off busy progress preserves damaged v1 before containment.
#[test]
fn off_busy_progress_preserves_damaged_v1_before_containment() {
    let root = crate::test_scratch::private_dir("off-progress-before-v1");
    let namespace = root.join("snapshots/destinations").join("b".repeat(64));
    std::fs::create_dir_all(&namespace).unwrap();
    let index_path = namespace.join("claude_code-scan-index-v3.json");
    let progress_path = snapshot_upload_progress_path(&index_path);
    let damaged = b"{broken-v1";
    std::fs::write(&index_path, damaged).unwrap();
    let busy = SnapshotProgressLock::acquire(&progress_path).unwrap();
    let error = load_source_checkpoints(
        &index_path,
        &progress_path,
        SnapshotSource::ClaudeCode,
        &root,
        &"b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .expect_err("busy progress must fail first");
    assert!(error.to_string().contains("owned by another daemon"));
    assert_eq!(std::fs::read(&index_path).unwrap(), damaged);
    assert!(!progress_path.exists());
    assert!(!std::fs::read_dir(&namespace).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".corrupt.")));
    drop(busy);
    // Releasing progress permits the native G=0 publication. Adoption waits
    // for the next ordinary pass, with the damaged bytes kept as its witness.
    let error = load_source_checkpoints(
        &index_path,
        &progress_path,
        SnapshotSource::ClaudeCode,
        &root,
        &"b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .expect_err("fresh publication requires the next pass");
    assert_eq!(
        error.downcast_ref::<crate::snapshots::state_v2::Hold>(),
        Some(&crate::snapshots::state_v2::Hold::ReloadRequired)
    );
    let witness = std::fs::read_dir(&namespace)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".corrupt.")
        })
        .expect("quarantine witness");
    assert_eq!(std::fs::read(witness).unwrap(), damaged);
    assert!(index_path.exists());
    let (_, origin, _) = load_source_checkpoints(
        &index_path,
        &progress_path,
        SnapshotSource::ClaudeCode,
        &root,
        &"b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert_eq!(origin, crate::snapshots::ScanIndexLoadOrigin::Loaded);
    assert!(index_path.exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// [regress] for every state v2 source, damaged custody or a stat error holds before progress
/// containment or transcript reads.
#[test]
fn published_custody_authenticates_before_damaged_progress_containment() {
    for (source, stat_error) in [SnapshotSource::ClaudeCode, SnapshotSource::Codex]
        .into_iter()
        .flat_map(|source| [(source, false), (source, true)])
    {
        let root = crate::test_scratch::private_dir("v2-route-before-progress");
        let namespace = root.join("snapshots/destinations").join("b".repeat(64));
        std::fs::create_dir_all(&namespace).unwrap();
        let index_path = namespace.join(format!("{}-scan-index-v3.json", source.api_slug()));
        let progress_path = snapshot_upload_progress_path(&index_path);
        std::fs::write(&index_path, b"{broken-fence").unwrap();
        std::fs::write(index_path.with_extension("json.v2.sqlite"), b"untrusted-db").unwrap();
        std::fs::write(&progress_path, b"{broken-progress").unwrap();
        let evidence = if stat_error {
            let kept = root.join("kept");
            std::fs::rename(&namespace, &kept).unwrap();
            std::os::unix::fs::symlink(&namespace, &namespace).unwrap();
            assert_eq!(
                std::fs::symlink_metadata(index_path.with_extension("json.v2.sqlite"))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ELOOP)
            );
            kept
        } else {
            namespace
        };
        let scope = crate::local_resource_diagnostics::claude_reread::Scope::begin(true);
        let (result, records) = crate::local_resource_diagnostics::capture(|| {
            load_source_checkpoints(
                &index_path,
                &progress_path,
                source,
                &root,
                &"b".repeat(64),
                snapshot_quarantine_witness(source),
            )
        });
        let counts = scope.finish();
        assert_eq!(counts, Default::default(), "no transcript acquisition");
        let error = result.expect_err("unauthenticated custody must hold");
        assert!(error.to_string().contains(if stat_error {
            "state_v2_db_unavailable"
        } else {
            "state_v2_fence_lost"
        }));
        assert!(records.iter().any(|r| r["stage"] == "claude_state_v2"
            && r["counts"]["latest"]["hold"]
                == if stat_error {
                    "db_unavailable"
                } else {
                    "fence_lost"
                }));
        let kept_progress = evidence.join(progress_path.file_name().unwrap());
        assert_eq!(std::fs::read(&kept_progress).unwrap(), b"{broken-progress");
        assert_eq!(
            std::fs::read(evidence.join(index_path.file_name().unwrap())).unwrap(),
            b"{broken-fence"
        );
        assert!(!kept_progress.with_extension("lock").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn test_quarantine_witness() -> SnapshotQuarantineWitness {
    snapshot_quarantine_witness(SnapshotSource::Codex)
}

fn entity_ack_response(count: u64) -> crate::snapshot_client::SnapshotBatchResponse {
    crate::snapshot_client::SnapshotBatchResponse {
        conflict_rescans: Default::default(),
        accepted: count,
        sessions_reconciled: count,
        session_ids: Vec::new(),
        disabled: false,
        disabled_reason: None,
        entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
        accepted_entities: Vec::new(),
        unchanged_entities: Vec::new(),
        rejected_entities: Vec::new(),
        conflict_entities: Vec::new(),
    }
}

fn accept_fingerprints(batch: &[&String]) -> crate::snapshot_client::SnapshotBatchResponse {
    accept_batch_with(batch, String::as_str)
}

fn accept_batch_with<T>(
    batch: &[&T],
    fingerprint: impl Fn(&T) -> &str,
) -> crate::snapshot_client::SnapshotBatchResponse {
    let mut response = entity_ack_response(batch.len() as u64);
    response.accepted_entities = batch
        .iter()
        .map(|item| entity_ack_ref(fingerprint(item)))
        .collect();
    response
}

fn entity_ack_ref(fingerprint: &str) -> crate::snapshot_client::SnapshotEntityRef {
    crate::snapshot_client::SnapshotEntityRef {
        source_session_id: format!("session-{fingerprint}"),
        snapshot_fingerprint: fingerprint.to_string(),
        occurrence_count: 1,
        body_witness_version: None,
        body_witness_digest: None,
        head_etag: None,
        head_challenge: None,
        unchanged_basis: None,
        cache_observations_state: None,
    }
}

fn entity_ack_batch<T: AsRef<str>>(
    accepted: &[T],
    unchanged: &[T],
    conflicted: &[T],
) -> crate::snapshot_client::SnapshotBatchResponse {
    crate::snapshot_client::SnapshotBatchResponse {
        accepted_entities: accepted
            .iter()
            .map(|fingerprint| entity_ack_ref(fingerprint.as_ref()))
            .collect(),
        unchanged_entities: unchanged
            .iter()
            .map(|fingerprint| entity_ack_ref(fingerprint.as_ref()))
            .collect(),
        conflict_entities: conflicted
            .iter()
            .map(|fingerprint| entity_ack_ref(fingerprint.as_ref()))
            .collect(),
        ..entity_ack_response(accepted.len().saturating_add(unchanged.len()) as u64)
    }
}

#[test]
fn resumable_upload_rejects_missing_ack_contract_and_reoffers_the_page() {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.cache_observations = None;
    item.session_account_evidence = None;
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "synthetic-machine".into(),
        collector_version: None,
        snapshots: vec![item],
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let response: crate::snapshot_client::SnapshotBatchResponse =
        serde_json::from_value(serde_json::json!({
            "accepted": 1,
            "sessions_reconciled": 1,
            "session_ids": [],
            "disabled": false
        }))
        .unwrap();
    let detail = "snapshot response lacks the entity ACK contract";
    assert_eq!(
        response
            .validate_entity_ack(&request)
            .unwrap_err()
            .to_string(),
        detail
    );

    let scope = unique_poison_scope();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let fingerprint = &request.snapshots[0].snapshot_fingerprint;
    let error = upload_resumable_batches_with_body_witness(
        &request.snapshots,
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| Ok(response.clone()),
        |_| panic!("a failed page must not save a settlement"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), detail);
    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::BackendResponse)
    );
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
    assert!(progress.accepted_body_witnesses.is_empty());
    assert!(progress.fresh_context_body_acks.is_empty());

    upload_resumable_batches_with_body_witness(
        &request.snapshots,
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            assert_eq!(batch.len(), 1);
            assert_eq!(&batch[0].snapshot_fingerprint, fingerprint);
            claude_money_e2_pipeline_tests::ack(batch)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(accepted, 1);
    assert!(progress.accepted_fingerprints.contains(fingerprint));
}

#[test]
fn resumable_upload_rejects_unknown_ack_contract_before_progress_advances() {
    let items = test_fingerprints(1);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let error = upload_resumable_batches(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            let mut response = entity_ack_response(batch.len() as u64);
            response.entity_ack_contract = Some("snapshot_entity_ack:v999".to_string());
            Ok(response)
        },
        |_| Ok(()),
    )
    .expect_err("unsupported ACK shapes cannot settle local progress");

    assert!(error
        .to_string()
        .contains("unsupported entity ACK contract"));
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
}

#[test]
#[serial(client_report)]
fn entity_ack_rejection_counts_one_poison_after_durable_quarantine() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};

    reset_for_test();
    let poison_scope = unique_poison_scope();
    let items = test_fingerprints(2);
    let accepted_fingerprint = items[0].clone();
    let rejected_fingerprint = items[1].clone();
    let mut progress = test_upload_progress();
    let mut accepted = 0;

    let result = upload_resumable_batches(
        &items,
        &poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| {
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: 1,
                sessions_reconciled: 1,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(
                    crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                ),
                accepted_entities: vec![crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: "accepted".to_string(),
                    snapshot_fingerprint: accepted_fingerprint.clone(),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                }],
                unchanged_entities: Vec::new(),
                rejected_entities: vec![crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: "rejected".to_string(),
                    snapshot_fingerprint: rejected_fingerprint.clone(),
                    reason: "invalid".to_string(),
                    detail: "permanent validation failure".to_string(),
                    permanent: true,
                    occurrence_count: 1,
                }],
                conflict_entities: Vec::new(),
            })
        },
        |_| Ok(()),
    )
    .expect("permanent entity rejection is durably settled");

    assert_eq!(result, ResumableUploadResult::Rejected { count: 1 });
    assert_eq!(accepted, 1);
    assert!(progress
        .accepted_fingerprints
        .contains(&accepted_fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&rejected_fingerprint));
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 1);
    assert_eq!(
        counted_poison_fingerprints_for_test(&poison_scope),
        BTreeSet::from([rejected_fingerprint])
    );
    reset_for_test();
}

/// A conflicting entity must not strand its accepted siblings or later pages.
///
/// Regression for the per-source starvation wedge: the uploader used to
/// return the moment `conflict_entities` was non-empty, before recording the
/// entities the backend had already written in that response and before
/// visiting the next fingerprint-sorted page. A persistent capacity conflict
/// therefore replayed its accepted siblings and starved every later entity on
/// the source at the five-minute cadence.
#[test]
#[serial(client_report)]
fn entity_ack_conflict_checkpoints_siblings_drains_later_batch_and_clears_on_revision() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};

    reset_for_test();
    let poison_scope = unique_poison_scope();
    let items = test_fingerprints(SNAPSHOT_BATCH_LIMIT + 1);
    let first_batch = items[..SNAPSHOT_BATCH_LIMIT].to_vec();
    let later_batch = items[SNAPSHOT_BATCH_LIMIT..].to_vec();
    let conflicted_fingerprint = first_batch[0].clone();
    let first_accepted = first_batch[1..SNAPSHOT_BATCH_LIMIT / 2].to_vec();
    let first_unchanged = first_batch[SNAPSHOT_BATCH_LIMIT / 2..].to_vec();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut uploaded_batches = Vec::new();
    let mut persisted = Vec::new();

    let result = upload_resumable_batches(
        &items,
        &poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            uploaded_batches.push(batch.iter().copied().cloned().collect::<Vec<_>>());
            if uploaded_batches.len() == 1 {
                Ok(entity_ack_batch(
                    &first_accepted,
                    &first_unchanged,
                    std::slice::from_ref(&conflicted_fingerprint),
                ))
            } else {
                Ok(entity_ack_batch(batch, &[], &[]))
            }
        },
        |state| {
            persisted.push(state.clone());
            Ok(())
        },
    )
    .expect("a per-entity conflict is retryable, not a whole-page failure");

    assert_eq!(
        result,
        ResumableUploadResult::Deferred {
            count: 1,
            isolated: 1,
            identity_503: 0
        }
    );
    assert_eq!(uploaded_batches, vec![first_batch.clone(), later_batch]);
    assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
    assert_eq!(persisted.len(), 2);
    assert!(first_accepted
        .iter()
        .chain(&first_unchanged)
        .all(|fingerprint| persisted[0].accepted_fingerprints.contains(fingerprint)));
    assert!(persisted[0]
        .quarantined_fingerprints
        .contains_key(&conflicted_fingerprint));
    assert!(!progress
        .accepted_fingerprints
        .contains(&conflicted_fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&conflicted_fingerprint));
    assert!(progress
        .accepted_fingerprints
        .contains(&items[SNAPSHOT_BATCH_LIMIT]));

    let deferred = snapshot_entity_deferred(1);
    assert_eq!(
        deferred
            .downcast_ref::<SnapshotEntityDeferred>()
            .map(|error| error.count),
        Some(1)
    );
    assert_eq!(
        safe_error(&deferred),
        "local snapshot upload deferred by unsettled entities"
    );

    // Model the next authoritative scan replacing the oversized canonical
    // body with a fitting revision. The old fingerprint disappears, so its
    // retry becomes an explicit superseded terminal before the replacement
    // is uploaded and settled.
    let replacement_fingerprint = format!("{:064x}", SNAPSHOT_BATCH_LIMIT + 1000);
    let mut revised_items = items[1..].to_vec();
    revised_items.push(replacement_fingerprint.clone());
    let revised_fingerprints = revised_items.iter().cloned().collect::<BTreeSet<_>>();
    assert!(progress.retain_current_quarantines(&revised_fingerprints, &ScanIndex::default()));
    let mut revision_accepted = 0;
    let mut revision_uploads = Vec::new();
    let revision_result = upload_resumable_batches(
        &revised_items,
        &poison_scope,
        &mut progress,
        &mut revision_accepted,
        String::as_str,
        |batch| {
            revision_uploads.push(batch.iter().copied().cloned().collect::<Vec<_>>());
            Ok(entity_ack_batch(batch, &[], &[]))
        },
        |_| Ok(()),
    )
    .expect("a fitting replacement revision clears the conflict");

    assert_eq!(revision_result, ResumableUploadResult::Completed);
    assert_eq!(
        revision_uploads,
        vec![vec![replacement_fingerprint.clone()]]
    );
    assert_eq!(revision_accepted, 1);
    assert_eq!(progress.quarantined_fingerprints.len(), 1);
    assert_eq!(
        progress.quarantined_fingerprints[&conflicted_fingerprint].disposition,
        SnapshotQuarantineDisposition::SupersededTerminal
    );
    assert!(progress
        .accepted_fingerprints
        .contains(&replacement_fingerprint));
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
    assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
    reset_for_test();
}

#[test]
fn entity_ack_all_conflict_page_stays_pending_and_surfaces_deferred_error() {
    let items = test_fingerprints(3);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut persisted = Vec::new();

    let result = upload_resumable_batches(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| Ok(entity_ack_batch(&[], &[], batch)),
        |state| {
            persisted.push(state.clone());
            Ok(())
        },
    )
    .expect("an all-conflict page remains retryable");

    assert_eq!(
        result,
        ResumableUploadResult::Deferred {
            count: 3,
            isolated: 3,
            identity_503: 0
        }
    );
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
    assert_eq!(
        progress
            .quarantined_fingerprints
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        items.iter().cloned().collect()
    );
    assert_eq!(persisted.last(), Some(&progress));

    let deferred = snapshot_entity_deferred(3);
    assert_eq!(
        deferred
            .downcast_ref::<SnapshotEntityDeferred>()
            .map(|error| error.count),
        Some(3)
    );
}

#[test]
fn retryable_conflict_never_consumes_permanent_reconstruction_attempts() {
    let fingerprint = "f".repeat(64);
    let mut progress = test_upload_progress();
    for _ in 0..9 {
        progress.quarantine_retryable_body(
            &fingerprint,
            &"a".repeat(64),
            quarantine_retry_after(&fingerprint),
        );
        let record = &progress.quarantined_fingerprints[&fingerprint];
        assert_eq!(record.failed_reconstruction_count, 1);
        assert_eq!(
            record.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert!(snapshot_quarantine_deadline_is_bounded(record));
        assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
        progress
            .quarantined_fingerprints
            .get_mut(&fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
    }
    assert!(!progress.contains_body(&fingerprint, &"b".repeat(64)));
    progress.record_body(&fingerprint, &"b".repeat(64));
    assert!(progress.quarantined_fingerprints.is_empty());
}

#[test]
#[serial(client_report)]
fn entity_ack_rejection_is_not_counted_before_quarantine_persists() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};

    reset_for_test();
    let poison_scope = unique_poison_scope();
    let items = test_fingerprints(1);
    let rejected_fingerprint = items[0].clone();
    let mut progress = test_upload_progress();
    let mut accepted = 0;

    let error = upload_resumable_batches(
        &items,
        &poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| {
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: 0,
                sessions_reconciled: 0,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(
                    crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                ),
                accepted_entities: Vec::new(),
                unchanged_entities: Vec::new(),
                rejected_entities: vec![crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: "rejected".to_string(),
                    snapshot_fingerprint: rejected_fingerprint.clone(),
                    reason: "invalid".to_string(),
                    detail: "permanent validation failure".to_string(),
                    permanent: true,
                    occurrence_count: 1,
                }],
                conflict_entities: Vec::new(),
            })
        },
        |_| Err(anyhow!("checkpoint unavailable")),
    )
    .expect_err("an undurable rejection quarantine cannot settle the source");

    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::LocalState)
    );
    assert_eq!(accepted, 0);
    assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
    reset_for_test();
}

mod packing_count_tests {
    use super::*;
    include!("packing_count_tests.rs");
}

mod e2_upload_tests {
    use super::*;
    include!("e2_upload_tests.rs");
}

pub(in crate::snapshot_sync) mod class_split_tests {
    use super::*;
    include!("class_split_tests.rs");
}

#[derive(Clone, Serialize)]
struct SizedUploadItem {
    fingerprint: String,
    body: String,
}

#[test]
#[serial(client_report)]
fn snapshot_upload_coalesces_duplicate_semantics_with_distinct_observation_metadata() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};

    reset_for_test();
    let poison_scope = unique_poison_scope();
    let duplicate = "d".repeat(64);
    let valid = "e".repeat(64);
    let items = vec![
        SizedUploadItem {
            fingerprint: duplicate.clone(),
            body: "source-file-observation-a".to_string(),
        },
        SizedUploadItem {
            fingerprint: valid.clone(),
            body: "valid".to_string(),
        },
        SizedUploadItem {
            fingerprint: duplicate.clone(),
            body: "source-file-observation-b".to_string(),
        },
    ];
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut uploaded = Vec::new();
    upload_resumable_batches(
        &items,
        &poison_scope,
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |batch| {
            uploaded.extend(batch.iter().map(|item| item.fingerprint.clone()));
            Ok(accept_batch_with(batch, |item| item.fingerprint.as_str()))
        },
        |_| Ok(()),
    )
    .expect("observation-only differences keep one semantic entity");

    assert_eq!(uploaded, vec![duplicate.clone(), valid.clone()]);
    assert_eq!(accepted, 2);
    assert!(progress.accepted_fingerprints.contains(&duplicate));
    assert!(progress.accepted_fingerprints.contains(&valid));
    assert!(progress.quarantined_fingerprints.is_empty());
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
    assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
    reset_for_test();
}

#[test]
fn snapshot_upload_byte_bound_closes_mixed_size_batches_early() {
    let body_sizes = [400 * 1024, 800 * 1024, 1_000 * 1024, 100 * 1024];
    let items = body_sizes
        .into_iter()
        .enumerate()
        .map(|(index, body_size)| SizedUploadItem {
            fingerprint: format!("{index:064x}"),
            body: "x".repeat(body_size),
        })
        .collect::<Vec<_>>();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut observed_batches = Vec::new();
    upload_resumable_batches(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |batch| {
            observed_batches.push((batch.len(), serde_json::to_vec(batch).unwrap().len()));
            Ok(accept_batch_with(batch, |item| item.fingerprint.as_str()))
        },
        |_| Ok(()),
    )
    .expect("byte-packed upload succeeds");

    assert_eq!(accepted, 4);
    assert_eq!(
        observed_batches
            .iter()
            .map(|(count, _)| *count)
            .collect::<Vec<_>>(),
        vec![2, 2]
    );
    assert!(observed_batches
        .iter()
        .all(|(_, size)| *size <= SNAPSHOT_BATCH_MAX_BYTES));
}

#[test]
fn snapshot_upload_single_oversize_entity_ships_alone() {
    let items = vec![
        SizedUploadItem {
            fingerprint: format!("{:064x}", 0),
            body: "x".repeat(SNAPSHOT_BATCH_MAX_BYTES + 1),
        },
        SizedUploadItem {
            fingerprint: format!("{:064x}", 1),
            body: "small".to_string(),
        },
    ];
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut observed_batches = Vec::new();
    upload_resumable_batches(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.fingerprint.as_str(),
        |batch| {
            observed_batches.push((batch.len(), serde_json::to_vec(batch).unwrap().len()));
            Ok(accept_batch_with(batch, |item| item.fingerprint.as_str()))
        },
        |_| Ok(()),
    )
    .expect("a single oversize entity is left for the server entity cap");

    assert_eq!(accepted, 2);
    assert_eq!(observed_batches.len(), 2);
    assert_eq!(observed_batches[0].0, 1);
    assert!(observed_batches[0].1 > SNAPSHOT_BATCH_MAX_BYTES);
    assert_eq!(observed_batches[1].0, 1);
    assert!(observed_batches[1].1 <= SNAPSHOT_BATCH_MAX_BYTES);
}

#[test]
#[serial(client_report)]
fn oversized_local_preflight_poison_cannot_pin_later_traversal_pages() {
    use crate::client_report::reset_for_test;

    reset_for_test();
    let poison_scope = &unique_poison_scope();
    let root = test_dir("snapshot-local-preflight-traversal");
    std::fs::create_dir_all(&root).expect("create traversal fixture root");
    for index in 0..3 {
        std::fs::write(
            root.join(format!("session-{index}.jsonl")),
            format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n",
                index + 1
            ),
        )
        .expect("write traversal fixture");
    }

    let index_path = root.join("pi-scan-index-v3.json");
    let progress_path = root.join("pi-upload-progress-v2.json");
    let mut index = ScanIndex::default();
    let mut first = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        &mut index,
        "2026-07-31T00:00:00Z",
        183,
        2,
    )
    .expect("scan first bounded page");
    assert!(!first.census_complete);
    assert_eq!(first.scanned_file_count, 2);
    assert_eq!(first.snapshots.len(), 2);
    let first_page_sessions = first
        .snapshots
        .iter()
        .map(|snapshot| snapshot.source_session_id.clone())
        .collect::<BTreeSet<_>>();

    // Model a long-lived session with enough ordinary hourly usage buckets
    // to exceed the daemon/backend per-item wire cap. Keep every aggregate
    // internally consistent so the only preflight failure is the byte cap.
    let bucket_count = 2_000_u64;
    let bucket_start =
        OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).expect("parse bucket start");
    let mut bucket_template = first.snapshots[0].usage_buckets[0].clone();
    assert_eq!(bucket_template.model_usage.len(), 1);
    let usage_buckets = (0..bucket_count)
        .map(|hour| {
            let timestamp = (bucket_start + TimeDuration::hours(hour as i64))
                .format(&Rfc3339)
                .expect("format bucket timestamp");
            bucket_template.bucket_start = timestamp.clone();
            bucket_template.first_activity_at = Some(timestamp.clone());
            bucket_template.last_activity_at = Some(timestamp);
            let row = &mut bucket_template.model_usage[0];
            row.input_tokens = 1;
            row.output_tokens = 1;
            row.cache_read_tokens = 0;
            row.cache_creation_5m_tokens = 0;
            row.cache_creation_1h_tokens = 0;
            row.reasoning_output_tokens = 0;
            row.unattributed_total_tokens = 0;
            row.request_count = 1;
            bucket_template.clone()
        })
        .collect::<Vec<_>>();
    let poison = &mut first.snapshots[0];
    assert_eq!(poison.model_usage.len(), 1);
    poison.input_tokens = bucket_count;
    poison.output_tokens = bucket_count;
    poison.cache_read_tokens = 0;
    poison.cache_creation_5m_tokens = 0;
    poison.cache_creation_1h_tokens = 0;
    poison.reasoning_output_tokens = 0;
    poison.unattributed_total_tokens = 0;
    poison.request_count = bucket_count;
    let top_row = &mut poison.model_usage[0];
    top_row.input_tokens = bucket_count;
    top_row.output_tokens = bucket_count;
    top_row.cache_read_tokens = 0;
    top_row.cache_creation_5m_tokens = 0;
    top_row.cache_creation_1h_tokens = 0;
    top_row.reasoning_output_tokens = 0;
    top_row.unattributed_total_tokens = 0;
    top_row.request_count = bucket_count;
    poison.usage_buckets = usage_buckets;
    finalize_scan_after_policy(SnapshotSource::Pi, &mut first, &mut index);
    let poison_fingerprint = first.snapshots[0].snapshot_fingerprint.clone();
    let healthy_fingerprint = first.snapshots[1].snapshot_fingerprint.clone();
    let poison_probe = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::Pi.api_slug().to_string(),
        machine_id: "machine-preflight-test".to_string(),
        collector_version: Some(collector_version()),
        snapshots: vec![first.snapshots[0].clone()],
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let poison_reason = validate_snapshot_batch_request(&poison_probe)
        .expect_err("long-lived session exceeds the item wire cap");
    assert!(poison_reason.contains("wire body"), "{poison_reason}");
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut network_uploads = Vec::new();
    let result = upload_resumable_batches(
        &first.snapshots,
        poison_scope,
        &mut progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        |snapshots| {
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: SnapshotSource::Pi.api_slug().to_string(),
                machine_id: "machine-preflight-test".to_string(),
                collector_version: Some(collector_version()),
                snapshots: snapshots.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            if let Err(reason) = validate_snapshot_batch_request(&request) {
                return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason,
                }));
            }
            network_uploads.extend(
                request
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone()),
            );
            claude_money_e2_pipeline_tests::ack(&request.items().collect::<Vec<_>>())
        },
        |state| state.save_fixture(&progress_path),
    )
    .expect("deterministic local poison is settled by quarantine");

    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(accepted, 1);
    assert_eq!(network_uploads, vec![healthy_fingerprint.clone()]);
    assert!(progress
        .accepted_fingerprints
        .contains(&healthy_fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&poison_fingerprint));
    assert!(progress_path.is_file(), "quarantine must be durable first");

    // Mirror the completed caller boundary: the server-held sibling and
    // quarantined poison become durable together with the traversal cursor,
    // then the redundant upload ledger may be cleared.
    index.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
    index
        .save_fixture(&index_path)
        .expect("save settled traversal page");
    progress
        .clear(&progress_path)
        .expect("clear redundant upload progress");

    let mut resumed = ScanIndex::load(&index_path).expect("reload traversal cursor");
    let second = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        &mut resumed,
        "2026-07-31T00:05:00Z",
        183,
        2,
    )
    .expect("scan later bounded page");
    assert!(second.census_complete);
    assert_eq!(second.scanned_file_count, 1);
    assert_eq!(second.snapshots.len(), 1);
    assert!(!first_page_sessions.contains(&second.snapshots[0].source_session_id));

    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
    reset_for_test();
}

#[test]
fn metadata_only_snapshot_still_uploads_and_settles_after_manifest_omission() {
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/snapshot-audit/snapshot-manifest-v2-metadata-only-golden.json"
    ))
    .expect("parse shared metadata-only golden");
    assert!(golden["semantic_activity"].is_null());
    assert_eq!(golden["manifest"]["entity_count"], 0);
    let fingerprint = golden["snapshot_fingerprint"].as_str().unwrap().to_string();
    let expected_occurrences = golden["expected_upload_ack_occurrence_count"]
        .as_u64()
        .unwrap();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut attempts = 0;

    upload_resumable_batches(
        std::slice::from_ref(&fingerprint),
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            assert_eq!(batch, &[&fingerprint]);
            let mut response = entity_ack_response(expected_occurrences);
            let mut entity = entity_ack_ref(&fingerprint);
            entity.occurrence_count = expected_occurrences;
            response.accepted_entities.push(entity);
            Ok(response)
        },
        |_| Ok(()),
    )
    .expect("metadata-only snapshot upload is independently acknowledged");

    assert_eq!(attempts, 1);
    assert_eq!(accepted, expected_occurrences);
    assert!(progress.accepted_fingerprints.contains(&fingerprint));
}

#[test]
#[serial(client_report)]
fn a_permanently_poisoned_item_is_counted_once_not_once_per_cycle() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};
    let poison_scope = &unique_poison_scope();
    reset_for_test();
    let items = test_fingerprints(1);
    let poison = items[0].clone();
    let upload = |batch: &[&String]| {
        assert!(batch.contains(&&poison));
        Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
            reason: "snapshot[0] exceeds local wire limit".into(),
        }))
    };

    // Three cycles over the same permanently invalid entity. Nothing ever
    // succeeds, so nothing ever commits the report; if each attempt counted,
    // one broken session would look like a growing stream of losses.
    for _ in 0..3 {
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            upload,
            |_| Ok(()),
        )
        .expect("a local poison hold completes with loss reported");
    }

    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 1);

    // A later scan that no longer carries the entity prunes the ledger, so
    // it stays bounded by the current scan rather than by all history.
    let other_items = test_fingerprints(2)[1..].to_vec();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    upload_resumable_batches(
        &other_items,
        poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| Ok(accept_fingerprints(batch)),
        |_| Ok(()),
    )
    .expect("valid scan succeeds");
    assert!(counted_poison_fingerprints_for_test(poison_scope).is_empty());
    reset_for_test();
}

#[test]
#[serial(client_report, source_cadences, source_upload_deadlines)]
fn a_shed_page_stops_the_pass_and_keeps_earlier_pages_checkpointed() {
    let poison_scope = &unique_poison_scope();
    use crate::client_report::{observe, reset_for_test, ClientReportReason};
    reset_for_test();
    let items = test_fingerprints(75);
    let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut attempts = 0usize;

    let result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts += 1;
            if batch == first_page.iter().collect::<Vec<_>>() {
                Ok(accept_fingerprints(batch))
            } else {
                Err(anyhow::Error::new(UploadShed {
                    status: 503,
                    retry_after: Some(Duration::from_secs(60)),
                    code: None,
                }))
            }
        },
        |_| Ok(()),
    )
    .expect("a shed page is not a cycle failure");

    // The shed page stops the pass instead of driving the remaining pages at
    // a server that just asked for room.
    assert_eq!(attempts, 2);
    assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
    assert_eq!(progress.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);
    match result {
        ResumableUploadResult::Shed { retry_after } => {
            // The pass reports the server's own number; turning it into a
            // wait belongs to the caller, which owns the shed history.
            assert_eq!(retry_after, Some(Duration::from_secs(60)));
            clear_shed_streak(SnapshotSource::Pi);
            let honoured = note_shed_and_backoff(SnapshotSource::Pi, retry_after);
            // Retry-After x uniform(1.0, 1.2): never before the server's 60s,
            // never more than 20% late.
            assert!(honoured >= Duration::from_secs(60));
            assert!(honoured <= Duration::from_secs(72));
            clear_shed_streak(SnapshotSource::Pi);
        }
        other => panic!("expected a shed result, got {other:?}"),
    }
    assert_eq!(observe().quantity(ClientReportReason::RatelimitBackoff), 1);
    reset_for_test();
}

mod inplace_retry_tests {
    include!("inplace_retry_tests.rs");
}

#[test]
fn session_cadence_tracks_power_without_delaying_paced_work() {
    use continuation::{session_power_stretch, PlatformState, PACED_BATTERY, PACING};
    let start = Instant::now();
    let minutes = |n: u64| Duration::from_secs(n * 60);
    for power in [
        PlatformState::Allowed,
        PlatformState::Unknown,
        PlatformState::Battery,
        PlatformState::Refused,
    ] {
        let stretch = session_power_stretch(power);
        let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
        cadence.set_power_stretch(stretch);
        assert_eq!(cadence.ordinary_interval(), MAX_CYCLE_INTERVAL, "cold");
        cadence.record_scan_success(start, 0);
        assert_eq!(
            cadence.ordinary_interval(),
            minutes(if stretch == 3 { 15 } else { 10 }),
            "idle"
        );
        cadence.record_scan_success(start, 1);
        assert_eq!(
            cadence.ordinary_interval(),
            SNAPSHOT_SYNC_INTERVAL * stretch,
            "warm"
        );
        cadence.record_file_event(start);
        assert_eq!(
            cadence.ordinary_interval(),
            SNAPSHOT_SYNC_INTERVAL * stretch,
            "hot"
        );
        cadence.request_paced_scan(start, Duration::ZERO, PACED_BATTERY, false);
        assert_eq!(cadence.paced_scan_due(), Some(start + minutes(3)));
        cadence.request_continuation(start, Duration::from_secs(1));
        assert_eq!(
            cadence.continuation_due(PACING),
            Some(start + Duration::from_secs(30))
        );
        cadence.request_continuation(start, Duration::from_secs(40));
        assert_eq!(
            cadence.continuation_due(PACING),
            (stretch == 3).then_some(start + minutes(6)),
            "stretch only widens continuation eligibility"
        );
        cadence.set_server_min_interval(Some(minutes(20)));
        assert_eq!(cadence.ordinary_interval(), minutes(20));
        cadence.set_server_min_interval(None);
        cadence.record_scan_failure(start);
        assert_eq!(cadence.ordinary_interval(), minutes(1), "failure unchanged");
    }
    let mut cadence = SourceCadence::new(CadenceConfig::cost_first(SNAPSHOT_SYNC_INTERVAL));
    cadence.record_scan_success(start, 1);
    let now = start + minutes(5);
    cadence.set_power_stretch(session_power_stretch(PlatformState::Battery));
    assert_eq!(cadence.next_scan_after(now), minutes(10), "unplugged");
    cadence.set_power_stretch(session_power_stretch(PlatformState::Allowed));
    assert_eq!(cadence.next_scan_after(now), Duration::ZERO, "plugged in");
    cadence.set_power_stretch(session_power_stretch(PlatformState::Refused));
    cadence.record_account_switch(now);
    assert_eq!(
        cadence.next_scan_after(now),
        Duration::ZERO,
        "account switch"
    );
}

#[test]
#[serial(source_cadences)]
fn a_server_scan_directive_is_read_bounded_and_cannot_starve_the_scan() {
    clear_cadence_state_for_test();
    let wait_for = |source, now| {
        with_source_cadence(source, |cadence| negotiated_wait(cadence, now)).expect("cadence")
    };

    // A directive in the past is "no minimum", not a negative wait.
    record_server_scan_directive(SnapshotSource::Codex, "2020-01-01T00:00:00Z");
    assert_eq!(
        wait_for(SnapshotSource::Codex, Instant::now()),
        Duration::ZERO
    );

    // A far-future directive is bounded by the ceiling: a server cannot
    // silence a source for a day.
    let scanned_at = Instant::now();
    with_source_cadence(SnapshotSource::Codex, |cadence| {
        cadence.record_scan_success(scanned_at, 1)
    });
    record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");
    assert_eq!(
        wait_for(SnapshotSource::Codex, scanned_at),
        MAX_CYCLE_INTERVAL
    );

    // An unparsable directive leaves the previous one alone rather than
    // inventing a value.
    record_server_scan_directive(SnapshotSource::Codex, "soon");
    assert_eq!(
        wait_for(SnapshotSource::Codex, scanned_at),
        MAX_CYCLE_INTERVAL
    );

    // The starvation case: re-reading a directive on every cycle must not push
    // its own deadline forward. Anchored to the last scan, the wait strictly
    // decreases as time passes — otherwise the scan would never run again, on a
    // machine where nothing looks wrong.
    let mut previous = MAX_CYCLE_INTERVAL + Duration::from_secs(1);
    for elapsed in [0u64, 60, 600] {
        record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");
        let wait = wait_for(
            SnapshotSource::Codex,
            scanned_at + Duration::from_secs(elapsed),
        );
        assert!(
            wait < previous,
            "a refreshed directive must never extend its own deadline"
        );
        previous = wait;
    }
    clear_cadence_state_for_test();
}

#[test]
#[serial(source_cadences, source_manifests)]
fn the_cadence_tier_never_reaches_the_wire_or_any_identity() {
    let _source_manifests = SourceManifestTestGuard::new();
    clear_cadence_state_for_test();
    // The cadence tier and the scan trigger are implementation state. If either
    // entered an identity, every session on a machine would re-mint its content
    // hash the moment the machine went idle.
    with_source_cadence(SnapshotSource::Codex, |cadence| {
        cadence.record_file_event(Instant::now())
    });
    record_server_scan_directive(SnapshotSource::Codex, "2099-01-01T00:00:00Z");

    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    report_checkin_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        None,
    )
    .expect("report check-in while a tier is hot");
    let requests = captured.lock().expect("captured requests").clone();
    for forbidden in [
        "cadence",
        "scan_trigger",
        "recommended_scan_after",
        "\"hot\"",
        "\"idle\"",
        "\"cold\"",
    ] {
        assert!(
            !requests[1].contains(forbidden),
            "{forbidden} must not travel on a receipt"
        );
    }
    clear_cadence_state_for_test();
}

#[test]
#[serial(client_report)]
fn local_preflight_quarantine_persist_failure_stays_unsettled() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};

    reset_for_test();
    let items = test_fingerprints(1);
    let poison_scope = unique_poison_scope();
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let error = upload_resumable_batches(
        &items,
        &poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| {
            Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                reason: format!(
                    "snapshot[0] wire body exceeds {} bytes",
                    crate::snapshots::MAX_SNAPSHOT_ITEM_WIRE_BYTES
                ),
            }))
        },
        |_| Err(anyhow!("checkpoint unavailable")),
    )
    .expect_err("an undurable quarantine cannot settle the source");

    assert_eq!(
        snapshot_upload_error_class(&error),
        Some(SnapshotUploadErrorClass::LocalState)
    );
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
    assert!(progress.quarantined_fingerprints.is_empty());
    assert!(counted_poison_fingerprints_for_test(&poison_scope).is_empty());
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
    reset_for_test();
}

#[test]
fn snapshot_upload_restart_resumes_after_durable_timeout_checkpoint() {
    let poison_scope = &unique_poison_scope();
    let root = test_dir("snapshot-upload-resume-timeout");
    let path = root.join("codex-scan-index-attribution-test-upload-progress.json");
    let items = test_fingerprints(75);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();

    let first_error = upload_resumable_batches(
        &items,
        poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            if batch == first_page.iter().collect::<Vec<_>>() {
                Ok(accept_fingerprints(batch))
            } else {
                Err(anyhow::Error::new(UploadFailureDiagnostics::for_test(
                    "local snapshot upload",
                    "snapshot_batch",
                    "transport_timeout",
                    true,
                    false,
                )))
            }
        },
        |state| state.save_fixture(&path),
    )
    .expect_err("persistent timeout stops after checkpointing the first page");

    assert!(is_snapshot_batch_split_failure(&first_error));
    assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
    let mut resumed = SnapshotUploadProgress::load(
        &path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("reload progress");
    assert_eq!(resumed.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);

    let mut resumed_accepted = 0;
    let mut resumed_items = Vec::new();
    let result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut resumed,
        &mut resumed_accepted,
        String::as_str,
        |batch| {
            resumed_items.extend(batch.iter().copied().cloned());
            Ok(accept_fingerprints(batch))
        },
        |state| state.save_fixture(&path),
    )
    .expect("restart uploads only remaining pages");

    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(resumed_accepted, 25);
    assert_eq!(resumed_items, items[SNAPSHOT_BATCH_LIMIT..]);
    assert!(resumed_items
        .iter()
        .all(|fingerprint| !first_page.contains(fingerprint)));
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn gateway_timeout_bisection_converges_from_entity_cursor_after_ambiguous_commit() {
    let poison_scope = &unique_poison_scope();
    let root = test_dir("snapshot-upload-gateway-timeout-cursor");
    let path = root.join("claude-scan-index-v3-upload-progress.json");
    let items = test_fingerprints(SNAPSHOT_BATCH_LIMIT);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let mut attempts = Vec::new();
    let mut remotely_held = BTreeSet::new();

    let result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut progress,
        &mut accepted,
        String::as_str,
        |batch| {
            attempts.push(batch.len());
            if batch.len() == SNAPSHOT_BATCH_LIMIT {
                // A gateway timeout does not prove whether the backend
                // committed. Model the ambiguous side as committed: the
                // smaller retries must remain idempotent at entity grain.
                remotely_held.extend(batch.iter().copied().cloned());
                return Err(anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
                    "local snapshot upload",
                    "snapshot_batch",
                    504,
                    true,
                )));
            }
            for fingerprint in batch {
                assert!(
                    !remotely_held.insert((*fingerprint).clone()),
                    "a smaller retry may revisit a held entity but cannot mint a second one"
                );
            }
            Ok(accept_fingerprints(batch))
        },
        |state| state.save_fixture(&path),
    )
    .expect("gateway timeout is bisected into resumable child pages");

    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(
        attempts,
        vec![
            SNAPSHOT_BATCH_LIMIT,
            SNAPSHOT_BATCH_LIMIT / 2,
            SNAPSHOT_BATCH_LIMIT - (SNAPSHOT_BATCH_LIMIT / 2),
        ]
    );
    assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
    assert_eq!(remotely_held.len(), SNAPSHOT_BATCH_LIMIT);
    assert_eq!(progress.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);

    let mut resumed = SnapshotUploadProgress::load(
        &path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .expect("reload entity-grain upload cursor");
    let mut resumed_accepted = 0;
    let mut resumed_upload_calls = 0;
    let resumed_result = upload_resumable_batches(
        &items,
        poison_scope,
        &mut resumed,
        &mut resumed_accepted,
        String::as_str,
        |_| {
            resumed_upload_calls += 1;
            panic!("already accepted page must not be uploaded")
        },
        |state| state.save_fixture(&path),
    )
    .expect("restart settles entirely from the durable entity cursor");

    assert_eq!(resumed_result, ResumableUploadResult::Completed);
    assert_eq!(resumed_upload_calls, 0);
    assert_eq!(resumed_accepted, 0);
    assert_eq!(remotely_held.len(), SNAPSHOT_BATCH_LIMIT);
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

#[test]
fn backfill_finalization_is_idempotent_across_index_state_and_progress_crashes() {
    let poison_scope = &unique_poison_scope();
    let root = test_dir("snapshot-backfill-finalization-crash");
    let index_path = root.join("pi-scan-index-v3.json");
    let progress_path = root.join("pi-upload-progress-v2.json");
    let destination = format!("{:064x}", 77);
    let fingerprint = format!("{:064x}", 78);

    // This is the exact first durable boundary in the production order: a
    // complete replay has uploaded, and its destination index is saved,
    // while the historical completion marker and ledger clear have not run.
    let mut index = ScanIndex::default();
    index
        .save_fixture(&index_path)
        .expect("save completed replay index");
    let mut progress = SnapshotUploadProgress::new(
        destination.clone(),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    );
    progress.record([fingerprint.as_str()]);
    progress
        .save_fixture(&progress_path)
        .expect("save accepted replay ledger");
    assert!(
        pending_backfill_sources_for_destination(&load_backfill_state(&root), &destination)
            .contains(&SnapshotSource::Pi)
    );

    // A restart before the marker save re-derives the same entity but the
    // accepted ledger makes the network portion a no-op.
    let mut resumed = SnapshotUploadProgress::load(
        &progress_path,
        &destination,
        snapshot_quarantine_witness(SnapshotSource::Pi),
    )
    .expect("reload accepted replay ledger");
    let mut accepted = 0;
    let mut upload_calls = 0;
    let result = upload_resumable_batches(
        std::slice::from_ref(&fingerprint),
        poison_scope,
        &mut resumed,
        &mut accepted,
        String::as_str,
        |_| {
            upload_calls += 1;
            panic!("already accepted replay must not be uploaded")
        },
        |state| state.save_fixture(&progress_path),
    )
    .expect("restart settles from the durable accepted ledger");
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(accepted, 0);
    assert_eq!(upload_calls, 0);

    let mut state = load_backfill_state(&root);
    mark_backfill_complete_for_destination(&mut state, SnapshotSource::Pi, &destination);
    save_backfill_state(&root, &state).expect("save replay completion marker");
    resumed.clear(&progress_path).expect("clear final ledger");
    assert!(
        !pending_backfill_sources_for_destination(&load_backfill_state(&root), &destination)
            .contains(&SnapshotSource::Pi)
    );
    assert!(!progress_path.exists());
    ScanIndex::load(&index_path).expect("completed replay index remains durable");
    let _ = std::fs::remove_dir_all(root);
    crate::snapshots::state_v2::close_removed_routes_for_test();
}
