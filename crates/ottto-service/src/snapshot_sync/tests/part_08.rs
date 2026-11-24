pub(super) mod permanent_finish_pipeline_tests {
    include!("permanent_finish_pipeline_tests.rs");
}
mod reason_reoffer_tests {
    include!("reason_reoffer_tests.rs");
}
mod authority_proof_correction_pipeline_tests {
    include!("authority_proof_correction_pipeline_tests.rs");
}
mod load_containment_tests {
    include!("load_containment_tests.rs");
}
#[test]
fn codex_union_native_transport_common_ack_crash_checkpoint_and_restart() {
    codex_union_native_transport_restart(false, false);
}
#[test]
fn codex_union_native_transport_priority_capture_survives_pre_post_and_ack_crashes() {
    codex_union_native_transport_restart(true, false);
}
#[test]
fn codex_union_native_transport_standard_ack_crash_member_loss_holds() {
    codex_union_native_transport_restart(false, true);
}
#[test]
fn codex_union_capture_failure_holds_only_protected_group_and_preserves_cas() {
    for priority in [false, true] {
        for failure in ["io", "cas", "authority", "source"] {
            let root = crate::snapshots::native_join_fixture_root(priority);
            let healthy = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
            let text = std::fs::read_to_string(root.join("sessions/a.jsonl"))
                .unwrap()
                .replace("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", healthy);
            std::fs::write(root.join("sessions/c.jsonl"), text).unwrap();
            let index_path = root.join("index.json");
            let progress_path = root.join("progress.json");
            let mut committed = ScanIndex::default();
            committed
                .save_fixture_for_source(&index_path, SnapshotSource::Codex)
                .unwrap();
            let mut working = committed.clone();
            let mut result = prepare_codex_union_fixture(&root, &mut working);
            assert_eq!(result.snapshots.len(), 3);
            let before = std::fs::read(&index_path).unwrap();
            let mut save_path = index_path.clone();
            match failure {
                "io" => {
                    save_path = root.join("directory.json");
                    std::fs::create_dir(&save_path).unwrap();
                }
                "cas" => {
                    let mut concurrent = committed.clone();
                    concurrent.save_fixture(&index_path).unwrap();
                }
                "source" => std::fs::write(root.join("sessions/b.jsonl"), "changed\n").unwrap(),
                _ => {}
            }
            let exact_disk = std::fs::read(&index_path).unwrap();
            capture_codex_recovery_evidence(
                &mut working,
                &mut committed,
                &mut result,
                &save_path,
                &progress_path,
                || {
                    anyhow::ensure!(failure != "authority", "synthetic authority changed");
                    Ok(())
                },
            );
            assert_eq!(result.snapshots.len(), 1);
            assert_eq!(result.snapshots[0].source_session_id, healthy);
            assert!(!result.census_complete);
            assert_eq!(result.ownership_incomplete_file_count, 2);
            assert!(serde_json::to_value(&working).unwrap()["traversal"]
                ["unhealthy_retry_not_before_unix_seconds"]
                .is_number());
            assert!(committed.files.is_empty());
            assert_eq!(
                working.files.len(),
                1,
                "only healthy member can be checkpointed"
            );
            assert_eq!(std::fs::read(&index_path).unwrap(), exact_disk);
            if failure != "cas" {
                assert_eq!(exact_disk, before);
            }
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
#[test]
// A rejected entity records Poisoned in the shared client_report counters.
#[serial(client_report)]
fn codex_union_native_transport_partial_rejection_keeps_capture_and_quarantine_gate() {
    for priority in [false, true] {
        let root = crate::snapshots::native_join_fixture_root(priority);
        let healthy_owner = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let text = std::fs::read_to_string(root.join("sessions/a.jsonl"))
            .unwrap()
            .replace("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", healthy_owner);
        std::fs::write(root.join("sessions/c.jsonl"), text).unwrap();
        let index_path = root.join("index.json");
        let progress_path = root.join("progress.json");
        let mut baseline = ScanIndex::default();
        baseline
            .save_fixture_for_source(&index_path, SnapshotSource::Codex)
            .unwrap();
        let mut working = baseline.clone();
        let mut result = prepare_codex_union_fixture(&root, &mut working);
        capture_codex_recovery_evidence(
            &mut working,
            &mut baseline,
            &mut result,
            &index_path,
            &progress_path,
            || Ok(()),
        );
        assert_eq!(result.snapshots.len(), 3);
        let rejected = result
            .snapshots
            .iter()
            .find(|item| item.source_session_id != healthy_owner)
            .unwrap();
        let healthy = result
            .snapshots
            .iter()
            .find(|item| item.source_session_id == healthy_owner)
            .unwrap();
        let accepted = same_source_fixture_ack(&[healthy]).unwrap();
        let entity = &accepted.accepted_entities[0];
        let ack = serde_json::json!({"accepted":1,"sessions_reconciled":1,"session_ids":[],
        "disabled":false,"disabled_reason":null,"entity_ack_contract":"snapshot_entity_ack:v1",
        "accepted_entities":[{"source_session_id":entity.source_session_id,"snapshot_fingerprint":entity.snapshot_fingerprint,
            "occurrence_count":1,"body_witness_version":entity.body_witness_version,"body_witness_digest":entity.body_witness_digest}],
        "unchanged_entities":[],"conflict_entities":[],"rejected_entities":[{
            "source_session_id":rejected.source_session_id,"snapshot_fingerprint":rejected.snapshot_fingerprint,
            "reason":"invalid","detail":"synthetic rejection","permanent":true,"occurrence_count":1}]}).to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_complete_http_request(&mut stream);
            let payload: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(payload["snapshots"].as_array().unwrap().len(), 2);
            bounded_native_response(&mut stream, "200 OK", &ack);
        });
        let mut progress = test_upload_progress();
        let mut accepted_count = 0;
        let outcome = upload_resumable_batches_with_body_witness(
            &result.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted_count,
            |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |snapshots| {
                client.upload_batch(
                    "synthetic-relay",
                    &SnapshotBatchRequest {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        source: "codex".into(),
                        machine_id: "machine".into(),
                        collector_version: Some(collector_version()),
                        snapshots: snapshots.to_vec(),
                        upload_policy: SnapshotUploadPolicy::default(),
                        client_report: crate::client_report::ClientReport::empty(),
                    },
                    false,
                )
            },
            |progress| progress.save_fixture(&progress_path),
        )
        .unwrap();
        assert_eq!(outcome, ResumableUploadResult::Rejected { count: 1 });
        server.join().unwrap();
        assert_eq!(accepted_count, 1);
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        let committed = checkpoint_partial_snapshot_index(
            &working,
            &baseline,
            &progress,
            &result.snapshots,
            None,
            &BTreeSet::new(),
            &index_path,
            &progress_path,
            || {
                result
                    .codex_joining_validator()
                    .unwrap()
                    .validate(&result.snapshots)
            },
        )
        .unwrap();
        assert_eq!(committed.files.len(), 3);
        assert_eq!(
            committed
                .files
                .values()
                .filter(|entry| entry.codex_captured_tier_receipt_required
                    && entry.codex_captured_uncommitted
                    && entry.codex_applied_tier_receipt.is_none())
                .count(),
            usize::from(priority)
        );
        if priority {
            crate::snapshots::older_build_logs_expired();
        }
        let mut loaded = ScanIndex::load(&index_path).unwrap();
        let quiet = prepare_codex_union_fixture(&root, &mut loaded);
        assert!(quiet.snapshots.is_empty());
        assert!(
            quiet.semantic_noop_count >= 2,
            "native quarantine holds both aliases"
        );
        assert!(
            quiet.scanned_session_count <= 1,
            "quarantined group must not be replayed"
        );
        assert_eq!(
            loaded
                .files
                .values()
                .filter(|entry| entry.codex_captured_uncommitted)
                .count(),
            2
        );
        std::fs::remove_dir_all(root).unwrap();
        crate::snapshots::state_v2::close_removed_routes_for_test();
    }
}
mod codex_counting_lifecycle_tests {
    include!("codex_counting_lifecycle_tests.rs");
}
fn prepare_codex_union_fixture(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        3,
    )
    .unwrap();
    index.bind_session_accounts(SnapshotSource::Codex, "machine", &mut scan.snapshots, &[]);
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    for item in &mut scan.snapshots {
        prepare_snapshot_cache_for_upload(item, &test_upload_progress(), false, false);
    }
    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, index);
    scan
}
fn codex_union_native_transport_restart(priority: bool, lose_member_after_ack: bool) {
    let root = crate::snapshots::native_join_fixture_root(priority);
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    let receipt_dir = root.canonicalize().unwrap().join("receipts");
    let mut baseline = ScanIndex::default();
    baseline.save_fixture(&index_path).unwrap();
    let prepare = |index: &mut ScanIndex| prepare_codex_union_fixture(&root, index);
    let mut working = baseline.clone();
    let mut result = prepare(&mut working);
    assert_eq!(result.snapshots.len(), 2);
    let fingerprints = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    if priority {
        assert!(result.snapshots.iter().all(|item| item
            .model_usage
            .iter()
            .filter(
                |row| row.selector_context.get("service_tier").map(String::as_str)
                    == Some("priority")
            )
            .map(|row| row.input_tokens)
            .sum::<u64>()
            == 200));
        capture_codex_recovery_evidence(
            &mut working,
            &mut baseline,
            &mut result,
            &index_path,
            &progress_path,
            || Ok(()),
        );
        let captured = ScanIndex::load(&index_path).unwrap();
        assert_eq!(
            captured.files.len(),
            2,
            "all joined aliases must be captured before POST"
        );
        assert!(captured
            .files
            .values()
            .all(|entry| entry.codex_captured_uncommitted
                && entry.codex_captured_joined_member_set.is_some()
                && entry.last_snapshot_fingerprint.is_none()
                && entry.last_upload_body_witness.is_none()
                && entry.codex_joined_member_set.is_none()
                && entry.codex_applied_tier_receipt.is_none()));
        assert!(captured.current_snapshot_fingerprints().is_empty());
        crate::snapshots::older_build_logs_expired();
        // Crash after capture, before POST: the capture must retain the old
        // selector without advancing membership or suppressing this upload.
        working = captured;
        result = prepare(&mut working);
        assert_eq!(result.snapshots.len(), 2);
        assert_eq!(
            result
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect::<BTreeSet<_>>(),
            fingerprints
        );
        capture_codex_recovery_evidence(
            &mut working,
            &mut baseline,
            &mut result,
            &index_path,
            &progress_path,
            || Ok(()),
        );
    }
    if !priority {
        capture_codex_recovery_evidence(
            &mut working,
            &mut baseline,
            &mut result,
            &index_path,
            &progress_path,
            || Ok(()),
        );
    }
    let validator = result.codex_joining_validator().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
        .with_receipt_state_dir(&receipt_dir);
    let representative = &result.snapshots[0];
    let version = match crate::snapshots::snapshot_upload_body_witness_version(representative) {
        Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_SESSION_ACCOUNT_VERSION) => {
            Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_SESSION_ACCOUNT_VERSION)
        }
        Some(
            crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_SESSION_ACCOUNT_VERSION,
        ) => Some(
            crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_EXCLUSIVE_SESSION_ACCOUNT_VERSION,
        ),
        None
        | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION)
        | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION) => None,
        other => panic!("unexpected synthetic union body witness {other:?}"),
    };
    let ack = serde_json::json!({"accepted":1,"sessions_reconciled":1,"session_ids":[],"disabled":false,
        "disabled_reason":null,"entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[{
            "source_session_id":representative.source_session_id,"snapshot_fingerprint":representative.snapshot_fingerprint,
            "occurrence_count":1,"body_witness_version":version,"body_witness_digest":snapshot_upload_body_witness(representative)}],
        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]}).to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_complete_http_request(&mut stream);
        let payload: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            payload["snapshots"].as_array().unwrap().len(),
            1,
            "transport sends one common body"
        );
        assert_eq!(payload["snapshots"][0]["input_tokens"], 300);
        bounded_native_response(&mut stream, "200 OK", &ack);
        request
    });
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &result.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |snapshots| {
            validator.validate(snapshots)?;
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "codex".into(),
                machine_id: "machine".into(),
                collector_version: Some(collector_version()),
                snapshots: snapshots.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            client.upload_batch("synthetic-relay", &request, false)
        },
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    assert!(matches!(outcome, ResumableUploadResult::Completed));
    assert_eq!(accepted, 1);
    server.join().unwrap();
    assert!(!crate::upload_receipts::read(&receipt_dir, 500, None, None)
        .unwrap()
        .receipts
        .is_empty());
    if lose_member_after_ack {
        std::fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
        let usage = serde_json::json!({"input_tokens":100,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":100});
        let after = serde_json::json!({"input_tokens":400,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":400});
        let rows = [
            serde_json::json!({"type":"token_usage_record","timestamp":"2026-10-01T10:04:00Z","payload":{"thread_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","response_id":"after-ack-late","usage":usage,"thread_token_usage":after}}),
            serde_json::json!({"type":"event_msg","timestamp":"2026-10-01T10:04:01Z","payload":{"type":"token_count","info":{"last_token_usage":usage,"total_token_usage":after}}}),
        ];
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(root.join("sessions/a.jsonl"))
            .unwrap();
        for row in rows {
            writeln!(file, "{}", serde_json::to_string(&row).unwrap()).unwrap();
        }
        drop(file);
        let mut loaded = ScanIndex::load(&index_path).unwrap();
        let held = prepare(&mut loaded);
        assert!(held.snapshots.is_empty(), "durable standard-tier ACK must not permit a smaller replacement after loss before index promotion: {:?}", held.snapshots.iter().map(|item| item.input_tokens).collect::<Vec<_>>());
        assert!(!held.census_complete);
        std::fs::remove_dir_all(root).unwrap();
        crate::snapshots::state_v2::close_removed_routes_for_test();
        return;
    }
    let before_promotion = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        before_promotion.files.len(),
        2,
        "ACK never promotes the index on its own"
    );
    assert!(before_promotion.current_snapshot_fingerprints().is_empty());
    let mut restarted_index = ScanIndex::load(&index_path).unwrap();
    let mut restarted = prepare(&mut restarted_index);
    capture_codex_recovery_evidence(
        &mut restarted_index,
        &mut baseline,
        &mut restarted,
        &index_path,
        &progress_path,
        || Ok(()),
    );
    assert_eq!(
        restarted
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>(),
        fingerprints
    );
    let mut restarted_progress = SnapshotUploadProgress::load(
        &progress_path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    let resumed = upload_resumable_batches_with_body_witness(
        &restarted.snapshots,
        &unique_poison_scope(),
        &mut restarted_progress,
        &mut 0,
        |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| panic!("durable common ACK must suppress a repeated POST"),
        |progress| progress.save_fixture(&progress_path),
    )
    .unwrap();
    assert!(matches!(resumed, ResumableUploadResult::Completed));
    let committed = checkpoint_partial_snapshot_index(
        &restarted_index,
        &baseline,
        &restarted_progress,
        &restarted.snapshots,
        None,
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || {
            restarted
                .codex_joining_validator()
                .unwrap()
                .validate(&restarted.snapshots)
        },
    )
    .unwrap();
    assert_eq!(committed.files.len(), 2);
    assert!(committed
        .files
        .values()
        .all(|entry| !entry.codex_captured_uncommitted
            && entry.codex_captured_joined_member_set.is_none()
            && !entry.codex_captured_tier_receipt_required
            && entry.codex_captured_tier_receipt.is_none()));
    assert_eq!(
        committed
            .files
            .values()
            .filter(|entry| entry.codex_applied_tier_receipt_required)
            .count(),
        usize::from(priority)
    );
    let mut loaded = ScanIndex::load(&index_path).unwrap();
    let quiet = prepare(&mut loaded);
    assert!(quiet.snapshots.is_empty());
    assert_eq!(quiet.semantic_noop_count, 2);
    std::fs::remove_dir_all(root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}

fn same_source_fixture_ack(
    items: &[&SnapshotItem],
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    integrated_ack(&SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    })
}

/// The fixture ACK on the production head-CAS contract: a cache-bearing
/// body or a CAS stage is acknowledged with `head` under its public body
/// witness version, and validated as the source upload validates it.
fn head_cas_fixture_ack(
    items: &[&SnapshotItem],
    enforce_head_cas: bool,
    head: &str,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let headed = enforce_head_cas
        || request
            .snapshots
            .iter()
            .any(|item| item.cache_observations.is_some());
    let entities = request
        .snapshots
        .iter()
        .map(|item| {
            let version = crate::snapshot_client::snapshot_ack_body_witness_version(item)?;
            // As the backend's entity ACK does, the digest travels only with
            // a witness version.
            Ok(serde_json::json!({
                "source_session_id": item.source_session_id,
                "snapshot_fingerprint": item.snapshot_fingerprint,
                "occurrence_count": 1,
                "body_witness_version": version,
                "body_witness_digest": version.map(|_| snapshot_upload_body_witness(item)),
                "head_etag": headed.then_some(head),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let response: crate::snapshot_client::SnapshotBatchResponse =
        serde_json::from_value(serde_json::json!({
            "accepted": entities.len(), "sessions_reconciled": entities.len(),
            "session_ids": [], "disabled": false, "disabled_reason": null,
            "entity_ack_contract": crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
            "accepted_entities": entities
        }))?;
    response.validate_entity_ack_with_head_cas(&request, enforce_head_cas)?;
    Ok(response)
}

// Offline candidate at the existing post-policy source/page boundary.
// It never receives an active parser/index borrow or an arbitrary disk merge.
struct SameSourceAckFixture {
    root: PathBuf,
    index_path: PathBuf,
    progress_path: PathBuf,
    baseline: ScanIndex,
    working: ScanIndex,
    items: Vec<SnapshotItem>,
    progress: SnapshotUploadProgress,
    keys: Vec<String>,
}
impl SameSourceAckFixture {
    fn new() -> Self {
        let root = cache_effective_wire_fixture_root();
        let first = "00000000-0000-7000-8000-000000000001";
        let first_path = root.join(format!("rollout-2026-09-30T10-00-00-{first}.jsonl"));
        let text = std::fs::read_to_string(&first_path).unwrap();
        for n in [2, 3] {
            let id = format!("00000000-0000-7000-8000-{n:012}");
            std::fs::write(
                root.join(format!("rollout-2026-09-30T10-00-00-{id}.jsonl")),
                text.replace(first, &id)
                    .replace("resp_effective_wire", &format!("resp_boundary_{n}")),
            )
            .unwrap();
        }
        let index_path = root.join("boundary-index.json");
        let progress_path = root.join("boundary-progress.json");
        let (mut baseline, mut working, mut progress) = Self::fresh_state(&root);
        baseline
            .save_fixture_for_source(&index_path, SnapshotSource::Codex)
            .unwrap();
        let mut items = Self::prepare(&root, &mut working, None).snapshots;
        items.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        assert_eq!(items.len(), 3);
        // The page's receipt candidates, taken after preparation and before
        // upload as the source pass does; each checkpoint accepts them.
        progress.context_receipt_candidates =
            working.file_upload_context_ack_candidates(&items, &BTreeMap::new());
        let keys = items
            .iter()
            .map(|item| {
                working
                    .file_snapshot_fingerprints
                    .iter()
                    .find(|(_, fps)| fps.contains(&item.snapshot_fingerprint))
                    .unwrap()
                    .0
                    .clone()
            })
            .collect();
        let mut f = Self {
            root,
            index_path,
            progress_path,
            baseline,
            working,
            items,
            progress,
            keys,
        };
        // C is an already accepted native file/sibling before this active prepared pass.
        f.send(2, same_source_fixture_ack).unwrap();
        f.checkpoint_boundary(|| Ok(())).unwrap();
        assert_eq!(f.baseline.files.len(), 1);
        assert!(f.baseline.files.contains_key(&f.keys[2]));
        f
    }
    /// The fixture's upload context, fingerprint-shaped as the ledger requires.
    fn context() -> String {
        format!("{:x}", Sha256::digest(b"boundary-current-policy"))
    }
    /// `cache` keeps the scanned cache evidence and finalizes with the source
    /// pass's effective (projected) body witness; `None` strips it.
    fn prepare(
        root: &Path,
        index: &mut ScanIndex,
        cache: Option<&SnapshotUploadProgress>,
    ) -> SourceScanResult {
        index.activate_upload_context(Self::context());
        index.activate_effective_upload_body_witness_revision(1);
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            &[root.to_path_buf()],
            index,
            "2026-09-30T10:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
        )
        .unwrap();
        for item in &mut scan.snapshots {
            if cache.is_none() {
                item.cache_observations = None;
                item.cache_observations_state = None;
            }
            item.session_account_evidence = None;
        }
        let Some(progress) = cache else {
            finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, index);
            return scan;
        };
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::Codex,
            &mut scan,
            index,
            |item| {
                effective_snapshot_upload_body_witness(
                    item,
                    progress,
                    true,
                    false,
                    &crate::snapshots::ClaudeUsageAuthorityDisposition::default(),
                )
            },
        );
        scan
    }
    fn send(
        &mut self,
        slot: usize,
        upload: impl FnMut(&[&SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    ) -> Result<SnapshotPageOutcome> {
        // Preserve the caller's canonical pending-page selection predicate.
        // The extracted attempt helper assumes selected indices are pending.
        // Do not invoke the whole resumable uploader on this one-item subset:
        // its cycle inventory pruning would discard accepted sibling ACKs.
        let item = &self.items[slot];
        if self.progress.contains_body(
            &item.snapshot_fingerprint,
            &snapshot_upload_body_witness(item),
        ) {
            return Ok(SnapshotPageOutcome::Settled {
                conflicted: 0,
                isolated: 0,
            });
        }
        attempt_snapshot_page(
            &self.items,
            &[slot],
            &unique_poison_scope(),
            &mut self.progress,
            &mut 0,
            &|i: &SnapshotItem| i.snapshot_fingerprint.as_str(),
            &snapshot_upload_body_witness,
            &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
            &mut { upload },
            &mut |p: &mut SnapshotUploadProgress| p.save_fixture(&self.progress_path),
        )
    }
    fn checkpoint_boundary(&mut self, authority: impl FnOnce() -> Result<()>) -> Result<usize> {
        let checkpoint = checkpoint_partial_snapshot_index(
            &self.working,
            &self.baseline,
            &self.progress,
            &self.items,
            None,
            &BTreeSet::new(),
            &self.index_path,
            &self.progress_path,
            authority,
        )?;
        assert_eq!(checkpoint.generation, self.baseline.generation + 1);
        let affected = checkpoint
            .files
            .iter()
            .filter(|(key, entry)| {
                self.baseline
                    .files
                    .get(*key)
                    .map(|old| serde_json::to_value(old).unwrap())
                    != Some(serde_json::to_value(entry).unwrap())
            })
            .count();
        // Adopt only the exact canonical checkpoint derived from this prepared
        // working/baseline pair under progress lock+index CAS. Never fast-forward
        // from an arbitrary reloaded generation. No staged file map is replaced.
        self.working.generation = checkpoint.generation;
        self.working.mark_bounded_sweep_unsettled();
        self.baseline = checkpoint;
        Ok(affected)
    }
    /// Reload as a restarted pass; returns the ordinary scan's counts.
    fn restart_preparation(&mut self) -> SourceScanResult {
        self.restart(false)
    }
    fn restart(&mut self, keep_cache: bool) -> SourceScanResult {
        self.baseline = ScanIndex::load(&self.index_path).unwrap();
        self.working = self.baseline.clone();
        self.progress = SnapshotUploadProgress::load(
            &self.progress_path,
            &self.progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        self.progress
            .prepare_historical_replay("boundary-pending-replay");
        activate_source_upload_context(
            SnapshotSource::Codex,
            Self::context(),
            &mut self.working,
            &mut self.progress,
        );
        let cache = keep_cache.then_some(&self.progress);
        let mut scan = Self::prepare(&self.root, &mut self.working, cache);
        self.items = std::mem::take(&mut scan.snapshots);
        self.items
            .sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        self.progress.context_receipt_candidates = self
            .working
            .file_upload_context_ack_candidates(&self.items, &BTreeMap::new());
        scan
    }
    /// A cold Full of this root: a fresh index, scanned as `new` scans it.
    fn cold_full(&self, keep_cache: bool) -> Vec<SnapshotItem> {
        Self::cold_full_of(&self.root, keep_cache)
    }
    /// A fresh baseline index, then the working index and ledger with the
    /// upload context bound first, as the source pass binds it.
    fn fresh_state(root: &Path) -> (ScanIndex, ScanIndex, SnapshotUploadProgress) {
        let mut baseline = ScanIndex::default();
        baseline.prepare_historical_replay("boundary-pending-replay".into());
        let mut working = baseline.clone();
        let mut progress = test_upload_progress();
        progress.destination_namespace_hash =
            format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()));
        progress.prepare_historical_replay("boundary-pending-replay");
        activate_source_upload_context(
            SnapshotSource::Codex,
            Self::context(),
            &mut working,
            &mut progress,
        );
        (baseline, working, progress)
    }
    fn cold_full_of(root: &Path, keep_cache: bool) -> Vec<SnapshotItem> {
        let (_, mut index, progress) = Self::fresh_state(root);
        let mut items = Self::prepare(root, &mut index, keep_cache.then_some(&progress)).snapshots;
        items.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        items
    }
    fn stable_context(index: &ScanIndex) {
        let value = serde_json::to_value(index).unwrap();
        assert!(value["upload_context_fingerprint"].is_null());
        assert!(value["completed_context_curve_replay_generation"].is_null());
        assert_eq!(
            value["historical_replay_generation"],
            "boundary-pending-replay"
        );
        assert_eq!(value["bounded_sweep_had_unsettled_upload"], true);
    }
}
/// The transition oracle's view of `items` sent as one Codex batch.
fn codex_route(
    mode: crate::snapshots::sampled_scan::transition_fixture::Mode,
    items: &[SnapshotItem],
) -> crate::snapshots::sampled_scan::transition_fixture::RouteResult {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "codex".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    crate::snapshots::sampled_scan::transition_fixture::RouteResult::emitted(
        mode,
        SnapshotSource::Codex,
        vec![serde_json::to_vec(&request).unwrap()],
        items,
    )
}
/// Money totals and account placement of `actual` equal `cold`, per entity.
fn assert_same_money(
    cold: &crate::snapshots::sampled_scan::transition_fixture::RouteResult,
    actual: &crate::snapshots::sampled_scan::transition_fixture::RouteResult,
) {
    use crate::snapshots::sampled_scan::transition_fixture::money_oracle;
    money_oracle::assert_placement_equivalent(cold, actual);
    let mut differences = Vec::new();
    money_oracle::entity_differences(cold, actual, &mut differences);
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}
impl Drop for SameSourceAckFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// [money] Progress past the former 11,182,080 B ACK custody bound, on a
/// mixed logical page: headless T (items[0]) and already-headed S
/// (items[1], no pending head). Settled off-page history (phase 1) and
/// live pending-head evidence (phase 2) are both kept: the batch or the
/// bootstrap probe posts once, no cache state or head is pruned, and the
/// receipt carries the exact saved ledger. Each arm posts the same bodies
/// and settles the same ACK ledger as a cold ledger (phase 0), and the
/// receiver's bodies carry the money totals and account placement of a
/// cold Full of the root (transition oracle). In phase 1, C (accepted
/// before this page and settled, with real cache observations) then grows:
/// the ordinary scan re-reads it once, its retained head rides the
/// head-CAS body with no bootstrap probe, and the repeated event ids leave
/// money and placement equal to a cold Full.
#[test]
#[serial]
fn v2_progress_above_old_bound_uploads_receipts_and_recovers_exactly() {
    use crate::snapshots::sampled_scan::transition_fixture::Mode;
    let event_ids = |state: &serde_json::Value| {
        state["observations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["event_id"].as_str().map(str::to_string))
            .collect::<BTreeSet<_>>()
    };
    // C's growth: a cache break (share 0.9 -> 0), which the detector
    // records as an observation.
    let grow = |path: &Path| {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        for row in [
            serde_json::json!({"type":"token_usage_record","timestamp":"2026-09-30T10:00:02Z","payload":{"response_id":"resp_reopened","usage":{"input_tokens":120000,"cached_input_tokens":0,"output_tokens":2}}}),
            serde_json::json!({"type":"event_msg","timestamp":"2026-09-30T10:00:02Z","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":220000,"cached_input_tokens":90000,"output_tokens":3},"last_token_usage":{"input_tokens":120000,"cached_input_tokens":0,"output_tokens":2}}}}),
        ] {
            std::io::Write::write_all(&mut file, format!("{row}\n").as_bytes()).unwrap();
        }
    };
    let headed =
        |items: &[&SnapshotItem]| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
            let mut response = same_source_fixture_ack(items)?;
            for entity in &mut response.accepted_entities {
                entity.head_etag = Some("e".repeat(64));
            }
            Ok(response)
        };
    let observations = crate::snapshots::cache_observations::CacheObservations {
        schema_version: 1,
        operations: Vec::new(),
        coverage: "complete".into(),
        omitted_observation_count: None,
        full_replacement: false,
    };
    let mut cold = BTreeMap::new();
    for (phase, bootstrap) in [
        (0, false),
        (0, true),
        (1, false),
        (1, true),
        (2, false),
        (2, true),
    ] {
        let mut f = SameSourceAckFixture::new();
        if bootstrap {
            let item = &f.items[0];
            f.progress.record_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(item),
            );
        }
        // C was accepted before this page: settled history, not on it.
        let c = cache_session_key(&f.items[2].source_session_id);
        // C's accepted cache state with real observations: a cold scan of
        // a copy of C's file grown with the same rows the reopen adds.
        let c_path = std::fs::read_dir(&f.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.to_string_lossy()
                    .ends_with(&format!("{}.jsonl", f.items[2].source_session_id))
            })
            .unwrap();
        let c_state = {
            let copy = std::env::temp_dir()
                .join(format!("ottto-ack-bound-c-copy-{}", unique_poison_scope()));
            std::fs::create_dir_all(&copy).unwrap();
            let copied = copy.join(c_path.file_name().unwrap());
            std::fs::copy(&c_path, &copied).unwrap();
            grow(&copied);
            let scanned = SameSourceAckFixture::cold_full_of(&copy, true);
            std::fs::remove_dir_all(&copy).unwrap();
            crate::snapshots::state_v2::close_removed_routes_for_test();
            let patch = scanned
                .iter()
                .find(|item| item.source_session_id == f.items[2].source_session_id)
                .and_then(|item| item.cache_observations.as_ref())
                .expect("C carries a cache patch");
            crate::snapshots::cache_state_from_patch(None, patch).unwrap()
        };
        assert!(!event_ids(&c_state).is_empty(), "non-empty observations");
        f.progress
            .accepted_cache_states
            .insert(c.clone(), c_state.clone());
        f.progress
            .accepted_cache_heads
            .insert(c.clone(), "c".repeat(64));
        let c_entry = serde_json::to_value(&f.baseline.files[&f.keys[2]]).unwrap();
        let c_item = f.items.pop().unwrap();
        // S is already headed with settled state and no pending head.
        let s = cache_session_key(&f.items[1].source_session_id);
        f.progress.accepted_cache_states.insert(
            s.clone(),
            serde_json::json!({"observations":[], "value":"s"}),
        );
        f.progress
            .accepted_cache_heads
            .insert(s.clone(), "d".repeat(64));
        // Reachable cumulative cache evidence; each record stays below 128 KiB.
        let sessions = (0..if phase == 0 { 0 } else { 115 })
            .map(|n| format!("old-{n}"))
            .collect::<Vec<_>>();
        for session in &sessions {
            f.progress.accepted_cache_states.insert(
                cache_session_key(session),
                serde_json::json!({"observations":[], "value":"x".repeat(100_000)}),
            );
            f.progress
                .accepted_cache_heads
                .insert(cache_session_key(session), "f".repeat(64));
        }
        // Pending head obligations mark sessions live: one in phase 1, all in 2.
        // Identifiers are fingerprint-shaped, as the progress loader requires.
        let live = if phase == 1 {
            &sessions[..1]
        } else {
            &sessions[..]
        };
        if !live.is_empty() {
            f.progress.pending_cache_heads.insert(
                cache_session_key("pending-file"),
                PendingCacheHeadFile {
                    source_file_fingerprint: cache_session_key("pending-source"),
                    group_fingerprint: cache_session_key("pending-group"),
                    entities: live
                        .iter()
                        .map(|session| {
                            (
                                cache_session_key(&format!("entity-{session}")),
                                cache_session_key(session),
                            )
                        })
                        .collect(),
                    reselected_heads: BTreeMap::new(),
                    settled_entities: BTreeSet::new(),
                },
            );
        }
        f.progress.save_fixture(&f.progress_path).unwrap();
        let bytes = std::fs::read(&f.progress_path).unwrap();
        assert!(
            phase == 0 || bytes.len() > OLD_PROGRESS_BOUND_FOR_TEST,
            "past the former bound"
        );
        let states = f
            .progress
            .accepted_cache_states
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut heads = f.progress.accepted_cache_heads.clone();
        let posts = std::cell::Cell::new(0);
        let sent = std::cell::RefCell::new(Vec::new());
        let sent_items = std::cell::RefCell::new(Vec::new());
        let post = |items: &[&SnapshotItem]| {
            posts.set(posts.get() + 1);
            sent_items
                .borrow_mut()
                .extend(items.iter().copied().cloned());
            sent.borrow_mut().extend(items.iter().map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                )
            }));
        };
        if bootstrap {
            bootstrap_cache_heads_with_budget(
                &f.items[..1],
                &unique_poison_scope(),
                &mut f.progress,
                &mut InplaceRetryBudget::default(),
                |items, _| {
                    post(items);
                    headed(items)
                },
                |progress| progress.save_fixture(&f.progress_path),
            )
            .unwrap();
            // Only T's head is new: the probe's.
            heads.insert(
                cache_session_key(&f.items[0].source_session_id),
                "e".repeat(64),
            );
        } else {
            f.send(0, |items| {
                post(items);
                same_source_fixture_ack(items)
            })
            .unwrap();
        }
        assert_eq!(posts.get(), 1, "one POST, no hold");
        assert!(states
            .iter()
            .all(|key| f.progress.accepted_cache_states.contains_key(key)));
        assert_eq!(f.progress.accepted_cache_heads, heads, "nothing pruned");
        let settled_ledger = |f: &SameSourceAckFixture| {
            let saved = std::fs::read(&f.progress_path).unwrap();
            assert!(phase == 0 || saved.len() > OLD_PROGRESS_BOUND_FOR_TEST);
        };
        settled_ledger(&f);
        if bootstrap {
            // S keeps its projected head; T gets the probe's head.
            let mut page = f.items.clone();
            for item in &mut page[..2] {
                item.cache_observations = Some(observations.clone());
            }
            page[1].cache_base_head_etag = Some("d".repeat(64));
            assert_eq!(
                apply_bootstrapped_cache_heads("codex", &mut page, &f.progress)
                    .unwrap()
                    .len(),
                0
            );
            assert_eq!(page[0].cache_base_head_etag, Some("e".repeat(64)));
            assert_eq!(page[1].cache_base_head_etag, Some("d".repeat(64)));
        }
        // Later transport batches of the same page settle; T's body is
        // already acknowledged by its probe in the bootstrap arm.
        f.send(0, |items| {
            post(items);
            same_source_fixture_ack(items)
        })
        .unwrap();
        f.send(1, |items| {
            post(items);
            same_source_fixture_ack(items)
        })
        .unwrap();
        assert_eq!(posts.get(), 2);
        // Each page body posts exactly once, as a cold Full would send it.
        let mut posted = sent.borrow().clone();
        let mut page = f
            .items
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                )
            })
            .collect::<Vec<_>>();
        posted.sort();
        page.sort();
        assert_eq!(posted, page, "each page body posts exactly once");
        let settled = (
            posted.into_iter().map(|(fp, _)| fp).collect::<Vec<_>>(),
            f.progress.accepted_fingerprints.clone(),
        );
        if phase == 0 {
            cold.insert(bootstrap, settled);
        } else {
            assert_eq!(
                cold[&bootstrap], settled,
                "same POSTs and ACK ledger as a cold ledger"
            );
        }
        // Money totals and account placement equal a cold Full of this
        // root, the receiver holding C's earlier body and this page's.
        let mut eventual = vec![c_item.clone()];
        eventual.extend(sent_items.borrow().iter().cloned());
        assert_same_money(
            &codex_route(Mode::ColdFull, &f.cold_full(false)),
            &codex_route(Mode::Restart, &eventual),
        );
        assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 2);
        assert_eq!(f.baseline.files.len(), 3);
        for item in &f.items {
            assert!(f.progress.contains_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(item)
            ));
        }
        settled_ledger(&f);
        if phase != 1 {
            continue;
        }
        // Quiet restart from the saved checkpoint: accepted bodies stay
        // suppressed until each file is current by its own receipt.
        let saved = std::fs::read(&f.progress_path).unwrap();
        let adopted = |index: &ScanIndex| {
            crate::snapshots::e2_pipeline_scan_fixture::upload_context_unproven_files_for_test(
                index,
            ) == 0
        };
        for _ in 0..3 {
            f.restart_preparation();
            assert!(f.items.is_empty(), "accepted bodies stay suppressed");
            f.working.save_fixture(&f.index_path).unwrap();
            if adopted(&f.working) {
                break;
            }
        }
        assert!(adopted(&f.working));
        // Settled C reopens: its rollout grows and the ordinary scan
        // re-reads only that file into one definite body.
        grow(&c_path);
        let scan = f.restart(true);
        assert_eq!(std::fs::read(&f.progress_path).unwrap(), saved);
        assert_eq!(scan.scanned_file_count, 1, "only the grown source is read");
        assert_eq!(
            f.items.len(),
            1,
            "one definite body for the reopened source"
        );
        assert_eq!(f.items[0].source_session_id, c_item.source_session_id);
        assert_ne!(f.items[0].snapshot_fingerprint, c_item.snapshot_fingerprint);
        assert!(
            f.items[0].cache_observations.is_some(),
            "real cache evidence"
        );
        let reopened_ids = event_ids(
            &crate::snapshots::cache_state_from_patch(
                None,
                f.items[0].cache_observations.as_ref().unwrap(),
            )
            .unwrap(),
        );
        assert!(
            event_ids(&c_state).is_subset(&reopened_ids),
            "the reopened patch repeats C's accepted event ids"
        );
        // Its retained head means no missing-head deferral and no probe.
        assert!(capture_deferred_cache_head_identities(
            SnapshotSource::Codex,
            &f.items,
            &f.progress,
            true,
            true,
            &crate::snapshots::ClaudeUsageAuthorityDisposition::default()
        )
        .is_empty());
        prepare_snapshot_cache_for_upload(&mut f.items[0], &f.progress, true, true);
        assert_eq!(f.items[0].cache_base_head_etag, Some("c".repeat(64)));
        assert!(f.items[0].cache_observations.is_some());
        let reopened = f.items[0].clone();
        f.send(0, |items| {
            post(items);
            head_cas_fixture_ack(items, false, &"a".repeat(64))
        })
        .unwrap();
        assert_eq!(posts.get(), 3, "no bootstrap offers for the retained head");
        // The repeated event ids change neither money nor placement.
        assert_same_money(
            &codex_route(Mode::ColdFull, &f.cold_full(false)),
            &codex_route(Mode::Restart, &sent_items.borrow()),
        );
        assert_eq!(f.progress.accepted_cache_heads[&c], "a".repeat(64));
        assert!(f.progress.contains_body(
            &reopened.snapshot_fingerprint,
            &snapshot_upload_body_witness(&reopened)
        ));
        assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
        assert_ne!(
            serde_json::to_value(&f.baseline.files[&f.keys[2]]).unwrap(),
            c_entry
        );
        assert!(f.baseline.file_snapshot_fingerprints[&f.keys[2]]
            .contains(&reopened.snapshot_fingerprint));
        settled_ledger(&f);
    }
}

/// [money] Placement past the former 11,182,080 B bound: the placement
/// oracle's bodies (two accounts, a mid-session switch, a side call, an
/// evidence gap and a tagged row) are stored-body ACKed into a ledger past
/// the old bound, saved, and restored by a restart after same-account
/// re-logins A→B→C. The restored ledger passes the transition oracle's
/// equivalence and placement assertions against the cold one.
#[test]
fn v2_identity_ledger_above_old_bound_recovers_cold_placement() {
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode};
    let cold = money_oracle::placement_tests::placement_fixture();
    let scratch = crate::test_scratch::ScratchDir::new("v2-placement-above-bound");
    let path = scratch.join("progress.json");
    let mut progress = test_upload_progress();
    progress.accepted_identity_buckets =
        crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
    for n in 0..115 {
        progress.accepted_cache_states.insert(
            cache_session_key(&format!("old-{n}")),
            serde_json::json!({"observations":[], "value":"x".repeat(100_000)}),
        );
    }
    progress.save_fixture(&path).unwrap();
    for snapshot in cold.snapshots.values() {
        progress.record_stored_state(snapshot, None).unwrap();
    }
    progress.save_fixture(&path).unwrap();
    let after = std::fs::read(&path).unwrap();
    assert!(
        after.len() > OLD_PROGRESS_BOUND_FOR_TEST,
        "past the former bound"
    );
    // The restart follows same-account re-logins A→B→C.
    let mut restored = SnapshotUploadProgress::load(
        &path,
        &relogin_namespace(&progress.destination_namespace_hash, 2),
        test_quarantine_witness(),
    )
    .unwrap();
    assert!(std::fs::read(&path).unwrap() == after, "the saved ledger");
    restored
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let ledger = cold
        .snapshots
        .keys()
        .map(|entity| {
            let state = restored
                .accepted_identity_buckets
                .get(entity)
                .expect("recovered entity");
            (entity.clone(), serde_json::to_value(state).unwrap())
        })
        .collect::<BTreeMap<_, _>>();
    let mut route = cold.clone();
    route.mode = Mode::Restart;
    route.accepted_identity_buckets = Some(serde_json::json!(ledger));
    money_oracle::assert_equivalent(&cold, &route);
}

#[test]
fn same_source_ack_boundary_rebases_only_canonical_checkpoint_and_keeps_pending_and_siblings() {
    let mut f = SameSourceAckFixture::new();
    let sibling = f.baseline.files[&f.keys[2]].clone();
    let a = f.items[0].snapshot_fingerprint.clone();
    let b = f.items[1].snapshot_fingerprint.clone();
    let c = f.items[2].snapshot_fingerprint.clone();
    let before = f.baseline.generation;
    f.send(0, same_source_fixture_ack).unwrap();
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    assert_eq!(f.working.generation, before + 1);
    assert_eq!(f.baseline.generation, before + 1);
    assert!(f.baseline.files.contains_key(&f.keys[0]));
    assert!(!f.baseline.files.contains_key(&f.keys[1]));
    assert!(f.working.files.contains_key(&f.keys[1]));
    assert_eq!(
        serde_json::to_value(&sibling).unwrap(),
        serde_json::to_value(&f.baseline.files[&f.keys[2]]).unwrap()
    );
    assert!(f
        .progress
        .contains_body(&a, &snapshot_upload_body_witness(&f.items[0])));
    assert!(f
        .progress
        .contains_body(&c, &snapshot_upload_body_witness(&f.items[2])));
    assert!(!f.progress.accepted_fingerprints.contains(&b));
    // C disappears from this staged partial view. It must not be pruned by B-only settlement.
    f.working.files.remove(&f.keys[2]);
    f.working.file_snapshot_fingerprints.remove(&f.keys[2]);
    f.send(1, same_source_fixture_ack).unwrap();
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    assert_eq!(f.baseline.files.len(), 3);
    assert_eq!(f.progress.accepted_fingerprints.len(), 3);
    SameSourceAckFixture::stable_context(&f.baseline);
    assert!(cached_source_manifest(
        &f.progress.destination_namespace_hash,
        SnapshotSource::Codex
    )
    .is_none());
    f.restart_preparation();
    assert!(
        f.items.is_empty(),
        "ordinary restarted scan suppresses all three exact accepted native files"
    );
    eprintln!("same-source boundary affected_files_per_ack=1 final_files=3 pending_B_preserved=true sibling_C_preserved=true final_generation={}",f.baseline.generation);
}

#[test]
fn same_source_ack_boundary_whole_file_group_is_not_certified_by_one_child() {
    let mut f = SameSourceAckFixture::new();
    let key = f.keys[0].clone();
    let sibling_key = f.keys[1].clone();
    let a = f.items[0].snapshot_fingerprint.clone();
    let b = f.items[1].snapshot_fingerprint.clone();
    // Synthetic two-entity file-layout oracle, not a claim that the native
    // one-session Codex fixture physically emits two entities from one file.
    f.working
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from([a, b]));
    f.working.files.remove(&sibling_key);
    f.working.file_snapshot_fingerprints.remove(&sibling_key);
    f.send(0, same_source_fixture_ack).unwrap();
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 0);
    assert!(!f.baseline.files.contains_key(&key));
    assert!(f.baseline.files.contains_key(&f.keys[2]));
    assert!(f.working.files.contains_key(&key));
    f.send(1, same_source_fixture_ack).unwrap();
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    assert!(f.baseline.files.contains_key(&key));
    assert_eq!(f.baseline.file_snapshot_fingerprints[&key].len(), 2);
    SameSourceAckFixture::stable_context(&f.baseline);
}

#[test]
fn same_source_ack_manual_index_race_is_not_generation_only_rebased() {
    let mut f = SameSourceAckFixture::new();
    f.send(0, same_source_fixture_ack).unwrap();
    let before = f.baseline.generation;
    let akey = f.keys[0].clone();
    let bkey = f.keys[1].clone();
    let mut manual = ScanIndex::load(&f.index_path).unwrap();
    let mut newer = f.working.files[&bkey].clone();
    newer.last_upload_body_witness = Some("f".repeat(64));
    manual.files.insert(bkey.clone(), newer.clone());
    manual.file_snapshot_fingerprints.insert(
        bkey.clone(),
        f.working.file_snapshot_fingerprints[&bkey].clone(),
    );
    manual
        .snapshot_activity_at
        .extend(f.working.snapshot_activity_at.clone());
    manual.save_fixture(&f.index_path).unwrap();
    let disk = std::fs::read(&f.index_path).unwrap();
    assert!(f.checkpoint_boundary(|| Ok(())).is_err());
    assert_eq!(f.baseline.generation, before);
    assert_eq!(f.working.generation, before);
    assert_eq!(std::fs::read(&f.index_path).unwrap(), disk);
    let loaded = ScanIndex::load(&f.index_path).unwrap();
    assert!(!loaded.files.contains_key(&akey));
    assert_eq!(
        serde_json::to_value(&loaded.files[&bkey]).unwrap(),
        serde_json::to_value(newer).unwrap()
    );
    // The ACK is durable even though the stale scan cannot publish its A delta.
    let durable = SnapshotUploadProgress::load(
        &f.progress_path,
        &f.progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert!(durable.contains_body(
        &f.items[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&f.items[0])
    ));
}

#[test]
fn same_source_ack_progress_manual_race_rejects_older_ledger() {
    let mut f = SameSourceAckFixture::new();
    f.send(0, same_source_fixture_ack).unwrap();
    let disk_index = std::fs::read(&f.index_path).unwrap();
    let before = f.baseline.generation;
    let mut newer = f.progress.clone();
    newer
        .accepted_cache_heads
        .insert(cache_session_key("newer"), "e".repeat(64));
    newer.save_fixture(&f.progress_path).unwrap();
    assert!(f.checkpoint_boundary(|| Ok(())).is_err());
    assert_eq!(f.baseline.generation, before);
    assert_eq!(f.working.generation, before);
    assert_eq!(std::fs::read(&f.index_path).unwrap(), disk_index);
    assert!(SnapshotUploadProgress::load(
        &f.progress_path,
        &f.progress.destination_namespace_hash,
        test_quarantine_witness()
    )
    .unwrap()
    .contains_body(
        &f.items[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&f.items[0])
    ));
}

#[test]
fn same_source_ack_crash_before_progress_then_after_progress_before_index_recovers_exactly() {
    let mut f = SameSourceAckFixture::new();
    let a = f.items[0].snapshot_fingerprint.clone();
    let before = std::fs::read(&f.index_path).unwrap();
    let mut physical = 0;
    // ACK received, progress save fails: no durable local ACK exists.
    let result = attempt_snapshot_page(
        &f.items,
        &[0],
        &unique_poison_scope(),
        &mut f.progress,
        &mut 0,
        &|i: &SnapshotItem| i.snapshot_fingerprint.as_str(),
        &snapshot_upload_body_witness,
        &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
        &mut |items| {
            physical += 1;
            same_source_fixture_ack(items)
        },
        &mut |_| Err(anyhow!("synthetic crash before ledger save")),
    );
    assert!(result.is_err());
    assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
    f.restart_preparation();
    assert_eq!(f.items.len(), 2);
    assert!(!f.progress.accepted_fingerprints.contains(&a));
    f.send(0, |items| {
        physical += 1;
        same_source_fixture_ack(items)
    })
    .unwrap();
    assert_eq!(physical, 2);
    // Crash after durable ACK, before any index update: ordinary preparation
    // re-derives A but canonical page operation recognizes the exact saved body.
    f.restart_preparation();
    assert_eq!(f.items.len(), 2);
    let mut unexpected_posts = 0;
    f.send(0, |_| {
        unexpected_posts += 1;
        Err(anyhow!("saved ACK must skip POST"))
    })
    .unwrap();
    assert_eq!(unexpected_posts, 0);
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    f.restart_preparation();
    assert_eq!(f.items.len(), 1);
    assert!(!f.items.iter().any(|i| i.snapshot_fingerprint == a));
    eprintln!("same-source crash_before_progress_reposts=1 crash_after_progress_reposts=0 ordinary_pending_files=1");
}

#[test]
fn same_source_ack_crash_after_index_before_adoption_reloads_and_blocks_stale_owner() {
    let mut f = SameSourceAckFixture::new();
    f.send(0, same_source_fixture_ack).unwrap();
    let old = f.working.generation;
    let checkpoint = checkpoint_partial_snapshot_index(
        &f.working,
        &f.baseline,
        &f.progress,
        &f.items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(checkpoint.generation, old + 1);
    // Simulated crash before assigning returned checkpoint to owner variables.
    assert!(f.checkpoint_boundary(|| Ok(())).is_err());
    assert_eq!(f.working.generation, old);
    f.restart_preparation();
    assert_eq!(f.items.len(), 1);
    assert_eq!(f.baseline.files.len(), 2);
    assert_eq!(f.baseline.generation, old + 1);
    f.send(0, same_source_fixture_ack).unwrap();
    assert_eq!(f.checkpoint_boundary(|| Ok(())).unwrap(), 1);
    assert_eq!(f.baseline.files.len(), 3);
}

#[test]
fn same_source_ack_account_destination_stop_invalidation_after_ack_keeps_ledger_without_index_publication(
) {
    for field in ["account", "destination", "stop"] {
        let mut f = SameSourceAckFixture::new();
        let before = std::fs::read(&f.index_path).unwrap();
        let generation = f.baseline.generation;
        f.send(0, same_source_fixture_ack).unwrap();
        assert!(f
            .checkpoint_boundary(|| Err(anyhow!("{field} authority changed")))
            .is_err());
        assert_eq!(f.baseline.generation, generation);
        assert_eq!(f.working.generation, generation);
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        let saved = SnapshotUploadProgress::load(
            &f.progress_path,
            &f.progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        assert!(saved.contains_body(
            &f.items[0].snapshot_fingerprint,
            &snapshot_upload_body_witness(&f.items[0])
        ));
        assert_eq!(
            saved.destination_namespace_hash,
            f.progress.destination_namespace_hash
        );
    }
}
#[test]
fn claude_p92_typed_mixed_uses_full_enrichment_order() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    // Legacy session-account wire shape; `e2` emits request-owned account partitions.

    use crate::claude_local_otel::ClaudeIdentityDisposition;
    use sha2::{Digest, Sha256};
    let (dir, raw, api, trace) = crate::snapshots::claude_request_account_mixed_fixture(4, false);
    let mut index =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&dir),
        &mut index,
        "2026-08-02T07:10:00Z",
        7,
        100,
    )
    .unwrap();
    scan.snapshots = vec![raw.clone()];
    assert!(scan.census_complete);
    let support = dir.join("support");
    let digest = format!("{:x}", Sha256::digest(raw.source_session_id.as_bytes()));
    let write = |kind: &str, rows: Vec<serde_json::Value>| {
        let path = support
            .join("local-otel")
            .join(kind)
            .join(format!("{digest}.jsonl"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            rows.iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    };
    let base = scan.clone();
    let before = raw.session_account_evidence.clone();
    for case in [
        "complete",
        "creator_org_conflict",
        "typed_conflict",
        "typed_invalid",
        "missing_trace",
        "missing_api",
        "original_conflict",
    ] {
        let mut api = api.clone();
        let mut trace = trace.clone();
        let rows = api.evidence.get_mut(&raw.source_session_id).unwrap();
        match case {
            "creator_org_conflict" => {
                std::sync::Arc::make_mut(rows[0].request_identity.as_mut().unwrap())
                    .organization
                    .log_record_hash = Some("d".repeat(64))
            }
            "typed_conflict" => {
                std::sync::Arc::make_mut(rows[3].request_identity.as_mut().unwrap()).disposition =
                    ClaudeIdentityDisposition::Conflict
            }
            "typed_invalid" => {
                std::sync::Arc::make_mut(rows[3].request_identity.as_mut().unwrap()).disposition =
                    ClaudeIdentityDisposition::Invalid
            }
            "missing_api" => {
                rows.pop();
            }
            "missing_trace" => {
                trace
                    .evidence
                    .get_mut(&raw.source_session_id)
                    .unwrap()
                    .pop();
            }
            _ => {}
        }
        for row in rows.iter_mut() {
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(row).unwrap())
            );
        }
        write(
            "claude-code-effort",
            rows.iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect(),
        );
        write(
            "claude-code-trace-ownership",
            trace.evidence[&raw.source_session_id]
                .iter()
                .map(|row| serde_json::to_value(row).unwrap())
                .collect(),
        );
        let mut candidate = base.clone();
        if case == "original_conflict" {
            candidate.snapshots[0]
                .session_account_evidence
                .as_mut()
                .unwrap()
                .identity_disposition = Some("conflict");
        }
        // An upgraded store's witness, stored from this case's rows: no
        // build proves a new one.
        let mut case_index = index.clone();
        let stored = case_index.install_stored_claude_family_witness_from_support_for_test(
            &raw.source_session_id,
            &candidate.snapshots,
            &support,
        );
        assert!(stored || case != "complete", "{case}");
        let (proof, _, _) =
            apply_claude_local_evidence_to_scan(&support, &mut candidate, &mut case_index);
        let item = &mut candidate.snapshots[0];
        if case == "complete" {
            assert_eq!(
                item.provenance.collector,
                "claude_code_jsonl:own_request_account_mixed:v1"
            );
            assert_eq!(item.session_account_evidence, before);
            assert_eq!(
                item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
                Some("4")
            );
            assert!(item
                .model_usage
                .iter()
                .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
                .all(|row| row.account_identifier_hash.is_none()));
            let mut retained =
                crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
            let (prior_dir, mut prior, _, _) =
                crate::snapshots::claude_request_account_mixed_fixture(2, true);
            retained.bind_session_accounts(
                SnapshotSource::ClaudeCode,
                "machine",
                std::slice::from_mut(&mut prior),
                &[],
            );
            assert!(retained
                .bind_session_accounts_with_mixed(
                    SnapshotSource::ClaudeCode,
                    "machine",
                    std::slice::from_mut(item),
                    &[],
                    (&[], &mut [0; 9]),
                    &proof.mixed_uploads
                )
                .is_empty());
            crate::snapshots::claude_request_account_output("native-mixed-production.json", item);
            std::fs::remove_dir_all(prior_dir).unwrap();
        } else {
            assert_ne!(
                item.provenance.collector, "claude_code_jsonl:own_request_account_mixed:v1",
                "{case}"
            );
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
// A shed page records RatelimitBackoff in the shared client_report counters.
#[serial(client_report)]
fn claude_p92_mixed_503_lost_ack_restart_preserves_candidate() {
    // Legacy session-account wire shape; `e2` emits request-owned account partitions.

    let (root, mut prior, _, _) = crate::snapshots::claude_request_account_mixed_fixture(2, true);
    let (candidate_root, mut candidate, api, trace) =
        crate::snapshots::claude_request_account_mixed_fixture(4, true);
    let mut index =
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default());
    index.bind_session_accounts(
        SnapshotSource::ClaudeCode,
        "machine",
        std::slice::from_mut(&mut prior),
        &[],
    );
    let owner = serde_json::to_value(&index).unwrap()["session_account_bindings"].clone();
    let proof = crate::snapshots::claude_request_accounts::apply(
        std::slice::from_mut(&mut candidate),
        &api,
        &trace,
    );
    assert!(index
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            std::slice::from_mut(&mut candidate),
            &[],
            (&[], &mut [0; 9]),
            &proof.mixed
        )
        .is_empty());
    let expected = serde_json::to_vec(&candidate).unwrap();
    let semantic = candidate.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&candidate);
    let path = root.join("progress.json");
    let index_path = root.join("index.json");
    index.save_fixture(&index_path).unwrap();
    let namespace = format!("{:064x}", 99);
    let mut progress = SnapshotUploadProgress::new(
        namespace.clone(),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    let mut accepted = 0;
    let scope = unique_poison_scope();
    let result = upload_resumable_batches_with_body_witness(
        &[candidate.clone()],
        &scope,
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            assert_eq!(serde_json::to_vec(&items[0]).unwrap(), expected);
            Err(anyhow::Error::new(UploadShed {
                status: 503,
                retry_after: Some(Duration::from_secs(60)),
                code: None,
            }))
        },
        |state| state.save_fixture(&path),
    )
    .unwrap();
    assert_eq!(
        result,
        ResumableUploadResult::Shed {
            retry_after: Some(Duration::from_secs(60))
        }
    );
    assert_eq!(accepted, 0);
    assert!(!progress.accepted_fingerprints.contains(&semantic));
    assert_eq!(
        serde_json::to_value(&index).unwrap()["session_account_bindings"],
        owner
    );
    // Save/reload the existing checkpoint domains. Fresh proof reconstructs
    // the same body; a marker-only restarted binder cannot release it.
    progress.save_fixture(&path).unwrap();
    let mut restored = SnapshotUploadProgress::load(
        &path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    let mut restarted = ScanIndex::load(&index_path).unwrap();
    restarted = crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(restarted);
    assert!(restarted
        .bind_session_accounts(
            SnapshotSource::ClaudeCode,
            "machine",
            &mut [candidate.clone()],
            &[]
        )
        .contains(&candidate.source_session_id));
    let (retry_root, mut retry, api, trace) =
        crate::snapshots::claude_request_account_mixed_fixture(4, true);
    let proof = crate::snapshots::claude_request_accounts::apply(
        std::slice::from_mut(&mut retry),
        &api,
        &trace,
    );
    assert!(restarted
        .bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "machine",
            std::slice::from_mut(&mut retry),
            &[],
            (&[], &mut [0; 9]),
            &proof.mixed
        )
        .is_empty());
    assert_eq!(serde_json::to_vec(&retry).unwrap(), expected);
    let lost = upload_resumable_batches_with_body_witness(
        &[retry.clone()],
        &scope,
        &mut restored,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            assert_eq!(serde_json::to_vec(&items[0]).unwrap(), expected);
            Err(anyhow!("synthetic response lost after server settlement"))
        },
        |state| state.save_fixture(&path),
    );
    assert!(lost.is_err());
    assert_eq!(accepted, 0);
    assert!(!restored.accepted_fingerprints.contains(&semantic));
    restored.save_fixture(&path).unwrap();
    let mut after_loss = SnapshotUploadProgress::load(
        &path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    upload_resumable_batches_with_body_witness(
        &[retry.clone()],
        &scope,
        &mut after_loss,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            assert_eq!(serde_json::to_vec(&items[0]).unwrap(), expected);
            assert_eq!(snapshot_upload_body_witness(items[0]), body);
            let mut response = entity_ack_response(1);
            response
                .accepted_entities
                .push(crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: items[0].source_session_id.clone(),
                    snapshot_fingerprint: semantic.clone(),
                    occurrence_count: 1,
                    body_witness_version: Some(if items[0].cache_observations.is_some() {
                        14
                    } else {
                        8
                    }),
                    body_witness_digest: Some(body.clone()),
                    head_etag: Some("f".repeat(64)),
                    head_challenge: None,
                    unchanged_basis: None,
                    cache_observations_state: None,
                });
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: "claude_code".into(),
                machine_id: "a".repeat(64),
                collector_version: Some(collector_version()),
                snapshots: items.to_vec(),
                upload_policy: SnapshotUploadPolicy::default(),
                client_report: crate::client_report::ClientReport::empty(),
            };
            response.validate_entity_ack_with_head_cas(&request, true)?;
            Ok(response)
        },
        |state| state.save_fixture(&path),
    )
    .unwrap();
    assert_eq!(accepted, 1);
    assert!(after_loss.accepted_fingerprints.contains(&semantic));
    assert_eq!(
        serde_json::to_value(&restarted).unwrap()["session_account_bindings"],
        owner,
        "settlement does not rewrite creator/retained owner"
    );
    let mut calls = 0;
    upload_resumable_batches_with_body_witness(
        &[retry],
        &scope,
        &mut after_loss,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| {
            calls += 1;
            panic!("already accepted body must not be uploaded")
        },
        |state| state.save_fixture(&path),
    )
    .unwrap();
    assert_eq!(calls, 0);
    assert_eq!(accepted, 1, "same settled candidate is a no-op");
    std::fs::remove_dir_all(root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
    std::fs::remove_dir_all(candidate_root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
    std::fs::remove_dir_all(retry_root).unwrap();
    crate::snapshots::state_v2::close_removed_routes_for_test();
}
