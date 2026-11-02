use super::*;

pub(crate) fn archive_upload_checkpoint(
    mut index: ScanIndex,
    scan: &SourceScanResult,
    previous: &ScanIndex,
    outcome: &str,
) -> ScanIndex {
    let root = crate::test_scratch::ScratchDir::new("archive-upload-checkpoint");
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    std::fs::write(&index_path, serde_json::to_vec(previous).unwrap()).unwrap();
    let mut progress = test_upload_progress();
    progress.save(&progress_path).unwrap();
    if outcome != "partial" {
        let result = upload_resumable_batches_with_body_witness(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut 0,
            |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |items| {
                if outcome == "shed" {
                    Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: None,
                        code: None,
                    }))
                } else {
                    ack_retention_tests::exact_ack(items)
                }
            },
            |state| state.save(&progress_path),
        )
        .unwrap();
        if outcome == "shed" {
            assert!(matches!(result, ResumableUploadResult::Shed { .. }));
        } else {
            assert_eq!(result, ResumableUploadResult::Completed);
        }
    }
    index.generation = previous.generation;
    if outcome == "accept" {
        index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        index.settle_archive_outcome(|fp| {
            progress.accepted_body_witnesses.get(fp).map(String::as_str)
        });
    }
    checkpoint_partial_snapshot_index(
        &index,
        previous,
        &progress,
        &scan.snapshots,
        Some(scan),
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    ScanIndex::load(&index_path).unwrap()
}
pub(crate) fn assert_archive_debt_preserves_replay_progress(
    mut index: ScanIndex,
    scan: SourceScanResult,
    expected_markers: usize,
) {
    assert!(scan.census_complete);
    let counts = SyncCounts::from_scan_result(&scan, 0, 7);
    assert!(counts.has_disclosed_loss());
    assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
    let causes = crate::snapshots::ownership_diagnostics::line(counts.causes);
    assert!(causes.contains("archive_owed"));
    assert!(!causes.contains("unattributed"));
    let root = crate::test_scratch::ScratchDir::new("archive-backfill-isolation");
    let support = root.join("support");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let _manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let url = snapshot_status_server(captured.clone());
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &url);
    let client = SnapshotApiClient::new(url);
    let device = LocalDeviceBinding {
        device_id: "archive-fixture".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    let destination = snapshot_upload_destination_namespace(&device, "device-secret");
    let daemon = test_daemon("otm_test");
    let path = support.join("index.json");
    std::fs::write(&path, serde_json::to_vec(&index).unwrap()).unwrap();
    let progress_path = support.join("progress.json");
    let mut progress = SnapshotUploadProgress::new(
        destination.clone(),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    progress.save(&progress_path).unwrap();
    let status = test_agent_status(SourceKind::Codex);
    let preparation = SourcePreparation {
            native_comparison_reservation: None, native_comparison_lease: None,
            prepared_claude_evidence: None, terminal_native_traversal: None,
            native_comparison_controller: None, retry_authority: None,
            source: SnapshotSource::Codex, claude_scan_roots: None,
            account_witness: daemon.snapshot_scan_account_witness().unwrap(),
            scan_started_at: scan.census_window_end.clone(),
            activity_hint: serde_json::from_value(serde_json::json!({"source":"codex", "server_time":scan.census_window_end, "last_data_at":null,
                "record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
                "backfill_window_days":7,"recommended_scan_after":"2026-10-07T12:00:00Z"})).unwrap(),
            receipt_window_days: 7, cache_observations_enabled: false,
            scan_agent_status_collection: Some(Arc::new(AgentStatusCollection { snapshots: vec![status.clone()], source_health_snapshot: status, codex_scan_homes: Vec::new(), codex_home_bindings: Vec::new() })),
            attribution_context: None, upload_policy: SnapshotUploadPolicy::default(),
            upload_destination_namespace: destination.clone(), receipt_client: client.clone(),
            index_path: path.clone(), upload_progress_path: progress_path.clone(),
            upload_progress: progress, committed_index: index.clone(),
            backfill_state: load_backfill_state(&support), backfill_pending: true,
            legacy_reconciliation_pending: BTreeSet::new(), active_legacy_reconciliation: BTreeSet::new(), scan: None,
        };
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    finish_sync_source(
        preparation,
        index,
        scan,
        &client,
        &device,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        &root,
        &support,
        &daemon,
        &mut transport,
        &mut retry,
    )
    .unwrap();
    let backfill = load_backfill_state(&support);
    let pending = pending_backfill_sources_for_destination(&backfill, &destination)
        .contains(&SnapshotSource::Codex);
    assert!(
        !pending,
        "production finish persisted the completed backfill"
    );
    assert!(cached_source_manifest(&destination, SnapshotSource::Codex).is_some());
    index = ScanIndex::load(&path).unwrap();
    match serde_json::to_value(&index).unwrap().get("archives") {
        Some(markers) => assert_eq!(markers.as_object().unwrap().len(), expected_markers),
        None => assert_eq!(expected_markers, 0, "empty archive map is omitted"),
    }
    let fp = "a".repeat(64);
    let mut progress =
        SnapshotUploadProgress::load(&progress_path, &destination, test_quarantine_witness())
            .unwrap();
    progress.quarantine([fp.as_str()]);
    assert_eq!(
        progress.quarantined_fingerprints[&fp].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    progress
        .quarantined_fingerprints
        .get_mut(&fp)
        .unwrap()
        .retry_after_unix_seconds = 0;
    index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
    prepare_upload_progress_for_cycle_with_reoffer(&mut progress, &index, "replay", pending, None);
    assert!(progress.active_quarantine_retries.contains(&fp));
    let requests = captured.lock().unwrap();
    let terminal = requests
        .iter()
        .map(|r| http_request_json(r))
        .find(|v| v.get("last_ownership_incomplete_file_count").is_some())
        .unwrap();
    assert!(
        terminal["last_ownership_incomplete_file_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(terminal.get("manifest").is_some());
}
