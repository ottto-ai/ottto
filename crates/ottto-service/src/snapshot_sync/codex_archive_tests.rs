use super::*;

pub(crate) fn archive_upload_checkpoint(
    index: ScanIndex,
    scan: &SourceScanResult,
    previous: &ScanIndex,
    outcome: &str,
) -> ScanIndex {
    index
        .checkpoint_with_captured_posts(scan, previous, outcome)
        .0
}

fn codex_transition_batch(items: Vec<SnapshotItem>) -> Vec<u8> {
    let request = snapshot_batch_request(
        SnapshotSource::Codex,
        "synthetic-machine",
        items,
        SnapshotUploadPolicy::default(),
        crate::client_report::ClientReport::empty(),
    );
    serde_json::to_vec(&request).unwrap()
}

/// Cold and restored drivers both use the ordinary uploader's native ordering
/// and batch envelope. No transcript read, remote POST or persisted ACK here.
pub(crate) fn codex_transition_cold_batches(items: &[SnapshotItem]) -> Vec<Vec<u8>> {
    let mut posts = Vec::new();
    let mut progress = test_upload_progress();
    let result = upload_resumable_batches_with_body_witness(
        items,
        &unique_poison_scope(),
        &mut progress,
        &mut 0,
        |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            posts.push(codex_transition_batch(items.clone()));
            ack_retention_tests::exact_ack(items)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    posts
}

impl ScanIndex {
    pub(crate) fn checkpoint_with_captured_posts(
        self,
        scan: &SourceScanResult,
        previous: &ScanIndex,
        outcome: &str,
    ) -> (ScanIndex, Vec<Vec<u8>>) {
        let mut index = self;
        let mut posts = Vec::new();
        let root = crate::test_scratch::ScratchDir::canonical("archive-upload-checkpoint");
        let route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index);
        let index_path = route.clone().unwrap_or_else(|| root.join("index.json"));
        let progress_path = snapshot_upload_progress_path(&index_path);
        if route.is_none() {
            std::fs::write(&index_path, serde_json::to_vec(previous).unwrap()).unwrap();
        }
        let expected = test_upload_progress();
        let destination = route
            .as_ref()
            .and_then(|path| path.parent()?.file_name()?.to_str())
            .unwrap_or(&expected.destination_namespace_hash);
        let recovery = crate::snapshots::ProgressRecovery::for_index(&index, &index_path).unwrap();
        let mut progress = SnapshotUploadProgress::load_with_recovery(
            &progress_path,
            destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
            recovery,
        )
        .unwrap();
        progress.context_receipt_candidates =
            index.file_upload_context_ack_candidates(&scan.snapshots);
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
                    posts.push(codex_transition_batch(items.to_vec()));
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
        progress.fresh_context_body_acks = progress.accepted_body_witnesses.clone();
        index.generation = previous.generation;
        if outcome == "accept" {
            index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        }
        if outcome == "wrong-body" {
            for witness in progress.accepted_body_witnesses.values_mut() {
                *witness = "0".repeat(64);
            }
            progress.save(&progress_path).unwrap();
        }
        let checkpoint = checkpoint_partial_snapshot_index(
            &index,
            previous,
            &progress,
            &scan.snapshots,
            Some(scan),
            &BTreeSet::new(),
            &index_path,
            &progress_path,
            || {
                if outcome == "wrong-destination" {
                    anyhow::bail!("synthetic destination changed before checkpoint");
                }
                Ok(())
            },
        );
        if outcome == "wrong-destination" {
            assert!(checkpoint.is_err());
        } else {
            checkpoint.unwrap();
        }
        (ScanIndex::load(&index_path).unwrap(), posts)
    }
}
pub(crate) fn assert_archive_debt_preserves_replay_progress(
    mut index: ScanIndex,
    scan: SourceScanResult,
    expected_files: usize,
) {
    assert!(scan.census_complete);
    let counts = SyncCounts::from_scan_result(&scan, 0, 7);
    assert!(counts.has_disclosed_loss());
    assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
    let causes = crate::snapshots::ownership_diagnostics::line(counts.causes);
    assert!(
        !causes.contains("archive_owed"),
        "retired policy has no live cause"
    );
    assert!(!causes.contains("unattributed"));
    let root = crate::test_scratch::ScratchDir::canonical("archive-backfill-isolation");
    let support = root.join("support");
    let secrets = root.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let _manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let url = snapshot_status_server_with_hint_extras_and_batch(
        captured.clone(),
        vec![(30, "")],
        Some(scan.snapshots.clone()),
    );
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
    let progress_path = snapshot_upload_progress_path(&path);
    let mut progress = SnapshotUploadProgress::new(
        destination.clone(),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    progress.save(&progress_path).unwrap();
    let fixture = ContinuationFixture {
        home: root.join("home"),
        support_dir: support.clone(),
        index_path: path.clone(),
        upload_progress_path: progress_path.clone(),
    };
    let preparation = SourcePreparation {
        account_witness: daemon.snapshot_scan_account_witness().unwrap(),
        scan_started_at: scan.census_window_end.clone(),
        activity_hint: serde_json::from_value(serde_json::json!({"source":"codex", "server_time":scan.census_window_end, "last_data_at":null,
            "record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
            "backfill_window_days":7,"recommended_scan_after":"2026-10-07T12:00:00Z"})).unwrap(),
        receipt_window_days: 7,
        upload_destination_namespace: destination.clone(),
        receipt_client: client.clone(),
        upload_progress: progress,
        committed_index: index.clone(),
        backfill_state: load_backfill_state(&support),
        backfill_pending: true,
        ..fixture.preparation(false)
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
    assert!(serde_json::to_value(&index)
        .unwrap()
        .get("archives")
        .is_none());
    assert_eq!(index.files.len(), expected_files);
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
