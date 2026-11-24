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

fn codex_transition_batch<T: std::borrow::Borrow<SnapshotItem>>(items: Vec<T>) -> Vec<u8> {
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
    codex_transition_upload(items).0
}

fn codex_transition_upload(items: &[SnapshotItem]) -> (Vec<Vec<u8>>, SnapshotUploadProgress) {
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
            posts.push(codex_transition_batch(items.to_vec()));
            ack_retention_tests::exact_ack(items)
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    (posts, progress)
}

pub(crate) fn codex_transition_acked_route(
    index: &ScanIndex,
    scan: &SourceScanResult,
    mode: crate::snapshots::sampled_scan::transition_fixture::Mode,
) -> crate::snapshots::sampled_scan::transition_fixture::RouteResult {
    use crate::snapshots::sampled_scan::transition_fixture::{self as fixture, RouteResult};
    let (posts, progress) = codex_transition_upload(&scan.snapshots);
    // Codex records exact stored-body witnesses, rather than Claude's
    // request-share ledger. Observe placement from the actual POST body
    // only after that exact body has a native stored-body ACK witness.
    let mut ledger = BTreeMap::new();
    for post in &posts {
        let body: serde_json::Value = serde_json::from_slice(post).unwrap();
        for item in body["snapshots"].as_array().unwrap() {
            let fingerprint = item["snapshot_fingerprint"].as_str().unwrap();
            let witness = progress
                .accepted_body_witnesses
                .get(fingerprint)
                .expect("exact stored-body ACK");
            ledger.insert(
                item["source_session_id"].as_str().unwrap().to_owned(),
                serde_json::json!({"body_witness":witness, "stored_body":item}),
            );
        }
    }
    let mut route = RouteResult::emitted(mode, SnapshotSource::Codex, posts, &scan.snapshots);
    route.codex_evidence = fixture::codex_evidence(index, scan);
    route.accepted_identity_buckets = Some(serde_json::json!(ledger));
    route
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
        let route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&index);
        let index_path = route.clone().unwrap_or_else(|| {
            // The returned index retains this route between pages; the corpus
            // owns its scanned roots and removes them when the fixture ends.
            let root = index
                .files
                .keys()
                .chain(previous.files.keys())
                .next()
                .and_then(|key| Path::new(key).parent().map(Path::to_owned))
                .expect("archive checkpoint has a fixture scan root");
            root.join(crate::test_scratch::unique_name(
                "archive-upload-checkpoint",
            ))
            .join("index.json")
        });
        // A prepare-time carry already committed both old/new keys. Match
        // the production constructor's baseline, without admitting later work.
        let prepared = (route.is_some() && index.generation != previous.generation)
            .then(|| ScanIndex::load(&index_path).unwrap());
        let seeded = route.is_none().then(|| {
            crate::snapshots::e2_pipeline_scan_fixture::bind_source_for_test(
                &index_path,
                SnapshotSource::Codex,
            );
            crate::snapshots::e2_pipeline_scan_fixture::seed_index_for_test(previous, &index_path)
        });
        let previous = prepared.as_ref().or(seeded.as_ref()).unwrap_or(previous);
        if let Some(seed) = &seeded {
            index.retain_persistence_baseline_from(seed);
            index.generation = seed.generation;
        }
        let progress_path = snapshot_upload_progress_path(&index_path);
        let (_, destination) =
            crate::snapshots::e2_pipeline_scan_fixture::binding_for_test(&index_path);
        let mut progress = SnapshotUploadProgress::load_for_index(
            &index,
            &index_path,
            &progress_path,
            &destination,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        progress.context_receipt_candidates =
            index.file_upload_context_ack_candidates(&scan.snapshots, &BTreeMap::new());
        progress.save_fixture(&progress_path).unwrap();
        // The service computes census-absent ACKs before the upload.
        let census_absent = progress.complete_census_ack_retirements(&index, scan.census_complete);
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
                |state| state.save_fixture(&progress_path),
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
        if outcome == "complete" {
            // A Completed upload with no local hold: the service saves the
            // whole scanned index (pruning included), as its finish does.
            let settled = settle_completed_upload(
                index,
                previous,
                &progress,
                &LocalHoldSettlement {
                    held_entity_count: 0,
                    retry_pending_family_count: 0,
                    held_fingerprints: BTreeSet::new(),
                    account_deferred_fingerprints: BTreeSet::new(),
                    progress_blocking: false,
                },
            );
            assert!(settled.fully_settled);
            let mut index = settled.index;
            let scan_referenced = progress.ack_retirement_scan_references(previous, &index);
            settle_index_after_upload(&mut index, previous, &progress);
            let mut retired = progress
                .stage_selected_ack_retirement(
                    previous,
                    &mut index,
                    &scan_referenced,
                    &BTreeSet::new(),
                    &census_absent,
                )
                .unwrap();
            let _ = index.accept_file_upload_context_acks(
                &progress.split_context_receipt_candidates(),
                &progress.fresh_context_body_acks,
                &progress.covered_stale_bodies(),
            );
            index.stamp_entity_upload_context_acks(
                &progress.destination_namespace_hash,
                &progress.accepted_body_witnesses,
                &progress.accepted_body_contexts,
            );
            scan.validate_codex_checkpoint().unwrap();
            index.save_fixture(&index_path).unwrap();
            progress.add_saved_handoff_retirements(&mut retired, &index);
            progress.retire_planned_acks_after_index_save(&index, &retired, &BTreeSet::new());
            progress.finish_cycle_fixture(&progress_path).unwrap();
            return (ScanIndex::load(&index_path).unwrap(), posts);
        }
        if outcome == "accept" {
            index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        }
        if outcome == "wrong-body" {
            for witness in progress.accepted_body_witnesses.values_mut() {
                *witness = "0".repeat(64);
            }
            progress.save_fixture(&progress_path).unwrap();
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
    let path = support
        .join("snapshots/destinations")
        .join(&destination)
        .join("codex-scan-index-v3.json");
    index = crate::snapshots::e2_pipeline_scan_fixture::seed_index_for_test(&index, &path);
    let (progress_path, mut progress) = routed_progress(
        &index,
        &path,
        SnapshotUploadProgress::new(
            destination.clone(),
            snapshot_quarantine_witness(SnapshotSource::Codex),
        ),
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
    finish_sync_source(
        preparation,
        index,
        scan,
        &device,
        "device-secret",
        "otm_test",
        &root,
        &support,
        &daemon,
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
