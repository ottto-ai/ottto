fn revert_archives(c: &Corpus, second_account: &str) -> Vec<PathBuf> {
    rollout(c, A, "a", 8);
    let original = c
        .root
        .join(format!("rollout-2026-10-27T07-00-00-{A}.jsonl"));
    let first = std::fs::read_to_string(&original).unwrap();
    rollout(c, A, second_account, 88);
    let mut second = std::fs::read_to_string(&original)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    second[0]["payload"]["history_base"] =
        json!({"thread_id": A, "end_ordinal_exclusive": 1, "end_byte_offset": 1});
    second[0]["payload"]["timestamp"] = json!("2026-10-27T07:01:00Z");
    second[0]["timestamp"] = json!("2026-10-27T07:01:00Z");
    for row in &mut second[1..] {
        row["timestamp"] = json!("2026-10-27T07:31:00Z");
    }
    let second = second
        .iter()
        .map(|row| row.to_string() + "\n")
        .collect::<String>();
    std::fs::remove_file(&original).unwrap();
    let paths = vec![
        original.with_extension("jsonl.zst"),
        c.root
            .join(format!("rollout-2026-10-27T07-01-00-{A}_{B}.jsonl.zst")),
    ];
    for (path, body) in paths.iter().zip([first, second]) {
        std::fs::write(path, zstd::stream::encode_all(body.as_bytes(), 1).unwrap()).unwrap();
    }
    paths
}

/// [money] Capture every physical revision, exact-ACK the combined body, recover
/// the receipt before saving source progress, then restart and upgrade quietly.
#[test]
fn combined_codex_ack_recovers_every_member_and_quiet_restarts_read_zero_bytes() {
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    let mut c = Corpus::new("codex-combined-ack-restart");
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    let paths = revert_archives(&c, "a");
    let (session, previous) =
        StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &c.base.join("state"));
    // The prior binary independently finished and uploaded 8 and 88 requests.
    // Its last accepted server body was the revert's 88, never the folded 96.
    let (mut legacy, mut old_scan) = fixture::codex_legacy_singletons(
        std::slice::from_ref(&c.root),
        &c.support,
        previous.clone(),
    );
    legacy.bind_session_accounts(SOURCE, "e2-synthetic-machine", &mut old_scan.snapshots, &[]);
    apply_upload_policy(
        SOURCE,
        &mut old_scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SOURCE, &mut old_scan, &mut legacy);
    old_scan.finish_codex_capture_boundary(&mut legacy);
    old_scan.snapshots.sort_by_key(|item| item.request_count);
    assert_eq!(
        old_scan
            .snapshots
            .iter()
            .map(|item| item.request_count)
            .collect::<Vec<_>>(),
        [8, 88]
    );
    assert_eq!(old_scan.snapshots.last().unwrap().request_count, 88);
    assert_eq!(legacy.files.len(), 2);
    assert!(legacy
        .files
        .values()
        .all(|entry| entry.codex_joined_member_set.is_none()));
    assert_ne!(
        old_scan.snapshots[0].source_file_fingerprint,
        old_scan.snapshots[1].source_file_fingerprint
    );
    legacy.record_accepted_snapshot_fingerprints(
        &old_scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    let mut legacy = session.save_reload(&mut legacy);
    assert!(legacy
        .files
        .values()
        .all(|entry| !entry.source_file_fingerprint.is_empty()));
    // Same existing first-load re-arm used by the source-aware install/restart
    // loader. It changes only owed source state and the observed-file queue.
    fixture::codex_rearm_unsettled(&mut legacy);
    assert!(legacy
        .files
        .values()
        .all(|entry| entry.source_file_fingerprint.is_empty()));
    let previous = legacy;
    let (mut index, scan, _) = page(&c, &E2ScanFixture::default(), previous.clone());
    assert_eq!(scan.snapshots.len(), 1, "one upload body for both files");
    assert_eq!(scan.snapshots[0].request_count, 96);
    let (mut captured, changed) = index.stage_codex_recovery_capture(&previous, &scan.snapshots);
    assert!(changed.contains(A));
    assert_eq!(
        captured
            .files
            .values()
            .filter(|entry| entry.codex_captured_joined_member_set.is_some())
            .count(),
        2
    );
    let captured = session.save_reload(&mut captured);
    index.generation = captured.generation;
    index.retain_persistence_baseline_from(&captured);

    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(SOURCE));
    let before = serde_json::to_vec(&progress).unwrap();
    let progress_path = c.base.join("codex-progress.json");
    ottto_core::write_owner_only_file_atomic(&progress_path, &before).unwrap();
    let recovery = crate::snapshots::ProgressRecovery::synthetic(
        &c.base.join("receipt-index"),
        &"a".repeat(64),
        captured.generation,
    );
    recovery.adopt_synthetic(Some(&before));
    // The same acquired body/proof remains in the attempt for an exact retry.
    let ((failed, failed_batches, _), retry_bytes) = fixture::observe_consumed(|| {
        upload_source_under(
            SOURCE,
            SnapshotUploadPolicy::default(),
            &scan.snapshots,
            &mut progress,
            |_| Err(anyhow::anyhow!("synthetic transient upload failure")),
        )
    });
    assert!(failed.is_err());
    assert_eq!(retry_bytes, 0);
    let (outcome, batches, _) = upload_source_under(
        SOURCE,
        SnapshotUploadPolicy::default(),
        &scan.snapshots,
        &mut progress,
        ack,
    );
    assert_eq!(outcome.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1);
    assert_eq!(
        failed_batches, batches,
        "retry sends the retained exact body"
    );
    progress.generation += 1;
    let after = serde_json::to_vec(&progress).unwrap();
    recovery
        .before_progress_save_bytes(Some(&before), &after)
        .unwrap();
    // Process loss after the exact receipt, before either progress/source save.
    recovery.recover(&progress_path).unwrap();
    assert_eq!(std::fs::read(&progress_path).unwrap(), after);
    let recovered: SnapshotUploadProgress = serde_json::from_slice(&after).unwrap();
    settle_index_after_upload(&mut index, &captured, &recovered);
    let mut prior = session.save_reload(&mut index);
    fixture::codex_rearm_unsettled(&mut prior);
    assert!(
        prior
            .files
            .values()
            .all(|entry| !entry.source_file_fingerprint.is_empty()),
        "a settled group never re-arms on install/restart"
    );
    assert!(prior
        .files
        .values()
        .all(|entry| entry.codex_captured_joined_member_set.is_none()));
    assert_eq!(
        prior
            .files
            .values()
            .filter(|entry| entry.codex_joined_member_set.is_some())
            .count(),
        2
    );
    for mode in [fixture::Mode::Restart, fixture::Mode::DiskRestore] {
        let ((_, quiet, modes), io) =
            fixture::observe_codex_quiet(|| page(&c, &E2ScanFixture::default(), prior.clone()));
        let mut route = fixture::scan_money(SOURCE, &prior, &quiet);
        route.mode = mode;
        route.modes = modes;
        route.io = io;
        // All files reached the metadata-only Skip branch: no acquisition,
        // sample or re-derivation reader was entered on this quiet pass.
        assert_eq!(quiet.semantic_noop_count, paths.len());
        fixture::money_oracle::assert_quiet_restart_zero_bytes(&route);
    }

    let mut accepted_route = fixture::scan_money(SOURCE, &prior, &scan);
    accepted_route.accepted.insert(
        A.into(),
        fixture::Accepted {
            body: accepted_route.snapshots[A].clone(),
            witness: snapshot_upload_body_witness(&scan.snapshots[0]),
        },
    );
    // New material stays owed: no accepted sealed member is read again merely
    // to recreate the vanished in-memory admitted-key proof.
    let bytes = zstd::stream::decode_all(std::fs::File::open(&paths[1]).unwrap()).unwrap();
    let mut grown = String::from_utf8(bytes).unwrap();
    grown += &(json!({"timestamp":"2026-10-27T07:32:00Z","type":"event_msg","payload":{"type":"token_count",
        "info":{"last_token_usage":{"input_tokens":100},"total_token_usage":{"input_tokens":8900}}}}).to_string()+"\n");
    std::fs::write(
        &paths[1],
        zstd::stream::encode_all(grown.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    let ((_, growth, _), bytes) =
        fixture::observe_consumed(|| page(&c, &E2ScanFixture::default(), prior.clone()));
    assert_eq!(bytes, 0, "growth cannot reread accepted sealed history");
    let mut held_route = fixture::scan_money(SOURCE, &prior, &growth);
    held_route.accepted = accepted_route.accepted.clone();
    fixture::money_oracle::assert_no_smaller_reemit(
        A,
        &accepted_route,
        &held_route,
        &accepted_route,
        true,
    );

    // A lost carrier retains the logical accepted body, never the survivor sum.
    std::fs::remove_file(&paths[1]).unwrap();
    let (_, held, _) = page(&c, &E2ScanFixture::default(), prior.clone());
    let mut deleted = fixture::scan_money(SOURCE, &prior, &held);
    deleted.accepted = accepted_route.accepted.clone();
    fixture::money_oracle::assert_held(A, &accepted_route, &deleted, &accepted_route);
    assert!(held
        .snapshots
        .iter()
        .all(|item| item.source_session_id != A));
    assert!(recovered
        .accepted_fingerprints
        .contains(&scan.snapshots[0].snapshot_fingerprint));
}

/// [money] File-level creator evidence cannot authorize a mixed-account union.
#[test]
fn combined_codex_account_switch_holds_without_request_evidence() {
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    let c = Corpus::new("codex-combined-account-switch");
    revert_archives(&c, "b");
    let original_account =
        ottto_core::billing_identity_hash("openai", "account", "synthetic-user-a").unwrap();
    let original_workspace =
        ottto_core::billing_identity_hash("openai", "workspace", "synthetic-workspace-a").unwrap();
    let mut prior = ScanIndex::default();
    let binding_key = fixture::codex_start_binding(
        &mut prior,
        "e2-synthetic-machine",
        A,
        original_account.clone(),
        Some(original_workspace),
    );
    let saved_binding =
        serde_json::to_value(&prior).unwrap()["session_account_bindings"][&binding_key].clone();
    let (after, scan, _) = page(&c, &E2ScanFixture::default(), prior);
    assert_eq!(
        serde_json::to_value(&after).unwrap()["session_account_bindings"][&binding_key],
        saved_binding,
        "the original saved starting binding survives the held revert"
    );
    assert_eq!(saved_binding["account_identifier_hash"], original_account);
    assert!(
        scan.snapshots
            .iter()
            .all(|item| item.source_session_id != A),
        "no carrier-account fallback or singleton"
    );
    assert!(scan.ownership_incomplete_file_count >= 2);
}

/// [money] The production recovery capture over a bound Codex state store
/// commits the re-armed group's markers while it holds the progress lock. It
/// does not hold the group or leave the store needing a reload; a guard built
/// before the capture refuses the adopted graph and a new one passes, and the
/// group then uploads one summed body and restarts quietly.
#[test]
fn codex_group_capture_commits_on_its_state_store_after_first_load_rearm() {
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    let mut c = Corpus::new("codex-group-capture-state-store");
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    let paths = revert_archives(&c, "a");
    let (session, previous) =
        StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &c.base.join("state"));
    // An earlier build finished and accepted both files as singletons.
    let (mut legacy, mut old_scan) =
        fixture::codex_legacy_singletons(std::slice::from_ref(&c.root), &c.support, previous);
    legacy.bind_session_accounts(SOURCE, "e2-synthetic-machine", &mut old_scan.snapshots, &[]);
    apply_upload_policy(
        SOURCE,
        &mut old_scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SOURCE, &mut old_scan, &mut legacy);
    old_scan.finish_codex_capture_boundary(&mut legacy);
    assert_eq!(old_scan.snapshots.len(), 2);
    legacy.record_accepted_snapshot_fingerprints(
        &old_scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    let mut committed = session.save_reload(&mut legacy);
    assert!(
        crate::snapshots::state_v2_growth_retention_active(&committed),
        "the state store route"
    );
    // First source-aware load: the unsettled group re-arms.
    fixture::codex_rearm_unsettled(&mut committed);
    assert!(committed
        .files
        .values()
        .all(|entry| entry.source_file_fingerprint.is_empty()));
    let generation = committed.generation;
    // The re-armed pass replays the group into one folded body.
    let (mut index, mut scan, _) = page(&c, &E2ScanFixture::default(), committed.clone());
    assert_eq!(scan.snapshots.len(), 1, "one upload body for both files");
    assert_eq!(scan.snapshots[0].request_count, 96);
    let before = fixture::scan_money(SOURCE, &index, &scan);
    let incomplete = scan.ownership_incomplete_file_count;

    // The finish boundary's guard, built before the capture as the pass does.
    let stale_guard = crate::snapshots::state_v2_side_effect_guard(session.path(), &index);
    stale_guard().expect("the pass starts on the current graph");
    let progress_path = snapshot_upload_progress_path(session.path());
    capture_codex_recovery_evidence(
        &mut index,
        &mut committed,
        &mut scan,
        session.path(),
        &progress_path,
        &stale_guard,
    );
    assert!(
        scan.snapshots
            .iter()
            .any(|item| item.source_session_id == A),
        "the recovery capture held the group"
    );
    assert_eq!(scan.ownership_incomplete_file_count, incomplete);
    assert!(committed.generation > generation, "the capture committed");
    assert_eq!(index.generation, committed.generation);
    assert!(
        stale_guard().is_err(),
        "a guard built before the capture refuses the adopted graph"
    );
    let fresh_guard = crate::snapshots::state_v2_side_effect_guard(session.path(), &index);
    fresh_guard().expect("the store needs no reload after the capture");
    let reloaded = ScanIndex::load(session.path()).unwrap();
    assert_eq!(reloaded.generation, committed.generation);
    assert_eq!(
        reloaded
            .files
            .values()
            .filter(|entry| entry.codex_captured_joined_member_set.is_some())
            .count(),
        2
    );
    // The capture changes no body, account or placement.
    let after = fixture::scan_money(SOURCE, &index, &scan);
    fixture::money_oracle::assert_equivalent(&before, &after);

    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(SOURCE));
    let mut posted = Vec::new();
    // Every upload boundary checks the store guard first, as the pass does.
    let (outcome, batches, _) = upload_source_under(
        SOURCE,
        SnapshotUploadPolicy::default(),
        &scan.snapshots,
        &mut progress,
        |batch| {
            fresh_guard()?;
            posted.extend(
                batch
                    .iter()
                    .map(|item| (item.source_session_id.clone(), item.request_count)),
            );
            ack(batch)
        },
    );
    assert_eq!(outcome.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(batches.len(), 1, "exactly one body");
    assert_eq!(
        posted,
        [(A.to_string(), 96)],
        "one summed body, no singleton"
    );
    assert!(progress
        .accepted_fingerprints
        .contains(&scan.snapshots[0].snapshot_fingerprint));
    settle_index_after_upload(&mut index, &committed, &progress);
    let mut prior = session.save_reload(&mut index);
    fixture::codex_rearm_unsettled(&mut prior);
    assert!(
        prior
            .files
            .values()
            .all(|entry| !entry.source_file_fingerprint.is_empty()),
        "an acknowledged group never re-arms again"
    );
    for mode in [fixture::Mode::Restart, fixture::Mode::DiskRestore] {
        let ((_, quiet, modes), io) =
            fixture::observe_codex_quiet(|| page(&c, &E2ScanFixture::default(), prior.clone()));
        let mut route = fixture::scan_money(SOURCE, &prior, &quiet);
        route.mode = mode;
        route.modes = modes;
        route.io = io;
        assert_eq!(quiet.semantic_noop_count, paths.len());
        fixture::money_oracle::assert_quiet_restart_zero_bytes(&route);
    }
}

/// [money] The production finish over a bound Codex state store, after the
/// first-load re-arm: its recovery capture commits, every later upload
/// boundary passes the store guard, and the group uploads one summed body
/// that is acknowledged, settles and restarts quietly.
#[test]
#[serial_test::serial]
#[serial_test::serial(source_cadences, source_manifests, client_report)]
fn codex_group_finish_uploads_after_its_capture_on_a_state_store() {
    use crate::snapshot_sync::tests::{
        http_request_json, snapshot_status_server_with_hint_extras_and_batch, test_daemon,
        ContinuationFixture, EnvVarGuard, SourceManifestTestGuard,
    };
    use std::sync::{Arc, Mutex};
    const DEVICE: &str = "codex-finish-guard-device";
    const SECRET: &str = "device-secret";
    let _decoder = fixture::codex_decoder_test_lock();
    let _cutover = crate::snapshots::TestCutover::set(i64::MAX);
    crate::snapshot_sync::forget_carried_namespaces_for_test(&[DEVICE]);
    let mut c = Corpus::new("codex-group-finish-state-store");
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    let paths = revert_archives(&c, "a");
    let (session, previous) =
        StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &c.base.join("state"));
    // An earlier build finished and accepted both files as singletons.
    let (mut legacy, mut old_scan) =
        fixture::codex_legacy_singletons(std::slice::from_ref(&c.root), &c.support, previous);
    legacy.bind_session_accounts(SOURCE, "e2-synthetic-machine", &mut old_scan.snapshots, &[]);
    apply_upload_policy(
        SOURCE,
        &mut old_scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    finalize_scan_after_policy(SOURCE, &mut old_scan, &mut legacy);
    old_scan.finish_codex_capture_boundary(&mut legacy);
    assert_eq!(old_scan.snapshots.len(), 2);
    legacy.record_accepted_snapshot_fingerprints(
        &old_scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    let mut committed = session.save_reload(&mut legacy);
    assert!(
        crate::snapshots::state_v2_growth_retention_active(&committed),
        "the state store route"
    );
    // First source-aware load: the unsettled group re-arms.
    fixture::codex_rearm_unsettled(&mut committed);
    let generation = committed.generation;
    // The body the pass will fold, for the receiver's exact ACK.
    let (_, expected, _) = page(&c, &E2ScanFixture::default(), committed.clone());
    assert_eq!(
        expected.snapshots.len(),
        1,
        "one upload body for both files"
    );
    assert_eq!(expected.snapshots[0].request_count, 96);
    // The collected page, before the finish binds, filters and captures it.
    let (index, scan, _) = E2ScanFixture::default().scan_other(
        SOURCE,
        std::slice::from_ref(&c.root),
        &c.support,
        committed.clone(),
        true,
    );

    // Relay credentials whose destination is this store's namespace.
    let support = c.base.join("service-support");
    let secrets = c.base.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let _manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let url = snapshot_status_server_with_hint_extras_and_batch(
        captured.clone(),
        vec![(183, "")],
        Some(expected.snapshots.clone()),
    );
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &url);
    let client = SnapshotApiClient::new(url);
    let device = ottto_core::LocalDeviceBinding {
        device_id: DEVICE.into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into()],
    };
    let namespace = "a".repeat(64);
    ottto_core::FileDeviceStore::default()
        .save_with_credential_generation(&ottto_core::LocalDeviceCredentialBinding {
            device: device.clone(),
            credential_generation: 1,
            continuity: ottto_core::DeviceCredentialContinuity {
                owner: None,
                snapshot_namespace: Some(ottto_core::SnapshotNamespaceAlias {
                    namespace: namespace.clone(),
                    secret_commitment_sha256: crate::control::secret_sha256(SECRET),
                }),
            },
        })
        .unwrap();
    std::fs::write(
        secrets.join(ottto_core::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        SECRET,
    )
    .unwrap();
    let (loaded, secret) = crate::snapshot_client::load_snapshot_device_credentials().unwrap();
    assert_eq!(loaded, device);
    assert_eq!(
        crate::snapshot_sync::snapshot_upload_destination_namespace(&device, &secret),
        namespace
    );
    let daemon = test_daemon("otm_test");
    let progress_path = snapshot_upload_progress_path(session.path());
    let recovery =
        crate::snapshots::ProgressRecovery::for_index(&committed, session.path()).unwrap();
    let progress = SnapshotUploadProgress::load_with_recovery(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SOURCE),
        recovery,
    )
    .unwrap();
    let home = c.base.join("home");
    let destination = ContinuationFixture {
        home: home.clone(),
        support_dir: support.clone(),
        index_path: session.path().to_path_buf(),
        upload_progress_path: progress_path.clone(),
    };
    let preparation = SourcePreparation {
        account_witness: daemon.snapshot_scan_account_witness().unwrap(),
        scan_started_at: scan.census_window_end.clone(),
        activity_hint: serde_json::from_value(json!({"source":"codex",
            "server_time":"2026-10-27T08:00:00Z","last_data_at":null,
            "record_count_15m":0,"record_count_24h":0,
            "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
            "recommended_scan_after":"2026-10-27T08:05:00Z"}))
        .unwrap(),
        receipt_window_days: 183,
        upload_destination_namespace: namespace.clone(),
        receipt_client: client.clone(),
        upload_progress: progress,
        committed_index: committed,
        ..destination.preparation(false)
    };
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut retry = crate::snapshot_sync::live_snapshot_retry::LiveRetryOwner::closed();
    // The capture moves the store to a new generation inside this call; every
    // later boundary (relay token, upload, checkpoint, final save) checks the
    // store guard, so a guard built before the capture fails the pass here.
    finish_sync_source(
        preparation,
        index,
        scan,
        &client,
        &device,
        &secret,
        SOURCE,
        "e2-synthetic-machine",
        &home,
        &support,
        &daemon,
        &mut transport,
        &mut retry,
    )
    .unwrap_or_else(|error| panic!("the finish refused a boundary after the capture: {error:#}"));

    let batches = captured
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.contains("/agent-session-snapshots/batches"))
        .map(|request| http_request_json(request.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(batches.len(), 1, "exactly one body");
    let posted = batches[0]["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["source_session_id"].as_str().unwrap().to_string(),
                item["request_count"].as_u64().unwrap(),
                item["snapshot_fingerprint"].as_str().unwrap().to_string(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        posted,
        [(
            A.to_string(),
            96,
            expected.snapshots[0].snapshot_fingerprint.clone()
        )],
        "one summed body, no singleton, not held"
    );
    let mut prior = ScanIndex::load(session.path()).unwrap();
    assert!(prior.generation > generation, "the pass committed");
    assert!(
        prior.accepted_snapshot_fingerprint_recorded(&expected.snapshots[0].snapshot_fingerprint),
        "the accepted ACK settled"
    );
    fixture::codex_rearm_unsettled(&mut prior);
    assert!(
        prior
            .files
            .values()
            .all(|entry| !entry.source_file_fingerprint.is_empty()),
        "an acknowledged group never re-arms again"
    );
    for mode in [fixture::Mode::Restart, fixture::Mode::DiskRestore] {
        let ((_, quiet, modes), io) =
            fixture::observe_codex_quiet(|| page(&c, &E2ScanFixture::default(), prior.clone()));
        let mut route = fixture::scan_money(SOURCE, &prior, &quiet);
        route.mode = mode;
        route.modes = modes;
        route.io = io;
        assert_eq!(quiet.semantic_noop_count, paths.len());
        fixture::money_oracle::assert_quiet_restart_zero_bytes(&route);
    }
    crate::snapshot_sync::forget_carried_namespaces_for_test(&[DEVICE]);
}
