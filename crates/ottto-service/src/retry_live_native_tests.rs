// Native capture/wait/policy/ACK execution; credentials are synthetic adapters.
struct PiLiveFixture {
    home: RotationRoot,
    daemon: LocalDaemon,
    support: PathBuf,
    roots: Vec<PathBuf>,
    hint: crate::snapshot_client::ActivityHintResponse,
    index_path: PathBuf,
    progress_path: PathBuf,
    baseline: ScanIndex,
    working: ScanIndex,
    items: Vec<SnapshotItem>,
    progress: SnapshotUploadProgress,
    live: Option<live_snapshot_retry::LiveAuthority>,
}
impl PiLiveFixture {
    fn new() -> Self {
        assert!(
            std::env::var_os("PI_CODING_AGENT_DIR").is_none(),
            "synthetic live retry tests require an isolated Pi root"
        );
        let home = test_dir("retry-live-pi");
        std::fs::create_dir_all(&home).unwrap();
        let home = RotationRoot(home.canonicalize().unwrap());
        let roots = SnapshotSource::Pi.default_roots(&home.0);
        std::fs::create_dir_all(&roots[0]).unwrap();
        let row = r#"{"type":"message_end","message":{"model":"gpt-5.4","timestamp":1791280801000,"usage":{"input":100,"output":1}}}"#;
        std::fs::write(roots[0].join("one.jsonl"), format!("{row}\n")).unwrap();
        let support = home.0.join("support");
        std::fs::create_dir_all(&support).unwrap();
        let hint = Self::hint();
        let index_path = support.join("index.json");
        let progress_path = support.join("progress.json");
        let mut baseline = ScanIndex::default();
        baseline.save(&index_path).unwrap();
        let mut progress = test_upload_progress();
        progress.save(&progress_path).unwrap();
        // The real hook freezes inputs before the native parser starts.
        let live = live_snapshot_retry::LiveAuthority::capture(
            SnapshotSource::Pi,
            &home.0,
            &support,
            &hint,
            &progress.destination_namespace_hash,
            &Default::default(),
        )
        .unwrap();
        let mut working = baseline.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Pi,
            &roots,
            &mut working,
            "2026-10-06T10:05:00Z",
            30,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
        )
        .unwrap();
        apply_upload_policy(
            SnapshotSource::Pi,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut working);
        assert_eq!(scan.snapshots.len(), 1);
        let items = scan.snapshots;
        live.validate_capture(&home.0, &items).unwrap();
        Self {
            daemon: test_daemon(&"a".repeat(64)),
            home,
            support,
            roots,
            hint,
            index_path,
            progress_path,
            baseline,
            working,
            items,
            progress,
            live: Some(live),
        }
    }
    fn hint() -> crate::snapshot_client::ActivityHintResponse {
        serde_json::from_value(
            serde_json::json!({"source":"pi", "server_time":"2026-10-06T10:05:00Z",
            "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
            "local_usage_reconciliation_enabled":true,"backfill_window_days":30,
            "recommended_scan_after":"2026-10-06T10:10:00Z"}),
        )
        .unwrap()
    }
    fn capture(&mut self, delay: Duration) -> live_snapshot_retry::LiveRetryOwner {
        self.baseline = checkpoint_partial_snapshot_index(
            &self.working,
            &self.baseline,
            &self.progress,
            &self.items,
            &BTreeSet::new(),
            &self.index_path,
            &self.progress_path,
            || Ok(()),
        )
        .unwrap();
        let mut owner = live_snapshot_retry::LiveRetryOwner::isolated();
        assert!(owner.capture_after_shed(
            self.live.take().unwrap(),
            &self.home.0,
            SnapshotSource::Pi,
            &"a".repeat(64),
            SnapshotUploadPolicy::default(),
            self.daemon.snapshot_scan_account_witness().unwrap(),
            &self.items,
            &mut self.working,
            &self.baseline,
            &self.progress,
            &self.index_path,
            &self.progress_path,
            Instant::now(),
            delay
        ));
        owner
    }
}

#[test]
fn bounded_retry_live_inputs_decline_rewrites_replacements_new_paths_and_cutoff() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for change in [
        "rewrite",
        "replace",
        "new_file",
        "new_directory",
        "cutoff",
        "uncovered",
        "workspace",
    ] {
        let mut f = PiLiveFixture::new();
        match change {
            "rewrite" => {
                let path = f.roots[0].join("one.jsonl");
                let bytes = std::fs::read_to_string(&path).unwrap();
                std::fs::write(path, bytes.replace("100", "200")).unwrap();
            }
            "replace" => {
                let path = f.roots[0].join("one.jsonl");
                let bytes = std::fs::read(&path).unwrap();
                std::fs::remove_file(&path).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            "new_file" => {
                std::fs::write(f.roots[0].join("two.jsonl"), "{}\n").unwrap();
            }
            "new_directory" => {
                std::fs::create_dir(f.roots[0].join("new")).unwrap();
            }
            "cutoff" => {
                crate::backfill::save_backfill_state(
                    &f.support,
                    &crate::backfill::BackfillState {
                        backfill_cutoff_at: Some("2026-10-06T11:00:00Z".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
            }
            "workspace" => f.items[0].workspace_hash = Some("b".repeat(64)),
            _ => f.items[0].source_file_fingerprint = Some("b".repeat(64)),
        }
        assert!(
            f.live
                .as_ref()
                .unwrap()
                .validate_capture(&f.home.0, &f.items)
                .is_err(),
            "{change}"
        );
    }
    let f = PiLiveFixture::new();
    assert!(live_snapshot_retry::LiveAuthority::capture(
        SnapshotSource::Codex,
        &f.home.0,
        &f.support,
        &f.hint,
        "synthetic",
        &Default::default()
    )
    .is_none());
    let mut hint = PiLiveFixture::hint();
    hint.session_attribution_enabled = true;
    assert!(live_snapshot_retry::policy_seal(&hint).is_none());
    hint.session_attribution_enabled = false;
    hint.snapshot_head_cas_required = true;
    assert!(live_snapshot_retry::policy_seal(&hint).is_none());
    let closed = live_snapshot_retry::LiveRetryOwner::production();
    assert!(!closed.enabled());
    let deadline = Instant::now() + Duration::from_secs(300);
    assert_eq!(closed.wake_before(deadline), deadline);
}

#[test]
fn bounded_retry_live_wait_sends_without_scan_and_preserves_ordinary_deadline_and_ack() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let (_, allocation) = crate::retry_allocation_probe::measure(|| {
        let mut f = PiLiveFixture::new();
        let mut owner = f.capture(Duration::from_millis(30));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_bounded_retry_loopback_http_for_test();
        let mut ack: serde_json::Value =
            serde_json::from_str(&bounded_native_ack(&f.items[0])).unwrap();
        // Legal response amplification: every empty array string still owns
        // its native String slot. Exercise the byte cap's decoded allocation.
        ack["session_ids"] = serde_json::json!(vec![""; 20_000]);
        let ack = ack.to_string();
        assert!(ack.len() < crate::snapshot_retry::RESPONSE_BYTES);
        let hint=serde_json::to_string(&serde_json::json!({"source":"pi", "server_time":"2026-10-06T10:05:00Z",
            "last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
            "backfill_window_days":30,"recommended_scan_after":"2026-10-06T10:10:00Z"})).unwrap();
        let server = std::thread::spawn(move || {
            let mut trace = Vec::new();
            for body in ["{\"token\":\"fresh\"}", hint.as_str(), ack.as_str()] {
                let (mut stream, _) = listener.accept().unwrap();
                trace.push(String::from_utf8_lossy(&bounded_native_read(&mut stream)).into_owned());
                bounded_native_response(&mut stream, "200 OK", body);
            }
            trace
        });
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let daemon = &f.daemon;
        let mut turns = 0;
        let mut anchored = None;
        let started = Instant::now();
        collect_file_activity_with_retry(
            Duration::from_millis(150),
            None,
            &mut ClaudeAccountSwitchProbe::default(),
            |ordinary| {
                assert_eq!(*anchored.get_or_insert(ordinary), ordinary);
                owner.isolated_boundary(|page| {
                    turns += 1;
                    assert!(page.bound() <= 1024 * 1024);
                    page.budget.force_gzip_for_test();
                    let expected_account = page.authority();
                    let live = page.take_live_authority()?;
                    let result = page.turn_live(
                        &client,
                        &device,
                        "synthetic-secret",
                        live.policy(),
                        &mut || {
                            anyhow::ensure!(daemon.snapshot_retry_running().unwrap(), "stopped");
                            anyhow::ensure!(
                                daemon.snapshot_scan_account_witness().unwrap() == expected_account,
                                "account changed"
                            );
                            live.validate_inputs(&f.home.0)
                        },
                    );
                    assert!(
                        matches!(result, Ok(SnapshotPageOutcome::Settled { conflicted: 0 })),
                        "live retry failed: {}",
                        result
                            .as_ref()
                            .err()
                            .map(|e| e.to_string())
                            .unwrap_or_default()
                    );
                    page.restore_live_authority(live);
                    result
                });
                owner.wake_before(ordinary)
            },
            || None,
        );
        assert_eq!(turns, 1);
        assert!(started.elapsed() >= Duration::from_millis(150));
        let trace = server.join().unwrap();
        assert!(trace[0].starts_with("POST ") && trace[0].contains("/relay-token "));
        assert!(trace[1].starts_with("GET ") && trace[1].contains("/activity-hints "));
        assert!(trace[2].contains("/batches "));
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
        let checkpoint = ScanIndex::load(&f.index_path).unwrap();
        assert!(checkpoint.files.len() == 1);
        let mut recovered = checkpoint.clone();
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Pi,
            &f.roots,
            &mut recovered,
            "2026-10-06T10:06:00Z",
            30,
            MAX_BACKFILL_FILES_PER_SOURCE,
            false,
        )
        .unwrap();
        assert!(scan.snapshots.is_empty());
        assert!(serde_json::to_value(checkpoint)
            .unwrap()
            .get("completed_historical_replay_generation")
            .is_none());
        eprintln!("native_live_wait turns=1 tokens=1 policy_gets=1 batches=1 fresh_scan=0 exact_ack_restart=true ordinary_anchor_preserved=true");
    });
    eprintln!(
        "native_live_allocation requested_peak={} usable_peak={} allocations={}",
        allocation.requested_peak, allocation.usable_peak, allocation.allocations
    );
    assert!(allocation.requested_peak < 20 * 1024 * 1024);
}

#[test]
fn bounded_retry_live_policy_and_stop_fences_prevent_batch_and_publication() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    for change in ["policy", "stop", "account", "file", "cutoff"] {
        let mut f = PiLiveFixture::new();
        let mut owner = f.capture(Duration::ZERO);
        let before = std::fs::read(&f.index_path).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()))
            .with_bounded_retry_loopback_http_for_test();
        let server = if change != "policy" {
            None
        } else {
            Some(std::thread::spawn(move || {
                for body in [
                    "{\"token\":\"fresh\"}",
                    r#"{"source":"pi","server_time":"2026-10-06T10:05:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":30,"session_titles_enabled":false,"recommended_scan_after":"2026-10-06T10:10:00Z"}"#,
                ] {
                    let (mut stream, _) = listener.accept().unwrap();
                    bounded_native_read(&mut stream);
                    bounded_native_response(&mut stream, "200 OK", body);
                }
                listener.set_nonblocking(true).unwrap();
                listener
            }))
        };
        let daemon = &f.daemon;
        if change == "stop" {
            daemon.stop_for_trusted_client().unwrap();
        }
        if change == "account" {
            let mut account = daemon.account_for_trusted_client().unwrap();
            account.connected_at = Some("changed".into());
            daemon.clone().with_account(account);
        }
        if change == "file" {
            std::fs::write(f.roots[0].join("one.jsonl"), "{}\n").unwrap();
        }
        if change == "cutoff" {
            crate::backfill::save_backfill_state(
                &f.support,
                &crate::backfill::BackfillState {
                    backfill_cutoff_at: Some("2026-10-06T11:00:00Z".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let device = LocalDeviceBinding {
            sources: vec!["pi".into()],
            ..bounded_native_device()
        };
        let mut attempted = 0;
        owner.isolated_boundary(|page| {
            attempted += 1;
            let expected_account = page.authority();
            let live = page.take_live_authority()?;
            let result = page.turn_live(
                &client,
                &device,
                "synthetic-secret",
                live.policy(),
                &mut || {
                    anyhow::ensure!(daemon.snapshot_retry_running().unwrap(), "stopped");
                    anyhow::ensure!(
                        daemon.snapshot_scan_account_witness().unwrap() == expected_account,
                        "account changed"
                    );
                    live.validate_inputs(&f.home.0)
                },
            );
            assert!(result.is_err());
            assert_eq!(page.budget.posts_left(), 3);
            page.restore_live_authority(live);
            result
        });
        assert_eq!(attempted, 1);
        assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
        if let Some(server) = server {
            let listener = server.join().unwrap();
            assert!(matches!(listener.accept(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
        }
    }
}

#[test]
fn bounded_retry_live_legacy_reconciliation_declines_without_count_only_settlement() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut f = PiLiveFixture::new();
    // Reopen an actual native index in the pre-settlement-ledger shape.
    let mut value = serde_json::to_value(&f.working).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("accepted_snapshot_fingerprint_ledger_version");
    object.remove("accepted_snapshot_fingerprints");
    f.working = serde_json::from_value(value).unwrap();
    let (pending, changed) = f
        .working
        .prepare_legacy_settlement_reconciliation(SnapshotSource::Pi, 50);
    assert!(changed && pending.contains(&f.items[0].snapshot_fingerprint));
    assert!(f.working.legacy_settlement_ledger_needs_migration());
    f.working.save(&f.index_path).unwrap();
    f.baseline = f.working.clone();
    let checkpoint = checkpoint_partial_snapshot_index(
        &f.working,
        &f.baseline,
        &f.progress,
        &f.items,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    let before = std::fs::read(&f.index_path).unwrap();
    let mut owner = live_snapshot_retry::LiveRetryOwner::isolated();
    assert!(!owner.capture_after_shed(
        f.live.take().unwrap(),
        &f.home.0,
        SnapshotSource::Pi,
        &"a".repeat(64),
        SnapshotUploadPolicy::default(),
        f.daemon.snapshot_scan_account_witness().unwrap(),
        &f.items,
        &mut f.working,
        &checkpoint,
        &f.progress,
        &f.index_path,
        &f.progress_path,
        Instant::now(),
        Duration::ZERO
    ));
    let mut turns = 0;
    owner.isolated_boundary(|_| {
        turns += 1;
        unreachable!("legacy reconciliation cannot reach a retained token or POST")
    });
    assert_eq!(turns, 0);
    assert_eq!(std::fs::read(&f.index_path).unwrap(), before);
    // Existing ordinary delivery still refuses a count-only ACK for these
    // native legacy fingerprints. No alternative classifier is introduced.
    assert!(require_normal_write_ack_for_legacy_reconciliation(
        &accepted_batch(1),
        &pending,
        &pending
    )
    .is_err());
    let durable = SnapshotUploadProgress::load(
        &f.progress_path,
        &f.progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert!(!durable.contains_body(
        &f.items[0].snapshot_fingerprint,
        &snapshot_upload_body_witness(&f.items[0])
    ));
    eprintln!("native_live_legacy_refusal turns=0 no_token_or_post=true count_only_ack_rejected=true no_index_publish=true");
}

#[test]
fn bounded_retry_json_escape_admission_declines_before_retained_copy_and_wire_growth() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut f = PiLiveFixture::new();
    f.items[0].session_display_name = Some("\u{0001}".repeat(30_000));
    assert!(!crate::snapshot_retry::json_fits(
        &f.items,
        crate::snapshot_retry::REQUEST_BYTES / 2
    ));
    let (_, stats) = crate::retry_allocation_probe::measure(|| {
        assert!(bounded_snapshot_retry::PreparedRetry::capture(
            SnapshotSource::Pi,
            &"a".repeat(64),
            SnapshotUploadPolicy::default(),
            [1; 32],
            &f.items,
            &f.working,
            &f.baseline,
            &f.progress,
            &f.index_path,
            &f.progress_path,
            Instant::now(),
            Duration::ZERO,
            1024 * 1024
        )
        .is_none());
    });
    assert!(stats.requested_peak < 16 * 1024);
    assert!(
        crate::snapshot_retry::encode_json(&f.items, crate::snapshot_retry::REQUEST_BYTES / 2)
            .is_err()
    );
    eprintln!(
        "native_escape_refusal requested_peak={} no_retained_copy=true",
        stats.requested_peak
    );
}
