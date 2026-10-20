// Exercise the actual finish_sync_source exit, not a copied settlement order.
// All transcripts, credentials and HTTP responses are synthetic and local.
use super::*;

#[derive(Clone, Copy, Debug)]
enum FinishOutcome {
    Permanent,
    Retryable,
    PermanentStatusFailure,
    PermanentWithoutSidecars,
    PermanentUncleanCensus,
}

struct FinishServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    offered: Arc<Mutex<Vec<serde_json::Value>>>,
    terminal: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl FinishServer {
    fn new(outcome: FinishOutcome) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let bodies = offered.clone();
        let terminal = Arc::new(Mutex::new(Vec::new()));
        let statuses = terminal.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic finish accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw = request.split_once("\r\n\r\n").unwrap().1;
                let value: serde_json::Value = if raw.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw).unwrap()
                };
                let mut status = "200 OK";
                let response = if request.contains("/relay-token") {
                    serde_json::json!({"token":"synthetic-finish-token","expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    serde_json::json!({"source":"claude_code","server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"})
                } else if request.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["claude_code"]})
                } else if let Some(items) = value.get("snapshots").and_then(|v| v.as_array()) {
                    assert!(!items.is_empty());
                    bodies.lock().unwrap().extend(items.iter().cloned());
                    let retryable = matches!(outcome, FinishOutcome::Retryable);
                    let references = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    let rejected = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "reason":"invalid","detail":"synthetic finish refusal",
                                "permanent":true,"occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({"accepted":0,"sessions_reconciled":0,"session_ids":[],
                        "disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                        "unchanged_entities":[],
                        "conflict_entities":if retryable { references } else { Vec::new() },
                        "rejected_entities":if retryable { Vec::new() } else { rejected }})
                } else {
                    if value["report_kind"] == "scan_status" {
                        statuses.lock().unwrap().push(value.clone());
                        if matches!(outcome, FinishOutcome::PermanentStatusFailure) {
                            status = "503 Service Unavailable";
                        }
                    }
                    serde_json::json!({"accepted":true,"source":"claude_code","machine_id":"otm_test","disabled":false})
                };
                bounded_native_response(&mut stream, status, &response.to_string());
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            offered,
            terminal,
        }
    }
}

impl Drop for FinishServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn permanent_finish_pipeline(outcome: FinishOutcome, expected_valid: bool) {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} supported_positive=UNEXECUTED layout_supported=false").unwrap();
        return;
    }
    let fixture = IdentityPipelineHome::new();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("permanent-finish-support");
    let secrets = fixture.base.join("permanent-finish-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(outcome);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "permanent-finish-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    if !matches!(outcome, FinishOutcome::PermanentWithoutSidecars) {
        write_native_bootstrap_sidecars(&fixture, &support);
    }
    if matches!(outcome, FinishOutcome::PermanentUncleanCensus) {
        // A real parse loss makes the native census unclean. Missing optional
        // sidecars alone does not invalidate this root's native request census.
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
        std::fs::OpenOptions::new()
            .append(true)
            .open(transcript)
            .unwrap()
            .write_all(b"{\n")
            .unwrap();
    }
    let client = SnapshotApiClient::new(server.url.clone());
    let daemon = test_daemon("otm_test");
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let cycles = if matches!(outcome, FinishOutcome::Permanent) {
        3
    } else {
        1
    };
    for cycle in 0..cycles {
        cadence.next_due_cycle();
        let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
            prepare_sync_source(
                &client,
                &device,
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &fixture.home,
                &support,
                &daemon,
                &mut transport,
                daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("real due native preparation");
        assert_eq!(frame.native_comparison_lease.as_ref().unwrap().allowed(), cycle == 2,
        "cycle {cycle}: no synthetic permit; the third same-context preparation must use its actual saved predecessor");
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        let unclean = matches!(outcome, FinishOutcome::PermanentUncleanCensus);
        assert_eq!(scan.census_complete, !unclean);
        assert_eq!(scan.malformed_json_line_count, usize::from(unclean));
        assert_eq!(
            scan.scanned_file_count,
            usize::from(cycle < 2),
            "actual native read, then ordinary quiet page"
        );
        if cycle == 0 {
            assert_eq!(scan.snapshots.len(), 1);
        }
        let index_path = preparation.index_path.clone();
        let progress_path = preparation.upload_progress_path.clone();
        let result = crate::agent_status_refresh::with_test_collection(collection(), || {
            finish_sync_source(
                preparation,
                index,
                scan,
                &client,
                &device,
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &fixture.home,
                &support,
                &daemon,
                &mut transport,
                &mut retry,
            )
        });
        assert_eq!(
            result.is_ok(),
            !matches!(outcome, FinishOutcome::Retryable),
            "{outcome:?}: {result:?}"
        );
        let saved = ScanIndex::load(&index_path).unwrap();
        assert!(saved.generation > 0, "real selected save");
        let offered = server.offered.lock().unwrap();
        assert_eq!(offered.len(), 1);
        let fingerprint = offered[0]["snapshot_fingerprint"].as_str().unwrap();
        assert!(
            !saved.accepted_snapshot_fingerprint_recorded(fingerprint),
            "a refusal is never an ACK"
        );
        assert!(saved
            .quarantined_snapshot_fingerprints
            .contains_key(fingerprint));
        let progress = SnapshotUploadProgress::load(
            &progress_path,
            &snapshot_upload_destination_namespace(&device, "device-secret"),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        assert!(!progress.accepted_fingerprints.contains(fingerprint));
        if !matches!(outcome, FinishOutcome::Retryable) {
            assert!(
                progress.permanent_rejections.contains_key(fingerprint),
                "permanent refusal debt survives finish"
            );
        }
        let terminal = server.terminal.lock().unwrap();
        assert_eq!(
            terminal.len(),
            cycle + 1,
            "one terminal report per actual finish"
        );
        assert_eq!(
            terminal[cycle]["last_error_code"],
            if matches!(outcome, FinishOutcome::Retryable) {
                "server_error"
            } else {
                "backend_validation_error"
            }
        );
        let retained_valid = daemon.native_comparison.retained_valid_for_test();
        assert_eq!(
            terminal[cycle]["last_malformed_json_line_count"],
            usize::from(unclean)
        );
        assert_eq!(terminal[cycle]["last_census_complete"], !unclean);
        if cycle > 0 || !matches!(outcome, FinishOutcome::Permanent) {
            assert_eq!(retained_valid, expected_valid,
            "{outcome:?}, cycle {cycle}: only an earned native conjunction or actual predecessor permit plus durable settlement and successful status may reach the common lease finalizer");
        }
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} cycle={cycle} selected_save=true refusal_not_accepted=true refusal_debt_retained=true retained_valid={retained_valid}").unwrap();
        if cycle == 0 && matches!(outcome, FinishOutcome::Permanent) {
            // Change only the source revision, not usage or its body witness. The
            // normal-window pass must perform its own native parse and retain the
            // original permanent refusal without offering that body again.
            let transcript = fixture
                .home
                .join(".claude/projects/-synthetic-repo")
                .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
            std::fs::OpenOptions::new()
                .append(true)
                .open(transcript)
                .unwrap()
                .write_all(b"\n")
                .unwrap();
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn permanent_finish_real_pipeline_preserves_earned_native_lease() {
    permanent_finish_pipeline(FinishOutcome::Permanent, true);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn permanent_finish_real_pipeline_keeps_ineligible_exits_revoked() {
    for outcome in [
        FinishOutcome::Retryable,
        FinishOutcome::PermanentStatusFailure,
        FinishOutcome::PermanentUncleanCensus,
    ] {
        permanent_finish_pipeline(outcome, false);
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn permanent_finish_real_pipeline_native_census_does_not_require_optional_sidecars() {
    permanent_finish_pipeline(FinishOutcome::PermanentWithoutSidecars, true);
}
