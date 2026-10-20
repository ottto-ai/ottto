// Exercise the actual finish_sync_source exit, not a copied settlement order.
// All transcripts, credentials and HTTP responses are synthetic and local.
use super::*;

#[derive(Clone, Copy, Debug)]
enum FinishOutcome {
    Permanent,
    Retryable,
    PermanentStatusFailure,
    PermanentIncompleteEvidence,
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
                    let permanent = !matches!(outcome, FinishOutcome::Retryable);
                    let rejected = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "reason":"invalid","detail":"synthetic finish refusal",
                                "permanent":permanent,"occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({"accepted":0,"sessions_reconciled":0,"session_ids":[],
                        "disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                        "unchanged_entities":[],"conflict_entities":[],"rejected_entities":rejected})
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
    let _cadence = IdentityPipelineCadence::new();
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
    if !matches!(outcome, FinishOutcome::PermanentIncompleteEvidence) {
        write_native_bootstrap_sidecars(&fixture, &support);
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
    assert!(
        !frame.native_comparison_lease.as_ref().unwrap().allowed(),
        "no synthetic or pre-existing permit"
    );
    let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
    assert!(scan.census_complete);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(scan.snapshots.len(), 1);
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
    assert_eq!(terminal.len(), 1, "one unchanged terminal report");
    assert_eq!(
        terminal[0]["last_error_code"],
        if matches!(outcome, FinishOutcome::Retryable) {
            "server_error"
        } else {
            "backend_validation_error"
        }
    );
    assert_eq!(daemon.native_comparison.retained_valid_for_test(), expected_valid,
        "{outcome:?}: only an earned native conjunction plus durable settlement and successful status may reach the common lease finalizer");
    writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} real_native_read=true selected_save=true refusal_not_accepted=true refusal_debt_retained=true retained_valid={expected_valid}").unwrap();
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
        FinishOutcome::PermanentIncompleteEvidence,
    ] {
        permanent_finish_pipeline(outcome, false);
    }
}
