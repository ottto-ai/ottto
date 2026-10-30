// Exercise the actual finish_sync_source exit, not a copied settlement order.
// All transcripts, credentials and HTTP responses are synthetic and local.
// Real prepare/finish calls mutate the process-global source manifest cache,
// so their tests also hold source_manifests across the whole cycle.
use super::*;

#[derive(Clone, Copy, Debug)]
enum FinishOutcome {
    Accept,
    Permanent,
    Retryable,
    PermanentStatusFailure,
    PermanentWithoutSidecars,
    PermanentUncleanCensus,
    /// Every body is refused for a reason the backend already dominates with
    /// an accepted record; `admit_residue` is the activity-hint admission of
    /// `census_residue_status:v1`.
    Dominated {
        reason: &'static str,
        admit_residue: bool,
    },
}

impl FinishOutcome {
    /// The refused body is retained, then two quiet cycles re-disclose it.
    fn retains_refusal_across_quiet_cycles(self) -> bool {
        matches!(
            self,
            FinishOutcome::Permanent | FinishOutcome::Dominated { .. }
        )
    }
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
                    let mut hint = serde_json::json!({"source":"claude_code","server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"});
                    if matches!(
                        outcome,
                        FinishOutcome::Dominated {
                            admit_residue: true,
                            ..
                        }
                    ) {
                        hint["census_residue_status_contract"] =
                            crate::snapshot_client::CENSUS_RESIDUE_STATUS_CONTRACT.into();
                    }
                    hint
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
                    let reason = match outcome {
                        FinishOutcome::Dominated { reason, .. } => reason,
                        _ => "invalid",
                    };
                    let rejected = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "reason":reason,"detail":"synthetic finish refusal",
                                "permanent":true,"occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    if matches!(outcome, FinishOutcome::Accept) {
                        let entities = items.iter().map(|item| {
                            assert!(item.get("cache_observations").is_none());
                            assert!(item.get("context_curve").is_none());
                            let mut payload = serde_json::Map::new();
                            for key in ["session_account_evidence", "tool_usage", "tool_usage_truncated"] {
                                if let Some(value) = item.get(key) { payload.insert(key.into(), value.clone()); }
                            }
                            let exclusive = item.get("usage_accounting_contract").and_then(|v| v.as_str())
                                == Some("session_exclusive_reported_usage:v1");
                            let version = item.get("session_account_evidence").is_some()
                                .then_some(if exclusive { 8u64 } else { 7u64 });
                            let digest = format!("{:x}", Sha256::digest(
                                crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()));
                            serde_json::json!({"source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
                                "body_witness_version":version,"body_witness_digest":version.map(|_|digest)})
                        }).collect::<Vec<_>>();
                        serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                            "session_ids":[],"disabled":false,"disabled_reason":null,
                            "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":entities,
                            "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]})
                    } else {
                        serde_json::json!({"accepted":0,"sessions_reconciled":0,"session_ids":[],
                        "disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                        "unchanged_entities":[],
                        "conflict_entities":if retryable { references } else { Vec::new() },
                        "rejected_entities":if retryable { Vec::new() } else { rejected }})
                    }
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
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        return terminal_off_on_permanent_finish_pipeline(outcome, expected_valid);
    }
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
        // Keep the healthy root available for an actual permanent response;
        // a separate damaged transcript prevents a complete native census.
        let broken = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join("2448a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        std::fs::write(broken, b"{\n").unwrap();
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
    let cycles = if outcome.retains_refusal_across_quiet_cycles() {
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
        let selected_losses = [
            scan.malformed_json_line_count,
            scan.invalid_utf8_line_count,
            scan.unreadable_path_count,
            scan.disappeared_file_count,
        ];
        assert_eq!(
            scan.scanned_file_count,
            if unclean { 2 } else { usize::from(cycle < 2) },
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
            match outcome {
                FinishOutcome::Retryable => "server_error",
                // The refused body is settled unproven-terminal residue; the
                // server already owns a better or newer record for it.
                FinishOutcome::Dominated {
                    admit_residue: true,
                    ..
                } => "census_residue",
                // A backend that predates the admission reads settled residue
                // only in the legacy shape.
                FinishOutcome::Dominated {
                    admit_residue: false,
                    ..
                } => "parse_error",
                _ => "backend_validation_error",
            },
            "{outcome:?}, cycle {cycle}"
        );
        if let FinishOutcome::Dominated { admit_residue, .. } = outcome {
            assert_eq!(terminal[cycle]["last_census_residue_settled"], true);
            assert_eq!(terminal[cycle]["last_snapshot_unproven_terminal_count"], 1);
            assert_eq!(
                terminal[cycle]["consecutive_failures"],
                u64::from(!admit_residue)
            );
            assert_eq!(
                terminal[cycle]["last_success_at"].is_string(),
                admit_residue
            );
        }
        let retained_valid = daemon.native_comparison.retained_valid_for_test();
        for (key, expected) in [
            "last_malformed_json_line_count",
            "last_invalid_utf8_line_count",
            "last_unreadable_path_count",
            "last_disappeared_file_count",
        ]
        .into_iter()
        .zip(selected_losses)
        {
            assert_eq!(
                terminal[cycle][key], expected,
                "terminal disclosure must equal the real selected scan, not a fixture assumption"
            );
        }
        assert_eq!(terminal[cycle]["last_census_complete"], !unclean);
        if cycle > 0 || !outcome.retains_refusal_across_quiet_cycles() {
            assert_eq!(retained_valid, expected_valid,
            "{outcome:?}, cycle {cycle}: only an earned native conjunction or actual predecessor permit plus durable settlement and successful status may reach the common lease finalizer");
        }
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} cycle={cycle} selected_save=true refusal_not_accepted=true refusal_debt_retained=true retained_valid={retained_valid}").unwrap();
        if cycle == 0 && outcome.retains_refusal_across_quiet_cycles() {
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

fn terminal_off_on_permanent_finish_pipeline(outcome: FinishOutcome, expected_valid: bool) {
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
        // Keep the healthy root available for an actual permanent response;
        // a separate damaged transcript prevents a complete native census.
        let broken = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join("2448a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        std::fs::write(broken, b"{\n").unwrap();
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
    let cycles = if outcome.retains_refusal_across_quiet_cycles() {
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
        assert!(!frame.native_comparison_lease.as_ref().unwrap().allowed(),
        "cycle {cycle}: no synthetic permit; terminal-off cannot admit a completion-derived predecessor");
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        let unclean = matches!(outcome, FinishOutcome::PermanentUncleanCensus);
        assert!(crate::snapshots::claude_terminal_off());
        assert!(!scan.census_complete);
        let selected_losses = [
            scan.malformed_json_line_count,
            scan.invalid_utf8_line_count,
            scan.unreadable_path_count,
            scan.disappeared_file_count,
        ];
        assert_eq!(
            scan.scanned_file_count,
            if cycle == 0 {
                if unclean {
                    2
                } else {
                    1
                }
            } else {
                0
            },
            "#901 exact current-context ACK stops UploadContext reselection"
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
            match outcome {
                FinishOutcome::Retryable => "server_error",
                // The refused body is settled unproven-terminal residue; the
                // server already owns a better or newer record for it.
                FinishOutcome::Dominated {
                    admit_residue: true,
                    ..
                } => "census_residue",
                // A backend that predates the admission reads settled residue
                // only in the legacy shape.
                FinishOutcome::Dominated {
                    admit_residue: false,
                    ..
                } => "parse_error",
                _ => "backend_validation_error",
            },
            "{outcome:?}, cycle {cycle}"
        );
        if let FinishOutcome::Dominated { admit_residue, .. } = outcome {
            assert_eq!(terminal[cycle]["last_census_residue_settled"], true);
            assert_eq!(terminal[cycle]["last_snapshot_unproven_terminal_count"], 1);
            assert_eq!(
                terminal[cycle]["consecutive_failures"],
                u64::from(!admit_residue)
            );
            assert_eq!(
                terminal[cycle]["last_success_at"].is_string(),
                admit_residue
            );
        }
        let retained_valid = daemon.native_comparison.retained_valid_for_test();
        for (key, expected) in [
            "last_malformed_json_line_count",
            "last_invalid_utf8_line_count",
            "last_unreadable_path_count",
            "last_disappeared_file_count",
        ]
        .into_iter()
        .zip(selected_losses)
        {
            assert_eq!(
                terminal[cycle][key], expected,
                "terminal disclosure must equal the real selected scan, not a fixture assumption"
            );
        }
        assert_eq!(terminal[cycle]["last_census_complete"], false);
        if cycle > 0 || !outcome.retains_refusal_across_quiet_cycles() {
            assert_eq!(retained_valid, expected_valid,
            "{outcome:?}, cycle {cycle}: only an earned native conjunction or actual predecessor permit plus durable settlement and successful status may reach the common lease finalizer");
        }
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} cycle={cycle} selected_save=true refusal_not_accepted=true refusal_debt_retained=true retained_valid={retained_valid}").unwrap();
        if cycle == 0 && outcome.retains_refusal_across_quiet_cycles() {
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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn permanent_finish_real_pipeline_preserves_earned_native_lease() {
    permanent_finish_pipeline(FinishOutcome::Permanent, true);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_real_pipeline_preserves_earned_native_lease() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    permanent_finish_pipeline(FinishOutcome::Permanent, false);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_real_pipeline_keeps_ineligible_exits_revoked() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn permanent_finish_real_pipeline_native_census_does_not_require_optional_sidecars() {
    permanent_finish_pipeline(FinishOutcome::PermanentWithoutSidecars, true);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_real_pipeline_native_census_does_not_require_optional_sidecars() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    permanent_finish_pipeline(FinishOutcome::PermanentWithoutSidecars, false);
}

/// T1/T6: the page's only permanent refusals are dominated, no holds. The
/// first refusal and both quiet retained cycles report settled residue, never
/// `backend_validation_error`, and the native lease outcome is unchanged.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn permanent_finish_dominated_refusals_report_settled_residue_every_cycle() {
    for reason in [
        "usage_accounting_authority_downgrade",
        "accepted_log_stale_older_upload",
    ] {
        permanent_finish_pipeline(
            FinishOutcome::Dominated {
                reason,
                admit_residue: true,
            },
            true,
        );
    }
}

/// T1/T6: the page's only permanent refusals are dominated, no holds. The
/// first refusal and both quiet retained cycles report settled residue, never
/// `backend_validation_error`, and the native lease outcome is unchanged.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_dominated_refusals_report_settled_residue_every_cycle() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for reason in [
        "usage_accounting_authority_downgrade",
        "accepted_log_stale_older_upload",
    ] {
        permanent_finish_pipeline(
            FinishOutcome::Dominated {
                reason,
                admit_residue: true,
            },
            true,
        );
    }
}

/// T4: a backend that does not admit `census_residue_status:v1` never
/// receives the `census_residue` code.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn permanent_finish_dominated_refusals_never_send_unadmitted_census_residue() {
    permanent_finish_pipeline(
        FinishOutcome::Dominated {
            reason: "usage_accounting_authority_downgrade",
            admit_residue: false,
        },
        true,
    );
}

/// T4: a backend that does not admit `census_residue_status:v1` never
/// receives the `census_residue` code.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_dominated_refusals_never_send_unadmitted_census_residue() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    permanent_finish_pipeline(
        FinishOutcome::Dominated {
            reason: "usage_accounting_authority_downgrade",
            admit_residue: false,
        },
        true,
    );
}

/// F1: body A is refused as dominated, then a newer body B of the same entity
/// gets a retryable conflict. A conflict finish leaves exactly one durable
/// fact for B: the index-owned `RetryPending(B)` quarantine beside the
/// permanent refusal of A. This fixture cannot vary only witness-bound
/// evidence, so that record is installed with the production retry deadline.
/// While B is pending, quiet cycles must not report a settled success.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn permanent_finish_dominated_refusal_with_pending_newer_body_is_not_success() {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "permanent_finish_pending_newer_body: supported_positive=UNEXECUTED layout_supported=false").unwrap();
        return;
    }
    let fixture = IdentityPipelineHome::new();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("pending-newer-body-support");
    let secrets = fixture.base.join("pending-newer-body-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Dominated {
        reason: "usage_accounting_authority_downgrade",
        admit_residue: true,
    });
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "pending-newer-body-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    write_native_bootstrap_sidecars(&fixture, &support);
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
    for cycle in 0..3 {
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
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(scan.census_complete);
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
        assert!(result.is_ok(), "cycle {cycle}: {result:?}");
        let fingerprint = {
            let offered = server.offered.lock().unwrap();
            assert_eq!(offered.len(), 1, "cycle {cycle}: no body is offered again");
            offered[0]["snapshot_fingerprint"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let progress = SnapshotUploadProgress::load(
            &progress_path,
            &snapshot_upload_destination_namespace(&device, "device-secret"),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        assert!(
            progress.permanent_rejections.contains_key(&fingerprint),
            "cycle {cycle}: the refusal of body A is retained"
        );
        let mut saved = ScanIndex::load(&index_path).unwrap();
        assert!(!saved.accepted_snapshot_fingerprint_recorded(&fingerprint));
        let terminal = server.terminal.lock().unwrap();
        assert_eq!(terminal.len(), cycle + 1);
        if cycle == 0 {
            assert_eq!(terminal[cycle]["last_error_code"], "census_residue");
            let record = saved
                .quarantined_snapshot_fingerprints
                .get_mut(&fingerprint)
                .unwrap();
            assert_eq!(
                record.disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            record.upload_body_witness = Some("b".repeat(64));
            record.failed_reconstruction_count = 1;
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
            record.retry_after_unix_seconds = quarantine_retry_after(&fingerprint);
            saved.save(&index_path).unwrap();
        } else {
            assert_eq!(
                saved.quarantined_snapshot_fingerprints[&fingerprint].disposition,
                SnapshotQuarantineDisposition::RetryPending,
                "cycle {cycle}: body B is still pending"
            );
            assert_eq!(
                terminal[cycle]["last_error_code"], "backend_validation_error",
                "cycle {cycle}: a refusal of an older body cannot settle a pending newer body"
            );
        }
        writeln!(
            std::io::stderr().lock(),
            "permanent_finish_pending_newer_body: cycle={cycle} code={}",
            terminal[cycle]["last_error_code"]
        )
        .unwrap();
    }
}

/// F1: body A is refused as dominated, then a newer body B of the same entity
/// gets a retryable conflict. A conflict finish leaves exactly one durable
/// fact for B: the index-owned `RetryPending(B)` quarantine beside the
/// permanent refusal of A. This fixture cannot vary only witness-bound
/// evidence, so that record is installed with the production retry deadline.
/// While B is pending, quiet cycles must not report a settled success.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_permanent_finish_dominated_refusal_with_pending_newer_body_is_not_success() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "permanent_finish_pending_newer_body: supported_positive=UNEXECUTED layout_supported=false").unwrap();
        return;
    }
    let fixture = IdentityPipelineHome::new();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("pending-newer-body-support");
    let secrets = fixture.base.join("pending-newer-body-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Dominated {
        reason: "usage_accounting_authority_downgrade",
        admit_residue: true,
    });
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "pending-newer-body-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    write_native_bootstrap_sidecars(&fixture, &support);
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
    for cycle in 0..3 {
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
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(!scan.census_complete);
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
        assert!(result.is_ok(), "cycle {cycle}: {result:?}");
        let fingerprint = {
            let offered = server.offered.lock().unwrap();
            assert_eq!(offered.len(), 1, "cycle {cycle}: no body is offered again");
            offered[0]["snapshot_fingerprint"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let progress = SnapshotUploadProgress::load(
            &progress_path,
            &snapshot_upload_destination_namespace(&device, "device-secret"),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        assert!(
            progress.permanent_rejections.contains_key(&fingerprint),
            "cycle {cycle}: the refusal of body A is retained"
        );
        let mut saved = ScanIndex::load(&index_path).unwrap();
        assert!(!saved.accepted_snapshot_fingerprint_recorded(&fingerprint));
        let terminal = server.terminal.lock().unwrap();
        assert_eq!(terminal.len(), cycle + 1);
        if cycle == 0 {
            assert_eq!(terminal[cycle]["last_error_code"], "census_residue");
            let record = saved
                .quarantined_snapshot_fingerprints
                .get_mut(&fingerprint)
                .unwrap();
            assert_eq!(
                record.disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            record.upload_body_witness = Some("b".repeat(64));
            record.failed_reconstruction_count = 1;
            record.disposition = SnapshotQuarantineDisposition::RetryPending;
            record.retry_after_unix_seconds = quarantine_retry_after(&fingerprint);
            saved.save(&index_path).unwrap();
        } else {
            assert_eq!(
                saved.quarantined_snapshot_fingerprints[&fingerprint].disposition,
                SnapshotQuarantineDisposition::RetryPending,
                "cycle {cycle}: body B is still pending"
            );
            assert_eq!(
                terminal[cycle]["last_error_code"], "backend_validation_error",
                "cycle {cycle}: a refusal of an older body cannot settle a pending newer body"
            );
        }
        writeln!(
            std::io::stderr().lock(),
            "permanent_finish_pending_newer_body: cycle={cycle} code={}",
            terminal[cycle]["last_error_code"]
        )
        .unwrap();
    }
}

/// StateMissing M1 (SOURCE d680b524) through the real `prepare_sync_source`
/// and `finish_sync_source`, the synthetic backend recording every offered
/// body. Beside the fixture's own session, family `R` has a root transcript
/// and subagent files `agents`; a first cycle sends everything. Then `R.jsonl`
/// is removed, the list is installed naming `R_<listed_member>`, or `R`
/// itself when `listed_member` is `None`, and the saved
/// index is corrupted, so the next load quarantines it and every file comes
/// back new (prior history). Returns the bodies the rebuilt cycle offered and
/// the local diagnostics it recorded.
fn rootless_family_real_pipeline(
    name: &str,
    agents: &[&str],
    listed_member: Option<&str>,
) -> Option<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
    const FAMILY: &str = "2558a80a-f36e-4cbc-a5bb-50fc66430ba5";
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(
            std::io::stderr().lock(),
            "{name}: supported_positive=UNEXECUTED layout_supported=false"
        )
        .unwrap();
        return None;
    }
    let fixture = IdentityPipelineHome::new();
    let project = fixture.home.join(".claude/projects/-synthetic-repo");
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(170))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let line = |agent: Option<&str>| {
        let request = agent.unwrap_or("root");
        serde_json::json!({"timestamp": at, "type": "assistant", "sessionId": FAMILY,
            "agentId": agent, "isSidechain": agent.is_some(),
            "requestId": format!("req_{request}"), "message": {"id": format!("m_{request}"),
            "model": "claude-haiku-4-5", "usage": {"input_tokens": 10, "output_tokens": 1}}})
        .to_string()
            + "\n"
    };
    let root_file = project.join(format!("{FAMILY}.jsonl"));
    std::fs::write(&root_file, line(None)).unwrap();
    let subagents = project.join(FAMILY).join("subagents");
    std::fs::create_dir_all(&subagents).unwrap();
    for agent in agents {
        std::fs::write(subagents.join(format!("{agent}.jsonl")), line(Some(agent))).unwrap();
    }
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join(format!("{name}-support"));
    let secrets = fixture.base.join(format!("{name}-secrets"));
    std::fs::create_dir_all(support.join("snapshots")).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: format!("{name}-device"),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    write_native_bootstrap_sidecars(&fixture, &support);
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
    let mut cycle = || {
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
        .expect("real due preparation");
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        let index_path = preparation.index_path.clone();
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
        assert!(result.is_ok(), "{name}: {result:?}");
        index_path
    };
    let index_path = cycle();
    {
        let mut offered = server.offered.lock().unwrap();
        for agent in agents {
            let id = format!("{FAMILY}_{agent}");
            assert!(
                offered
                    .iter()
                    .any(|item| item["source_session_id"] == id.as_str()),
                "{name}: the first cycle sends {agent}"
            );
        }
        offered.clear();
    }
    std::fs::remove_file(&root_file).unwrap();
    let listed = listed_member.map_or_else(|| FAMILY.to_owned(), |stem| format!("{FAMILY}_{stem}"));
    std::fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("# synthetic\n{:x}\n", Sha256::digest(listed.as_bytes())),
    )
    .unwrap();
    std::fs::write(&index_path, b"{not json").unwrap();
    let ((), lines) = crate::local_resource_diagnostics::capture(|| {
        cycle();
    });
    let offered = server.offered.lock().unwrap().clone();
    let family_offers = offered
        .iter()
        .filter_map(|item| item["source_session_id"].as_str())
        .filter(|id| id.starts_with(FAMILY))
        .collect::<Vec<_>>();
    assert!(
        family_offers.is_empty(),
        "{name}: no body of the listed family is offered: {family_offers:?}"
    );
    assert!(
        offered
            .iter()
            .any(|item| item["source_session_id"] == IDENTITY_PIPELINE_ROOT),
        "{name}: the unlisted session's history is still offered"
    );
    Some((offered, lines))
}

/// The members the history gate held only through a listed family root
/// whose root file is absent, as the real cycle's diagnostics recorded them.
fn root_absent_family_closure_count(lines: &[serde_json::Value]) -> u64 {
    lines
        .iter()
        .filter(|line| line["stage"] == "claude_reemission_family_closure_root_absent_excluded")
        .map(|line| {
            line["counts"]["claude_reemission_family_closure_root_absent_excluded"]
                .as_u64()
                .unwrap()
        })
        .sum()
}

/// SOURCE d680b524 (a), real prepare/finish: the list names only
/// `R_agent-a`, `R.jsonl` is gone. No sibling is offered, whether traversal
/// decides it after agent-a (`agent-b`) or before it (`agent-0`); the sibling
/// counts once (agent-a is listed by its own line).
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn rootless_family_member_list_offers_no_sibling_through_the_real_pipeline() {
    for (sibling, name) in [
        ("agent-b", "rootless-member-after"),
        ("agent-0", "rootless-member-before"),
    ] {
        let Some((_, lines)) =
            rootless_family_real_pipeline(name, &["agent-a", sibling], Some("agent-a"))
        else {
            return;
        };
        assert_eq!(root_absent_family_closure_count(&lines), 1, "{name}");
    }
}

/// SOURCE d680b524 (a), real prepare/finish: the list names only
/// `R_agent-a`, `R.jsonl` is gone. No sibling is offered, whether traversal
/// decides it after agent-a (`agent-b`) or before it (`agent-0`); the sibling
/// counts once (agent-a is listed by its own line).
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_rootless_family_member_list_offers_no_sibling_through_the_real_pipeline() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for (sibling, name) in [
        ("agent-b", "rootless-member-after"),
        ("agent-0", "rootless-member-before"),
    ] {
        let Some((_, lines)) =
            rootless_family_real_pipeline(name, &["agent-a", sibling], Some("agent-a"))
        else {
            return;
        };
        assert_eq!(root_absent_family_closure_count(&lines), 1, "{name}");
    }
}

/// SOURCE d680b524 (b), real prepare/finish: the list names the root `R`,
/// `R.jsonl` is gone and only subagent files remain. None is offered, and
/// each counts as held through the absent root.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn rootless_family_root_list_offers_no_subagent_through_the_real_pipeline() {
    let Some((_, lines)) =
        rootless_family_real_pipeline("rootless-root-listed", &["agent-a", "agent-b"], None)
    else {
        return;
    };
    assert_eq!(root_absent_family_closure_count(&lines), 2);
}

/// SOURCE d680b524 (b), real prepare/finish: the list names the root `R`,
/// `R.jsonl` is gone and only subagent files remain. None is offered, and
/// each counts as held through the absent root.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn terminal_off_on_rootless_family_root_list_offers_no_subagent_through_the_real_pipeline() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let Some((_, lines)) =
        rootless_family_real_pipeline("rootless-root-listed", &["agent-a", "agent-b"], None)
    else {
        return;
    };
    assert_eq!(root_absent_family_closure_count(&lines), 2);
}

// Same real finish fixture; the new tests own only a test-thread observer.
pub(crate) mod prior_index_lifetime_tests {
    include!("prior_index_lifetime_tests.rs");
}

// Same real prepare/finish pipeline; owns a test-thread re-offer clock.
pub(crate) mod reason_reoffer_pipeline_tests {
    include!("reason_reoffer_pipeline_tests.rs");
}

thread_local! {
    static ACK_POST_SAVE_FAILURE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static ACK_CACHE_PROBE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The cache producer's ownership proof is covered separately. Supply a
/// synthetic cache patch after that fold to isolate finish's bootstrap exit.
pub(in crate::snapshot_sync) fn ack_cache_probe_for_test(items: &mut [SnapshotItem]) {
    if ACK_CACHE_PROBE.with(|slot| slot.replace(false)) {
        items
            .first_mut()
            .expect("fixture has a current body")
            .cache_observations = pending_head_index_item().1.cache_observations;
    }
}

pub(in crate::snapshot_sync) fn ack_post_save_failure(stage: &'static str) -> Result<()> {
    if ACK_POST_SAVE_FAILURE.with(|slot| slot.get() == Some(stage)) {
        ACK_POST_SAVE_FAILURE.with(|slot| slot.set(None));
        return Err(anyhow!("synthetic post-index-save failure: {stage}"));
    }
    Ok(())
}

struct AckPostSaveFailure;
impl Drop for AckPostSaveFailure {
    fn drop(&mut self) {
        ACK_POST_SAVE_FAILURE.with(|slot| slot.set(None));
        ACK_CACHE_PROBE.with(|slot| slot.set(false));
    }
}

fn ack_finish_pipeline_case(stage: &'static str) {
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        return terminal_off_on_ack_finish_pipeline_case(stage);
    }
    crate::client_report::reset_for_test();
    let fixture = IdentityPipelineHome::new();
    let _cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("ack-post-save-support");
    let secrets = fixture.base.join("ack-post-save-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "ack-post-save-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
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
    .expect("actual due source preparation");
    let (mut preparation, index, mut scan) = collect_native_preparation_with_rotation(frame, false);
    assert!(scan.census_complete);
    if stage == "bootstrap_capacity" {
        preparation.cache_observations_enabled = true;
        ACK_CACHE_PROBE.with(|slot| slot.set(true));
    }
    if stage == "first_install" {
        let template = scan.snapshots[0].clone();
        scan.snapshots = (0..4100)
            .map(|entity| {
                let mut item = template.clone();
                item.source_session_id = format!("first-install-{entity}");
                item.snapshot_fingerprint = format!("{entity:064x}");
                item
            })
            .collect();
        assert_eq!(
            preparation
                .committed_index
                .current_snapshot_fingerprints()
                .len(),
            0
        );
    }
    // Simulate accepted siblings whose source disappeared before adoption.
    // Neither the current scanner delta nor the selected index contains it.
    let stale = "f".repeat(64);
    if stage != "first_install" {
        preparation
            .upload_progress
            .record_body(&stale, &"e".repeat(64));
    }
    if matches!(stage, "capacity" | "bootstrap_capacity") {
        for entity in 0..5000 {
            let fp = format!("{entity:064x}");
            preparation.upload_progress.record_body(&fp, &fp);
        }
    }
    preparation
        .upload_progress
        .save(&preparation.upload_progress_path)
        .unwrap();
    let index_path = preparation.index_path.clone();
    let progress_path = preparation.upload_progress_path.clone();
    let namespace = preparation.upload_destination_namespace.clone();
    ACK_POST_SAVE_FAILURE.with(|slot| {
        slot.set(
            (!matches!(stage, "capacity" | "bootstrap_capacity" | "first_install"))
                .then_some(stage),
        )
    });
    let _reset = AckPostSaveFailure;
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
    if stage == "first_install" {
        result.expect("actual first install over 4096 has no artificial capacity stop");
        assert_eq!(server.offered.lock().unwrap().len(), 4100);
        assert!(matches!(
            source_cadences().lock().unwrap()["claude_code"].state(),
            ottto_protocol::LocalCollectorState::Warm
        ));
        let saved = ScanIndex::load(&index_path).unwrap();
        assert_eq!(saved.current_snapshot_fingerprints().len(), 4100);
        let last = server.offered.lock().unwrap().last().unwrap()["snapshot_fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(saved.accepted_snapshot_fingerprint_recorded(&last));
        return;
    }
    let error = result.unwrap_err();
    if matches!(stage, "capacity" | "bootstrap_capacity") {
        let settlement = error
            .downcast_ref::<ack_retention::AckSettlementRequired>()
            .expect("actual finish preserves typed local capacity outcome");
        if stage == "bootstrap_capacity" {
            assert!(
                error.chain().any(|cause| cause
                    .to_string()
                    .contains("cache-head bootstrap ACK settlement pending")),
                "probe path actually stopped"
            );
        }
        assert_eq!(settlement.retained_stale_ack_count, 5001);
        assert!(settlement.deferred_entity_count > 0);
        assert!(
            server.offered.lock().unwrap().is_empty(),
            "no HTTP upload attempt"
        );
        assert!(matches!(
            source_cadences().lock().unwrap()["claude_code"].state(),
            ottto_protocol::LocalCollectorState::Warm
        ));
        assert_eq!(
            crate::client_report::observe()
                .quantity(crate::client_report::ClientReportReason::NetworkError),
            0
        );
        assert_eq!(
            crate::client_report::observe()
                .quantity(crate::client_report::ClientReportReason::RatelimitBackoff),
            0
        );
        let terminal = server.terminal.lock().unwrap();
        assert_eq!(terminal.last().unwrap()["last_error_code"], "scan_error");
        assert_eq!(
            terminal.last().unwrap()["last_error_message"],
            "local snapshot ACK settlement pending"
        );
    } else {
        assert!(error.to_string().contains(stage));
    }
    assert!(
        ACK_POST_SAVE_FAILURE.with(|slot| slot.get().is_none()),
        "actual exit reached"
    );
    let mut saved = ScanIndex::load(&index_path).unwrap();
    assert!(saved
        .upload_ack_retirement_handoff
        .as_ref()
        .unwrap()
        .bodies
        .contains_key(&stale));
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert_eq!(
        progress.accepted_fingerprints.contains(&stale),
        !matches!(stage, "capacity" | "bootstrap_capacity"),
        "ordinary exit keeps ACK; capacity partial save may already clean it durably"
    );
    progress
        .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path)
        .unwrap();
    let loaded = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(
        !loaded.accepted_fingerprints.contains(&stale),
        "{stage}: exact proof recovers cleanup"
    );
}

fn terminal_off_on_ack_finish_pipeline_case(stage: &'static str) {
    crate::client_report::reset_for_test();
    let fixture = IdentityPipelineHome::new();
    let _cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("ack-post-save-support");
    let secrets = fixture.base.join("ack-post-save-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "ack-post-save-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
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
    .expect("actual due source preparation");
    let (mut preparation, index, mut scan) = collect_native_preparation_with_rotation(frame, false);
    assert!(!scan.census_complete);
    if stage == "bootstrap_capacity" {
        preparation.cache_observations_enabled = true;
        ACK_CACHE_PROBE.with(|slot| slot.set(true));
    }
    if stage == "first_install" {
        let template = scan.snapshots[0].clone();
        scan.snapshots = (0..4100)
            .map(|entity| {
                let mut item = template.clone();
                item.source_session_id = format!("first-install-{entity}");
                item.snapshot_fingerprint = format!("{entity:064x}");
                item
            })
            .collect();
        assert_eq!(
            preparation
                .committed_index
                .current_snapshot_fingerprints()
                .len(),
            0
        );
    }
    // Simulate accepted siblings whose source disappeared before adoption.
    // Neither the current scanner delta nor the selected index contains it.
    let stale = "f".repeat(64);
    if stage != "first_install" {
        preparation
            .upload_progress
            .record_body(&stale, &"e".repeat(64));
    }
    if matches!(stage, "capacity" | "bootstrap_capacity") {
        for entity in 0..5000 {
            let fp = format!("{entity:064x}");
            preparation.upload_progress.record_body(&fp, &fp);
        }
    }
    preparation
        .upload_progress
        .save(&preparation.upload_progress_path)
        .unwrap();
    let index_path = preparation.index_path.clone();
    let progress_path = preparation.upload_progress_path.clone();
    let namespace = preparation.upload_destination_namespace.clone();
    ACK_POST_SAVE_FAILURE.with(|slot| {
        slot.set(
            (!matches!(stage, "capacity" | "bootstrap_capacity" | "first_install"))
                .then_some(stage),
        )
    });
    let _reset = AckPostSaveFailure;
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
    if stage == "first_install" {
        result.expect("actual first install over 4096 has no artificial capacity stop");
        assert_eq!(server.offered.lock().unwrap().len(), 4100);
        assert!(matches!(
            source_cadences().lock().unwrap()["claude_code"].state(),
            ottto_protocol::LocalCollectorState::Warm
        ));
        let saved = ScanIndex::load(&index_path).unwrap();
        assert_eq!(saved.current_snapshot_fingerprints().len(), 4100);
        let last = server.offered.lock().unwrap().last().unwrap()["snapshot_fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(saved.accepted_snapshot_fingerprint_recorded(&last));
        return;
    }
    let error = result.unwrap_err();
    if matches!(stage, "capacity" | "bootstrap_capacity") {
        let settlement = error
            .downcast_ref::<ack_retention::AckSettlementRequired>()
            .expect("actual finish preserves typed local capacity outcome");
        if stage == "bootstrap_capacity" {
            assert!(
                error.chain().any(|cause| cause
                    .to_string()
                    .contains("cache-head bootstrap ACK settlement pending")),
                "probe path actually stopped"
            );
        }
        assert_eq!(settlement.retained_stale_ack_count, 5001);
        assert!(settlement.deferred_entity_count > 0);
        assert!(
            server.offered.lock().unwrap().is_empty(),
            "no HTTP upload attempt"
        );
        assert!(matches!(
            source_cadences().lock().unwrap()["claude_code"].state(),
            ottto_protocol::LocalCollectorState::Warm
        ));
        assert_eq!(
            crate::client_report::observe()
                .quantity(crate::client_report::ClientReportReason::NetworkError),
            0
        );
        assert_eq!(
            crate::client_report::observe()
                .quantity(crate::client_report::ClientReportReason::RatelimitBackoff),
            0
        );
        let terminal = server.terminal.lock().unwrap();
        assert_eq!(terminal.last().unwrap()["last_error_code"], "scan_error");
        assert_eq!(
            terminal.last().unwrap()["last_error_message"],
            "local snapshot ACK settlement pending"
        );
    } else {
        assert!(error.to_string().contains(stage));
    }
    assert!(
        ACK_POST_SAVE_FAILURE.with(|slot| slot.get().is_none()),
        "actual exit reached"
    );
    let mut saved = ScanIndex::load(&index_path).unwrap();
    assert!(
        saved.upload_ack_retirement_handoff.is_none(),
        "terminal-off creates no complete-census retirement handoff"
    );
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(
        progress.accepted_fingerprints.contains(&stale),
        "unrelated stale ACK custody survives ordinary and capacity exits"
    );
    progress
        .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path)
        .unwrap();
    let loaded = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(
        loaded.accepted_fingerprints.contains(&stale),
        "{stage}: no complete-census proof exists, so ACK custody is retained"
    );
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_retirement_survives_each_real_finish_post_index_error_exit() {
    for stage in [
        "native_receipt",
        "unverified_marker",
        "backfill_completion",
        "finish_cycle",
    ] {
        ack_finish_pipeline_case(stage);
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_retirement_survives_each_real_finish_post_index_error_exit() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for stage in [
        "native_receipt",
        "unverified_marker",
        "backfill_completion",
        "finish_cycle",
    ] {
        ack_finish_pipeline_case(stage);
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_capacity_real_finish_has_no_upload_loss_or_failure_backoff() {
    ack_finish_pipeline_case("capacity");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_capacity_real_finish_has_no_upload_loss_or_failure_backoff() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ack_finish_pipeline_case("capacity");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_bootstrap_capacity_real_finish_commits_census_retirement() {
    ack_finish_pipeline_case("bootstrap_capacity");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_bootstrap_capacity_real_finish_commits_census_retirement() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ack_finish_pipeline_case("bootstrap_capacity");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_first_install_real_finish_uploads_4100_live_entities_without_a_capacity_stop() {
    ack_finish_pipeline_case("first_install");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_first_install_real_finish_uploads_4100_live_entities_without_a_capacity_stop() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ack_finish_pipeline_case("first_install");
}

/// #794: one scripted response per snapshot POST; an empty script accepts.
#[derive(Clone, Copy, Debug)]
enum AckScriptedPost {
    Accept,
    /// Not shed (429/503), not resent in place (500/502), not split as a
    /// batch deadline (504): an ordinary failed upload.
    UnretriedServerError,
    Disabled,
}

struct AckScriptedServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// Every snapshot offered, accepted or not.
    offered: Arc<Mutex<Vec<serde_json::Value>>>,
    script: Arc<Mutex<VecDeque<AckScriptedPost>>>,
}

impl AckScriptedServer {
    fn new() -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let bodies = offered.clone();
        let script = Arc::new(Mutex::new(VecDeque::new()));
        let posts = script.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic scripted accept: {error}"),
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
                    let post = posts
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or(AckScriptedPost::Accept);
                    match post {
                        AckScriptedPost::UnretriedServerError => {
                            status = "507 Insufficient Storage";
                            serde_json::json!({"detail":"synthetic server error"})
                        }
                        AckScriptedPost::Disabled => serde_json::json!({"accepted":0,
                            "sessions_reconciled":0,"session_ids":[],"disabled":true,
                            "disabled_reason":"synthetic_disabled","accepted_entities":[],
                            "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]}),
                        AckScriptedPost::Accept => {
                            let entities = items.iter().map(|item| {
                                let mut payload = serde_json::Map::new();
                                for key in ["session_account_evidence", "tool_usage", "tool_usage_truncated"] {
                                    if let Some(value) = item.get(key) { payload.insert(key.into(), value.clone()); }
                                }
                                let exclusive = item.get("usage_accounting_contract").and_then(|v| v.as_str())
                                    == Some("session_exclusive_reported_usage:v1");
                                let version = item.get("session_account_evidence").is_some()
                                    .then_some(if exclusive { 8u64 } else { 7u64 });
                                let digest = format!("{:x}", Sha256::digest(
                                    crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()));
                                serde_json::json!({"source_session_id":item["source_session_id"],
                                    "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
                                    "body_witness_version":version,"body_witness_digest":version.map(|_|digest)})
                            }).collect::<Vec<_>>();
                            serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                                "session_ids":[],"disabled":false,"disabled_reason":null,
                                "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":entities,
                                "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]})
                        }
                    }
                } else {
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
            script,
        }
    }

    fn offered_fingerprints(&self) -> Vec<String> {
        self.offered
            .lock()
            .unwrap()
            .iter()
            .map(|item| item["snapshot_fingerprint"].as_str().unwrap().to_owned())
            .collect()
    }
}

impl Drop for AckScriptedServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

/// Real prepare/finish for one synthetic Claude home. Each finished scan is
/// marked census-incomplete (see `prepare`) so complete-census cleanup never
/// retires the injected unrelated debt.
struct AckFinishHome {
    fixture: IdentityPipelineHome,
    cadence: IdentityPipelineCadence,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    transport: crate::net_resilience::TransportCycleOutcome,
    retry: live_snapshot_retry::LiveRetryOwner,
    _env: [EnvVarGuard; 3],
}

impl AckFinishHome {
    fn new(server: &AckScriptedServer) -> Self {
        crate::client_report::reset_for_test();
        let fixture = IdentityPipelineHome::new();
        let cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join("ack-followup-support");
        let secrets = fixture.base.join("ack-followup-secrets");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        let env = [
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
        ];
        let device = LocalDeviceBinding {
            device_id: "ack-followup-device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        Self {
            fixture,
            cadence,
            support,
            device,
            client: SnapshotApiClient::new(server.url.clone()),
            daemon: test_daemon("otm_test"),
            transport: crate::net_resilience::TransportCycleOutcome::default(),
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
            _env: env,
        }
    }

    fn collection() -> AgentStatusCollection {
        AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        }
    }

    fn prepare(&mut self, cycle: &str) -> (SourcePreparation, ScanIndex, SourceScanResult) {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_prepare(cycle);
        }
        self.cadence.next_due_cycle();
        let frame = crate::agent_status_refresh::with_test_collection(Self::collection(), || {
            prepare_sync_source(
                &self.client,
                &self.device,
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &self.fixture.home,
                &self.support,
                &self.daemon,
                &mut self.transport,
                self.daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("actual due source preparation");
        let (preparation, index, mut scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(scan.census_complete, "{cycle}: the real scan is clean");
        assert_eq!(
            scan.snapshots.len(),
            1,
            "{cycle}: the never-committed transcript is read again"
        );
        // Finish reads this flag only for census-dependent decisions
        // (complete-census ACK cleanup, backfill and manifest completion).
        // Marking it incomplete keeps the injected debt unretired.
        scan.census_complete = false;
        (preparation, index, scan)
    }

    fn terminal_off_on_prepare(&mut self, cycle: &str) -> (SourcePreparation, ScanIndex, SourceScanResult) {
        assert!(
            crate::snapshots::claude_terminal_off(),
            "finish pipeline requires production policy"
        );
        self.cadence.next_due_cycle();
        let frame = crate::agent_status_refresh::with_test_collection(Self::collection(), || {
            prepare_sync_source(
                &self.client,
                &self.device,
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &self.fixture.home,
                &self.support,
                &self.daemon,
                &mut self.transport,
                self.daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("actual due source preparation");
        let (preparation, index, mut scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(
            !scan.census_complete,
            "{cycle}: terminal-off retains the real scan owner"
        );
        assert_eq!(
            scan.snapshots.len(),
            1,
            "{cycle}: the never-committed transcript is read again"
        );
        // Finish reads this flag only for census-dependent decisions
        // (complete-census ACK cleanup, backfill and manifest completion).
        // Marking it incomplete keeps the injected debt unretired.
        scan.census_complete = false;
        (preparation, index, scan)
    }

    fn finish(
        &mut self,
        preparation: SourcePreparation,
        index: ScanIndex,
        scan: SourceScanResult,
    ) -> Result<()> {
        crate::agent_status_refresh::with_test_collection(Self::collection(), || {
            finish_sync_source(
                preparation,
                index,
                scan,
                &self.client,
                &self.device,
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &self.fixture.home,
                &self.support,
                &self.daemon,
                &mut self.transport,
                &mut self.retry,
            )
        })
    }

    fn progress(&self, preparation_paths: &(PathBuf, String)) -> SnapshotUploadProgress {
        SnapshotUploadProgress::load(
            &preparation_paths.0,
            &preparation_paths.1,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap()
    }
}

fn ack_followup_debt(entities: usize) -> Vec<String> {
    (0..entities)
        .map(|entity| format!("{entity:064x}"))
        .collect()
}

fn ack_followup_set_debt(preparation: &mut SourcePreparation, debt: &[String], present: bool) {
    let progress = &mut preparation.upload_progress;
    if present {
        for fp in debt {
            progress.record_body(fp, fp);
        }
    } else {
        let debt = debt.iter().collect::<BTreeSet<_>>();
        progress
            .accepted_body_witnesses
            .retain(|fp, _| !debt.contains(fp));
        progress
            .accepted_fingerprints
            .retain(|fp| !debt.contains(fp));
    }
    progress.save(&preparation.upload_progress_path).unwrap();
}

/// #794 F3: incomplete-census capacity stop, then a Disabled finish, then
/// another incomplete-census capacity stop. The Disabled exit resets the
/// consecutive count, so the second stop reports 1, not 2.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_census_wait_count_resets_on_a_disabled_finish_between_capacity_stops() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let source = SnapshotSource::ClaudeCode;
    ack_retention::note_capacity_stop_census(source, false, true);
    let debt = ack_followup_debt(5000);
    for (cycle, (with_debt, expected)) in [(true, 1), (false, 0), (true, 1)].into_iter().enumerate()
    {
        let (mut preparation, index, scan) = home.prepare(&format!("cycle {cycle}"));
        ack_followup_set_debt(&mut preparation, &debt, with_debt);
        if !with_debt {
            server
                .script
                .lock()
                .unwrap()
                .push_back(AckScriptedPost::Disabled);
        }
        let offered_before = server.offered.lock().unwrap().len();
        let result = home.finish(preparation, index, scan);
        if with_debt {
            let error = result.unwrap_err();
            assert!(
                error
                    .downcast_ref::<ack_retention::AckSettlementRequired>()
                    .is_some(),
                "cycle {cycle}: actual capacity stop"
            );
            assert_eq!(server.offered.lock().unwrap().len(), offered_before);
        } else {
            result.unwrap_or_else(|error| {
                panic!("cycle {cycle}: the backend disabled upload: {error:#}")
            });
            assert_eq!(
                server.offered.lock().unwrap().len(),
                offered_before + 1,
                "the Disabled response came from an actual POST"
            );
            assert!(server.script.lock().unwrap().is_empty());
        }
        assert_eq!(
            ack_retention::incomplete_census_capacity_stops(source),
            expected,
            "cycle {cycle}"
        );
    }
    ack_retention::note_capacity_stop_census(source, false, true);
}

/// #794 F3: incomplete-census capacity stop, then a Disabled finish, then
/// another incomplete-census capacity stop. The Disabled exit resets the
/// consecutive count, so the second stop reports 1, not 2.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_census_wait_count_resets_on_a_disabled_finish_between_capacity_stops() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let source = SnapshotSource::ClaudeCode;
    ack_retention::note_capacity_stop_census(source, false, true);
    let debt = ack_followup_debt(5000);
    for (cycle, (with_debt, expected)) in [(true, 1), (false, 0), (true, 1)].into_iter().enumerate()
    {
        let (mut preparation, index, scan) = home.prepare(&format!("cycle {cycle}"));
        ack_followup_set_debt(&mut preparation, &debt, with_debt);
        if !with_debt {
            server
                .script
                .lock()
                .unwrap()
                .push_back(AckScriptedPost::Disabled);
        }
        let offered_before = server.offered.lock().unwrap().len();
        let result = home.finish(preparation, index, scan);
        if with_debt {
            let error = result.unwrap_err();
            assert!(
                error
                    .downcast_ref::<ack_retention::AckSettlementRequired>()
                    .is_some(),
                "cycle {cycle}: actual capacity stop"
            );
            assert_eq!(server.offered.lock().unwrap().len(), offered_before);
        } else {
            result.unwrap_or_else(|error| {
                panic!("cycle {cycle}: the backend disabled upload: {error:#}")
            });
            assert_eq!(
                server.offered.lock().unwrap().len(),
                offered_before + 1,
                "the Disabled response came from an actual POST"
            );
            assert!(server.script.lock().unwrap().is_empty());
        }
        assert_eq!(
            ack_retention::incomplete_census_capacity_stops(source),
            expected,
            "cycle {cycle}"
        );
    }
    ack_retention::note_capacity_stop_census(source, false, true);
}

/// #794 F2: real prepare/scan and real finish finalization (incidence and the
/// file body-set witness come from production code) for one file group of
/// 5,000 entities next to 4,096 unrelated ACKs of debt. Current Claude and
/// Codex parsers emit one file-backed entity per parsed file, so no real
/// transcript yields 5,000; the scanned item is the template for the group,
/// exactly as the first-install finish case does. The finish pipeline derives
/// each entity fingerprint itself, so the file set is read back from what it
/// offered and ACKed. A real HTTP failure stops the first finish after
/// accepted pages; the second finish offers only the remainder and transfers
/// every file ACK to the saved index.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn ack_huge_file_real_finish_converges_after_transport_failure_with_full_debt() {
    const ENTITIES: usize = 5000;
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let debt = ack_followup_debt(4096);
    let debt_set = debt.iter().cloned().collect::<BTreeSet<_>>();
    let group = |scan: &mut SourceScanResult| {
        let template = scan.snapshots[0].clone();
        scan.snapshots = (0..ENTITIES)
            .map(|entity| {
                let mut item = template.clone();
                item.source_session_id = format!("huge-file-{entity}");
                item.snapshot_fingerprint = format!("{:064x}", 1_000_000 + entity);
                item
            })
            .collect();
    };

    let (mut preparation, index, mut scan) = home.prepare("first finish");
    group(&mut scan);
    ack_followup_set_debt(&mut preparation, &debt, true);
    let paths = (
        preparation.upload_progress_path.clone(),
        preparation.upload_destination_namespace.clone(),
    );
    let index_path = preparation.index_path.clone();
    {
        let mut script = server.script.lock().unwrap();
        script.extend([AckScriptedPost::Accept; 30]);
        script.push_back(AckScriptedPost::UnretriedServerError);
    }
    let error = home
        .finish(preparation, index, scan)
        .err()
        .unwrap_or_else(|| {
            panic!(
                "first finish settled: offered={} script_left={}",
                server.offered.lock().unwrap().len(),
                server.script.lock().unwrap().len()
            )
        });
    assert!(
        error
            .downcast_ref::<ack_retention::AckSettlementRequired>()
            .is_none(),
        "the whole live file was admitted beside full debt: {error:#}"
    );
    assert!(server.script.lock().unwrap().is_empty(), "failure reached");
    let first_offers = server
        .offered_fingerprints()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        first_offers.len(),
        server.offered.lock().unwrap().len(),
        "distinct file entities"
    );
    assert!(first_offers.is_disjoint(&debt_set));
    let progress = home.progress(&paths);
    assert!(
        debt_set.is_subset(&progress.accepted_fingerprints),
        "unrelated debt is kept"
    );
    let retained = progress
        .accepted_fingerprints
        .difference(&debt_set)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        (1..ENTITIES).contains(&retained.len()),
        "{}",
        retained.len()
    );
    assert!(
        retained.is_subset(&first_offers),
        "only accepted file pages are retained"
    );
    assert!(
        first_offers.len() > retained.len(),
        "the failed page was offered but not acknowledged"
    );
    let saved = ScanIndex::load(&index_path).unwrap();
    assert!(
        !saved
            .upload_progress_ack_incidence()
            .any(|fp| first_offers.contains(fp)),
        "an unsettled file is not committed"
    );

    server.offered.lock().unwrap().clear();
    let (preparation, index, mut scan) = home.prepare("second finish");
    group(&mut scan);
    home.finish(preparation, index, scan)
        .unwrap_or_else(|error| panic!("second finish settles the file: {error:#}"));
    let second_offers = server
        .offered_fingerprints()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        second_offers.len(),
        ENTITIES - retained.len(),
        "accepted pages are not re-sent"
    );
    assert_eq!(server.offered.lock().unwrap().len(), second_offers.len());
    assert!(second_offers.is_disjoint(&retained));
    assert!(second_offers.is_disjoint(&debt_set));
    let file_fingerprints = retained
        .union(&second_offers)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(file_fingerprints.len(), ENTITIES);
    let saved = ScanIndex::load(&index_path).unwrap();
    assert!(file_fingerprints
        .iter()
        .all(|fp| saved.accepted_snapshot_fingerprint_recorded(fp)));
    assert_eq!(
        saved
            .current_snapshot_fingerprints()
            .intersection(&file_fingerprints)
            .count(),
        ENTITIES,
        "production finalization recorded the whole file group"
    );
    let progress = home.progress(&paths);
    assert!(
        file_fingerprints
            .iter()
            .all(|fp| !progress.accepted_fingerprints.contains(fp)),
        "every file ACK transferred to the index"
    );
    assert_eq!(
        upload_context_resend::last_counts(),
        (0, 0),
        "same-context retry is not a context resend"
    );
    assert_eq!(
        progress.accepted_fingerprints, debt_set,
        "only the unrelated debt remains"
    );
}

/// #794 F2: real prepare/scan and real finish finalization (incidence and the
/// file body-set witness come from production code) for one file group of
/// 5,000 entities next to 4,096 unrelated ACKs of debt. Current Claude and
/// Codex parsers emit one file-backed entity per parsed file, so no real
/// transcript yields 5,000; the scanned item is the template for the group,
/// exactly as the first-install finish case does. The finish pipeline derives
/// each entity fingerprint itself, so the file set is read back from what it
/// offered and ACKed. A real HTTP failure stops the first finish after
/// accepted pages; the second finish offers only the remainder and transfers
/// every file ACK to the saved index.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_on_ack_huge_file_real_finish_converges_after_transport_failure_with_full_debt() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    const ENTITIES: usize = 5000;
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let debt = ack_followup_debt(4096);
    let debt_set = debt.iter().cloned().collect::<BTreeSet<_>>();
    let group = |scan: &mut SourceScanResult| {
        let template = scan.snapshots[0].clone();
        scan.snapshots = (0..ENTITIES)
            .map(|entity| {
                let mut item = template.clone();
                item.source_session_id = format!("huge-file-{entity}");
                item.snapshot_fingerprint = format!("{:064x}", 1_000_000 + entity);
                item
            })
            .collect();
    };

    let (mut preparation, index, mut scan) = home.prepare("first finish");
    group(&mut scan);
    ack_followup_set_debt(&mut preparation, &debt, true);
    let paths = (
        preparation.upload_progress_path.clone(),
        preparation.upload_destination_namespace.clone(),
    );
    let index_path = preparation.index_path.clone();
    {
        let mut script = server.script.lock().unwrap();
        script.extend([AckScriptedPost::Accept; 30]);
        script.push_back(AckScriptedPost::UnretriedServerError);
    }
    let error = home
        .finish(preparation, index, scan)
        .err()
        .unwrap_or_else(|| {
            panic!(
                "first finish settled: offered={} script_left={}",
                server.offered.lock().unwrap().len(),
                server.script.lock().unwrap().len()
            )
        });
    assert!(
        error
            .downcast_ref::<ack_retention::AckSettlementRequired>()
            .is_none(),
        "the whole live file was admitted beside full debt: {error:#}"
    );
    assert!(server.script.lock().unwrap().is_empty(), "failure reached");
    let first_offers = server
        .offered_fingerprints()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        first_offers.len(),
        server.offered.lock().unwrap().len(),
        "distinct file entities"
    );
    assert!(first_offers.is_disjoint(&debt_set));
    let progress = home.progress(&paths);
    assert!(
        debt_set.is_subset(&progress.accepted_fingerprints),
        "unrelated debt is kept"
    );
    let retained = progress
        .accepted_fingerprints
        .difference(&debt_set)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        (1..ENTITIES).contains(&retained.len()),
        "{}",
        retained.len()
    );
    assert!(
        retained.is_subset(&first_offers),
        "only accepted file pages are retained"
    );
    assert!(
        first_offers.len() > retained.len(),
        "the failed page was offered but not acknowledged"
    );
    let saved = ScanIndex::load(&index_path).unwrap();
    assert!(
        !saved
            .upload_progress_ack_incidence()
            .any(|fp| first_offers.contains(fp)),
        "an unsettled file is not committed"
    );

    server.offered.lock().unwrap().clear();
    let (preparation, index, mut scan) = home.prepare("second finish");
    group(&mut scan);
    home.finish(preparation, index, scan)
        .unwrap_or_else(|error| panic!("second finish settles the file: {error:#}"));
    let second_offers = server
        .offered_fingerprints()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        second_offers.len(),
        ENTITIES - retained.len(),
        "accepted pages are not re-sent"
    );
    assert_eq!(server.offered.lock().unwrap().len(), second_offers.len());
    assert!(second_offers.is_disjoint(&retained));
    assert!(second_offers.is_disjoint(&debt_set));
    let file_fingerprints = retained
        .union(&second_offers)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(file_fingerprints.len(), ENTITIES);
    let saved = ScanIndex::load(&index_path).unwrap();
    assert!(file_fingerprints
        .iter()
        .all(|fp| saved.accepted_snapshot_fingerprint_recorded(fp)));
    assert_eq!(
        saved
            .current_snapshot_fingerprints()
            .intersection(&file_fingerprints)
            .count(),
        ENTITIES,
        "production finalization recorded the whole file group"
    );
    let progress = home.progress(&paths);
    assert!(
        file_fingerprints
            .iter()
            .all(|fp| !progress.accepted_fingerprints.contains(fp)),
        "every file ACK transferred to the index"
    );
    assert_eq!(
        upload_context_resend::last_counts(),
        (0, 0),
        "same-context retry is not a context resend"
    );
    assert_eq!(
        progress.accepted_fingerprints, debt_set,
        "only the unrelated debt remains"
    );
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn terminal_off_real_finish_uploads_acks_and_settles_with_no_manifest() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let (preparation, index, scan) = home.prepare("terminal-off");
    assert!(!scan.census_complete);
    assert!(index.has_retained_traversal_for_terminal_off());
    let fingerprints = scan
        .snapshots
        .iter()
        .map(|i| i.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    let path = preparation.index_path.clone();
    let paths = (
        preparation.upload_progress_path.clone(),
        preparation.upload_destination_namespace.clone(),
    );
    home.finish(preparation, index, scan).unwrap();
    let offered = server
        .offered_fingerprints()
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        offered.len(),
        fingerprints.len(),
        "the ordinary terminal page uploads"
    );
    let fingerprints = offered;
    let saved = ScanIndex::load(&path).unwrap();
    assert!(saved.has_retained_traversal_for_terminal_off());
    assert!(
        cached_source_manifest(&paths.1, SnapshotSource::ClaudeCode).is_none(),
        "no complete manifest, including stale/deleted incidence, can publish"
    );
    assert!(fingerprints
        .iter()
        .all(|fp| saved.accepted_snapshot_fingerprint_recorded(fp)));
    let progress = home.progress(&paths);
    // Successful selected-save transfers exact ACK custody into the index.
    assert!(progress.accepted_fingerprints.is_empty());
    let offered = server.offered.lock().unwrap();
    assert_eq!(offered.len(), 1);
    let item = &offered[0];
    assert!(item.get("cache_observations").is_none());
    assert!(item.get("context_curve").is_none());
    let mut payload = serde_json::Map::new();
    for key in [
        "session_account_evidence",
        "tool_usage",
        "tool_usage_truncated",
    ] {
        if let Some(value) = item.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    // This is the exact digest the scripted HTTP ACK sent and the client
    // validated, folded with the production file-witness function.
    let ack_body = format!(
        "{:x}",
        Sha256::digest(
            crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()
        )
    );
    assert_eq!(saved.files.len(), 1);
    assert_eq!(
        saved
            .files
            .values()
            .next()
            .unwrap()
            .last_upload_body_witness,
        Some(crate::snapshots::snapshot_file_upload_body_set_for_test(&[
            ack_body
        ]))
    );
    assert!(!crate::snapshots::claude_terminal_authority(
        &saved,
        true,
        "2099-01-01T00:00:00Z"
    ));
}
