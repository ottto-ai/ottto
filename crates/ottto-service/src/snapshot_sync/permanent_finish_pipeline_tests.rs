// Exercise the actual finish_sync_source exit, not a copied settlement order.
// All transcripts, credentials and HTTP responses are synthetic and local.
// Real prepare/finish calls mutate the process-global source manifest cache,
// so their tests also hold source_manifests across the whole cycle.
use super::*;

#[derive(Clone, Copy, Debug)]
enum FinishOutcome {
    /// The backend accepts every body.
    Accept,
    Retryable,
    Identity,
    Validation,
    Witness,
    ConflictValidation,
    /// Every body is refused as ordinary non-permanent mixed usage.
    Mixed,
    PermanentStatusFailure,
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
        matches!(self, FinishOutcome::Dominated { .. })
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
                    let retryable = matches!(
                        outcome,
                        FinishOutcome::Retryable | FinishOutcome::ConflictValidation
                    );
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
                    let mixed = matches!(outcome, FinishOutcome::Mixed);
                    let reason = match outcome {
                        FinishOutcome::Dominated { reason, .. } => reason,
                        FinishOutcome::Mixed => "accepted_log_stale_older_mixed",
                        _ => "invalid",
                    };
                    let rejected = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "reason":reason,"detail":"synthetic finish refusal",
                                "permanent":!mixed,"occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    let validation_index = items
                        .iter()
                        .position(|item| item["source_session_id"] == IDENTITY_PIPELINE_ROOT);
                    if matches!(outcome, FinishOutcome::Identity) {
                        status = "503 Service Unavailable";
                        serde_json::json!({"code":"snapshot_original_identity_unavailable", "errors":(0..items.len()).map(|i| serde_json::json!({"loc":["body","snapshots",i]})).collect::<Vec<_>>()})
                    } else if let Some(index) = validation_index.filter(|_| {
                        matches!(
                            outcome,
                            FinishOutcome::Validation | FinishOutcome::ConflictValidation
                        )
                    }) {
                        status = "422 Unprocessable Entity";
                        serde_json::json!({"errors":[{"loc":["body","snapshots",index,"field"]}]})
                    } else if matches!(outcome, FinishOutcome::Accept | FinishOutcome::Witness) {
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
                                "body_witness_version":version,"body_witness_digest":version.map(|_| if matches!(outcome, FinishOutcome::Witness) { "0".repeat(64) } else { digest })})
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
                if status == "503 Service Unavailable" && matches!(outcome, FinishOutcome::Identity)
                {
                    let body = response.to_string();
                    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nRetry-After: 60\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                } else {
                    bounded_native_response(&mut stream, status, &response.to_string());
                }
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

/// Stops a loopback test server and joins its worker. A worker panic fails
/// the test unless the test is already unwinding.
pub(super) fn stop_server(
    stop: &std::sync::atomic::AtomicBool,
    worker: &mut Option<std::thread::JoinHandle<()>>,
) {
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let result = worker.take().unwrap().join();
    if !std::thread::panicking() {
        result.unwrap();
    }
}

impl Drop for FinishServer {
    fn drop(&mut self) {
        stop_server(&self.stop, &mut self.worker);
    }
}

fn permanent_finish_pipeline(outcome: FinishOutcome) {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} supported_positive=UNEXECUTED layout_supported=false").unwrap();
        return;
    }
    let fixture = IdentityPipelineHome::new();
    if matches!(outcome, FinishOutcome::ConflictValidation) {
        let project = fixture.home.join(".claude/projects/-synthetic-repo");
        let original =
            std::fs::read_to_string(project.join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl")))
                .unwrap();
        let sibling = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        std::fs::write(
            project.join(format!("{sibling}.jsonl")),
            original
                .replace(IDENTITY_PIPELINE_ROOT, sibling)
                .replace("req_", "sibling_req_"),
        )
        .unwrap();
    }
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
    write_native_bootstrap_sidecars(&fixture, &support);
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
        let (preparation, index, scan) = collect_preparation_with_rotation(frame);
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
            if unclean || matches!(outcome, FinishOutcome::ConflictValidation) {
                2
            } else {
                usize::from(cycle < 2)
            },
            "actual native read, then ordinary quiet page"
        );
        if cycle == 0 {
            assert_eq!(
                scan.snapshots.len(),
                if matches!(outcome, FinishOutcome::ConflictValidation) {
                    2
                } else {
                    1
                }
            );
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
            !matches!(
                outcome,
                FinishOutcome::Validation
                    | FinishOutcome::Witness
                    | FinishOutcome::ConflictValidation
            ),
            "{outcome:?}: {result:?}"
        );
        // A held entity has its own quarantine clock: no finished cycle,
        // conflicts included, enters the whole-source failure ladder.
        let failing = source_cadences()
            .lock()
            .unwrap()
            .get("claude_code")
            .map(|cadence| cadence.state() == ottto_protocol::LocalCollectorState::Failing);
        assert_eq!(failing, Some(false), "{outcome:?}, cycle {cycle}");
        let saved = ScanIndex::load(&index_path).unwrap();
        assert!(saved.generation > 0, "real selected save");
        let offered = server.offered.lock().unwrap();
        assert_eq!(
            offered.len(),
            if matches!(outcome, FinishOutcome::ConflictValidation) {
                3
            } else {
                1
            }
        );
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
        if matches!(outcome, FinishOutcome::ConflictValidation) {
            assert_eq!(saved.quarantined_snapshot_fingerprints.len(), 2);
            for item in offered.iter() {
                let fp = item["snapshot_fingerprint"].as_str().unwrap();
                let record = &saved.quarantined_snapshot_fingerprints[fp];
                assert_eq!(
                    record.disposition,
                    SnapshotQuarantineDisposition::RetryPending
                );
                assert_eq!(
                    record.upload_body_witness.as_ref(),
                    offered_witnesses.get(fp)
                );
                assert!(!saved.accepted_snapshot_fingerprint_recorded(fp));
            }
        }
        if let FinishOutcome::Dominated {
            reason: "accepted_log_stale_older_upload",
            ..
        } = outcome
        {
            assert!(progress.permanent_rejections[fingerprint]
                .exposure
                .is_some());
            // Finish transfers terminal quarantine custody to the saved
            // index. Rebind it through ordinary preparation before counting
            // dominance, exactly as the next source cycle does.
            let mut rebound = progress.clone();
            rebound.prepare_quarantine_retries(&saved.quarantined_snapshot_fingerprints);
            let refusals = PermanentRefusalCounts::of(&rebound);
            assert_eq!(
                refusals.dominated, 1,
                "fresh server coverage survives reload"
            );
            assert_eq!(refusals.exposure.owed_entities, 0);
        }
        if matches!(
            outcome,
            FinishOutcome::Mixed
                | FinishOutcome::Retryable
                | FinishOutcome::Identity
                | FinishOutcome::Validation
                | FinishOutcome::Witness
                | FinishOutcome::ConflictValidation
        ) {
            assert!(!progress.permanent_rejections.contains_key(fingerprint));
            assert_eq!(
                saved.quarantined_snapshot_fingerprints[fingerprint].disposition,
                SnapshotQuarantineDisposition::RetryPending,
                "the refused body stays owed in the saved index"
            );
        } else if !matches!(outcome, FinishOutcome::Retryable) {
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
                // The held body stays disclosed even when the pass finishes.
                FinishOutcome::Retryable
                | FinishOutcome::Mixed
                | FinishOutcome::Identity
                | FinishOutcome::ConflictValidation => "server_error",
                FinishOutcome::Validation | FinishOutcome::Witness => "server_error",
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
        writeln!(std::io::stderr().lock(), "permanent_finish_pipeline: outcome={outcome:?} cycle={cycle} selected_save=true refusal_not_accepted=true refusal_debt_retained=true").unwrap();
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
fn permanent_finish_real_pipeline_preserves_refusal_and_status_failures() {
    for outcome in [
        FinishOutcome::PermanentStatusFailure,
        FinishOutcome::PermanentUncleanCensus,
    ] {
        permanent_finish_pipeline(outcome);
    }
}

/// [regress] A cycle whose only offered entity conflicts quarantines that
/// entity on its own retry clock. It used to count as a source failure and
/// climb the whole-source 1 min to 1 h ladder. A pass whose only refusal is
/// an ordinary mixed-usage one, held alone, used to fail as deferred too;
/// it now finishes with that body still owed and disclosed.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn entity_conflict_finish_keeps_the_ordinary_source_cadence() {
    for outcome in [FinishOutcome::Retryable, FinishOutcome::Mixed] {
        permanent_finish_pipeline(outcome);
    }
}

/// A server identity deadline isolates the hold without claiming its bytes were ACKed.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn identity_backoff_finish_keeps_retry_custody_and_returns_ok() {
    permanent_finish_pipeline(FinishOutcome::Identity);
}

/// Neither validation nor witness review becomes an isolated success.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn validation_and_witness_finish_still_defer() {
    for outcome in [FinishOutcome::Validation, FinishOutcome::Witness] {
        permanent_finish_pipeline(outcome);
    }
}

/// An isolated conflict cannot hide a validation hold in the same pass.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn mixed_conflict_and_validation_finish_still_defer() {
    permanent_finish_pipeline(FinishOutcome::ConflictValidation);
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
        let (preparation, index, scan) = collect_preparation_with_rotation(frame);
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

// Same real finish fixture; the new tests own only a test-thread observer.
pub(crate) mod prior_index_lifetime_tests {
    include!("prior_index_lifetime_tests.rs");
}

// Same real prepare/finish pipeline; owns a test-thread re-offer clock.
pub(crate) mod reason_reoffer_pipeline_tests {
    include!("reason_reoffer_pipeline_tests.rs");
}

// Same real prepare/finish pipeline across a same-account re-login.
pub(crate) mod relogin_pipeline_tests {
    include!("relogin_pipeline_tests.rs");
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

/// #794: one scripted response per snapshot POST; an empty script accepts.
#[derive(Clone, Copy, Debug)]
enum AckScriptedPost {
    Accept,
    Disabled,
    /// Every entity is a held conflict: a Deferred page.
    Conflict,
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
                let status = "200 OK";
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
                        AckScriptedPost::Conflict => {
                            let conflicts = items
                                .iter()
                                .map(|item| {
                                    serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "occurrence_count":1})
                                })
                                .collect::<Vec<_>>();
                            serde_json::json!({"accepted":0,"sessions_reconciled":0,
                                "session_ids":[],"disabled":false,"disabled_reason":null,
                                "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                                "unchanged_entities":[],"rejected_entities":[],
                                "conflict_entities":conflicts})
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
}

impl Drop for AckScriptedServer {
    fn drop(&mut self) {
        stop_server(&self.stop, &mut self.worker);
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
        let (preparation, index, mut scan) = collect_preparation_with_rotation(frame);
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

/// [money] Claude telemetry retention on the real prepare/finish: a selected
/// save that fails after a completed upload, and a page whose upload is held
/// as a conflict (Deferred), never reach retention and unlink nothing, with a
/// complete roster in place; an accepted page with a clean save reaches it.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn telemetry_retention_follows_only_a_completed_upload_and_saved_index() {
    const UNREAD: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let newer_index = || {
        let mut newer = serde_json::to_value(ScanIndex::default()).unwrap();
        newer["generation"] = 7.into();
        newer
    };
    for arm in ["save_fails", "deferred", "completed"] {
        let server = AckScriptedServer::new();
        let mut home = AckFinishHome::new(&server);
        let stem = crate::claude_local_otel::telemetry_stem(UNREAD);
        let pair = ["claude-code-effort", "claude-code-trace-ownership"].map(|dir| {
            let path = home
                .support
                .join("local-otel")
                .join(dir)
                .join(format!("{stem}.jsonl"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let row = serde_json::json!({"session_id":UNREAD, "request_id":"g0",
                "observed_at":"2026-08-02T07:00:10Z"});
            std::fs::write(&path, row.to_string() + "\n").unwrap();
            path
        });
        let (preparation, index, scan) = home.prepare(arm);
        let index_path = preparation.index_path.clone();
        crate::snapshots::money_freshness::walk_ended_for_test(
            SnapshotSource::ClaudeCode,
            Some((u64::MAX / 2, BTreeMap::new())),
        );
        crate::snapshots::claude_telemetry_retention::take_runs_for_test();
        match arm {
            "save_fails" => {
                // Another writer advanced the saved index: the selected
                // save's compare-and-swap refuses.
                std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
                std::fs::write(&index_path, serde_json::to_vec(&newer_index()).unwrap()).unwrap();
            }
            "deferred" => server
                .script
                .lock()
                .unwrap()
                .push_back(AckScriptedPost::Conflict),
            _ => {}
        }
        let offered = server.offered.lock().unwrap().len();
        let result = home.finish(preparation, index, scan);
        assert_eq!(
            server.offered.lock().unwrap().len(),
            offered + 1,
            "{arm}: an actual upload"
        );
        let runs = crate::snapshots::claude_telemetry_retention::take_runs_for_test();
        match arm {
            "save_fails" => {
                assert!(result.is_err(), "{arm}");
                assert_eq!(
                    std::fs::read(&index_path).unwrap(),
                    serde_json::to_vec(&newer_index()).unwrap(),
                    "{arm}: the selected save never committed"
                );
                assert_eq!(runs, 0, "{arm}");
            }
            "deferred" => assert_eq!(runs, 0, "{arm}: {result:?}"),
            _ => {
                result.unwrap_or_else(|error| panic!("{arm}: {error:#}"));
                assert_eq!(runs, 1, "{arm}: the completed page reaches retention");
            }
        }
        if arm != "completed" {
            assert!(pair.iter().all(|path| path.exists()), "{arm}: zero unlinks");
        }
    }
}
