// Contract-5 master-on acceptance through the real `prepare_sync_source`: the
// cycle's own hint decides capture and emission. A mock backend answers the
// relay-token, activity-hint and status calls; the status collection is
// injected, so no provider or credential state is read. Fixtures are synthetic.

const IDENTITY_PIPELINE_ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const IDENTITY_PIPELINE_ORG: &str = "11111111-1111-4111-8111-111111111111";

struct IdentityPipelineHome {
    base: PathBuf,
    home: PathBuf,
}

impl IdentityPipelineHome {
    /// One Claude session: an owned org marker, then two requests.
    fn new() -> Self {
        let base = test_dir("c5-identity-pipeline");
        let home = base.join("home");
        let project = home
            .join(".claude")
            .join("projects")
            .join("-synthetic-repo");
        std::fs::create_dir_all(&project).expect("create synthetic Claude project");
        // An empty Desktop store: its census completes, so only the capture
        // mode decides whether a witness is kept.
        std::fs::create_dir_all(
            home.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude-code-sessions"),
        )
        .expect("create empty Desktop store");
        let at = |minutes_ago: i64| {
            (OffsetDateTime::now_utc() - TimeDuration::minutes(minutes_ago))
                .replace_nanosecond(0)
                .expect("whole seconds")
                .format(&Rfc3339)
                .expect("format clock")
        };
        let root = IDENTITY_PIPELINE_ROOT;
        let lines = [
            serde_json::json!({"timestamp": at(180), "type": "attachment", "sessionId": root,
                "attachment": {"type": "credential_org", "organizationUuid": IDENTITY_PIPELINE_ORG}}),
            serde_json::json!({"timestamp": at(179), "type": "assistant", "sessionId": root,
                "requestId": "req_1", "message": {"id": "m1", "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 1}}}),
            serde_json::json!({"timestamp": at(178), "type": "assistant", "sessionId": root,
                "requestId": "req_2", "message": {"id": "m2", "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 20, "output_tokens": 2}}}),
        ];
        std::fs::write(
            project.join(format!("{root}.jsonl")),
            lines
                .iter()
                .map(|line| line.to_string() + "\n")
                .collect::<String>(),
        )
        .expect("write synthetic transcript");
        Self { base, home }
    }
}

impl Drop for IdentityPipelineHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

struct IdentityPipelineCycle {
    prepared_before_body: bool,
    body: Vec<u8>,
    snapshots: Vec<SnapshotItem>,
    /// The scan index before finish's evidence stage.
    scanned_index: ScanIndex,
    /// The same cycle's pre-flip shape: no capture, no permit.
    dark_oracle: Vec<u8>,
}

/// Runs one real preparation under `hint_extra`, steps its scan to completion,
/// then applies finish's Claude evidence stage with the permit finish derives.
fn identity_pipeline_cycle(
    fixture: &IdentityPipelineHome,
    name: &str,
    hint_extra: &'static str,
) -> Result<IdentityPipelineCycle> {
    let source = SnapshotSource::ClaudeCode;
    let support = fixture.base.join(format!("support-{name}"));
    std::fs::create_dir_all(&support).expect("create support dir");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let client = SnapshotApiClient::new(snapshot_status_server_with_hint_extras(
        Arc::new(Mutex::new(Vec::new())),
        vec![(183, hint_extra)],
    ));
    let daemon = test_daemon("otm_test");
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let preparation = crate::agent_status_refresh::with_test_collection(
        AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        },
        || {
            prepare_sync_source(
                &client,
                &report_kind_test_device(),
                "device-secret",
                source,
                "otm_test",
                &fixture.home,
                &support,
                &daemon,
                &mut transport,
                [7; 32],
                false,
            )
        },
    )?
    .expect("a due Claude cycle prepares a scan");
    let roots = preparation
        .claude_scan_roots
        .clone()
        .expect("Claude preparation keeps its roots");
    let mut oracle = crate::snapshots::OwnedSourceScan::new_with_identity_capture(
        source,
        &roots,
        preparation.committed_index.clone(),
        &preparation.scan_started_at,
        scan_request_window_days(
            preparation.receipt_window_days,
            preparation.backfill_pending,
            false,
        ),
        MAX_BACKFILL_FILES_PER_SOURCE,
        preparation.upload_policy.session_artifacts_enabled,
        Some(&support),
        &[],
        false,
        preparation.context_curve_enabled,
        false,
    );
    let (mut oracle_index, mut oracle_scan) = loop {
        match oracle.step(None) {
            crate::snapshots::OwnedSourceScanStep::Pending(next) => oracle = next,
            crate::snapshots::OwnedSourceScanStep::Complete { index, scan, .. } => {
                break (index, scan)
            }
        }
    };
    apply_claude_local_evidence_to_scan_with_permit(
        &support,
        &mut oracle_scan,
        &mut oracle_index,
        None,
    );
    let mut frame = preparation;
    let (preparation, mut index, mut scan) = loop {
        match frame.step() {
            SourcePreparationStep::Pending(next) => frame = next,
            SourcePreparationStep::Complete {
                preparation,
                index,
                scan,
            } => break (preparation, index, scan),
        }
    };
    let scanned_index = index.clone();
    let prepared_before_body = preparation.prepared_claude_evidence.is_some();
    apply_claude_local_evidence_to_scan_with_prepared(
        &support,
        &mut scan,
        &mut index,
        cycle_request_identity_permit(source, &preparation.activity_hint),
        preparation.prepared_claude_evidence,
    );
    Ok(IdentityPipelineCycle {
        prepared_before_body,
        body: serde_json::to_vec(&scan.snapshots).expect("serialize body"),
        snapshots: scan.snapshots,
        scanned_index,
        dark_oracle: serde_json::to_vec(&oracle_scan.snapshots).expect("serialize oracle"),
    })
}

#[test]
#[serial]
fn native_comparison_real_source_preparation_stays_base_without_paired_evidence() {
    let fixture = IdentityPipelineHome::new();
    let _scope = crate::snapshots::claude_native_comparison::enable_for_test();
    let cycle = identity_pipeline_cycle(&fixture, "native-preparation", "").unwrap();
    assert!(cycle.prepared_before_body);
    assert!(!cycle.snapshots.is_empty());
    assert!(cycle
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    // The read-only phase is exercised by actual SourcePreparation::step;
    // absent paired evidence yields zero coverage and the existing base path.
    writeln!(std::io::stderr().lock(), "native_comparison_checkpoint: real_source_preparation=true missing_pairs_base=true reuse_activated=false").unwrap();
}

#[test]
#[serial]
fn master_on_emits_contract5_only_under_the_cycles_exact_hint_token() {
    use crate::snapshots::claude_request_identity as identity;
    let fixture = IdentityPipelineHome::new();
    let session = |cycle: &IdentityPipelineCycle| {
        cycle
            .snapshots
            .iter()
            .find(|item| item.source_session_id == IDENTITY_PIPELINE_ROOT)
            .expect("the synthetic session is scanned")
            .clone()
    };

    // The exact token: contract-5 output, with markers and the Desktop census
    // witness captured for it.
    let permitted = identity_pipeline_cycle(
        &fixture,
        "token",
        r#","session_request_identity_contract":"own_request_identity_rows:v1""#,
    )
    .expect("permitted cycle");
    let item = session(&permitted);
    assert_eq!(item.provenance.collector, identity::COLLECTOR);
    assert!(item.claude_org_markers.is_some(), "markers are captured");
    assert!(identity::desktop_census(&permitted.scanned_index).is_some());
    // Without telemetry the only basis is the marker org, and only when the
    // pass settled; nothing is refused and usage is unchanged.
    assert!(item
        .request_evidence
        .iter()
        .all(|evidence| evidence.identity_basis == identity::TRANSCRIPT_ORG));
    assert_eq!(item.request_identity_refusals, 0);
    assert_eq!(
        (item.request_count, item.input_tokens, item.output_tokens),
        (2, 30, 3)
    );
    assert_ne!(permitted.body, permitted.dark_oracle);

    // No token, null, another version, a prefixed token, or the collector
    // name: today's body bytes, no marker or census capture.
    for (name, extra) in [
        ("absent", ""),
        ("null", r#","session_request_identity_contract":null"#),
        (
            "other",
            r#","session_request_identity_contract":"own_request_identity_rows:v2""#,
        ),
        (
            "prefixed",
            r#","session_request_identity_contract":" own_request_identity_rows:v1""#,
        ),
        (
            "collector",
            r#","session_request_identity_contract":"claude_code_jsonl:own_request_identity_rows:v1""#,
        ),
    ] {
        let dark = identity_pipeline_cycle(&fixture, name, extra).expect("dark cycle");
        assert_eq!(dark.body, dark.dark_oracle, "{name}: pre-flip body bytes");
        let item = session(&dark);
        assert_ne!(item.provenance.collector, identity::COLLECTOR, "{name}");
        assert!(item.request_evidence.is_empty(), "{name}");
        assert!(
            dark.snapshots
                .iter()
                .all(|item| item.claude_org_markers.is_none()),
            "{name}: no marker capture"
        );
        assert!(
            identity::desktop_census(&dark.scanned_index).is_none(),
            "{name}: no census witness"
        );
        assert_eq!(
            (item.request_count, item.input_tokens, item.output_tokens),
            (2, 30, 3)
        );
    }

    // A hint that cannot be read aborts the cycle: no scan, no fallback body.
    let support = fixture.base.join("support-unreadable");
    assert!(identity_pipeline_cycle(
        &fixture,
        "unreadable",
        r#","session_request_identity_contract":"#,
    )
    .is_err());
    assert!(
        std::fs::read_dir(&support)
            .expect("support dir")
            .next()
            .is_none(),
        "an aborted cycle writes no scan state"
    );
}

/// Offline transport for the real source lifecycle. It ACKs exactly the wire
/// entities it receives, including creator evidence, rather than marking index
/// entries accepted or manufacturing a process lease in the fixture.
struct NativeBootstrapServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    bodies: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl NativeBootstrapServer {
    fn new() -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = bodies.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw_body = request.split_once("\r\n\r\n").unwrap().1;
                let value: serde_json::Value = if raw_body.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw_body).unwrap()
                };
                let response = if request.contains("/relay-token") {
                    serde_json::json!({"token":"synthetic-native-token", "expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    serde_json::json!({"source":"claude_code", "server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"})
                } else if let Some(items) =
                    value.get("snapshots").and_then(|items| items.as_array())
                {
                    let entities = items.iter().map(|item| {
                        // These fixtures declare no cache/curve evidence. Hash
                        // the actual wire creator/tool leaves independently.
                        assert!(item.get("cache_observations").is_none());
                        assert!(item.get("context_curve").is_none());
                        let mut payload = serde_json::Map::new();
                        for key in ["session_account_evidence", "tool_usage", "tool_usage_truncated"] {
                            if let Some(value) = item.get(key) { payload.insert(key.into(), value.clone()); }
                        }
                        let exclusive = item.get("usage_accounting_contract").and_then(|v|v.as_str())
                            == Some("session_exclusive_reported_usage:v1");
                        let creator = item.get("session_account_evidence").is_some();
                        let version = creator.then_some(if exclusive { 8u64 } else { 7u64 });
                        let digest = format!("{:x}", Sha256::digest(
                            crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()));
                        serde_json::json!({"source_session_id":item["source_session_id"],
                            "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
                            "body_witness_version":version,"body_witness_digest":version.map(|_|digest)})
                    }).collect::<Vec<_>>();
                    captured.lock().unwrap().extend(items.iter().cloned());
                    serde_json::json!({"accepted":items.len(),"sessions_reconciled":items.len(),
                        "session_ids":[],"disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":entities,
                        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]})
                } else {
                    serde_json::json!({"accepted":true,"source":"claude_code", "machine_id":"otm_test", "disabled":false})
                };
                bounded_native_response(&mut stream, "200 OK", &response.to_string());
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            bodies,
        }
    }
}

impl Drop for NativeBootstrapServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let outcome = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            outcome.unwrap();
        }
    }
}

fn write_native_bootstrap_sidecars(fixture: &IdentityPipelineHome, support: &Path) {
    let transcript = fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let rows = std::fs::read_to_string(transcript)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|row| row["type"] == "assistant")
        .collect::<Vec<_>>();
    let mut api_lines = String::new();
    let mut trace_lines = String::new();
    for (sequence, row) in rows.iter().enumerate() {
        let request = row["requestId"].as_str().unwrap();
        let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
            capture_revision: "claude_api_request:v2".into(),
            session_id: IDENTITY_PIPELINE_ROOT.into(),
            request_id: request.into(),
            client_request_id: format!("client-{request}"),
            observed_at: row["timestamp"].as_str().unwrap().into(),
            model: "claude-haiku-4-5".into(),
            effort: "high".into(),
            query_source: "user".into(),
            speed: "fast".into(),
            app_version: "2.1.226".into(),
            event_sequence: Some(sequence as u64 + 1),
            cost_usd_micros: Some(100),
            input_tokens: row["message"]["usage"]["input_tokens"].as_u64().unwrap(),
            output_tokens: row["message"]["usage"]["output_tokens"].as_u64().unwrap(),
            request_count: 1,
            ..Default::default()
        };
        api.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&api).unwrap())
        );
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
            capture_revision: "claude_llm_request_ownership:v1".into(),
            session_id: IDENTITY_PIPELINE_ROOT.into(),
            request_id: request.into(),
            client_request_id: format!("client-{request}"),
            observed_at: api.observed_at.clone(),
            ..Default::default()
        };
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        api_lines.push_str(&(serde_json::to_string(&api).unwrap() + "\n"));
        trace_lines.push_str(&(serde_json::to_string(&trace).unwrap() + "\n"));
    }
    for (kind, lines) in [
        ("claude-code-effort", api_lines),
        ("claude-code-trace-ownership", trace_lines),
    ] {
        let directory = support.join("local-otel").join(kind);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!(
                "{:x}.jsonl",
                Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
            )),
            lines,
        )
        .unwrap();
    }
}

#[test]
#[serial]
fn native_comparison_real_source_finish_bootstraps_only_after_exact_ack_and_save() {
    let fixture = IdentityPipelineHome::new();
    let _scope = crate::snapshots::claude_native_comparison::enable_for_test();
    let support = fixture.base.join("native-bootstrap-support");
    let secrets = fixture.base.join("native-bootstrap-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = NativeBootstrapServer::new();
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "native-bootstrap-device".into(),
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
    let witness = daemon.snapshot_scan_account_witness().unwrap();
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    let mut completed = 0;
    let mut bootstrap_observed = false;
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    for _ in 0..6 {
        let mut frame = crate::agent_status_refresh::with_test_collection(collection(), || {
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
                witness,
                false,
            )
        })
        .unwrap()
        .expect("ordinary full source cycle");
        let allowed = frame.native_comparison_lease.as_ref().unwrap().allowed();
        if completed == 0 {
            assert!(!allowed, "disk rows alone cannot bootstrap");
        }
        if allowed {
            assert!(completed > 0);
            bootstrap_observed = true;
            drop(frame); // Abandoning a new preparation must revoke again.
            break;
        }
        let (preparation, index, scan) = loop {
            match frame.step() {
                SourcePreparationStep::Pending(next) => frame = next,
                SourcePreparationStep::Complete {
                    preparation,
                    index,
                    scan,
                } => break (preparation, index, scan),
            }
        };
        assert!(preparation.prepared_claude_evidence.is_some());
        assert!(scan.census_complete);
        let index_path = preparation.index_path.clone();
        crate::agent_status_refresh::with_test_collection(collection(), || {
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
        })
        .unwrap();
        let saved = ScanIndex::load(&index_path).unwrap();
        assert!(saved.generation > 0);
        completed += 1;
    }
    assert!(
        bootstrap_observed,
        "real finish must mint after a clean native conjunction and durable exact settlement"
    );
    let bodies = server.bodies.lock().unwrap();
    assert!(
        !bodies.is_empty(),
        "the real uploader must perform an exact wire ACK"
    );
    assert!(bodies
        .iter()
        .any(|body| body["usage_accounting_contract"] == "session_exclusive_reported_usage:v1"));
    drop(bodies);
    let abandoned = crate::agent_status_refresh::with_test_collection(collection(), || {
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
            witness,
            false,
        )
    })
    .unwrap()
    .expect("same-scope preparation after abandonment");
    assert!(!abandoned
        .native_comparison_lease
        .as_ref()
        .unwrap()
        .allowed());
    drop(abandoned);
    writeln!(std::io::stderr().lock(), "native_comparison_source_bootstrap: actual_prepare_step_finish=true completed_saved_cycles={completed} actual_wire_ack=true next_real_preparation_allowed=true abandoned_preparation_revokes=true actual_positive_retained_layout_unproved=true").unwrap();
}
