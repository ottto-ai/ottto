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

/// Own only this synthetic Claude cadence slot. The named serial key below
/// excludes cadence tests; the default key excludes environment fixtures.
/// Restore pre-test state on every exit, including panic.
struct IdentityPipelineCadence(Option<SourceCadence>);

impl IdentityPipelineCadence {
    fn new() -> Self {
        Self(source_cadences().lock().unwrap().remove("claude_code"))
    }

    fn next_due_cycle(&self) {
        // Test-only fresh cadence represents the next already-due cycle. The
        // real prepare gate and all index/ACK/lifecycle state remain unchanged.
        source_cadences().lock().unwrap().remove("claude_code");
    }
}

impl Drop for IdentityPipelineCadence {
    fn drop(&mut self) {
        let mut cadences = source_cadences().lock().unwrap();
        cadences.remove("claude_code");
        if let Some(previous) = self.0.take() {
            cadences.insert("claude_code", previous);
        }
    }
}

struct IdentityPipelineCycle {
    prepared_before_body: bool,
    body: Vec<u8>,
    snapshots: Vec<SnapshotItem>,
    /// The same cycle on the ordinary path, without early prepared evidence.
    dark_oracle: Vec<u8>,
}

/// Runs one real preparation under `hint_extra`, steps its scan to completion,
/// then applies finish's Claude evidence stage (contract 5 always on).
fn identity_pipeline_cycle(
    fixture: &IdentityPipelineHome,
    name: &str,
    hint_extra: &'static str,
) -> Result<IdentityPipelineCycle> {
    let _cadence = IdentityPipelineCadence::new();
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
        crate::snapshots::claude_request_identity::captures(source),
    );
    let (mut oracle_index, mut oracle_scan) = loop {
        match oracle.step(None) {
            crate::snapshots::OwnedSourceScanStep::Pending(next) => oracle = next,
            crate::snapshots::OwnedSourceScanStep::Complete { index, scan, .. } => {
                break (index, scan)
            }
        }
    };
    apply_claude_local_evidence_to_scan(&support, &mut oracle_scan, &mut oracle_index);
    let (preparation, mut index, mut scan) =
        collect_native_preparation_with_rotation(preparation, false);
    let prepared_before_body = preparation.prepared_claude_evidence.is_some();
    apply_claude_local_evidence_to_scan_with_prepared(
        &support,
        &mut scan,
        &mut index,
        preparation.prepared_claude_evidence,
    );
    Ok(IdentityPipelineCycle {
        prepared_before_body,
        body: serde_json::to_vec(&scan.snapshots).expect("serialize body"),
        snapshots: scan.snapshots,
        dark_oracle: serde_json::to_vec(&oracle_scan.snapshots).expect("serialize oracle"),
    })
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn native_comparison_real_source_preparation_stays_base_without_paired_evidence() {
    // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let fixture = IdentityPipelineHome::new();
    let _scope = crate::snapshots::claude_native_comparison::enable_for_test();
    let cycle = identity_pipeline_cycle(&fixture, "native-preparation", "").unwrap();
    if crate::heap_layout_bound::layout_supported() {
        assert!(cycle.prepared_before_body);
    } else {
        assert!(
            !cycle.prepared_before_body,
            "unsupported layout refuses optional early rows"
        );
        assert_eq!(
            cycle.body, cycle.dark_oracle,
            "unsupported preparation remains exact ordinary BASE"
        );
        writeln!(std::io::stderr().lock(), "native_comparison_real_prepare: unsupported_BASE_body_equal=true optional_early_rows=false positive_preparation=UNEXECUTED").unwrap();
    }
    assert!(!cycle.snapshots.is_empty());
    assert!(cycle
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
    // The read-only phase is exercised by actual SourcePreparation::step;
    // absent paired evidence yields zero coverage and the existing base path.
    writeln!(std::io::stderr().lock(), "native_comparison_checkpoint: real_source_preparation=true missing_pairs_base=true reuse_activated=false").unwrap();
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
                } else if request.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["claude_code"]})
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
#[serial(source_cadences, source_manifests)]
// finish_sync_source leases and commits the shared client_report counters.
#[serial(client_report)]
fn native_comparison_real_source_finish_bootstraps_only_after_exact_ack_and_save() {
    // Legacy reported-body proof/delivery; E2 publishes a request-owned literal instead.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "native_comparison_real_bootstrap: supported_positive=UNEXECUTED layout_supported=false; actual unsupported BASE preparation covered separately").unwrap();
        return;
    }
    let fixture = IdentityPipelineHome::new();
    let _scope = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
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
    let mut previous_context = None;
    let mut last_index_path = None;
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    for cycle in 0..=2 {
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
                witness,
                false,
            )
        })
        .unwrap()
        .expect("ordinary full source cycle");
        let context = frame
            .scan
            .as_ref()
            .unwrap()
            .native_comparison_context()
            .unwrap()
            .to_owned();
        assert_eq!(frame.backfill_pending, cycle == 0);
        let allowed = frame.native_comparison_lease.as_ref().unwrap().allowed();
        match cycle {
            0 => assert!(!allowed, "disk rows alone cannot bootstrap"),
            1 => {
                assert_ne!(
                    previous_context.as_ref(),
                    Some(&context),
                    "the full-backfill to negotiated-window transition changes actual scan context"
                );
                assert!(
                    !allowed,
                    "a backfill-scope grant cannot cross into the normal window"
                );
            }
            _ => {
                assert_eq!(previous_context.as_ref(), Some(&context));
                assert!(allowed,
                    "real normal-scope native conjunction plus exact ACK/save must bootstrap the next real preparation");
                assert_eq!(completed, 2);
                bootstrap_observed = true;
                drop(frame); // Abandoning a new preparation must revoke again.
                break;
            }
        }
        previous_context = Some(context);
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(preparation.prepared_claude_evidence.is_some());
        assert!(scan.census_complete);
        assert_eq!(
            scan.scanned_file_count, 1,
            "both bootstrap opportunities require a real native read"
        );
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(
            scan.snapshots[0].request_count,
            if cycle == 0 { 2 } else { 3 }
        );
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
        last_index_path = Some(index_path);
        assert!(saved.generation > 0);
        assert!(
            daemon.native_comparison.retained_valid_for_test(),
            "actual finish must retain its own native saved grant before any next-context check"
        );
        assert!(
            source_cadence_wait(SnapshotSource::ClaudeCode).is_some(),
            "successful real finish must still enforce ordinary cadence"
        );
        let before_wait_bodies = server.bodies.lock().unwrap().len();
        for _ in 0..2 {
            let skipped = crate::agent_status_refresh::with_test_collection(collection(), || {
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
            .unwrap();
            assert!(
                skipped.is_none(),
                "real negotiated cadence performs no scan"
            );
            assert!(
                daemon.native_comparison.retained_valid_for_test(),
                "a cadence-only prepare must preserve the actual exact-ACK/save grant"
            );
            assert_eq!(
                ScanIndex::load(last_index_path.as_ref().unwrap())
                    .unwrap()
                    .generation,
                saved.generation
            );
            assert_eq!(server.bodies.lock().unwrap().len(), before_wait_bodies);
        }
        writeln!(std::io::stderr().lock(), "native_comparison_real_cadence: two_actual_prepare_waits=true no_scan_or_upload=true exact_saved_grant_retained=true index_generation_unchanged=true").unwrap();
        completed += 1;
        if cycle == 0 {
            // An ordinary new request, not a forced rearm or fake lease, gives
            // the new normal scope its own complete native conjunction.
            let transcript = fixture
                .home
                .join(".claude/projects/-synthetic-repo")
                .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
            let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(177))
                .replace_nanosecond(0)
                .unwrap()
                .format(&Rfc3339)
                .unwrap();
            let row = serde_json::json!({"timestamp":at,"type":"assistant",
                "sessionId":IDENTITY_PIPELINE_ROOT,"requestId":"req_3",
                "message":{"id":"m3","model":"claude-haiku-4-5",
                    "usage":{"input_tokens":30,"output_tokens":3}}});
            std::fs::OpenOptions::new()
                .append(true)
                .open(transcript)
                .unwrap()
                .write_all((row.to_string() + "\n").as_bytes())
                .unwrap();
            write_native_bootstrap_sidecars(&fixture, &support);
        }
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
    if crate::heap_layout_bound::layout_supported() {
        // Reuse this actual saved proof and healthy opened sidecars to cover
        // the loader's single resource boundary. This second synthetic root
        // is only an input-admission fixture, never a native proof/permit.
        let saved = ScanIndex::load(&last_index_path.unwrap()).unwrap();
        let mut raw = serde_json::to_value(&saved).unwrap();
        let witness = raw["claude_usage_family_witnesses"][IDENTITY_PIPELINE_ROOT].clone();
        assert!(witness.is_object());
        let refused_root = "unaffordable-optional-root";
        raw["claude_usage_family_witnesses"][refused_root] = witness;
        let index: ScanIndex = serde_json::from_value(raw).unwrap();
        let path = support.join("local-otel/claude-code-effort").join(format!(
            "{:x}.jsonl",
            Sha256::digest(refused_root.as_bytes())
        ));
        std::fs::File::create(path)
            .unwrap()
            .set_len((crate::source_rotation::PARKED_BUDGET * 2) as u64)
            .unwrap();
        let allowance = crate::source_rotation::PARKED_BUDGET;
        let mut paid =
            crate::source_rotation::PaidReservation::from_remainder(Some(allowance), allowance, 0)
                .unwrap();
        let (prepared, allocation) = crate::retry_allocation_probe::measure_process(|| {
            PreparedClaudeLocalEvidence::load_paid_eligible(
                &support,
                &index,
                [IDENTITY_PIPELINE_ROOT, IDENTITY_PIPELINE_ROOT, refused_root].into_iter(),
                &mut paid,
                0,
            )
            .unwrap()
        });
        assert_eq!(prepared.sessions.len(), 1);
        assert!(prepared.healthy_roots.contains(IDENTITY_PIPELINE_ROOT));
        assert!(!prepared.sessions.contains(refused_root));
        assert!(prepared.frozen_roots_are_current(
            &support,
            &BTreeSet::from([IDENTITY_PIPELINE_ROOT.to_owned()])
        ));
        // Unused capacity is retired at refusal. The initial reservation,
        // not the final live charge, covered earlier decode overlap.
        let prepaid = allowance;
        assert!(
            allocation.requested_peak_with_overlap <= prepaid,
            "subset input construction must fit its actual paid reservation"
        );
        eprintln!("native paid evidence subset: requested_roots=2 retained_healthy=1 pressure_root_base=true duplicate_root_loaded_once=true actual_requested_peak={} prepaid_peak={prepaid} ordinary_final_cohort_unchanged=true not_RSS=true", allocation.requested_peak_with_overlap);
    }
    writeln!(std::io::stderr().lock(), "native_comparison_source_bootstrap: actual_prepare_step_finish=true completed_saved_cycles={completed} actual_wire_ack=true next_real_preparation_allowed=true abandoned_preparation_revokes=true test_only_due_cadence_slot=true ordinary_post_finish_wait_verified=true backfill_to_normal_scope_revokes=true new_request_native_conjunction=true actual_positive_retained_layout_unproved=true").unwrap();
}

/// Loading drops one unbound authority record and clears its member, then the
/// real progress save fails its generation check. Both comparison gate states
/// must retain exactly one local normalization event, without changing the error.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn preparation_error_preserves_normalization_counts_with_and_without_a_lease() {
    for leased in [false, true] {
        let _enabled = leased.then(crate::snapshots::claude_native_comparison::enable_for_test);
        let fixture = IdentityPipelineHome::new();
        let _cadence = IdentityPipelineCadence::new();
        let source = SnapshotSource::ClaudeCode;
        let support = fixture.base.join("error-diagnostics-support");
        std::fs::create_dir_all(&support).unwrap();
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let device = report_kind_test_device();
        let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
        let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&support, source),
            &namespace,
        ));
        std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
        let root = IDENTITY_PIPELINE_ROOT;
        let key = format!("/synthetic/projects/{root}.jsonl");
        let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
        value["files"] = serde_json::json!({key: {
            "size_bytes": 1, "modified_unix_seconds": 1,
            "source_file_fingerprint": "a".repeat(64),
            "last_snapshot_fingerprint": "b".repeat(64)
        }});
        // Structurally valid, but no retained witness binds this record.
        value["claude_usage_authority_quarantine"] = serde_json::json!({root: {
            "contract": "claude_usage_authority_quarantine:v1",
            "proven_witness_fingerprint": "9".repeat(64),
            "member_source_file_fingerprints": {root: "a".repeat(64)},
            "failed_reconstruction_count": 1, "disposition": "retry_pending",
            "retry_after_unix_seconds": 0
        }});
        std::fs::write(&index_path, serde_json::to_vec(&value).unwrap()).unwrap();
        let progress_path = snapshot_upload_progress_path(&index_path);
        let mut progress =
            SnapshotUploadProgress::new(namespace, snapshot_quarantine_witness(source));
        progress.generation = u64::MAX;
        std::fs::write(&progress_path, serde_json::to_vec(&progress).unwrap()).unwrap();
        let client = SnapshotApiClient::new(snapshot_status_server_with_hint_extras(
            Arc::new(Mutex::new(Vec::new())),
            vec![(183, "")],
        ));
        let daemon = test_daemon("otm_test");
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        let (result, rows) = crate::local_resource_diagnostics::capture(|| {
            crate::agent_status_refresh::with_test_collection(
                AgentStatusCollection {
                    snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
                    source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
                    codex_scan_homes: Vec::new(),
                    codex_home_bindings: Vec::new(),
                },
                || {
                    prepare_sync_source(
                        &client,
                        &device,
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
            )
        });
        let error = result
            .err()
            .expect("the progress generation cannot advance");
        assert!(
            error
                .to_string()
                .contains("snapshot upload progress generation overflow"),
            "{error:#}"
        );
        let events = rows
            .iter()
            .filter(|row| {
                row["counts"]["claude_reread"]["authority_normalization_cleared"]
                    .as_u64()
                    .is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "leased={leased}: {rows:?}");
        assert_eq!(events[0]["stage"], "native_comparison_decision");
        assert_eq!(events[0]["source"], "claude_code");
        assert_eq!(
            events[0]["counts"]["claude_reread"]["authority_normalization_cleared"],
            1
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&progress_path).unwrap())
                .unwrap()["generation"],
            u64::MAX
        );
        assert!(!crate::local_resource_diagnostics::claude_reread::active());
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn transport_errors_keep_the_contract_without_observation() {
    for leased in [false, true] {
        let _enabled = leased.then(crate::snapshots::claude_native_comparison::enable_for_test);
        for failure in ["fetch", "hint", "invalid_hint"] {
            let fetch = failure == "fetch";
            let invalid_hint = failure == "invalid_hint";
            let fixture = IdentityPipelineHome::new();
            let _cadence = IdentityPipelineCadence::new();
            let support = fixture.base.join("failure-support");
            std::fs::create_dir_all(&support).unwrap();
            let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client =
                SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
            let server = std::thread::spawn(move || {
                for step in 0..if fetch { 1 } else { 2 } {
                    let (mut stream, _) = listener.accept().unwrap();
                    read_complete_http_request(&mut stream);
                    let token = !fetch && step == 0;
                    let body = if token {
                        r#"{"token":"synthetic-token","expires_at":"2026-08-02T10:00:00Z"}"#
                    } else if invalid_hint {
                        r#"{"source":"claude_code","server_time":"2026-08-02T10:00:00Z","last_data_at":null,"record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,"backfill_window_days":18446744073709551615,"recommended_scan_after":"2026-08-02T10:05:00Z"}"#
                    } else {
                        r#"{"error":"synthetic"}"#
                    };
                    let status = if token || invalid_hint {
                        "200 OK"
                    } else {
                        "500 Internal Server Error"
                    };
                    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                }
            });
            let device = report_kind_test_device();
            let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
            let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
                &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
                &namespace,
            ));
            let mut saved = serde_json::to_value(ScanIndex::default()).unwrap();
            saved["claude_request_identity_contract"] =
                serde_json::json!(crate::snapshots::claude_request_identity::COLLECTOR);
            saved["claude_request_identity_contract_changed"] = serde_json::json!(true);
            std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
            let bytes = serde_json::to_vec(&saved).unwrap();
            std::fs::write(&index_path, &bytes).unwrap();
            let daemon = test_daemon("otm_test");
            let mut transport = crate::net_resilience::TransportCycleOutcome::default();
            let (result, rows) = crate::local_resource_diagnostics::capture(|| {
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
                    [7; 32],
                    false,
                )
            });
            assert!(result.is_err());
            server.join().unwrap();
            assert_eq!(
                std::fs::read(&index_path).unwrap(),
                bytes,
                "error preserves last contract and latch"
            );
            // The retired permit counters are gone; nothing observes a
            // contract on a failed preparation.
            for row in &rows {
                assert!(row["counts"].get("request_identity_permit").is_none());
                assert!(row["counts"].get("identity_contract_transition").is_none());
            }
            assert!(!crate::local_resource_diagnostics::claude_reread::active());
        }
    }
}
