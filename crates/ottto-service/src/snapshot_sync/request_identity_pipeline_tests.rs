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
    let (preparation, mut index, mut scan) =
        collect_native_preparation_with_rotation(preparation, false);
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
#[serial(source_cadences)]
fn native_comparison_real_source_preparation_stays_base_without_paired_evidence() {
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

#[test]
#[serial]
#[serial(source_cadences)]
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
                        "recommended_scan_after":"2099-01-01T00:00:00Z",
                        "session_request_identity_contract": if std::env::var_os("OTTTO_MONEY_PARITY_ROOT").is_some() { Some("own_request_identity_rows:v1") } else { None }})
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
#[serial(source_cadences)]
// finish_sync_source leases and commits the shared client_report counters.
#[serial(client_report)]
fn native_comparison_real_source_finish_bootstraps_only_after_exact_ack_and_save() {
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

/// CI runs this exact test source at main and the candidate against the same
/// saved input tree. No production endpoint or host account is involved.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn money_gate_off_saved_fixture_receipt() {
    let (Ok(root), Ok(output)) = (
        std::env::var("OTTTO_MONEY_PARITY_ROOT"),
        std::env::var("OTTTO_MONEY_PARITY_OUTPUT"),
    ) else {
        return;
    };
    let base = PathBuf::from(root);
    std::fs::create_dir_all(&base).unwrap();
    let home = base.join("home");
    if !home.exists() {
        let seed = IdentityPipelineHome::new();
        std::fs::rename(&seed.home, &home).unwrap();
    }
    let fixture = std::mem::ManuallyDrop::new(IdentityPipelineHome {
        base: base.clone(),
        home,
    });
    let support = base.join("support");
    let secrets = base.join("secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    if !support.join("local-otel").exists() {
        // Keep the two checked logins in the SAME hour and row grain, so
        // C1 requires real identity_parts rather than two single-login rows.
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
        let hour = (OffsetDateTime::now_utc() - TimeDuration::hours(3))
            .replace_minute(0)
            .unwrap()
            .replace_second(0)
            .unwrap()
            .replace_nanosecond(0)
            .unwrap();
        let mut lines = std::fs::read_to_string(&transcript)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        for (n, line) in lines.iter_mut().enumerate() {
            line["timestamp"] = (hour + TimeDuration::seconds(n as i64))
                .format(&Rfc3339)
                .unwrap()
                .into();
        }
        std::fs::write(
            &transcript,
            lines
                .iter()
                .map(|line| line.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        write_native_bootstrap_sidecars(&fixture, &support);
        let path = support.join("local-otel/claude-code-effort").join(format!(
            "{:x}.jsonl",
            Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
        ));
        let text = std::fs::read_to_string(&path).unwrap();
        let mut rows = text
            .lines()
            .map(|line| {
                serde_json::from_str::<crate::claude_local_otel::ClaudeLocalOtelEvidence>(line)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for (n, row) in rows.iter_mut().enumerate() {
            row.account_identifier_hash = Some(if n == 0 { "a" } else { "b" }.repeat(64));
            row.account_identity_checked = true;
            row.request_identity = Some(serde_json::from_value(serde_json::json!({
                "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
                "account":{"origin":"resource","disposition":"complete","resource_hash":row.account_identifier_hash},
                "organization":{"origin":"resource","disposition":"complete","resource_hash":"c".repeat(64)}
            })).unwrap());
        }
        // Both a missing-trace row and an auxiliary observer-clock row are
        // present in the saved evidence, alongside the split logins/marker.
        let mut missing = rows[0].clone();
        missing.request_id = "req_missing_trace".into();
        missing.client_request_id = "client-missing".into();
        missing.event_sequence = Some(3);
        let mut side = rows[0].clone();
        side.request_id = "req_side_call".into();
        side.client_request_id = "client-side".into();
        side.event_sequence = Some(4);
        // A paired auxiliary row is counted, but its observer clock cannot
        // qualify identity: this must reach BadClock, not missing-trace.
        let trace_path = support
            .join("local-otel/claude-code-trace-ownership")
            .join(format!(
                "{:x}.jsonl",
                Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
            ));
        let mut trace: crate::claude_local_otel::ClaudeTraceOwnershipEvidence =
            serde_json::from_str(
                std::fs::read_to_string(&trace_path)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap(),
            )
            .unwrap();
        trace.request_id = side.request_id.clone();
        trace.client_request_id = side.client_request_id.clone();
        trace.fingerprint.clear();
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        std::fs::OpenOptions::new()
            .append(true)
            .open(trace_path)
            .unwrap()
            .write_all((serde_json::to_string(&trace).unwrap() + "\n").as_bytes())
            .unwrap();
        rows.extend([missing.clone(), side]);
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
        let extra = serde_json::json!({"timestamp":missing.observed_at,"type":"assistant","sessionId":IDENTITY_PIPELINE_ROOT,"requestId":missing.request_id,"message":{"id":"missing-trace-message","model":missing.model,"usage":{"input_tokens":missing.input_tokens,"output_tokens":missing.output_tokens}}});
        std::fs::OpenOptions::new()
            .append(true)
            .open(transcript)
            .unwrap()
            .write_all((extra.to_string() + "\n").as_bytes())
            .unwrap();
        for row in &mut rows {
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
        }
        std::fs::write(
            path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let _scope = crate::snapshots::claude_native_comparison::enable_for_test();
    let device = LocalDeviceBinding {
        device_id: "money-baseline-device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device).unwrap();
    std::fs::write(
        secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .unwrap();
    let mut receipts = Vec::new();
    for history in [0, 20_000] {
        let _cadence = IdentityPipelineCadence::new();
        let _ = std::fs::remove_dir_all(support.join("snapshots"));
        let server = NativeBootstrapServer::new();
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
        let client = SnapshotApiClient::new(server.url.clone());
        let daemon = test_daemon("otm_test");
        let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
        let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
            &namespace,
        ));
        let mut seed = serde_json::to_value(ScanIndex::default()).unwrap();
        seed["accepted_snapshot_fingerprints"] = serde_json::json!((0..history)
            .map(|n| format!("{n:064x}"))
            .collect::<Vec<_>>());
        std::fs::create_dir_all(index_path.parent().unwrap()).unwrap();
        std::fs::write(&index_path, serde_json::to_vec(&seed).unwrap()).unwrap();
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
        let collection = || {
            let mut status = test_agent_status(SourceKind::ClaudeCode);
            status.account = Some(test_agent_account(&"a".repeat(64), &"c".repeat(64)));
            AgentStatusCollection {
                snapshots: vec![status.clone()],
                source_health_snapshot: status,
                codex_scan_homes: Vec::new(),
                codex_home_bindings: Vec::new(),
            }
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
        });
        let mut decision = "refused";
        let mut accepted = 0;
        let mut local_markers = Vec::new();
        if let Ok(Some(mut frame)) = frame {
            for n in 0..history {
                frame
                    .upload_progress
                    .accepted_fingerprints
                    .insert(format!("{n:064x}"));
                frame
                    .upload_progress
                    .accepted_body_witnesses
                    .insert(format!("{n:064x}"), "historical-body".into());
            }
            frame
                .upload_progress
                .save(&frame.upload_progress_path)
                .unwrap();
            let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
            for item in &scan.snapshots {
                assert!(
                    item.claude_org_markers.is_some(),
                    "C1 marker must be captured locally"
                );
                local_markers.push(format!("{:?}", item.claude_org_markers));
            }
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
            decision = if result.is_ok() { "accepted" } else { "failed" };
            let progress = SnapshotUploadProgress::load(
                &progress_path,
                &namespace,
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            accepted = progress.accepted_fingerprints.len();
        }
        let mut offers = server.bodies.lock().unwrap().clone();
        for item in &mut offers {
            item.as_object_mut().unwrap().remove("collected_at");
        }
        if history == 0 {
            assert!(!offers.is_empty(), "baseline must exercise real upload");
            assert!(accepted > 0);
            let item = offers
                .iter()
                .find(|item| item["source_session_id"] == IDENTITY_PIPELINE_ROOT)
                .unwrap();
            assert!(
                item["session_account_evidence"].is_object(),
                "C1 populated creator evidence: {item}"
            );
            assert!(
                !item["request_evidence"].as_array().unwrap().is_empty(),
                "C1 real C5 evidence"
            );
            assert_eq!(
                item["request_identity_refusals"], 2,
                "missing trace + paired BadClock side call: {item}"
            );
            for rows in [
                item["model_usage"].as_array().unwrap().clone(),
                item["usage_buckets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|bucket| bucket["model_usage"].as_array().unwrap().iter().cloned())
                    .collect(),
            ] {
                assert!(
                    rows.iter()
                        .any(
                            |row| row["identity_parts"].as_array().is_some_and(|parts| parts
                                .iter()
                                .filter(|part| part["account_identifier_hash"].is_string())
                                .count()
                                >= 2)
                        ),
                    "C1 requires a populated split at row AND bucket grain: {rows:?}"
                );
            }
        }
        // Keep the local-only marker comparison separate from the upload
        // identity bytes. The workflow diffs both receipts against main.
        receipts.push(serde_json::json!({"history":history,"decision":decision,"accepted":accepted,
            "local_claude_org_markers":local_markers,"offers":offers,
            "saved_fingerprints":ScanIndex::load(&index_path).unwrap().current_snapshot_fingerprints()}));
    }
    std::fs::write(output, serde_json::to_vec_pretty(&receipts).unwrap()).unwrap();
}
