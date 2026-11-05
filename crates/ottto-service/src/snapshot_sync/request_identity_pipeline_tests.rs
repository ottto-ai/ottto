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
    body: Vec<u8>,
    snapshots: Vec<SnapshotItem>,
    /// The same cycle through the direct ordinary scan path.
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
        ),
        MAX_BACKFILL_FILES_PER_SOURCE,
        Some(&support),
        &[],
        false,
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
    let (_preparation, mut index, mut scan) = collect_preparation_with_rotation(preparation);
    apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
    Ok(IdentityPipelineCycle {
        body: serde_json::to_vec(&scan.snapshots).expect("serialize body"),
        snapshots: scan.snapshots,
        dark_oracle: serde_json::to_vec(&oracle_scan.snapshots).expect("serialize oracle"),
    })
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn ordinary_source_preparation_matches_direct_scan_without_paired_evidence() {
    run_on_scan_worker_stack(
        ordinary_source_preparation_matches_direct_scan_without_paired_evidence_on_scan_worker,
    );
}

fn ordinary_source_preparation_matches_direct_scan_without_paired_evidence_on_scan_worker() {
    // Contract-5 transcript/reported classification; `e2` allocates final grains before tagging.

    let fixture = IdentityPipelineHome::new();
    crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(
        &fixture.base.join("support-native-preparation"),
        &[IDENTITY_PIPELINE_ROOT],
    );
    let cycle = identity_pipeline_cycle(&fixture, "native-preparation", "").unwrap();
    assert_eq!(
        cycle.body, cycle.dark_oracle,
        "ordinary preparation preserves direct-scan body bytes"
    );
    assert!(!cycle.snapshots.is_empty());
    assert!(cycle
        .snapshots
        .iter()
        .all(|item| item.usage_accounting_contract.is_none()));
}

/// Contract 5 is always on: with the old cohort token, without it, or with
/// any other value, a real Claude cycle captures markers and the Desktop
/// census witness and emits the same contract-5 body. Was
/// `master_on_emits_contract5_only_under_the_cycles_exact_hint_token`, whose
/// non-exact tokens kept the pre-flip bytes with no capture.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn always_on_emits_contract5_whatever_the_hint_token() {
    run_on_scan_worker_stack(always_on_emits_contract5_whatever_the_hint_token_on_scan_worker);
}

fn always_on_emits_contract5_whatever_the_hint_token_on_scan_worker() {
    // Contract-5 transcript/reported classification; `e2` allocates final grains before tagging.

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
    let mut bodies = BTreeSet::new();
    for (name, extra) in [
        ("absent", ""),
        ("null", r#","session_request_identity_contract":null"#),
        (
            "token",
            r#","session_request_identity_contract":"own_request_identity_rows:v1""#,
        ),
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
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(
            &fixture.base.join(format!("support-{name}")),
            &[IDENTITY_PIPELINE_ROOT],
        );
        let cycle = identity_pipeline_cycle(&fixture, name, extra).expect("cycle");
        let item = session(&cycle);
        assert_eq!(item.provenance.collector, identity::COLLECTOR, "{name}");
        assert!(
            item.claude_org_markers.is_some(),
            "{name}: markers captured"
        );
        // Even a settled pass withdraws marker-only tags. Nothing is refused
        // and usage is unchanged.
        assert!(item.request_evidence.is_empty(), "{name}");
        assert_eq!(item.request_identity_refusals, 0, "{name}");
        assert_eq!(
            (item.request_count, item.input_tokens, item.output_tokens),
            (2, 30, 3)
        );
        // Each cycle scans at its own wall time, so compare what the hint
        // could change: the contract and every tagged row.
        bodies.insert(
            serde_json::to_vec(&(
                &item.provenance.collector,
                &item.request_evidence,
                item.request_identity_refusals,
                &item.model_usage,
                &item.usage_buckets,
            ))
            .expect("serialize identity projection"),
        );
    }
    assert_eq!(
        bodies.len(),
        1,
        "the hint token changes no identity or usage"
    );

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

    // Telemetry-owned tags need no org marker and no cohort token, and are
    // the same every run (was `claude_contract5_bodies_need_no_cohort_token`).
    let transcript = fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let unmarked = std::fs::read_to_string(&transcript)
        .expect("read synthetic transcript")
        .lines()
        .filter(|line| !line.contains("credential_org"))
        .map(|line| line.to_owned() + "\n")
        .collect::<String>();
    std::fs::write(&transcript, unmarked).expect("drop the org marker");
    let mut telemetry_bodies = BTreeSet::new();
    for name in ["telemetry-first", "telemetry-again"] {
        let telemetry_support = fixture.base.join(format!("support-{name}"));
        write_native_bootstrap_sidecars(&fixture, &telemetry_support);
        // Bootstrap rows prove usage, but intentionally contain no login.
        // This identity guard needs the same paired rows with real typed
        // login/org evidence, as the deleted unit specimen supplied.
        let api_path = telemetry_support
            .join("local-otel/claude-code-effort")
            .join(format!(
                "{:x}.jsonl",
                Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
            ));
        let rows = std::fs::read_to_string(&api_path)
            .unwrap()
            .lines()
            .map(|line| {
                let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                    serde_json::from_str(line).unwrap();
                row.account_identifier_hash = Some("a".repeat(64));
                use crate::claude_local_otel::{
                    ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin,
                    ClaudeIdentityDisposition, ClaudeRequestIdentityEvidence,
                };
                row.account_identity_checked = true;
                row.request_identity = Some(ClaudeRequestIdentityEvidence {
                    identity_hash_scheme: "provider-sha256:v1".into(),
                    disposition: ClaudeIdentityDisposition::Complete,
                    account: ClaudeIdentityAttributeEvidence {
                        disposition: ClaudeIdentityDisposition::Complete,
                        origin: ClaudeIdentityAttributeOrigin::LogRecord,
                        log_record_hash: row.account_identifier_hash.clone(),
                        resource_hash: None,
                    },
                    organization: ClaudeIdentityAttributeEvidence {
                        disposition: ClaudeIdentityDisposition::Complete,
                        origin: ClaudeIdentityAttributeOrigin::LogRecord,
                        log_record_hash: ottto_core::billing_identity_hash(
                            "anthropic",
                            "organization",
                            IDENTITY_PIPELINE_ORG,
                        ),
                        resource_hash: None,
                    },
                });
                row.fingerprint.clear();
                row.fingerprint = format!(
                    "sha256:{:x}",
                    Sha256::digest(serde_json::to_vec(&row).unwrap())
                );
                serde_json::to_string(&row).unwrap() + "\n"
            })
            .collect::<String>();
        std::fs::write(api_path, rows).unwrap();
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(
            &fixture.base.join(format!("support-{name}")),
            &[IDENTITY_PIPELINE_ROOT],
        );
        let cycle = identity_pipeline_cycle(&fixture, name, "").expect("cycle");
        let item = session(&cycle);
        assert_eq!(item.provenance.collector, identity::COLLECTOR, "{name}");
        assert!(
            item.claude_org_markers.is_none(),
            "{name}: fresh tags need no org marker"
        );
        assert!(
            !item.request_evidence.is_empty(),
            "{name}: fresh contract-5 bodies get identity tags"
        );
        assert_eq!(item.request_identity_refusals, 0, "{name}");
        assert_eq!(
            (item.request_count, item.input_tokens, item.output_tokens),
            (2, 30, 3),
            "{name}"
        );
        telemetry_bodies.insert(
            serde_json::to_vec(&(
                &item.provenance.collector,
                &item.request_evidence,
                item.request_identity_refusals,
                &item.model_usage,
                &item.usage_buckets,
            ))
            .expect("serialize identity projection"),
        );
    }
    assert_eq!(
        telemetry_bodies.len(),
        1,
        "telemetry-owned tags are the same every run"
    );
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

/// Loading drops one unbound authority record and clears its member, then the
/// real progress save fails its generation check. The ordinary path retains
/// exactly one local normalization event, without changing the error.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn preparation_error_preserves_normalization_counts() {
    run_on_scan_worker_stack(preparation_error_preserves_normalization_counts_on_scan_worker);
}

fn preparation_error_preserves_normalization_counts_on_scan_worker() {
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
    let mut progress = SnapshotUploadProgress::new(namespace, snapshot_quarantine_witness(source));
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
    assert_eq!(events.len(), 1, "{rows:?}");
    assert_eq!(events[0]["stage"], "native_collection_page");
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

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
fn transport_errors_keep_the_contract_without_observation() {
    run_on_scan_worker_stack(transport_errors_keep_the_contract_without_observation_on_scan_worker);
}

fn transport_errors_keep_the_contract_without_observation_on_scan_worker() {
    for failure in ["fetch", "hint", "invalid_hint"] {
        let fetch = failure == "fetch";
        let invalid_hint = failure == "invalid_hint";
        let fixture = IdentityPipelineHome::new();
        let _cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join("failure-support");
        std::fs::create_dir_all(&support).unwrap();
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = SnapshotApiClient::new(format!("http://{}", listener.local_addr().unwrap()));
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
            "error preserves the last contract"
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
