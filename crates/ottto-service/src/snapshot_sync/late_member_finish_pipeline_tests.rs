// A late Task member through the real prepare, collect and finish: the member
// file appears after the native page completed and before finish folds the
// evidence. Only source finish's own hand-off can queue its exact hint, keep
// the census open and withdraw the source manifest; nothing here calls it.
use super::*;

const SECRET: &str = "late-member-secret";
const MEMBER_AGENT: &str = "agent-000";

fn member_session() -> String {
    format!("{IDENTITY_PIPELINE_ROOT}_{MEMBER_AGENT}")
}

fn minutes_ago(minutes: i64) -> String {
    (OffsetDateTime::now_utc() - TimeDuration::minutes(minutes))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

fn transcript_line(request: &str, at: &str, input: u64) -> String {
    serde_json::json!({"timestamp": at, "type": "assistant",
        "sessionId": IDENTITY_PIPELINE_ROOT, "requestId": request,
        "message": {"id": format!("msg-{request}"), "model": "claude-haiku-4-5",
        "usage": {"input_tokens": input, "output_tokens": 1}}})
    .to_string()
        + "\n"
}

fn pending_hint(index: &ScanIndex, path: &Path) -> bool {
    let state = serde_json::to_value(index).unwrap();
    state["traversal"]["pending_candidates"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|candidate| {
            candidate["path"] == serde_json::json!(path)
                && candidate["census_member"] == true
                && candidate["watcher_hint"] == true
        })
}

fn money(body: &serde_json::Value) -> (u64, u64) {
    (
        body["request_count"].as_u64().unwrap(),
        body["input_tokens"].as_u64().unwrap(),
    )
}

/// The synthetic home of `IdentityPipelineHome` (root requests 10 + 20 input
/// tokens), its bootstrap sidecars, an empty installed re-emission list and an
/// accepting backend. One real cycle at a time.
struct LateMemberPipeline {
    _manifests: SourceManifestTestGuard,
    fixture: IdentityPipelineHome,
    cadence: IdentityPipelineCadence,
    support: PathBuf,
    server: FinishServer,
    device: LocalDeviceBinding,
    retry: live_snapshot_retry::LiveRetryOwner,
    _env: [EnvVarGuard; 3],
}

impl LateMemberPipeline {
    fn new(name: &str) -> Self {
        let manifests = SourceManifestTestGuard::new();
        let fixture = IdentityPipelineHome::new();
        let cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join(format!("{name}-support"));
        let secrets = fixture.base.join(format!("{name}-secrets"));
        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        let server = FinishServer::new(FinishOutcome::Accept);
        let env = [
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
        ];
        let device = LocalDeviceBinding {
            device_id: format!("{name}-device"),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT), SECRET).unwrap();
        write_native_bootstrap_sidecars(&fixture, &support);
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            "# installed synthetic list, no protected sessions\n",
        )
        .unwrap();
        let pipeline = Self {
            _manifests: manifests,
            fixture,
            cadence,
            support,
            server,
            device,
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
            _env: env,
        };
        // The family directory exists; only its member transcript is late.
        std::fs::create_dir_all(pipeline.member().parent().unwrap()).unwrap();
        pipeline
    }

    fn project(&self) -> PathBuf {
        self.fixture.home.join(".claude/projects/-synthetic-repo")
    }
    fn root(&self) -> PathBuf {
        self.project()
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
    }
    fn member(&self) -> PathBuf {
        self.project()
            .join(IDENTITY_PIPELINE_ROOT)
            .join("subagents")
            .join(format!("{MEMBER_AGENT}.jsonl"))
    }
    fn namespace(&self) -> String {
        snapshot_upload_destination_namespace(&self.device, SECRET)
    }
    fn manifest_published(&self) -> bool {
        cached_source_manifest(&self.namespace(), SnapshotSource::ClaudeCode).is_some()
    }

    /// Appends two request rows the trace names for the late member: `m`
    /// (also in the member transcript) and the side call `s`.
    fn append_late_evidence(&self, m_at: &str, s_at: &str) {
        let mut api_lines = String::new();
        let mut trace_lines = String::new();
        for (sequence, request, at, input) in [(3, "req_m", m_at, 30), (4, "req_s", s_at, 5)] {
            let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
                capture_revision: "claude_api_request:v2".into(),
                session_id: IDENTITY_PIPELINE_ROOT.into(),
                request_id: request.into(),
                client_request_id: format!("client-{request}"),
                observed_at: at.into(),
                model: "claude-haiku-4-5".into(),
                effort: "high".into(),
                query_source: "user".into(),
                speed: "fast".into(),
                app_version: "2.1.226".into(),
                event_sequence: Some(sequence),
                cost_usd_micros: Some(100),
                input_tokens: input,
                output_tokens: 1,
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
                agent_id: MEMBER_AGENT.into(),
                observed_at: at.into(),
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
            let path = self.support.join("local-otel").join(kind).join(format!(
                "{:x}.jsonl",
                Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
            ));
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(lines.as_bytes())
                .unwrap();
        }
    }

    /// One due cycle: prepare, collect the native page to completion, run
    /// `before_finish` on what finish will receive, then finish. Returns the
    /// offered bodies and the saved index path.
    fn cycle(
        &mut self,
        before_finish: impl FnOnce(&ScanIndex, &SourceScanResult),
    ) -> (Vec<serde_json::Value>, PathBuf) {
        let collection = || AgentStatusCollection {
            snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
            source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
        };
        self.cadence.next_due_cycle();
        self.server.offered.lock().unwrap().clear();
        let client = SnapshotApiClient::new(self.server.url.clone());
        let daemon = test_daemon("otm_test");
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
            prepare_sync_source(
                &client,
                &self.device,
                SECRET,
                SnapshotSource::ClaudeCode,
                "otm_test",
                &self.fixture.home,
                &self.support,
                &daemon,
                &mut transport,
                daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("due preparation");
        let (preparation, index, scan) = collect_preparation_with_rotation(frame);
        before_finish(&index, &scan);
        let index_path = preparation.index_path.clone();
        crate::agent_status_refresh::with_test_collection(collection(), || {
            finish_sync_source(
                preparation,
                index,
                scan,
                &client,
                &self.device,
                SECRET,
                SnapshotSource::ClaudeCode,
                "otm_test",
                &self.fixture.home,
                &self.support,
                &daemon,
                &mut transport,
                &mut self.retry,
            )
        })
        .unwrap();
        let offered = self.server.offered.lock().unwrap().clone();
        (offered, index_path)
    }

    /// Cycle 1 uploads the root (2 requests, 30 input tokens) and publishes
    /// the manifest. Returns that accepted root body.
    fn accepted_root(&mut self) -> serde_json::Value {
        let (offered, _) = self.cycle(|_, _| {});
        assert_eq!(offered.len(), 1, "cycle 1 uploads the root");
        assert_eq!(offered[0]["source_session_id"], IDENTITY_PIPELINE_ROOT);
        assert_eq!(money(&offered[0]), (2, 30));
        assert!(self.manifest_published(), "baseline: complete census");
        offered[0].clone()
    }
}

/// The finish inputs for the late member: the changed sidecars re-read the
/// unchanged root, and the native page completed its census with no traversal
/// left and no member file to list.
fn assert_completed_page(root: &Path, member: &Path, index: &ScanIndex, scan: &SourceScanResult) {
    assert!(
        scan.completed_parses()
            .any(|(key, _)| Path::new(key) == root),
        "the root was read on this page"
    );
    assert!(scan.census_complete, "the native page completed");
    assert!(
        serde_json::to_value(index).unwrap()["traversal"].is_null(),
        "no traversal left"
    );
    assert!(!member.exists());
}

/// [regress] The member transcript is written after the native page and
/// before finish. Finish queues its exact hint before the index save, keeps
/// the census open (the manifest is withdrawn) and leaves the root's
/// accepted money alone; later due cycles read the member once, with m, gap
/// and s, and publish the manifest again.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn late_member_finish_queues_exact_hint_and_reopens_census() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut pipeline = LateMemberPipeline::new("late-member-finish");
    let accepted = pipeline.accepted_root();
    let (m_at, s_at, gap_at) = (minutes_ago(170), minutes_ago(169), minutes_ago(168));
    pipeline.append_late_evidence(&m_at, &s_at);
    let (root, member) = (pipeline.root(), pipeline.member());
    let contents = transcript_line("req_m", &m_at, 30) + &transcript_line("req_gap", &gap_at, 7);
    let (offered, index_path) = pipeline.cycle(|index, scan| {
        assert_completed_page(&root, &member, index, scan);
        std::fs::write(&member, &contents).unwrap();
    });
    for body in &offered {
        assert_eq!(body["source_session_id"], IDENTITY_PIPELINE_ROOT);
        assert_eq!(body, &accepted, "the root's accepted body is unchanged");
    }
    assert!(
        pending_hint(&ScanIndex::load(&index_path).unwrap(), &member),
        "finish saved the exact hint"
    );
    assert!(
        !pipeline.manifest_published(),
        "the census stays open until the member is read"
    );

    let mut member_bodies = 0;
    for _ in 0..8 {
        let (offered, _) = pipeline.cycle(|_, _| {});
        for body in &offered {
            if body["source_session_id"] == member_session().as_str() {
                assert_eq!(money(body), (3, 42), "m, gap and s once");
                member_bodies += 1;
            } else {
                assert_eq!(body, &accepted, "the root's accepted body is unchanged");
            }
        }
        if member_bodies > 0 {
            assert!(
                !pending_hint(&ScanIndex::load(&index_path).unwrap(), &member),
                "a read member is never hinted again"
            );
            if pipeline.manifest_published() {
                break;
            }
        }
    }
    assert_eq!(member_bodies, 1, "the member is offered exactly once");
    assert!(pipeline.manifest_published(), "the census completes again");
}

/// Control: the same changed sidecars with no member transcript. Finish
/// queues nothing, the census stays complete (the manifest stays published)
/// and the root counts m and s as its fallback.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn late_member_absent_at_finish_keeps_manifest_and_root_fallback() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut pipeline = LateMemberPipeline::new("late-member-absent");
    pipeline.accepted_root();
    pipeline.append_late_evidence(&minutes_ago(170), &minutes_ago(169));
    let (root, member) = (pipeline.root(), pipeline.member());
    let (offered, index_path) = pipeline.cycle(|index, scan| {
        assert_completed_page(&root, &member, index, scan);
    });
    assert!(!pending_hint(
        &ScanIndex::load(&index_path).unwrap(),
        &member
    ));
    assert!(pipeline.manifest_published(), "nothing reopened the census");
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0]["source_session_id"], IDENTITY_PIPELINE_ROOT);
    assert_eq!(money(&offered[0]), (4, 65), "a, b, m and s on the root");
}
