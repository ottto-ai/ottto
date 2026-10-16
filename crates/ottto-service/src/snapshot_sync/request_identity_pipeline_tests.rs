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
            crate::snapshots::OwnedSourceScanStep::Complete { index, scan } => break (index, scan),
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
