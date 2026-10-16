// Real LocalDaemon -> prepare_sync_source -> OwnedSourceScan policy tests.
// All data and HTTP responses are synthetic; no provider collection occurs.

const COPY_OWNER_HEALTHY: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";

fn copy_owner_prepare(
    fixture: &IdentityPipelineHome,
    support: &Path,
    daemon: &LocalDaemon,
) -> Result<SourcePreparation> {
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support);
    let client = SnapshotApiClient::new(snapshot_status_server_with_hint_extras(
        Arc::new(Mutex::new(Vec::new())),
        vec![(183, "")],
    ));
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
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
                &report_kind_test_device(),
                "device-secret",
                SnapshotSource::ClaudeCode,
                "otm_test",
                &fixture.home,
                support,
                daemon,
                &mut transport,
                [7; 32],
                false,
            )
        },
    )?
    .ok_or_else(|| anyhow!("expected a due synthetic Claude preparation"))
}

fn copy_owner_complete(mut frame: SourcePreparation) -> (ScanIndex, SourceScanResult) {
    loop {
        match frame.step() {
            SourcePreparationStep::Pending(next) => frame = next,
            SourcePreparationStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
}

fn copy_owner_seed(fixture: &IdentityPipelineHome, support: &Path) -> (PathBuf, String) {
    std::fs::create_dir_all(support).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let destination =
        snapshot_upload_destination_namespace(&report_kind_test_device(), "device-secret");
    let path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(support, source),
        &destination,
    ));
    let own = fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let key = own.to_string_lossy().into_owned();
    let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
    // A fully withheld uncommitted revision legitimately has debt without a
    // committed file entry. The test seeds debt, never a positive wake context.
    value["claude_copy_holds"] = serde_json::json!({(key.clone()): {
        "revision": {"version": 1, "reason": "copied_overlap_unproven",
            "source_revision": "c".repeat(64), "comparison_context": "d".repeat(64),
            "first_observed_unix_seconds": null},
        "peers": ["e".repeat(64)]
    }});
    let mut index: ScanIndex = serde_json::from_value(value).unwrap();
    index.save(&path).unwrap();
    let healthy = own.with_file_name(format!("{COPY_OWNER_HEALTHY}.jsonl"));
    let timestamp = (OffsetDateTime::now_utc() - TimeDuration::minutes(120))
        .format(&Rfc3339)
        .unwrap();
    std::fs::write(
        healthy,
        serde_json::json!({"type":"assistant",
            "sessionId": COPY_OWNER_HEALTHY, "timestamp": timestamp,
            "requestId":"req_healthy_own", "message":{"id":"msg_healthy_own",
                "model":"claude-haiku-4-5", "usage":{"input_tokens":7,"output_tokens":1}}
        })
        .to_string()
            + "\n",
    )
    .unwrap();
    (path, key)
}

#[test]
#[serial]
fn copy_containment_real_preparation_process_policy_survives_cache_clear_reload_and_generation() {
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-owner");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let daemon = test_daemon("otm_test");
    assert!(!daemon.transcript_cache.copy_containment_required());
    let (_, base) = copy_owner_complete(copy_owner_prepare(&fixture, &support, &daemon).unwrap());
    assert_eq!(
        base.scanned_file_count, 2,
        "disabled ordinary owner remains BASE"
    );
    daemon.transcript_cache.require_copy_containment_for_test();
    let clone = daemon.clone();
    assert!(Arc::ptr_eq(
        &daemon.transcript_cache,
        &clone.transcript_cache
    ));
    assert!(clone.transcript_cache.copy_containment_required());
    let before = serde_json::to_value(ScanIndex::load_for_copy_containment(&path).unwrap())
        .unwrap()["claude_copy_holds"]
        .clone();
    for cycle in 0..3 {
        if cycle == 1 {
            // Real optional reduction-cache eviction cannot revoke required
            // debt policy or mint a fresh read allowance.
            daemon.transcript_cache.clear();
        }
        let prep = copy_owner_prepare(&fixture, &support, &clone).unwrap();
        assert_eq!(prep.index_path, path);
        let (index, scan) = copy_owner_complete(prep);
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(index.copy_hold_count(), 1);
        assert_eq!(index.copy_parked_count(), 1);
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != IDENTITY_PIPELINE_ROOT));
        assert!(scan
            .snapshots
            .iter()
            .any(|item| item.source_session_id == COPY_OWNER_HEALTHY));
        assert_eq!(
            serde_json::to_value(&index).unwrap()["claude_copy_holds"],
            before
        );
        // A saved generation/reload is not a meaningful W1-W5 change. Keep
        // the same canonical debt, independently of this unuploaded test scan.
        let mut saved = ScanIndex::load_for_copy_containment(&path).unwrap();
        saved.save(&path).unwrap();
        assert_eq!(
            serde_json::to_value(&saved).unwrap()["claude_copy_holds"][&key],
            before[&key]
        );
    }
    // Simulated new process opts into the same required policy, not into a
    // restart read. There is no positive context/cache-refill promise here.
    let restarted = test_daemon("otm_test");
    restarted
        .transcript_cache
        .require_copy_containment_for_test();
    let (index, scan) =
        copy_owner_complete(copy_owner_prepare(&fixture, &support, &restarted).unwrap());
    assert_eq!(index.copy_parked_count(), 1);
    assert_eq!(scan.scanned_file_count, 1);
    writeln!(std::io::stderr().lock(), "copy_containment_real_owner: actual_LocalDaemon_prepare_step=true default_disabled_base_reads=2 required_held_reads=0 healthy_reads_per_cycle=1 cache_clear_keeps_policy=true generation_reload_no_read_grant=true simulated_process_required_no_restart_read=true positive_wake_witnesses_unavailable=true runtime_production_disabled=true healthy_ack_unproved_here=true").unwrap();
}

#[test]
#[serial]
fn copy_containment_real_preparation_rejects_invalid_required_index_without_rebuilding() {
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-owner-invalid");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["claude_copy_holds"][&key]["revision"]["version"] = serde_json::json!(99);
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let error = match copy_owner_prepare(&fixture, &support, &daemon) {
        Err(error) => error,
        Ok(_) => panic!("invalid required debt must stop before an owned scan exists"),
    };
    assert!(error
        .to_string()
        .contains("containment-required scan index"));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(ScanIndex::load_for_copy_containment(&path).is_err());
}
