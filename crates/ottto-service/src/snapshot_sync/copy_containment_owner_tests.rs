// Real LocalDaemon -> prepare_sync_source -> OwnedSourceScan policy tests.
// All data and HTTP responses are synthetic; no provider collection occurs.

const COPY_OWNER_HEALTHY: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";

fn copy_owner_prepare(
    fixture: &IdentityPipelineHome,
    support: &Path,
    daemon: &LocalDaemon,
) -> Result<SourcePreparation> {
    copy_owner_prepare_with_account_witness(fixture, support, daemon, [7; 32])
}
fn copy_owner_prepare_with_account_witness(
    fixture: &IdentityPipelineHome,
    support: &Path,
    daemon: &LocalDaemon,
    account_witness: [u8; 32],
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
                account_witness,
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
    // A typed hold records an actually evaluated opened revision. Arbitrary
    // digest fixtures would falsely appear to be a proved W1 change now that
    // own changes are independent of unrelated UNKNOWN peer/slot inputs.
    let daemon = test_daemon("otm_test");
    let (_, observed) = copy_owner_complete(copy_owner_prepare(fixture, support, &daemon).unwrap());
    let revision = observed
        .snapshots
        .iter()
        .find(|item| item.source_session_id == IDENTITY_PIPELINE_ROOT)
        .and_then(|item| item.source_file_fingerprint.clone())
        .expect("actual synthetic native opened revision");
    let mut value = serde_json::to_value(&index).unwrap();
    value["claude_copy_holds"][&key]["revision"]["source_revision"] = serde_json::json!(revision);
    let mut bound: ScanIndex = serde_json::from_value(value).unwrap();
    bound.save(&path).unwrap();
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

#[test]
#[serial]
fn copy_containment_real_own_change_evaluates_once_without_ack_or_other_known_wakes() {
    use std::io::Write;
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-owner-own-change");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let previous = ScanIndex::load_for_copy_containment(&path).unwrap();
    let old_debt = serde_json::to_value(&previous).unwrap()["claude_copy_holds"][&key].clone();
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let mut file = std::fs::OpenOptions::new().append(true).open(&key).unwrap();
    writeln!(file, "{}", serde_json::json!({"type":"assistant",
        "sessionId":IDENTITY_PIPELINE_ROOT,
        "timestamp":(OffsetDateTime::now_utc() - TimeDuration::minutes(119)).format(&Rfc3339).unwrap(),
        "requestId":"req_own_meaningful_change", "message":{"id":"msg_own_meaningful_change",
            "model":"claude-haiku-4-5","usage":{"input_tokens":9,"output_tokens":2}}
    })).unwrap();
    drop(file);
    let (mut index, mut scan) =
        copy_owner_complete(copy_owner_prepare(&fixture, &support, &daemon).unwrap());
    assert!(index.copy_registered_slot_fingerprint().is_none());
    if !crate::heap_layout_bound::layout_supported() {
        assert_eq!(scan.scanned_file_count, 1);
        assert_eq!(index.copy_parked_count(), 1);
        assert_eq!(index.copy_hold_count(), 1);
        writeln!(std::io::stderr().lock(), "copy_containment_real_own_event: layout_unavailable=true attempted_read_refused=true healthy_progress=true positive_actual_event_save_reload_executed=false").unwrap();
        return;
    }
    assert_eq!(scan.scanned_file_count, 2, "own event plus healthy sibling");
    assert_eq!(index.copy_parked_count(), 0);
    assert!(scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == IDENTITY_PIPELINE_ROOT));
    let (_authority, _, _) = apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.source_session_id != IDENTITY_PIPELINE_ROOT));
    crate::snapshots::finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
    let mut selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    let new_debt = serde_json::to_value(&selected).unwrap()["claude_copy_holds"][&key].clone();
    assert_ne!(
        new_debt["revision"]["source_revision"],
        old_debt["revision"]["source_revision"]
    );
    assert_eq!(
        new_debt["revision"]["reason"],
        old_debt["revision"]["reason"]
    );
    assert_eq!(
        new_debt["revision"]["first_observed_unix_seconds"],
        old_debt["revision"]["first_observed_unix_seconds"]
    );
    assert_eq!(new_debt["peers"], old_debt["peers"]);
    assert_eq!(selected.copy_hold_count(), 1);
    assert_eq!(
        selected.current_snapshot_fingerprints(),
        previous.current_snapshot_fingerprints()
    );
    selected.save(&path).unwrap(); // No body ACK and no debt drain.
    daemon.transcript_cache.clear();
    let restarted = test_daemon("otm_test");
    restarted
        .transcript_cache
        .require_copy_containment_for_test();
    for owner in [&daemon, &restarted] {
        let (index, scan) =
            copy_owner_complete(copy_owner_prepare(&fixture, &support, owner).unwrap());
        assert_eq!(index.copy_hold_count(), 1);
        assert_eq!(index.copy_parked_count(), 1);
        assert_eq!(
            scan.scanned_file_count, 1,
            "healthy sibling only after durable evaluation"
        );
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != IDENTITY_PIPELINE_ROOT));
    }
    writeln!(std::io::stderr().lock(), "copy_containment_real_own_event: actual_LocalDaemon_prepare_native_fold_selected_save=true independent_W1_read=1 other_wakes_unknown=true held_body_offered=false no_ACK_or_debt_drain=true unchanged_after_cache_clear_or_process_reads=0 healthy_progress=true failed_save_attempt_guard_unproved=true").unwrap();
}

#[test]
#[serial]
fn copy_containment_real_preparation_reads_semantic_slot_input_without_granting_unknown_other_wakes(
) {
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-owner-slots");
    let (path, _) = copy_owner_seed(&fixture, &support);
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let (index, scan) =
        copy_owner_complete(copy_owner_prepare(&fixture, &support, &daemon).unwrap());
    assert!(
        index.copy_registered_slot_fingerprint().is_none(),
        "missing required registry is UNKNOWN"
    );
    assert_eq!(index.copy_parked_count(), 1);
    assert_eq!(scan.scanned_file_count, 1);
    let before = std::fs::read(&path).unwrap();
    let registry = support.join(ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME);
    let mut value = serde_json::json!({"schema_version":2, "background_upkeep_consent":false,
        "registered_slots":[]});
    std::fs::write(&registry, serde_json::to_vec(&value).unwrap()).unwrap();
    let (index, scan) =
        copy_owner_complete(copy_owner_prepare(&fixture, &support, &daemon).unwrap());
    let known = index.copy_registered_slot_fingerprint().unwrap().to_owned();
    assert_eq!(known.len(), 64);
    assert_eq!(
        index.copy_parked_count(),
        1,
        "slot input alone cannot complete W1-W5"
    );
    assert_eq!(scan.scanned_file_count, 1);
    value["background_upkeep_consent"] = serde_json::json!(true);
    value["background_upkeep_consent_chosen"] = serde_json::json!(true);
    value["last_poll_at"] = serde_json::json!("2026-10-16T22:00:00Z");
    std::fs::write(&registry, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let (index, scan) =
        copy_owner_complete(copy_owner_prepare(&fixture, &support, &daemon).unwrap());
    assert_eq!(
        index.copy_registered_slot_fingerprint(),
        Some(known.as_str())
    );
    assert_eq!(index.copy_parked_count(), 1);
    assert_eq!(scan.scanned_file_count, 1);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "acquisition cannot settle or rewrite debt"
    );
    writeln!(std::io::stderr().lock(), "copy_containment_registered_binding_owner: actual_prepare_acquisition=true missing_required_unknown=true explicit_empty_registry_known=true maintenance_hash_stable=true held_reads=0 healthy_reads_per_cycle=1 other_required_wakes_unknown=true no_read_grant=true full_W5_unproved=true").unwrap();
}

#[test]
#[serial]
fn copy_containment_real_failed_parse_same_event_does_not_repeat_after_cache_or_connection_churn() {
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-attempt-parse-failure");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let before = std::fs::read(&path).unwrap();
    std::fs::write(&key, b"malformed native JSON\n").unwrap();
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let mut attempts = 0;
    let mut malformed = 0;
    for cycle in 0..3 {
        daemon.transcript_cache.clear();
        let (index, scan) = copy_owner_complete(
            copy_owner_prepare_with_account_witness(&fixture, &support, &daemon, [7 + cycle; 32])
                .unwrap(),
        );
        assert_eq!(index.copy_hold_count(), 1);
        assert!(scan
            .snapshots
            .iter()
            .any(|item| item.source_session_id == COPY_OWNER_HEALTHY));
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != IDENTITY_PIPELINE_ROOT));
        attempts += scan.scanned_file_count.saturating_sub(1);
        malformed += scan.malformed_json_line_count;
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "no fake durable evaluation"
        );
    }
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(attempts, 1);
        assert_eq!(malformed, 1);
    } else {
        assert_eq!(attempts, 0, "unavailable admission must park");
        assert_eq!(malformed, 0);
    }
    writeln!(std::io::stderr().lock(), "copy_containment_failed_parse_attempt: actual_LocalDaemon_preparations=3 held_native_attempts={attempts} malformed_lines={malformed} optional_clear_and_connection_witness_churn=true canonical_debt_bytes_preserved=true positive_failure_suppression_executed={} restart_crash_proof=false", crate::heap_layout_bound::layout_supported()).unwrap();
}

#[test]
#[serial]
fn copy_containment_real_losing_selected_save_same_event_does_not_repeat() {
    use std::io::Write;
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-attempt-cas-failure");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let before = serde_json::to_value(ScanIndex::load_for_copy_containment(&path).unwrap())
        .unwrap()["claude_copy_holds"]
        .clone();
    let mut file = std::fs::OpenOptions::new().append(true).open(&key).unwrap();
    writeln!(file, "{}", serde_json::json!({"type":"assistant", "sessionId":IDENTITY_PIPELINE_ROOT,
        "timestamp":(OffsetDateTime::now_utc() - TimeDuration::minutes(119)).format(&Rfc3339).unwrap(),
        "requestId":"req_cas_failure", "message":{"id":"msg_cas_failure", "model":"claude-haiku-4-5",
            "usage":{"input_tokens":13,"output_tokens":1}}})).unwrap();
    drop(file);
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let mut attempts = 0;
    let mut losers = 0;
    for cycle in 0..3 {
        daemon.transcript_cache.clear();
        let previous = ScanIndex::load_for_copy_containment(&path).unwrap();
        let (mut index, mut scan) = copy_owner_complete(
            copy_owner_prepare_with_account_witness(&fixture, &support, &daemon, [7 + cycle; 32])
                .unwrap(),
        );
        attempts += scan.scanned_file_count.saturating_sub(1);
        let _ = apply_claude_local_evidence_to_scan(&support, &mut scan, &mut index);
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != IDENTITY_PIPELINE_ROOT));
        assert!(scan
            .snapshots
            .iter()
            .any(|item| item.source_session_id == COPY_OWNER_HEALTHY));
        crate::snapshots::finalize_scan_after_policy(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut index,
        );
        let mut selected = index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        let mut winner = ScanIndex::load_for_copy_containment(&path).unwrap();
        winner.save(&path).unwrap(); // Real competing generation, no held event advance.
        assert!(
            selected.save(&path).is_err(),
            "stale selected save must actually lose CAS"
        );
        losers += 1;
        let canonical = ScanIndex::load_for_copy_containment(&path).unwrap();
        assert_eq!(
            serde_json::to_value(canonical).unwrap()["claude_copy_holds"],
            before
        );
    }
    assert_eq!(losers, 3);
    assert_eq!(
        attempts,
        usize::from(crate::heap_layout_bound::layout_supported())
    );
    writeln!(std::io::stderr().lock(), "copy_containment_failed_save_attempt: actual_LocalDaemon_preparations=3 real_generation_CAS_losers={losers} held_native_attempts={attempts} no_ACK_or_debt_drain=true healthy_progress=true optional_clear_and_connection_churn=true positive_failure_suppression_executed={} crash_lifetime_unproved=true", crate::heap_layout_bound::layout_supported()).unwrap();
}
