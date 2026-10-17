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

#[test]
#[serial]
fn copy_containment_local_status_is_bounded_deduplicated_and_absent_from_backend_evidence() {
    let fixture = IdentityPipelineHome::new();
    let support = fixture.base.join("support-copy-local-status");
    let (path, key) = copy_owner_seed(&fixture, &support);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let index = ScanIndex::load_for_copy_containment(&path).unwrap();
    let daemon = test_daemon("otm_test");
    let unrelated = {
        let mut state = daemon.state().unwrap();
        crate::push_local_health_event(
            &mut state,
            "UnrelatedSyntheticEvidence",
            "unrelated",
            ottto_protocol::LocalHealthAuthority::Runtime,
            serde_json::json!({"unchanged":true}),
        );
        state.local_health_events.last().unwrap().clone()
    };
    record_copy_containment_status(&daemon, &index, "uncommitted_scan_observation").unwrap();
    assert_eq!(
        daemon.state().unwrap().local_health_events.len(),
        1,
        "defaultdisabled creates no event"
    );
    let before = crate::status_from_state(&daemon.state().unwrap());
    let original_ref = before
        .canonical_health
        .unwrap()
        .evidence
        .into_iter()
        .find(|value| value.event_id == unrelated.event_id)
        .unwrap();
    let original_bytes = serde_json::to_vec(&original_ref).unwrap();
    daemon.transcript_cache.require_copy_containment_for_test();
    record_copy_containment_status(&daemon, &index, "uncommitted_scan_observation").unwrap();
    let (first_id, first_sequence) = {
        let state = daemon.state().unwrap();
        let event = state
            .local_health_events
            .iter()
            .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
            .unwrap();
        (event.event_id.clone(), event.sequence)
    };
    for _ in 0..200 {
        record_copy_containment_status(&daemon, &index, "uncommitted_scan_observation").unwrap();
    }
    {
        let state = daemon.state().unwrap();
        assert_eq!(
            state.local_health_events.len(),
            2,
            "one aggregate, no event-per-pass history"
        );
        let event = state
            .local_health_events
            .iter()
            .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
            .unwrap();
        assert_eq!(event.event_id, first_id, "unchanged payload deduplicates");
        assert_eq!(event.payload["observation"]["held_revision_count"], 1);
        assert_eq!(
            event.payload["observation"]["past_acceptance_unknown_count"],
            1
        );
        assert!(event.payload["observation"]["new_without_prior_local_ack_count"].is_null());
        assert!(!serde_json::to_string(&event.payload)
            .unwrap()
            .contains(&key));
        assert!(!serde_json::to_string(&event.payload)
            .unwrap()
            .contains(IDENTITY_PIPELINE_ROOT));
    }
    let mut previous_id = first_id;
    let mut previous_sequence = first_sequence;
    for basis in [
        "durable_partial_selection",
        "uncommitted_scan_observation",
        "durable_selected_index",
    ] {
        record_copy_containment_status(&daemon, &index, basis).unwrap();
        let state = daemon.state().unwrap();
        let event = state
            .local_health_events
            .iter()
            .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
            .unwrap();
        assert_ne!(
            event.event_id, previous_id,
            "changed payload cannot reuse an event id"
        );
        assert_eq!(
            event.sequence,
            previous_sequence + 1,
            "bounded replacement still advances sequence"
        );
        previous_id = event.event_id.clone();
        previous_sequence = event.sequence;
    }
    let state = daemon.state().unwrap();
    assert_eq!(
        state.local_health_events.len(),
        2,
        "changed basis replaces one event"
    );
    assert_eq!(
        state
            .local_health_events
            .iter()
            .find(|event| event.event_type == "UnrelatedSyntheticEvidence")
            .unwrap(),
        &unrelated
    );
    let mut status = crate::status_from_state(&state);
    drop(state);
    let local_event = status
        .local_health_events
        .iter()
        .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
        .unwrap()
        .clone();
    assert_eq!(local_event.payload["basis"], "durable_selected_index");
    // Both actual backend projection and browser health paths consume only
    // canonical_health. Reprojection must not reintroduce the local reference.
    for _ in 0..2 {
        let health = status.canonical_health.as_ref().unwrap();
        let bytes = serde_json::to_vec(health).unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        assert!(!wire.contains(COPY_CONTAINMENT_EVENT_TYPE));
        assert!(!wire.contains(&local_event.event_id));
        let kept = health
            .evidence
            .iter()
            .find(|value| value.event_id == unrelated.event_id)
            .unwrap();
        assert_eq!(serde_json::to_vec(kept).unwrap(), original_bytes);
        assert!(status
            .local_health_events
            .iter()
            .any(|event| event.event_id == local_event.event_id));
        crate::refresh_canonical_local_health(&mut status);
    }
    writeln!(std::io::stderr().lock(), "copy_containment_status_envelope: default_disabled_no_event=true repeated_observations=200 own_retained_events=1 unchanged_payload_dedup=true changed_basis_replaces=true changed_payload_sequence_and_id_advance=true local_event_retained=true canonical_backend_type_and_id_absent=true unrelated_evidence_bytes_unchanged=true no_content=true").unwrap();
}

/// API ownership-transfer characterization, not a required-budget gate.
/// Caller-retained outputs after transfer are outside scan/cache31MiB.
/// The existing protocol values escape both producer and daemon lifetimes.
#[test]
fn copy_containment_status_caller_outputs_survive_api_ownership_transfer() {
    use std::io::Write;
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let index = ScanIndex::default();
    record_copy_containment_status(&daemon, &index, "uncommitted_scan_observation").unwrap();
    let (event_id, message_pointer) = {
        let state = daemon.state().unwrap();
        let event = state
            .local_health_events
            .iter()
            .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
            .unwrap();
        (
            event.event_id.clone(),
            event.payload["message"].as_str().unwrap().as_ptr() as usize,
        )
    };
    let ((statuses, serialized), allocations) = crate::retry_allocation_probe::measure(|| {
        let statuses = (0..4)
            .map(|_| daemon.status_for_trusted_client().unwrap())
            .collect::<Vec<_>>();
        let serialized = statuses
            .iter()
            .map(|status| serde_json::to_vec(status).unwrap())
            .collect::<Vec<_>>();
        (statuses, serialized)
    });
    assert!(allocations.requested_live > 0);
    let mut pointers = BTreeSet::new();
    for status in &statuses {
        let event = status
            .local_health_events
            .iter()
            .find(|event| event.event_id == event_id)
            .unwrap();
        let pointer = event.payload["message"].as_str().unwrap().as_ptr() as usize;
        assert_ne!(pointer, message_pointer, "status owns a DEEP payload copy");
        assert!(
            pointers.insert(pointer),
            "returned outputs do not alias payload storage"
        );
        assert!(!status
            .canonical_health
            .as_ref()
            .unwrap()
            .evidence
            .iter()
            .any(|evidence| evidence.event_type == COPY_CONTAINMENT_EVENT_TYPE));
    }
    drop(index);
    // Synthetic producer removal cannot retract already returned output.
    daemon
        .state()
        .unwrap()
        .local_health_events
        .retain(|event| event.event_id != event_id);
    drop(daemon);
    for (status, wire) in statuses.iter().zip(&serialized) {
        assert!(status
            .local_health_events
            .iter()
            .any(|event| event.event_id == event_id));
        assert_eq!(*wire, serde_json::to_vec(status).unwrap());
    }
    let later_clone = statuses[0].clone();
    assert!(later_clone
        .local_health_events
        .iter()
        .any(|event| event.event_id == event_id));
    writeln!(std::io::stderr().lock(), "copy_containment_status_output_escape: returned_statuses=4 serialized_outputs=4 deep_payloads=4 producer_and_daemon_dropped=true later_protocol_clone=true requested_live_all_output_including_baseline={} frame_credit_carrier=false no_admission_claim=true", allocations.requested_live).unwrap();
}

/// Private typed owner prototype, not ordinary producer/control attachment.
#[test]
fn copy_containment_typed_status_actual_reads_preserve_interleaved_sequences_and_disable() {
    use std::io::Write;
    let daemon = test_daemon("otm_test");
    let index = ScanIndex::default();
    let observation = index.copy_containment_status(Some(100));
    {
        let mut state = daemon.state().unwrap();
        assert_eq!(
            state.copy_observation.replace(
                &daemon.transcript_cache,
                observation.clone(),
                "durable_selected_index",
                1
            ),
            Some(false)
        );
        assert_eq!(state.copy_observation.last_sequence(), 0);
        crate::push_local_health_event(
            &mut state,
            "BeforeTypedObservation",
            "before_typed",
            ottto_protocol::LocalHealthAuthority::Runtime,
            serde_json::json!({"before":true}),
        );
    }
    daemon.transcript_cache.require_copy_containment_for_test();
    let result = {
        let mut state = daemon.state().unwrap();
        let next = crate::next_local_health_sequence(&state);
        state.copy_observation.replace(
            &daemon.transcript_cache,
            observation.clone(),
            "durable_selected_index",
            next,
        )
    };
    if result.is_none() {
        // Exact closed guard: unsupported branches must never be reported as
        // executed positive ordering/allocation proof.
        assert_eq!(daemon.state().unwrap().copy_observation.last_sequence(), 0);
        assert!(!daemon
            .status_for_trusted_client()
            .unwrap()
            .local_health_events
            .iter()
            .any(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE));
        writeln!(std::io::stderr().lock(), "copy_containment_typed_status_actual_owner: supported_projection=false multiread_interleaving_disable_positive=UNEXECUTED producer_unwired=true").unwrap();
        return;
    }
    assert_eq!(result, Some(true));
    {
        let mut state = daemon.state().unwrap();
        assert_eq!(state.copy_observation.last_sequence(), 2);
        crate::push_local_health_event(
            &mut state,
            "AfterTypedObservation",
            "after_typed",
            ottto_protocol::LocalHealthAuthority::Runtime,
            serde_json::json!({"after":true}),
        );
        assert_eq!(state.local_health_events.last().unwrap().sequence, 3);
        assert_eq!(
            state.local_health_events.len(),
            2,
            "typed slot never grows shared event history"
        );
    }
    let first = daemon.status_for_trusted_client().unwrap();
    let kept = first
        .local_health_events
        .iter()
        .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
        .unwrap()
        .clone();
    assert_eq!(kept.event_id, "evt_claude_copy_containment_2");
    assert_eq!(kept.payload["basis"], "durable_selected_index");
    assert_eq!(
        kept.payload["observation"],
        serde_json::to_value(&observation).unwrap()
    );
    for _ in 0..4 {
        let mut status = daemon.status_for_trusted_client().unwrap();
        assert_eq!(
            status
                .local_health_events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            status
                .local_health_events
                .iter()
                .find(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE),
            Some(&kept)
        );
        assert_eq!(
            crate::next_local_health_sequence(&daemon.state().unwrap()),
            4,
            "status projection never mutates state sequence"
        );
        for _ in 0..2 {
            crate::refresh_canonical_local_health(&mut status);
            assert_eq!(
                status
                    .local_health_events
                    .iter()
                    .filter(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE)
                    .count(),
                1
            );
            assert!(!status
                .canonical_health
                .as_ref()
                .unwrap()
                .evidence
                .iter()
                .any(|entry| entry.event_type == COPY_CONTAINMENT_EVENT_TYPE));
        }
    }
    {
        let mut state = daemon.state().unwrap();
        let next = crate::next_local_health_sequence(&state);
        assert_eq!(
            state.copy_observation.replace(
                &daemon.transcript_cache,
                observation.clone(),
                "durable_selected_index",
                next
            ),
            Some(false)
        );
        assert_eq!(state.copy_observation.last_sequence(), 2);
        assert_eq!(
            state.copy_observation.replace(
                &daemon.transcript_cache,
                observation,
                "durable_partial_selection",
                next
            ),
            Some(true)
        );
        assert_eq!(state.copy_observation.last_sequence(), 4);
        state.copy_observation.clear();
        assert_eq!(crate::next_local_health_sequence(&state), 5);
    }
    assert!(!daemon
        .status_for_trusted_client()
        .unwrap()
        .local_health_events
        .iter()
        .any(|event| event.event_type == COPY_CONTAINMENT_EVENT_TYPE));
    drop(daemon);
    assert!(
        first.local_health_events.iter().any(|event| event == &kept),
        "returned API values survive private slot disable/drop"
    );
    writeln!(std::io::stderr().lock(), "copy_containment_typed_status_actual_owner: supported_projection=true multiread=4 equal_payload_id_stable=true interleaved_order=true private_highwater_survives_clear=true reads_never_advance_sequence=true repeated_projection_no_duplicate=true canonical_exclusion=true caller_output_survives_drop=true producer_unwired=true").unwrap();
}

#[test]
#[serial]
fn copy_containment_control_status_lexical_guard_preserves_response_contract_and_private_sequence()
{
    use std::io::Write;
    let daemon = test_daemon("otm_test");
    daemon.transcript_cache.require_copy_containment_for_test();
    let index = ScanIndex::default();
    let admitted = daemon
        .state()
        .unwrap()
        .copy_observation
        .replace(
            &daemon.transcript_cache,
            index.copy_containment_status(Some(100)),
            "durable_selected_index",
            1,
        )
        .is_some();
    let request = serde_json::from_value::<ottto_protocol::LocalControlRequest>(serde_json::json!({
        "request_id":"req_copy_status_synthetic", "protocol_version":ottto_protocol::PROTOCOL_VERSION,
        "token":"token", "client_kind":"cli", "command":"status", "refresh_agent_status":false
    })).unwrap();
    let response = crate::control::handle_request(&daemon, request);
    assert!(response.ok, "{}", serde_json::to_string(&response).unwrap());
    assert_eq!(response.request_id, "req_copy_status_synthetic");
    let payload = response.payload.unwrap();
    let observations = payload["local_health_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["event_type"] == COPY_CONTAINMENT_EVENT_TYPE)
        .collect::<Vec<_>>();
    if admitted {
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["event_id"], "evt_claude_copy_containment_1");
        assert_eq!(daemon.state().unwrap().copy_observation.last_sequence(), 1);
    } else {
        assert!(observations.is_empty());
        assert_eq!(daemon.state().unwrap().copy_observation.last_sequence(), 0);
    }
    assert!(!serde_json::to_string(&payload["canonical_health"])
        .unwrap()
        .contains(COPY_CONTAINMENT_EVENT_TYPE));
    writeln!(std::io::stderr().lock(), "copy_containment_control_status: actual_handle_request=true refresh_agent_status=false protocol_unchanged=true canonical_exclusion=true private_sequence_unchanged=true positive_typed_slot_and_lexical_control_projection={} provider_fixture_calls=0 transport_unchanged=true", if admitted { "EXECUTED" } else { "UNEXECUTED" }).unwrap();
}
