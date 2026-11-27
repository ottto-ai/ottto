#[test]
#[serial]
fn local_health_refresh_hold_stays_on_the_binding_its_requests_used() {
    clear_setup_run_refresh_hold();
    let root = test_dir("local-health-refresh-hold-request-binding");
    let support_dir = root.join("support");
    let secrets_dir = root.join("secrets");
    std::fs::create_dir_all(&support_dir).expect("create support dir");
    std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let api_base_url = format!("http://{}", listener.local_addr().expect("local address"));
    let connection = {
        let api_base_url = api_base_url.clone();
        move |setup_run_id: &str| LocalConnectionBinding {
            setup_run_id: setup_run_id.to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("otm_test".to_string()),
            claim_code: None,
            api_base_url: api_base_url.clone(),
        }
    };
    const DEVICE_REJECTED: &str =
        r#"{"error":"AuthenticationError","detail":"Telemetry device is not active"}"#;
    // (status, body, setup run the user attaches while this request is in flight)
    let script: Vec<(u16, &'static str, Option<&'static str>)> = vec![
        // Run A: relay token, then a refresh answered terminally while B is attached.
        (401, DEVICE_REJECTED, None),
        (401, DEVICE_REJECTED, Some("setup_b")),
        // Run B: relay token, refresh succeeds, retry rejected while C is attached.
        (401, DEVICE_REJECTED, None),
        (
            200,
            r#"{"setup_run_token":"otsr_b","expires_at":"2026-05-05T11:00:00Z"}"#,
            None,
        ),
        (401, DEVICE_REJECTED, Some("setup_c")),
        // Run C: tried again.
        (401, DEVICE_REJECTED, None),
        (
            401,
            r#"{"detail":"Setup run not found for this device"}"#,
            None,
        ),
    ];
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_captured = captured.clone();
    let server_connection = connection.clone();
    let server = std::thread::spawn(move || {
        for (status, body, reattach) in script {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_complete_http_request(&mut stream);
            server_captured
                .lock()
                .expect("capture request")
                .push(request);
            if let Some(setup_run_id) = reattach {
                FileConnectionStore::default()
                    .save(&server_connection(setup_run_id))
                    .expect("reattach during the request");
            }
            let response = format!(
                "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });

    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    FileDeviceStore::default()
        .save(&device)
        .expect("save device");
    FileConnectionStore::default()
        .save(&connection("setup_a"))
        .expect("save connection");
    std::fs::write(
        secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        "device-secret",
    )
    .expect("save device secret");
    let daemon = test_daemon("otm_test");
    let client = SnapshotApiClient::new(api_base_url);
    let pass = || {
        let error = upload_local_health_projection_reporting(
            &client,
            &crate::control::capture_credential_authority().expect("capture credential"),
            SnapshotSource::Codex,
            "otm_test",
            &daemon,
        )
        .expect_err("a rejected device cannot upload");
        assert!(error.downcast_ref::<LocalHealthRefreshHeld>().is_none());
    };
    let requests = || captured.lock().expect("captured requests").len();

    // A's terminal refresh answer parks A, not B attached meanwhile.
    pass();
    assert_eq!(requests(), 2);
    pass();
    assert_eq!(requests(), 5, "B is tried, not held by A's answer");
    // B's rejected retry backs off B, not C attached meanwhile.
    pass();
    assert_eq!(requests(), 7, "C is tried, not held by B's rejection");

    server.join().expect("scripted backend");
    let captured = captured.lock().expect("captured requests").clone();
    for (index, setup_run_id) in [(1, "setup_a"), (3, "setup_b"), (6, "setup_c")] {
        assert!(
            captured[index].contains(&format!(
                "POST /api/v1/setup-runs/{setup_run_id}/local-client/refresh"
            )),
            "request {index} refreshes {setup_run_id}"
        );
    }

    clear_setup_run_refresh_hold();
    let _ = std::fs::remove_dir_all(root);
}

/// [regress] A settled upload changes only the refresh hold of the binding
/// its pass used: a hold another setup run or credential set meanwhile is
/// neither cleared nor overwritten.
#[test]
#[serial]
fn upload_hold_changes_touch_only_their_own_binding() {
    use super::telemetry_only::clear_setup_run_refresh_hold_for;
    use super::telemetry_only::note_setup_run_refresh_failed;
    use super::telemetry_only::setup_run_refresh_hold;
    let held = || {
        setup_run_refresh_hold()
            .lock()
            .expect("hold")
            .map(|hold| (hold.binding, hold.until.is_none()))
    };
    let ours = [1u8; 32];
    let theirs = [2u8; 32];
    clear_setup_run_refresh_hold();
    note_setup_run_refresh_failed(&theirs, true);
    note_setup_run_refresh_failed(&ours, false);
    assert_eq!(
        held(),
        Some((theirs, true)),
        "a late failure keeps the newer hold"
    );
    clear_setup_run_refresh_hold_for(&ours);
    assert_eq!(held(), Some((theirs, true)), "a late success keeps it too");
    clear_setup_run_refresh_hold_for(&theirs);
    assert_eq!(held(), None);
    note_setup_run_refresh_failed(&ours, false);
    assert_eq!(held(), Some((ours, false)));
    clear_setup_run_refresh_hold();
}

#[test]
#[serial(source_manifests)]
fn collector_status_report_mints_fresh_relay_token() {
    let _source_manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let api_base_url = snapshot_status_server(captured.clone());
    let client = SnapshotApiClient::new(api_base_url);
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };

    report_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::Withdraw,
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2026-06-01T10:00:00Z",
            counts: SyncCounts::for_policy(30),
            state: CollectorState::Success,
        },
    )
    .expect("report status with fresh relay token");

    let requests = captured.lock().expect("captured requests").clone();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
    assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
    assert!(requests[0].contains("\"source\":\"codex\""));
    assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
    assert!(requests[1].contains("Authorization:"));
    assert!(requests[1].contains("relay-token-codex"));
    assert!(requests[1].contains("\"schema_version\":5"));
    assert!(requests[1].contains("\"source\":\"codex\""));
    assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
}

fn report_kind_test_device() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    }
}

#[test]
#[serial(source_manifests)]
fn terminal_scan_status_reads_the_durable_first_census_cutoff() {
    let _guard = SourceManifestTestGuard::new();
    let support = test_terminal_status_support_dir();
    let destination =
        snapshot_upload_destination_namespace(&report_kind_test_device(), "device-secret");
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let absent = captured_terminal_receipt_for_source_under_hint(
            source,
            SyncCounts::for_policy(183),
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            "",
        );
        assert!(absent.get("first_read_cutoff").is_none());
        crate::backfill::record_first_census(
            support,
            source,
            &destination,
            "2026-11-12T12:00:00Z",
            true,
        )
        .unwrap();
        for width in [30, 183] {
            let present = captured_terminal_receipt_for_source_under_hint(
                source,
                SyncCounts::for_policy(width),
                CollectorState::Success,
                TerminalManifestSource::Withdraw,
                width,
                "",
            );
            assert_eq!(present["first_read_cutoff"], "2026-09-13T12:00:00.000Z");
            assert_eq!(present["last_backfill_window_days"], width);
            assert!(present.get("first_read").is_none());
        }
        let beat = captured_checkin_receipt(None);
        assert!(beat.get("first_read_cutoff").is_none());
    }
}

/// Capture the wire body of one liveness beat, with or without a cycle-start clock.
fn captured_checkin_receipt(scan_started_at: Option<&str>) -> serde_json::Value {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
    report_checkin_status_with_fresh_relay_token(
        &client,
        &report_kind_test_device(),
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        scan_started_at,
    )
    .expect("liveness beat");
    let requests = captured.lock().expect("captured requests").clone();
    http_request_json(&requests[1])
}

/// Capture the wire body of one terminal receipt for a given outcome.
fn captured_terminal_receipt(
    counts: SyncCounts,
    state: CollectorState<'_>,
    manifest_source: TerminalManifestSource<'_>,
    hint_days: u64,
) -> serde_json::Value {
    captured_terminal_receipt_under_hint(counts, state, manifest_source, hint_days, "")
}

/// Same, with extra JSON members appended to the activity hint the server
/// answers — the backend's additive capability advertisements.
fn captured_terminal_receipt_under_hint(
    counts: SyncCounts,
    state: CollectorState<'_>,
    manifest_source: TerminalManifestSource<'_>,
    hint_days: u64,
    hint_extra: &'static str,
) -> serde_json::Value {
    captured_terminal_receipt_for_source_under_hint(
        SnapshotSource::Codex,
        counts,
        state,
        manifest_source,
        hint_days,
        hint_extra,
    )
}

fn captured_terminal_receipt_for_source_under_hint(
    source: SnapshotSource,
    counts: SyncCounts,
    state: CollectorState<'_>,
    manifest_source: TerminalManifestSource<'_>,
    hint_days: u64,
    hint_extra: &'static str,
) -> serde_json::Value {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server_with_hint_extras(
        captured.clone(),
        vec![(hint_days, hint_extra)],
    ));
    report_status_with_fresh_relay_token(
        &client,
        &report_kind_test_device(),
        "device-secret",
        test_terminal_status_support_dir(),
        source,
        manifest_source,
        CollectorStatus {
            source,
            machine_id: "otm_test",
            scan_started_at: "2026-06-01T10:00:00Z",
            counts,
            state,
        },
    )
    .expect("terminal receipt");
    let requests = captured.lock().expect("captured requests").clone();
    http_request_json(&requests[1])
}

/// A serving daemon's check-in reports its local control
/// plane beside upload liveness.
#[test]
#[serial(source_manifests)]
fn a_serving_daemons_checkin_carries_control_plane_health() {
    let _source_manifests = SourceManifestTestGuard::new();
    crate::control_plane_health::mark_serving(
        crate::control_plane_health::ControlTransport::UnixSocket,
    );

    let beat = captured_checkin_receipt(None);

    assert_eq!(beat["report_kind"], "checkin");
    let control_plane = beat["control_plane"]
        .as_object()
        .expect("check-in carries a control_plane object");
    assert_eq!(control_plane["transport"], "unix_socket");
    assert!(control_plane["listener_bound"].is_boolean());
    assert!(
        control_plane["listener_draining"].is_boolean()
            || control_plane["listener_draining"].is_null()
    );
    assert!(control_plane["requests_served"].is_u64());
    assert!(control_plane["request_errors"].is_u64());
    assert!(control_plane["started_at"].is_string());
    assert!(control_plane.contains_key("last_request_served_at"));
    // Never a socket path: it would carry the user's home directory.
    let mut members: Vec<&str> = control_plane.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "last_request_served_at",
            "listener_bound",
            "listener_draining",
            "request_errors",
            "requests_served",
            "started_at",
            "transport",
        ]
    );
    // The check-in's other members are untouched, and so is its declared
    // schema version: the field is additive.
    assert_eq!(beat["schema_version"], SNAPSHOT_STATUS_SCHEMA_VERSION);
}

/// Only check-ins carry control-plane health. A scan result keeps the
/// exact wire shape it had before the field existed, even from a serving
/// daemon.
#[test]
#[serial(source_manifests)]
fn terminal_receipts_never_carry_control_plane_health() {
    let _source_manifests = SourceManifestTestGuard::new();
    crate::control_plane_health::mark_serving(
        crate::control_plane_health::ControlTransport::UnixSocket,
    );
    let mut counts = SyncCounts::for_policy(30);
    counts.census_complete = true;

    let terminal = captured_terminal_receipt(
        counts,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        30,
    );

    assert_eq!(terminal["report_kind"], "scan_status");
    assert!(terminal.get("control_plane").is_none(), "{terminal}");
}

/// A liveness beat may only repeat evidence the backend has already
/// accepted. `report_checkin_status` has no path to the last terminal
/// receipt, so a beat replays nothing at all: every scan-result field is
/// literally absent, zero, or false, and the only carried witness is the
/// cached manifest from the last completed terminal report.
#[test]
#[serial(source_manifests)]
fn a_liveness_beat_discloses_nothing_the_backend_has_not_accepted() {
    let _source_manifests = SourceManifestTestGuard::new();
    let beat = captured_checkin_receipt(Some("2026-06-01T10:00:00Z"));
    assert_eq!(beat["report_kind"], "checkin");
    assert_eq!(beat["enabled"], true);
    for absent in [
        "disabled_reason",
        "last_scan_finished_at",
        "last_success_at",
        "last_error_code",
        "last_error_message",
        "next_retry_at",
    ] {
        assert!(beat[absent].is_null(), "{absent} must be absent on a beat");
    }
    assert_eq!(beat["last_scan_cap_hit"], false);
    // The KEY must be missing, not present-and-false. The backend resolves
    // census completeness by whether the field was declared at all: an
    // omitted one retains what it already accepted, an explicit `false`
    // lowers it. `is_null()` would pass for a serialized `null` too, so
    // assert on the object's keys.
    assert!(
        !beat
            .as_object()
            .expect("beat is a JSON object")
            .contains_key("last_census_complete"),
        "a beat must not put last_census_complete on the wire at all: {beat}"
    );
    for counter in [
        "last_uploaded_count",
        "last_scanned_session_count",
        "last_scanned_file_count",
        "last_zero_snapshot_confirmed_count",
        "last_zero_snapshot_usage_evidence_count",
        "last_dropped_usage_record_count",
        "last_ownership_incomplete_file_count",
        "last_snapshot_unproven_terminal_count",
        "last_snapshot_superseded_terminal_count",
        "last_backfill_file_limit",
        "last_discovered_file_count",
        "last_skipped_file_count_due_to_limit",
        "last_semantic_noop_count",
        "last_symlink_rejected_count",
        "last_unreadable_path_count",
        "last_oversized_file_count",
        "last_disappeared_file_count",
        "last_malformed_json_line_count",
        "last_invalid_utf8_line_count",
        "last_over_line_cap_count",
        "last_recognized_usage_drop_count",
        "consecutive_failures",
    ] {
        assert_eq!(beat[counter], 0, "{counter} must be zero on a beat");
    }
}

/// Census completeness is the one census field with no arithmetic identity,
/// so its wire treatment differs from every counter above and is asserted
/// on its own.
///
/// The backend merges a check-in's census into what it already accepted.
/// Counters take a `max`, for which a beat's honest `0` is the identity and
/// therefore harmless. Completeness takes a conjunction resolved through
/// `model_fields_set`: an OMITTED value retains the accepted one, an
/// explicitly declared `false` asserts incompleteness and lowers it. A beat
/// has run no census, so it must send neither `false` (which would retract
/// a complete census on every heartbeat) nor `true` (which would assert one
/// it never measured) — it must send nothing. The terminal path, which did
/// run the census, still states the measured value in both directions.
#[test]
#[serial(source_manifests)]
fn only_a_scan_result_puts_census_completeness_on_the_wire() {
    let _source_manifests = SourceManifestTestGuard::new();

    for scan_started_at in [None, Some("2026-06-01T10:00:00Z")] {
        let beat = captured_checkin_receipt(scan_started_at);
        assert_eq!(beat["report_kind"], "checkin");
        assert!(
            !beat
                .as_object()
                .expect("beat is a JSON object")
                .contains_key("last_census_complete"),
            "the key must be absent, not null and not false: {beat}"
        );
    }

    // Both terminal outcomes still declare what the census actually found.
    let mut complete = SyncCounts::for_policy(30);
    complete.census_complete = true;
    let terminal_complete = captured_terminal_receipt(
        complete,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        30,
    );
    assert_eq!(terminal_complete["report_kind"], "scan_status");
    assert_eq!(terminal_complete["last_census_complete"], true);

    let mut incomplete = SyncCounts::for_policy(30);
    incomplete.census_complete = false;
    let terminal_incomplete = captured_terminal_receipt(
        incomplete,
        CollectorState::Error {
            code: "scan_error",
            message: "local snapshot scan failed",
        },
        TerminalManifestSource::Withdraw,
        30,
    );
    assert_eq!(terminal_incomplete["report_kind"], "scan_status");
    assert_eq!(terminal_incomplete["last_census_complete"], false);
}

#[test]
#[serial(source_manifests)]
fn a_new_or_changed_error_declares_a_scan_status() {
    let _source_manifests = SourceManifestTestGuard::new();
    for (code, message) in [
        ("scan_error", "local snapshot scan failed"),
        ("upload_error", "local snapshot upload failed"),
    ] {
        let terminal = captured_terminal_receipt(
            SyncCounts::for_policy(30),
            CollectorState::Error { code, message },
            TerminalManifestSource::Withdraw,
            30,
        );
        assert_eq!(terminal["report_kind"], "scan_status");
        assert_eq!(terminal["last_error_code"], code);
        assert_eq!(terminal["consecutive_failures"], 1);
    }

    // The derived parse_error: a scan that "succeeded" while losing
    // recognized usage is a changed loss census, never a liveness beat.
    let mut counts = SyncCounts::for_policy(30);
    counts.census_complete = true;
    counts.discovered_file_count = 1;
    counts.dropped_usage_record_count = 1_105;
    counts.recognized_usage_drop_count = 1_105;
    counts.ownership_incomplete_file_count = 1;
    let lossy = captured_terminal_receipt(
        counts,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        30,
    );
    assert_eq!(lossy["report_kind"], "scan_status");
    assert_eq!(lossy["last_error_code"], "parse_error");
    assert_eq!(lossy["last_dropped_usage_record_count"], 1_105);

    // [money] Loss is never a settled zero-dollar result, and an accepted
    // healthy sibling cannot hide the dropped record.
    for healthy_sibling in [false, true] {
        let mut counts = SyncCounts::for_policy(30);
        counts.census_complete = true;
        counts.discovered_file_count = 1;
        if healthy_sibling {
            counts.scanned_session_count = 1;
            counts.uploaded_count = 1;
            counts.dropped_usage_record_count = 1;
        } else {
            counts.zero_snapshot_usage_evidence_count = 1;
        }
        let receipt = captured_terminal_receipt_for_source_under_hint(
            SnapshotSource::Pi,
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            30,
            "",
        );
        assert_eq!(receipt["report_kind"], "scan_status");
        assert_eq!(receipt["last_error_code"], "parse_error");
        assert!(receipt["last_success_at"].is_null());
        assert_eq!(receipt["consecutive_failures"], 1);
        if healthy_sibling {
            assert_eq!(receipt["last_dropped_usage_record_count"], 1);
            assert_eq!(receipt["last_uploaded_count"], 1);
        } else {
            assert_eq!(receipt["last_zero_snapshot_usage_evidence_count"], 1);
            assert_eq!(receipt["last_uploaded_count"], 0);
        }
    }
}

/// `checkin` + disabled is a backend 400 by contract. It is also
/// unreachable here: the disabled transition is a durable state report and
/// only the terminal path can express it.
#[test]
#[serial(source_manifests)]
fn a_disabled_state_report_declares_a_scan_status_and_never_a_checkin() {
    let _source_manifests = SourceManifestTestGuard::new();
    let disabled = captured_terminal_receipt(
        SyncCounts::for_policy(30),
        CollectorState::Disabled(Some("disabled_by_admin".to_string())),
        TerminalManifestSource::Withdraw,
        30,
    );
    assert_eq!(disabled["report_kind"], "scan_status");
    assert_eq!(disabled["enabled"], false);
    assert_eq!(disabled["disabled_reason"], "disabled_by_admin");

    // The server-authoritative zero-width tombstone withdraws the census
    // without claiming a scan; it is still a state report, not liveness.
    let tombstone = captured_terminal_receipt(
        SyncCounts::for_policy(0),
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        0,
    );
    assert_eq!(tombstone["report_kind"], "scan_status");
    assert_eq!(tombstone["last_backfill_window_days"], 0);
    assert_eq!(tombstone["last_census_complete"], false);
}

/// Mutation proof for Attack 2: take the REAL receipt the collector builds
/// for a fresh error and force its declared kind to `checkin`. The egress
/// guard refuses it, so no code path — present or future — can beat while
/// disclosing scan evidence the backend has not accepted.
#[test]
#[serial(source_manifests)]
fn forcing_a_checkin_onto_a_receipt_carrying_a_new_error_never_reaches_the_wire() {
    let _source_manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));

    let mut request = collector_status_request(
        "destination",
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2026-06-01T10:00:00Z",
            counts: SyncCounts::for_policy(30),
            state: CollectorState::Error {
                code: "scan_error",
                message: "local snapshot scan failed",
            },
        },
        false,
    )
    .expect("terminal error receipt");
    assert_eq!(request.report_kind, SnapshotStatusReportKind::ScanStatus);
    assert_eq!(request.last_error_code.as_deref(), Some("scan_error"));
    // Truthfully declared, it travels.
    client
        .report_status("relay-token-codex", &request)
        .expect("a scan status carrying an error is accepted");

    // The mutation: only the declaration changes.
    request.report_kind = SnapshotStatusReportKind::Checkin;
    let refused = client
        .report_status("relay-token-codex", &request)
        .expect_err("a beat may not disclose a new error");
    assert!(
        refused.to_string().contains("report_kind=checkin"),
        "unexpected refusal: {refused}"
    );

    // Exactly one receipt reached the server: the truthful one.
    let requests = captured.lock().expect("captured requests").clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        http_request_json(&requests[0])["report_kind"],
        "scan_status"
    );
}

/// [off=main] Absent/null/unknown admission preserves the complete legacy
/// payload for all three sources, including failures=1 and no retry deadline.
/// [behaviour] The real hint boundary and shared builder emit all six
/// causes plus advancing work, with fixed priority and truthful retries.
#[test]
#[serial(source_manifests)]
fn census_status_contract_reports_first_gate_and_real_retry() {
    let _source_manifests = SourceManifestTestGuard::new();
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        // One row per cause; each earlier row also fails later gates.
        for (
            cause,
            (
                unreadable,
                disappeared,
                state,
                transport,
                reconciliation,
                ownership,
                pending,
                retryable,
            ),
        ) in [
            (
                Some("unreadable_events"),
                (2, 3, true, true, true, 1, true, true),
            ),
            (
                Some("disappeared_files"),
                (0, 3, true, true, true, 1, true, true),
            ),
            (
                Some("state_loader"),
                (0, 0, true, true, true, 1, true, true),
            ),
            (
                Some("transport_reservation"),
                (0, 0, false, true, true, 1, true, true),
            ),
            (
                Some("ownership_incomplete"),
                (0, 0, false, false, true, 1, true, true),
            ),
            (Some("other"), (0, 0, false, false, true, 0, true, true)),
            (None, (0, 0, false, false, false, 1, true, false)),
        ] {
            let mut counts = SyncCounts::for_policy(183);
            counts.skipped_file_count_due_to_limit = 7;
            counts.scan_cap_hit = true;
            counts.unreadable_path_count = unreadable;
            counts.disappeared_file_count = disappeared;
            counts.ownership_incomplete_file_count = ownership;
            counts.census_status = crate::snapshots::CensusStatus {
                pending_work: pending,
                retryable_problem: retryable,
                transport_reservation_refused: transport,
                state_loader_failed: state,
                reconciliation_incomplete: reconciliation,
                retry_attempt: 4,
                retry_not_before_unix_seconds: Some(60),
            };
            let receipt = captured_terminal_receipt_for_source_under_hint(
                source,
                counts,
                CollectorState::Success,
                TerminalManifestSource::Withdraw,
                183,
                // A retired hint token the daemon no longer reads.
                r#","census_status_contract":"census_status:v1""#,
            );
            assert_eq!(
                receipt["last_error_code"],
                if cause.is_some() {
                    "census_blocked"
                } else {
                    "census_incomplete"
                }
            );
            assert_eq!(
                receipt.get("last_census_block_cause"),
                cause.map(|value| serde_json::json!(value)).as_ref()
            );
            assert_eq!(receipt["last_census_pending_file_count"], 7);
            assert_eq!(receipt["consecutive_failures"], 4);
            assert_eq!(receipt["next_retry_at"], "1970-01-01T00:01:00Z");
            assert_eq!(receipt["last_success_at"], serde_json::Value::Null);
            assert_eq!(receipt["last_census_complete"], false);
        }
    }
}

mod census_ownership_tests {
    use super::*;

    /// [regress] Settled ownership does not block a draining census; an
    /// additional account-deferred hold still blocks through the shared gate.
    #[test]
    #[serial(source_manifests)]
    fn draining_census_blocks_only_unsettled_ownership() {
        let _source_manifests = SourceManifestTestGuard::new();
        for source in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ] {
            for deferred_hold in [false, true] {
                let index = if deferred_hold {
                    claude_index_with(serde_json::json!({
                        "claude_account_deferred_holds": {"/opaque/deferred.jsonl": "deferred-source"},
                    }))
                } else {
                    ScanIndex::default()
                };
                let mut counts = SyncCounts::for_policy(183);
                counts.ownership_incomplete_file_count = 1;
                counts.terminal_ownership_incomplete_file_count = 1;
                counts.skipped_file_count_due_to_limit = 7;
                counts.census_status.pending_work = true;
                counts.census_status.reconciliation_incomplete = true;
                let receipt = captured_terminal_receipt_for_source_under_hint(
                    source,
                    counts.with_snapshot_terminal_counts(&index),
                    CollectorState::Success,
                    TerminalManifestSource::Withdraw,
                    183,
                    RESIDUE_ADMITTING_HINT,
                );
                assert_eq!(
                    receipt["last_error_code"],
                    if deferred_hold {
                        "census_blocked"
                    } else {
                        "census_incomplete"
                    }
                );
                assert_eq!(
                    receipt.get("last_census_block_cause"),
                    deferred_hold
                        .then(|| serde_json::json!("ownership_incomplete"))
                        .as_ref()
                );
                assert_eq!(receipt["last_census_complete"], false);
                assert_eq!(receipt["last_census_pending_file_count"], 7);
                assert_eq!(
                    receipt["last_ownership_incomplete_file_count"],
                    1 + u64::from(deferred_hold)
                );
                assert_eq!(receipt["last_terminal_ownership_incomplete_file_count"], 1);
            }
        }
    }
}

/// The codex witness once its residue settles: a COMPLETED
/// census whose every nonzero loss class equals its terminal counterpart,
/// with the witness reported as counts only.
fn m1_named_residue_counts() -> SyncCounts {
    let mut counts = SyncCounts::for_policy(183);
    counts.census_complete = true;
    counts.discovered_file_count = 448;
    counts.scanned_file_count = 448;
    counts.scanned_session_count = 442;
    counts.ownership_incomplete_file_count = 1;
    counts.zero_snapshot_usage_evidence_count = 1;
    counts.recognized_usage_drop_count = 1_105;
    counts.dropped_usage_record_count = 1_105;
    counts.terminal_ownership_incomplete_file_count = 1;
    counts.terminal_zero_snapshot_usage_evidence_count = 1;
    counts.terminal_recognized_usage_drop_count = 1_105;
    counts.terminal_dropped_usage_record_count = 1_105;
    counts.census_residue_index_key_count = 1;
    counts.census_residue_archived_rollout_count = 1;
    counts
}

/// The activity-hint member a backend that admits the code advertises.
const RESIDUE_ADMITTING_HINT: &str =
    r#","census_residue_status_contract":"census_residue_status:v1""#;

fn claude_usage_authority_index(dispositions: &[(&str, usize)]) -> ScanIndex {
    let quarantine = dispositions
        .iter()
        .enumerate()
        .map(|(family_index, (disposition, member_count))| {
            let members = (0..*member_count)
                .map(|member_index| {
                    (
                        format!("session-{family_index}-{member_index}"),
                        serde_json::Value::String(format!(
                            "{:064x}",
                            family_index * 100 + member_index + 1
                        )),
                    )
                })
                .collect::<serde_json::Map<_, _>>();
            (
                format!("root-{family_index}"),
                serde_json::json!({
                    "contract": "claude_usage_authority_quarantine:v1",
                    "proven_witness_fingerprint": format!("{:064x}", family_index + 1_000),
                    "member_source_file_fingerprints": members,
                    "failed_reconstruction_count": if *disposition == "unproven_terminal" { 4 } else { 1 },
                    "disposition": disposition,
                    "retry_after_unix_seconds": 0,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let mut serialized = serde_json::to_value(ScanIndex::default()).expect("serialize index");
    serialized
        .as_object_mut()
        .expect("index is an object")
        .insert(
            "claude_usage_authority_quarantine".to_string(),
            serde_json::Value::Object(quarantine),
        );
    serde_json::from_value(serialized).expect("deserialize authority quarantine fixture")
}

fn claude_usage_authority_census_counts(
    fixture_name: &str,
    dispositions: &[(&str, usize)],
) -> SyncCounts {
    let root = test_dir(fixture_name);
    std::fs::create_dir_all(&root).expect("create empty Claude scan root");
    // A RetryPending family is present on disk: a raw-complete census
    // retires a wholly absent one (path-(a) bridge), so its debt would
    // no longer withhold anything.
    for (family_index, (disposition, _)) in dispositions.iter().enumerate() {
        if *disposition == "retry_pending" {
            let session = format!("root-{family_index}");
            std::fs::write(
                root.join(format!("{session}.jsonl")),
                format!(
                    "{{\"timestamp\":\"2026-06-01T09:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"req_{session}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
                ),
            )
            .expect("write the held family's present member");
        }
    }
    let mut index = claude_usage_authority_index(dispositions);
    let mut scan = crate::snapshots::scan_source_roots(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut index,
        "2026-06-01T10:00:00Z",
        183,
    )
    .expect("scan empty Claude root");
    if index.account_claude_usage_authority_census_health(&mut scan) {
        scan.census_complete = false;
        scan.scan_cap_hit = true;
    }
    let counts = SyncCounts::from_scan_result(&scan, 0, 183);
    let _ = std::fs::remove_dir_all(root);
    counts
}

/// A named mutation of the receipt counts, for table-driven vetoes.
type CountsMutation = (&'static str, fn(&mut SyncCounts));

const RESIDUE_TERMINAL_PAIRS: [(&str, &str); 5] = [
    (
        "last_terminal_ownership_incomplete_file_count",
        "last_ownership_incomplete_file_count",
    ),
    (
        "last_terminal_zero_snapshot_usage_evidence_count",
        "last_zero_snapshot_usage_evidence_count",
    ),
    (
        "last_terminal_recognized_usage_drop_count",
        "last_recognized_usage_drop_count",
    ),
    (
        "last_terminal_dropped_usage_record_count",
        "last_dropped_usage_record_count",
    ),
    (
        "last_terminal_over_line_cap_count",
        "last_over_line_cap_count",
    ),
];

/// A census that completed with only settled, non-progressing residue is
/// a successful scan. Once the backend admits the code the receipt says
/// so: `census_residue`, zero failures, and the success clock bound to
/// the finish clock — with each settled share equal to the public loss it
/// settles, so a consumer can prove the residue class by class instead of
/// trusting the code.
#[test]
#[serial(source_manifests)]
fn a_settled_residue_census_reports_census_residue_once_the_backend_admits_it() {
    let _source_manifests = SourceManifestTestGuard::new();
    let receipt = captured_terminal_receipt_under_hint(
        m1_named_residue_counts(),
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert_eq!(receipt["report_kind"], "scan_status");
    assert_eq!(receipt["enabled"], true);
    assert_eq!(receipt["last_error_code"], "census_residue");
    assert_eq!(
        receipt["last_error_message"],
        "census completed with settled non-progressing residue: \
             ownership_incomplete_files=1, zero_snapshot_usage_evidence_files=1, \
             recognized_usage_drops=1105, dropped_usage_records=1105, over_line_cap_lines=0"
    );
    assert_eq!(receipt["consecutive_failures"], 0);
    assert!(receipt["next_retry_at"].is_null());
    assert_eq!(receipt["last_census_complete"], true);
    assert_eq!(receipt["last_scan_cap_hit"], false);
    assert_eq!(receipt["last_skipped_file_count_due_to_limit"], 0);
    // The scan succeeded, so the clock binds. This is the identity every
    // backend terminal predicate reads.
    assert!(receipt["last_success_at"].is_string());
    assert_eq!(receipt["last_success_at"], receipt["last_scan_finished_at"]);
    for (terminal, public) in RESIDUE_TERMINAL_PAIRS {
        assert_eq!(receipt[terminal], receipt[public], "{terminal}");
    }
    assert_eq!(receipt["last_terminal_ownership_incomplete_file_count"], 1);
    assert_eq!(
        receipt["last_terminal_zero_snapshot_usage_evidence_count"],
        1
    );
    assert_eq!(receipt["last_terminal_recognized_usage_drop_count"], 1_105);
    assert_eq!(receipt["last_terminal_dropped_usage_record_count"], 1_105);
    assert_eq!(receipt["last_terminal_over_line_cap_count"], 0);
    assert_eq!(receipt["last_census_residue_settled"], true);
    assert_eq!(receipt["last_census_residue_index_key_count"], 1);
    assert_eq!(receipt["last_census_residue_archived_rollout_count"], 1);
    assert!(receipt
        .get("last_census_residue_blocked_session_count")
        .is_none());
    // Counts only. The backend refuses a path-shaped message outright,
    // and the witness's index keys never leave the index.
    let message = receipt["last_error_message"].as_str().expect("message");
    for fragment in [
        "/",
        "\\",
        ".jsonl",
        ".codex",
        ".claude",
        "transcript_path",
        "workspace_path",
    ] {
        assert!(!message.contains(fragment), "{fragment:?} in {message:?}");
    }
}

#[test]
#[serial(source_manifests)]
fn exhausted_claude_authority_is_terminal_residue() {
    let _source_manifests = SourceManifestTestGuard::new();
    let exhausted = claude_usage_authority_census_counts(
        "exhausted-claude-authority-receipt",
        &[("unproven_terminal", 3)],
    );
    assert!(exhausted.census_complete);
    assert!(!exhausted.scan_cap_hit);
    assert_eq!(exhausted.ownership_incomplete_file_count, 3);
    assert_eq!(exhausted.terminal_ownership_incomplete_file_count, 3);
    assert_eq!(exhausted.zero_snapshot_usage_evidence_count, 0);
    assert_eq!(exhausted.dropped_usage_record_count, 0);

    let receipt = captured_terminal_receipt_for_source_under_hint(
        SnapshotSource::ClaudeCode,
        exhausted,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert_eq!(receipt["source"], "claude_code");
    assert_eq!(receipt["last_error_code"], "census_residue");
    assert_eq!(receipt["consecutive_failures"], 0);
    assert!(receipt["last_success_at"].is_string());
    assert_eq!(receipt["last_success_at"], receipt["last_scan_finished_at"]);
    assert_eq!(
        receipt["last_terminal_ownership_incomplete_file_count"],
        receipt["last_ownership_incomplete_file_count"]
    );
    assert_eq!(receipt["last_terminal_ownership_incomplete_file_count"], 3);
}

/// A RetryPending-only authority family has no per-file residue to count,
/// but it still vetoes census completion. Exercise the complete production
/// derivation path so that zero disclosed-loss counters can never turn the
/// pending family into a clean terminal receipt.
#[test]
#[serial(source_manifests)]
fn retry_pending_only_claude_authority_reports_census_status() {
    let _source_manifests = SourceManifestTestGuard::new();
    let retry_pending = claude_usage_authority_census_counts(
        "retry-pending-only-claude-authority-receipt",
        &[("retry_pending", 1)],
    );
    assert!(!retry_pending.census_complete);
    assert!(retry_pending.scan_cap_hit);
    assert_eq!(retry_pending.ownership_incomplete_file_count, 0);
    assert_eq!(retry_pending.terminal_ownership_incomplete_file_count, 0);
    assert_eq!(retry_pending.zero_snapshot_usage_evidence_count, 0);
    assert_eq!(retry_pending.dropped_usage_record_count, 0);

    let receipt = captured_terminal_receipt_for_source_under_hint(
        SnapshotSource::ClaudeCode,
        retry_pending,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert_eq!(receipt["source"], "claude_code");
    assert_eq!(receipt["last_census_complete"], false);
    assert_eq!(receipt["last_scan_cap_hit"], true);
    let code = receipt["last_error_code"]
        .as_str()
        .expect("census status code");
    assert!(
        matches!(code, "census_blocked" | "census_incomplete"),
        "{code}"
    );
    assert!(receipt["last_success_at"].is_null());
}

fn claude_index_with(entries: serde_json::Value) -> ScanIndex {
    let mut serialized = serde_json::to_value(ScanIndex::default()).expect("serialize index");
    let object = serialized.as_object_mut().expect("index is an object");
    for (key, value) in entries.as_object().expect("entries are an object") {
        object.insert(key.clone(), value.clone());
    }
    serde_json::from_value(serialized).expect("deserialize index fixture")
}

/// An account-deferred hold is retried every generation. It joins the
/// public ownership-incomplete count but never the settled share, so even
/// beside settled terminal authority residue the Claude receipt stays an
/// unsettled `parse_error` while the hold persists.
#[test]
#[serial(source_manifests)]
fn account_deferred_holds_keep_the_claude_receipt_unsettled() {
    let _source_manifests = SourceManifestTestGuard::new();
    let held = claude_index_with(serde_json::json!({
        "claude_account_deferred_holds": {"/opaque/deferred.jsonl": "deferred-source"},
    }));
    assert_eq!(held.claude_account_deferred_hold_count(), 1);
    let counts = claude_usage_authority_census_counts(
        "account-deferred-hold-receipt",
        &[("unproven_terminal", 1)],
    )
    .with_snapshot_terminal_counts(&held);
    assert!(counts.census_complete);
    assert_eq!(counts.ownership_incomplete_file_count, 2);
    assert_eq!(counts.terminal_ownership_incomplete_file_count, 1);

    let receipt = captured_terminal_receipt_for_source_under_hint(
        SnapshotSource::ClaudeCode,
        counts,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert_eq!(receipt["last_error_code"], "parse_error");
    assert_eq!(receipt["consecutive_failures"], 1);
    assert!(receipt["last_success_at"].is_null());
    assert_eq!(receipt["last_ownership_incomplete_file_count"], 2);
    assert_eq!(receipt["last_terminal_ownership_incomplete_file_count"], 1);

    // Without a hold the same terminal residue settles.
    let settled = claude_usage_authority_census_counts(
        "account-deferred-hold-released-receipt",
        &[("unproven_terminal", 1)],
    )
    .with_snapshot_terminal_counts(&ScanIndex::default());
    assert_eq!(
        settled.ownership_incomplete_file_count,
        settled.terminal_ownership_incomplete_file_count
    );
}

/// A completed upload whose holds can still change in this traversal keeps
/// the conservative partial commit and owes a clean follow-up; one whose
/// holds cannot progress reverts only the held key and may settle.
#[test]
fn completed_upload_with_local_holds_settles_only_non_progressing_holds() {
    let activity = "2026-08-02T07:00:00Z";
    let entry = |source: &str, fingerprint: &str| {
        serde_json::json!({
            "size_bytes": 1,
            "modified_unix_seconds": 2,
            "source_file_fingerprint": source,
            "last_snapshot_fingerprint": fingerprint,
            "scan_identity_version": "semantic_sync:v2",
        })
    };
    let committed = claude_index_with(serde_json::json!({
        "files": {
            "/opaque/held.jsonl": entry("held-old-source", "held-old"),
            "/opaque/sibling.jsonl": entry("sibling-old-source", "sibling-old"),
        },
        "file_snapshot_fingerprints": {
            "/opaque/held.jsonl": ["held-old"],
            "/opaque/sibling.jsonl": ["sibling-old"],
        },
        "snapshot_activity_at": {"held-old": activity, "sibling-old": activity},
    }));
    let scanned = claude_index_with(serde_json::json!({
        "files": {
            "/opaque/held.jsonl": entry("held-new-source", "held-new"),
            "/opaque/sibling.jsonl": entry("sibling-new-source", "sibling-new"),
        },
        "file_snapshot_fingerprints": {
            "/opaque/held.jsonl": ["held-new"],
            "/opaque/sibling.jsonl": ["sibling-new"],
        },
        "snapshot_activity_at": {"held-new": activity, "sibling-new": activity},
    }));
    let held = BTreeSet::from(["held-new".to_string()]);
    let mut upload_progress = test_upload_progress();
    upload_progress
        .accepted_fingerprints
        .insert("sibling-new".to_string());

    let settled = commit_completed_with_local_holds(
        scanned.clone(),
        &committed,
        &upload_progress,
        &held,
        &BTreeSet::new(),
        false,
    );
    assert!(!settled.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        settled.files["/opaque/held.jsonl"]
            .last_snapshot_fingerprint
            .as_deref(),
        Some("held-old")
    );
    assert_eq!(
        settled.files["/opaque/held.jsonl"].source_file_fingerprint,
        "held-old-source"
    );
    assert_eq!(
        settled.files["/opaque/sibling.jsonl"]
            .last_snapshot_fingerprint
            .as_deref(),
        Some("sibling-new")
    );
    assert!(settled.snapshot_activity_at.contains_key("held-old"));
    assert!(!settled.snapshot_activity_at.contains_key("held-new"));

    // An account-deferred hold additionally owes a reparse every generation.
    let deferred = commit_completed_with_local_holds(
        scanned.clone(),
        &committed,
        &upload_progress,
        &held,
        &held,
        false,
    );
    assert!(!deferred.bounded_sweep_had_unsettled_upload());
    assert!(deferred.files["/opaque/held.jsonl"]
        .source_file_fingerprint
        .is_empty());

    let blocked = commit_completed_with_local_holds(
        scanned,
        &committed,
        &upload_progress,
        &held,
        &BTreeSet::new(),
        true,
    );
    assert!(blocked.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        blocked.files["/opaque/held.jsonl"]
            .last_snapshot_fingerprint
            .as_deref(),
        Some("held-old")
    );
}

/// Path-(a) bridge: RetryPending debt elsewhere settles a page without
/// local holds as no debt would and keeps only full completion pending; a
/// second cause beside the debt (a retryable server conflict) still marks
/// the sweep.
#[test]
fn retry_pending_debt_elsewhere_marks_the_sweep_only_with_a_second_cause() {
    let committed = claude_index_with(serde_json::json!({}));
    let debt_only = LocalHoldSettlement {
        held_entity_count: 0,
        retry_pending_family_count: 1,
        held_fingerprints: BTreeSet::new(),
        account_deferred_fingerprints: BTreeSet::new(),
        progress_blocking: false,
    };
    let progress = test_upload_progress();
    let completed = settle_completed_upload(committed.clone(), &committed, &progress, &debt_only);
    assert!(!completed.index.bounded_sweep_had_unsettled_upload());
    assert!(completed
        .index
        .bounded_sweep_unsettled_cause_names()
        .is_empty());
    assert!(
        !completed.fully_settled,
        "the debt keeps completion pending"
    );
    let rejected = settle_checkpointed_upload(
        committed.clone(),
        &committed,
        &progress,
        &debt_only,
        true,
        UnsettledUploadCause::DeferredConflict,
    );
    assert!(!rejected.index.bounded_sweep_had_unsettled_upload());
    assert!(rejected
        .index
        .bounded_sweep_unsettled_cause_names()
        .is_empty());
    assert!(!rejected.fully_settled);
    let deferred = settle_checkpointed_upload(
        committed.clone(),
        &committed,
        &progress,
        &debt_only,
        false,
        UnsettledUploadCause::DeferredConflict,
    );
    assert!(
        deferred.index.bounded_sweep_had_unsettled_upload(),
        "a retryable server conflict beside the debt still marks the sweep"
    );
    assert_eq!(
        deferred.index.bounded_sweep_unsettled_cause_names(),
        ["deferred_conflict"],
        "the second cause names itself; the debt names nothing"
    );
    assert!(!deferred.fully_settled);
}

/// The backend's error-code set is closed and its forward tolerance covers
/// unknown fields, never unknown values: `census_residue` against a backend
/// that does not admit it would reject the ENTIRE receipt. So until the
/// exact contract is advertised the receipt keeps today's shape —
/// `parse_error`, one failure, no success clock — while the additive
/// counters still travel for a backend that declares them.
#[test]
#[serial(source_manifests)]
fn a_settled_residue_census_keeps_the_legacy_shape_until_the_backend_admits_the_code() {
    let _source_manifests = SourceManifestTestGuard::new();
    for hint_extra in [
        "",
        r#","census_residue_status_contract":null"#,
        r#","census_residue_status_contract":"census_residue_status:v2""#,
        r#","census_residue_status_contract":"census_residue""#,
    ] {
        let receipt = captured_terminal_receipt_under_hint(
            m1_named_residue_counts(),
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            hint_extra,
        );
        assert_eq!(receipt["report_kind"], "scan_status", "{hint_extra:?}");
        assert_eq!(receipt["last_error_code"], "parse_error", "{hint_extra:?}");
        assert_eq!(
            receipt["last_error_message"], "local usage evidence produced no session snapshot",
            "{hint_extra:?}"
        );
        assert_eq!(receipt["consecutive_failures"], 1, "{hint_extra:?}");
        assert!(receipt["last_success_at"].is_null(), "{hint_extra:?}");
        assert_eq!(receipt["last_census_complete"], true, "{hint_extra:?}");
        // The disclosure is the same either way; only the code differs.
        assert_eq!(
            receipt["last_census_residue_settled"], true,
            "{hint_extra:?}"
        );
        for (terminal, public) in RESIDUE_TERMINAL_PAIRS {
            assert_eq!(receipt[terminal], receipt[public], "{terminal}");
        }
        assert_eq!(receipt["last_terminal_dropped_usage_record_count"], 1_105);
        assert_eq!(receipt["last_census_residue_index_key_count"], 1);
        assert_eq!(receipt["last_census_residue_archived_rollout_count"], 1);
    }
}

/// A retryable problem beside the residue vetoes the settled verdict even
/// when the backend admits the code: a walk that could not enter, open,
/// read, or parse something has not proved the residue non-progressing.
/// The receipt keeps the retryable shape.
#[test]
#[serial(source_manifests)]
fn a_retryable_problem_beside_settled_residue_still_reports_parse_error() {
    let _source_manifests = SourceManifestTestGuard::new();
    let vetoes: [CountsMutation; 7] = [
        ("symlink_rejected", |counts| {
            counts.symlink_rejected_count = 1
        }),
        ("unreadable_path", |counts| counts.unreadable_path_count = 1),
        ("oversized_file", |counts| counts.oversized_file_count = 1),
        ("disappeared_file", |counts| {
            counts.disappeared_file_count = 1
        }),
        ("malformed_json_line", |counts| {
            counts.malformed_json_line_count = 1
        }),
        ("invalid_utf8_line", |counts| {
            counts.invalid_utf8_line_count = 1
        }),
        // Over-line-cap loss beyond its terminal share is bounded line
        // loss not yet given its per-file terminal disposition.
        ("unterminal_over_line_cap", |counts| {
            counts.over_line_cap_count = 1
        }),
    ];
    for (veto_name, veto) in vetoes {
        let mut counts = m1_named_residue_counts();
        veto(&mut counts);
        let receipt = captured_terminal_receipt_under_hint(
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            RESIDUE_ADMITTING_HINT,
        );
        assert_eq!(receipt["last_error_code"], "parse_error", "{veto_name}");
        assert_eq!(receipt["consecutive_failures"], 1, "{veto_name}");
        assert!(receipt["last_success_at"].is_null(), "{veto_name}");
        assert_eq!(receipt["last_census_residue_settled"], false, "{veto_name}");
        // The settled shares are still disclosed as measured.
        assert_eq!(
            receipt["last_terminal_dropped_usage_record_count"], 1_105,
            "{veto_name}"
        );
    }
}

/// Residue the generation has not settled — one class above its terminal
/// counterpart — and residue on a census that did not complete both keep
/// the retryable shape, admission or not. Only the exact per-class
/// equality on a completed census earns the settled verdict.
#[test]
#[serial(source_manifests)]
fn unsettled_residue_and_an_incomplete_census_still_report_parse_error() {
    let _source_manifests = SourceManifestTestGuard::new();
    let unsettled: [CountsMutation; 5] = [
        ("ownership_incomplete unsettled", |counts| {
            counts.terminal_ownership_incomplete_file_count = 0
        }),
        ("zero_snapshot_usage_evidence unsettled", |counts| {
            counts.terminal_zero_snapshot_usage_evidence_count = 0
        }),
        ("recognized_usage_drop unsettled", |counts| {
            counts.terminal_recognized_usage_drop_count = 1_104
        }),
        ("dropped_usage_record unsettled", |counts| {
            counts.terminal_dropped_usage_record_count = 1_104
        }),
        // A settled share above its public counter is not a shape the
        // scan can produce; it must never read as settled either.
        ("terminal above public", |counts| {
            counts.terminal_ownership_incomplete_file_count = 2
        }),
    ];
    for (case, mutate) in unsettled {
        let mut counts = m1_named_residue_counts();
        mutate(&mut counts);
        let receipt = captured_terminal_receipt_under_hint(
            counts,
            CollectorState::Success,
            TerminalManifestSource::Withdraw,
            183,
            RESIDUE_ADMITTING_HINT,
        );
        assert_eq!(receipt["last_error_code"], "parse_error", "{case}");
        assert_eq!(receipt["consecutive_failures"], 1, "{case}");
        assert!(receipt["last_success_at"].is_null(), "{case}");
        assert_eq!(receipt["last_census_residue_settled"], false, "{case}");
    }

    // An incomplete census reports its census status instead, still
    // without a success clock or a settled verdict.
    let mut incomplete = m1_named_residue_counts();
    incomplete.census_complete = false;
    let receipt = captured_terminal_receipt_under_hint(
        incomplete,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert_eq!(receipt["last_error_code"], "census_blocked");
    assert_eq!(receipt["last_census_block_cause"], "other");
    assert!(receipt["last_success_at"].is_null());
    assert_eq!(receipt["last_census_residue_settled"], false);

    // And a clean census is untouched by the admission: no code, no
    // message, no settled verdict.
    let mut clean = SyncCounts::for_policy(183);
    clean.census_complete = true;
    let receipt = captured_terminal_receipt_under_hint(
        clean,
        CollectorState::Success,
        TerminalManifestSource::Withdraw,
        183,
        RESIDUE_ADMITTING_HINT,
    );
    assert!(receipt["last_error_code"].is_null());
    assert!(receipt["last_error_message"].is_null());
    assert_eq!(receipt["consecutive_failures"], 0);
    assert_eq!(receipt["last_success_at"], receipt["last_scan_finished_at"]);
    assert_eq!(receipt["last_census_residue_settled"], false);
}

/// The exact body the backend admits for a named-residue census — its
/// status model's residue admission — pinned as a fixture. Exact equality
/// is also the privacy fence: any member added to the wire, an index key
/// or a session id included, fails here. Only the finish/success clock and
/// the build identity are live.
#[test]
#[serial(source_manifests)]
fn the_census_residue_receipt_matches_the_backend_admitted_wire_fixture() {
    let _source_manifests = SourceManifestTestGuard::new();
    let index = ScanIndex::default();
    let mut receipt = captured_terminal_receipt_under_hint(
        m1_named_residue_counts(),
        CollectorState::Success,
        TerminalManifestSource::CompleteCensus(&index),
        183,
        RESIDUE_ADMITTING_HINT,
    );
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../fixtures/collector-status/census-residue-scan-status-v1.json"
    ))
    .expect("census residue wire fixture");

    let finished_at = receipt["last_scan_finished_at"].clone();
    assert!(finished_at.is_string());
    assert_eq!(receipt["last_success_at"], finished_at);
    for clock in ["last_scan_finished_at", "last_success_at"] {
        receipt[clock] = expected[clock].clone();
    }
    assert_eq!(receipt["collector_version"], collector_version());
    receipt["collector_version"] = expected["collector_version"].clone();

    assert_eq!(receipt, expected);
    // The fixture itself carries no identifier-shaped member and no path.
    let serialized = serde_json::to_string(&expected).expect("fixture text");
    for forbidden in ["index_keys", "session_ids", "/Users/", ".codex", ".claude"] {
        assert!(!serialized.contains(forbidden), "{forbidden}");
    }
}

#[test]
#[serial(source_manifests)]
fn fenced_census_native_scan_projection_stays_private_and_off_wire() {
    let _guard = SourceManifestTestGuard::new();
    let support = test_terminal_status_support_dir();
    let roots = support.join("isolated-home/.codex/sessions");
    std::fs::create_dir_all(&roots).unwrap();
    let mut index = ScanIndex::default();
    let mut scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Codex,
        &[roots],
        &mut index,
        "2026-10-09T00:00:00Z",
        183,
    )
    .unwrap();
    let diagnostic = scan
        .local_codex_diagnostics
        .as_mut()
        .expect("native Codex scan diagnostic");
    diagnostic.generation = 17;
    diagnostic.state_titles.first_failure_root_digest = Some([241; 32]);
    index.generation = 18;
    let (private_index, _) = pending_head_index_item();
    index.files.insert(
        "PRIVATE_PATH_CANARY".into(),
        private_index.files.values().next().unwrap().clone(),
    );
    let before_index = serde_json::to_vec(&index).unwrap();
    let before_snapshots = serde_json::to_vec(&scan.snapshots).unwrap();
    let mut calls = 0;
    codex_scan_diagnostics::after_existing_census_fence(
        SnapshotSource::Codex,
        support,
        || {
            calls += 1;
            Ok(())
        },
        || codex_scan_diagnostics::write_fenced_census(support, &scan, &index),
    )
    .unwrap();
    assert_eq!(calls, 1);
    let path = support.join("snapshots/codex-fenced-census-v1.json");
    let bytes = std::fs::read(&path).unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(evidence["scan_input_generation"], 17);
    assert_eq!(evidence["index"]["generation"], 18);
    assert_eq!(evidence["index"]["file_count"], 1);
    assert_eq!(evidence["producer_pid"], std::process::id());
    assert_eq!(evidence["gates"]["census_complete"], scan.census_complete);
    let text = String::from_utf8(bytes).unwrap();
    for excluded in [
        "PRIVATE_PATH_CANARY",
        "first_failure_root_digest",
        "lineage",
        "fingerprint",
        "namespace",
        "root_digest",
    ] {
        assert!(!text.contains(excluded), "private field {excluded}");
    }
    assert_eq!(serde_json::to_vec(&index).unwrap(), before_index);
    assert_eq!(
        serde_json::to_vec(&scan.snapshots).unwrap(),
        before_snapshots
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
        captured.clone(),
        vec![30],
    ));
    let device = LocalDeviceBinding {
        device_id: "fixture_device".into(),
        machine_id: Some("fixture_machine".into()),
        sources: vec!["codex".into()],
    };
    report_status_with_fresh_relay_token(
        &client,
        &device,
        "synthetic-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::Withdraw,
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "fixture_machine",
            scan_started_at: "2026-10-09T00:00:00Z",
            counts: SyncCounts::from_scan_result(&scan, 0, 30),
            state: CollectorState::Success,
        },
    )
    .unwrap();
    let requests = captured.lock().unwrap();
    let terminal = http_request_json(requests.last().unwrap());
    for private in [
        "local_codex_diagnostics",
        "local_codex_counting_v2",
        "index",
        "scope",
        "producer_pid",
        "scan_input_generation",
        "index_view",
    ] {
        assert!(
            terminal.get(private).is_none(),
            "local field leaked to status HTTP: {private}"
        );
    }
    scan.local_codex_diagnostics = None;
    codex_scan_diagnostics::after_existing_census_fence(
        SnapshotSource::Codex,
        support,
        || Ok(()),
        || codex_scan_diagnostics::write_fenced_census(support, &scan, &index),
    )
    .unwrap();
    assert!(
        !path.exists(),
        "missing scan evidence must not retain offered diagnostic"
    );
}

#[test]
#[serial(source_manifests)]
fn terminal_receipt_is_posted_and_liveness_stays_liveness() {
    let _source_manifests = SourceManifestTestGuard::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
        captured.clone(),
        vec![30, 30],
    ));
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let mut counts = SyncCounts::for_policy(30);
    counts.scan_cap_hit = false;
    counts.census_complete = true;
    counts.recognized_usage_drop_count = 1_105;
    counts.dropped_usage_record_count = 1_105;
    counts.ownership_incomplete_file_count = 1;

    report_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::Withdraw,
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2026-09-01T07:44:00Z",
            counts,
            state: CollectorState::Success,
        },
    )
    .expect("emit terminal loss receipt");
    report_checkin_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        Some("2026-09-01T08:12:28Z"),
    )
    .expect("post a liveness receipt");

    let requests = captured.lock().expect("captured requests").clone();
    let terminal = http_request_json(&requests[1]);
    assert_eq!(terminal["last_recognized_usage_drop_count"], 1_105);
    assert_eq!(terminal["last_dropped_usage_record_count"], 1_105);
    assert_eq!(terminal["last_ownership_incomplete_file_count"], 1);
    assert_eq!(terminal["last_error_code"], "parse_error");
    assert_eq!(terminal["last_scan_started_at"], "2026-09-01T07:44:00Z");
    assert!(terminal["last_scan_finished_at"].is_string());

    // The liveness beat that follows it is NOT the terminal body. Its wire
    // shape is exactly what the backend classifies as a check-in receipt,
    // so the terminal report stays the single source of scan truth.
    let checkin = http_request_json(&requests[3]);
    assert_ne!(checkin, terminal);
    assert!(checkin["last_scan_finished_at"].is_null());
    assert!(checkin["last_error_code"].is_null());
    assert!(checkin["last_error_message"].is_null());
    assert!(checkin["next_retry_at"].is_null());
    assert_eq!(checkin["enabled"], true);
    assert_eq!(checkin["consecutive_failures"], 0);
    assert_eq!(checkin["last_scan_cap_hit"], false);
    assert_eq!(checkin["last_scan_started_at"], "2026-09-01T08:12:28Z");
    assert_eq!(checkin["last_recognized_usage_drop_count"], 0);
    assert_eq!(checkin["last_dropped_usage_record_count"], 0);
}

#[test]
#[serial(source_manifests)]
fn receipts_carry_the_scan_index_manifest_once_a_scan_has_published_one() {
    let _source_manifests = SourceManifestTestGuard::new();
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let destination_namespace = &snapshot_upload_destination_namespace(&device, "device-secret");

    // Before any scan completes the manifest is absent, not zeroed: a
    // fabricated `entity_count: 0` would read as "this machine has nothing",
    // which is a different and wrong statement.
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
    report_checkin_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        None,
    )
    .expect("report check-in before any scan");
    let requests = captured.lock().expect("captured requests").clone();
    assert!(!requests[1].contains("\"manifest\""));

    let scratch = crate::test_scratch::ScratchDir::new("scan-manifest-index");
    let mut index = ScanIndex::load(&scratch.join("scan-index.json")).expect("empty scan index");
    index.file_snapshot_fingerprints.insert(
        "/tmp/rollout-session-1.jsonl".to_string(),
        BTreeSet::from(["a".repeat(64)]),
    );
    index
        .snapshot_activity_at
        .insert("a".repeat(64), Some("2099-12-31T12:00:00Z".to_string()));
    let mut manifest = index.manifest(SnapshotSource::Codex, 30);
    manifest.window_start = "2099-12-02T00:00:00Z".to_string();
    manifest.window_end = "2100-01-01T00:00:00Z".to_string();
    publish_source_manifest(
        destination_namespace,
        SnapshotSource::Codex,
        manifest.clone(),
    );

    for scan_started_at in [None, Some("2026-06-01T10:00:00Z")] {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            scan_started_at,
        )
        .expect("report check-in after a scan");
        let requests = captured.lock().expect("captured requests").clone();
        assert!(requests[1].contains("\"entity_count\":1"));
        assert!(requests[1].contains(&format!("\"rolling_hash\":\"{}\"", manifest.rolling_hash)));
        // The scope and window travel with the count. Without them a
        // consumer would compare this against its whole stored set and
        // report a mismatch for every session the historical bootstrap
        // uploaded from outside the scan window.
        assert!(requests[1].contains("\"contract_version\":\"snapshot_manifest:v2\""));
        assert!(requests[1].contains("\"scope\":\"semantic_activity_window\""));
        assert!(requests[1].contains("\"window_start\":\"2099-12-02T00:00:00Z\""));
        assert!(requests[1].contains("\"window_end\":\"2100-01-01T00:00:00Z\""));
        assert!(requests[1].contains("\"last_backfill_window_days\":30"));
        assert!(!requests[1].contains("\"window_days\""));
        assert!(!requests[1].contains("\"server_accepted_entity_count\""));
    }

    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
    let mut counts = SyncCounts::for_policy(30);
    counts.semantic_noop_count = 718;
    report_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::CompleteCensus(&index),
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2100-01-01T00:00:00Z",
            counts,
            state: CollectorState::Success,
        },
    )
    .expect("report terminal status");
    let requests = captured.lock().expect("captured requests").clone();
    // The suppression count is the difference between "nothing changed" and
    // "the collector dropped what changed".
    assert!(requests[1].contains("\"last_semantic_noop_count\":718"));
    assert!(requests[1].contains("\"entity_count\":1"));
    assert!(requests[1].contains("\"last_scan_started_at\":\"2100-01-01T00:00:00Z\""));

    let mismatch = report_status(
        &client,
        "relay-token-codex",
        destination_namespace,
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2026-06-01T10:00:00Z",
            counts: SyncCounts::for_policy(30),
            state: CollectorState::Success,
        },
    )
    .expect_err("terminal receipt cannot detach a manifest from its census boundary");
    assert!(mismatch
        .to_string()
        .contains("manifest window end does not match terminal scan start"));

    // An account switch replaces the relay binding without restarting the
    // daemon. The new destination must not receive the previous account's
    // entity count and rolling hash — that is both a false witness and a
    // disclosure of the previous account's local session set.
    let switched = LocalDeviceBinding {
        device_id: "device_switched".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
    report_checkin_status_with_fresh_relay_token(
        &client,
        &switched,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        None,
    )
    .expect("report check-in after an account switch");
    let requests = captured.lock().expect("captured requests").clone();
    assert!(!requests[1].contains("\"manifest\""));
    assert!(!requests[1].contains(&manifest.rolling_hash));

    // Publishing for the new destination retires the old one outright.
    let new_namespace = snapshot_upload_destination_namespace(&switched, "device-secret");
    publish_source_manifest(&new_namespace, SnapshotSource::Codex, manifest.clone());
    assert!(cached_source_manifest(destination_namespace, SnapshotSource::Codex).is_none());
}

#[test]
#[serial(source_manifests)]
fn incomplete_census_withdraws_only_its_stale_source_manifest() {
    let _source_manifests = SourceManifestTestGuard::new();
    let destination = "destination";
    let codex = ScanIndex::default().manifest(SnapshotSource::Codex, 183);
    let claude = ScanIndex::default().manifest(SnapshotSource::ClaudeCode, 183);
    publish_source_manifest(destination, SnapshotSource::Codex, codex);
    publish_source_manifest(destination, SnapshotSource::ClaudeCode, claude.clone());

    withdraw_source_manifest(destination, SnapshotSource::Codex);

    assert!(cached_source_manifest(destination, SnapshotSource::Codex).is_none());
    assert_eq!(
        cached_source_manifest(destination, SnapshotSource::ClaudeCode),
        Some(claude)
    );
}

#[test]
#[serial(source_manifests)]
fn terminal_incomplete_error_and_disabled_receipts_carry_explicit_withdrawal_shape() {
    let _source_manifests = SourceManifestTestGuard::new();
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let destination = snapshot_upload_destination_namespace(&device, "device-secret");
    let manifest = ScanIndex::default().manifest(SnapshotSource::Codex, 183);
    let capture_terminal_without_manifest = |state| {
        publish_source_manifest(&destination, SnapshotSource::Codex, manifest.clone());
        withdraw_source_manifest(&destination, SnapshotSource::Codex);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let mut counts = SyncCounts::for_policy(183);
        counts.census_complete = false;
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            test_terminal_status_support_dir(),
            SnapshotSource::Codex,
            TerminalManifestSource::Withdraw,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts,
                state,
            },
        )
        .expect("report terminal manifest withdrawal");
        captured.lock().expect("captured requests")[1].clone()
    };

    for request in [
        capture_terminal_without_manifest(CollectorState::Success),
        capture_terminal_without_manifest(CollectorState::Error {
            code: "scan_error",
            message: "local snapshot scan failed",
        }),
        capture_terminal_without_manifest(CollectorState::Disabled(Some(
            "disabled_by_admin".to_string(),
        ))),
    ] {
        assert!(!request.contains("\"last_scan_finished_at\":null"));
        assert!(request.contains("\"last_census_complete\":false"));
        // Terminal + absent manifest is the explicit withdrawal shape.
        // Nonterminal + absent manifest remains liveness-only/unknown.
        assert!(!request.contains("\"manifest\""));
    }
}

#[test]
#[serial(source_manifests)]
fn completed_upload_save_failure_cannot_leave_the_stale_manifest_cached() {
    let _source_manifests = SourceManifestTestGuard::new();
    let destination = "destination";
    publish_source_manifest(
        destination,
        SnapshotSource::Codex,
        ScanIndex::default().manifest(SnapshotSource::Codex, 183),
    );
    let root = test_dir("completed-upload-index-save-failure");
    let invalid_index_path = root.join("index-is-a-directory");
    std::fs::create_dir_all(&invalid_index_path).expect("create invalid index target");
    let mut replacement = ScanIndex::default();

    save_index_and_publish_manifest(
        &mut replacement,
        &invalid_index_path,
        destination,
        SnapshotSource::Codex,
        true,
        "2026-01-01T00:00:00Z",
        "2026-07-01T00:00:00Z",
    )
    .expect_err("post-ACK index save must fail at the invalid target");

    assert!(cached_source_manifest(destination, SnapshotSource::Codex).is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn backfill_replay_keeps_report_width_at_current_hint() {
    let receipt_window_days = validated_receipt_window_days(183).expect("valid hint");
    assert_eq!(
        scan_request_window_days(receipt_window_days, false),
        receipt_window_days,
        "after replay the scan returns to the current policy width"
    );

    {
        let (replay_name, backfill_pending) = ("backfill", true);
        assert_eq!(
            scan_request_window_days(receipt_window_days, backfill_pending),
            u64::MAX,
            "{replay_name} replay requests the scanner's broad local range"
        );

        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            let root = test_dir(&format!(
                "{replay_name}-replay-window-{}",
                source.api_slug()
            ));
            std::fs::create_dir_all(&root).expect("create empty source root");
            let mut index = ScanIndex::default();
            let result = crate::snapshots::scan_source_roots(
                source,
                std::slice::from_ref(&root),
                &mut index,
                "2026-08-30T12:00:00Z",
                scan_request_window_days(receipt_window_days, backfill_pending),
            )
            .expect("broad replay scan");
            assert_eq!(
                result.backfill_window_days,
                crate::snapshots::BACKFILL_WINDOW_DAYS,
                "the local scanner keeps its 730-day replay ceiling"
            );
            let counts = SyncCounts::from_scan_result(&result, 0, receipt_window_days);
            assert_eq!(
                counts.backfill_window_days, receipt_window_days,
                "{replay_name} terminal status reports the exact hint"
            );
            let (window_start, window_end) =
                snapshot_manifest_window(&result.census_window_end, receipt_window_days)
                    .expect("policy-width replay manifest");
            let manifest = index
                .manifest_for_window(source, &window_start, &window_end)
                .expect("replay manifest");
            assert_eq!(
                snapshot_manifest_window_days(&manifest).unwrap(),
                receipt_window_days,
                "{replay_name} terminal manifest reports the exact hint"
            );
            assert!(counts.census_complete);
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[test]
fn replay_scan_discovers_session_older_than_policy_window() {
    let root = test_dir("replay-discovers-beyond-policy-window");
    std::fs::create_dir_all(&root).expect("create replay root");
    let path = root.join("session.jsonl");
    std::fs::write(
        &path,
        concat!(
            "{\"type\":\"session\",\"id\":\"replay-session\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n",
            "{\"type\":\"message\",\"timestamp\":\"2026-01-01T00:01:00Z\",\"message\":{\"role\":\"assistant\",\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"usage\":{\"input\":12,\"output\":4}}}\n"
        ),
    )
    .expect("write old replay fixture");
    // Older than the policy window, inside the first-read bound.
    let old_mtime = OffsetDateTime::parse("2026-07-16T12:00:00Z", &Rfc3339)
        .expect("old fixture mtime")
        .unix_timestamp() as u64;
    std::fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .expect("open old replay fixture")
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(old_mtime)),
        )
        .expect("set old replay fixture mtime");

    let mut policy_index = ScanIndex::default();
    let policy_scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        &mut policy_index,
        "2026-08-30T12:00:00Z",
        scan_request_window_days(30, false),
    )
    .expect("policy-width scan");
    assert_eq!(policy_scan.discovered_file_count, 0);
    assert!(policy_scan.snapshots.is_empty());

    let mut replay_index = ScanIndex::default();
    let replay_scan = crate::snapshots::scan_source_roots(
        SnapshotSource::Pi,
        std::slice::from_ref(&root),
        &mut replay_index,
        "2026-08-30T12:00:00Z",
        scan_request_window_days(30, true),
    )
    .expect("wide replay scan");
    assert_eq!(replay_scan.backfill_window_days, 730);
    assert_eq!(replay_scan.discovered_file_count, 1);
    assert_eq!(replay_scan.scanned_file_count, 1);
    assert_eq!(replay_scan.snapshots.len(), 1);
    assert_eq!(replay_scan.snapshots[0].source_session_id, "replay-session");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[serial(source_manifests)]
fn mid_replay_policy_change_rebuilds_terminal_manifest_from_report_time_hint() {
    let _source_manifests = SourceManifestTestGuard::new();
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let destination = snapshot_upload_destination_namespace(&device, "device-secret");
    let inside = "a".repeat(64);
    let replay_only = "b".repeat(64);
    let mut index = ScanIndex::default();
    index
        .file_snapshot_fingerprints
        .insert("inside.jsonl".to_string(), BTreeSet::from([inside.clone()]));
    index.file_snapshot_fingerprints.insert(
        "replay-only.jsonl".to_string(),
        BTreeSet::from([replay_only.clone()]),
    );
    index.snapshot_activity_at = crate::snapshots::SharedMap::from([
        (inside, Some("2026-08-29T00:00:00Z".to_string())),
        (replay_only, Some("2026-04-01T00:00:00Z".to_string())),
    ]);
    let scan_started_at = "2026-08-30T12:00:00Z";
    let (old_start, old_end) = snapshot_manifest_window(scan_started_at, 183).unwrap();
    publish_source_manifest(
        &destination,
        SnapshotSource::Codex,
        index
            .manifest_for_window(SnapshotSource::Codex, &old_start, &old_end)
            .unwrap(),
    );

    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
        captured.clone(),
        vec![30],
    ));
    let mut counts = SyncCounts::for_policy(183);
    counts.census_complete = true;
    report_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::CompleteCensus(&index),
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at,
            counts,
            state: CollectorState::Success,
        },
    )
    .expect("report terminal with refreshed policy");

    let requests = captured.lock().expect("captured requests").clone();
    let status = http_request_json(&requests[1]);
    assert_eq!(status["last_backfill_window_days"], 30);
    assert_eq!(status["manifest"]["entity_count"], 1);
    let manifest = cached_source_manifest(&destination, SnapshotSource::Codex)
        .expect("report-time manifest cached");
    assert_eq!(snapshot_manifest_window_days(&manifest).unwrap(), 30);
    assert_eq!(status["manifest"]["window_start"], manifest.window_start);
    assert_eq!(status["manifest"]["window_end"], manifest.window_end);
    assert_eq!(status["manifest"]["rolling_hash"], manifest.rolling_hash);
}

#[test]
#[serial(source_manifests)]
fn zero_hint_emits_manifest_free_terminal_tombstone_and_manifest_free_heartbeats() {
    let _source_manifests = SourceManifestTestGuard::new();
    let device = LocalDeviceBinding {
        device_id: "device_test".to_string(),
        machine_id: Some("otm_test".to_string()),
        sources: vec!["codex".to_string()],
    };
    let destination = snapshot_upload_destination_namespace(&device, "device-secret");
    let index = ScanIndex::default();
    publish_source_manifest(
        &destination,
        SnapshotSource::Codex,
        index.manifest(SnapshotSource::Codex, 183),
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let client = SnapshotApiClient::new(snapshot_status_server_with_hints(
        captured.clone(),
        vec![0, 0],
    ));

    let mut counts = SyncCounts::for_policy(183);
    counts.census_complete = true;
    report_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        test_terminal_status_support_dir(),
        SnapshotSource::Codex,
        TerminalManifestSource::CompleteCensus(&index),
        CollectorStatus {
            source: SnapshotSource::Codex,
            machine_id: "otm_test",
            scan_started_at: "2026-08-30T12:00:00Z",
            counts,
            state: CollectorState::Success,
        },
    )
    .expect("zero-width terminal tombstone");
    assert!(cached_source_manifest(&destination, SnapshotSource::Codex).is_none());
    report_checkin_status_with_fresh_relay_token(
        &client,
        &device,
        "device-secret",
        SnapshotSource::Codex,
        "otm_test",
        None,
    )
    .expect("zero-width heartbeat");

    let requests = captured.lock().expect("captured requests").clone();
    let terminal = http_request_json(&requests[1]);
    assert_eq!(terminal["last_backfill_window_days"], 0);
    assert_eq!(terminal["last_census_complete"], false);
    assert_eq!(terminal["enabled"], true);
    assert!(terminal["last_scan_finished_at"].is_string());
    assert!(terminal["last_success_at"].is_null());
    assert!(terminal["last_error_code"].is_null());
    assert!(terminal["last_error_message"].is_null());
    assert!(terminal.get("manifest").is_none());

    let heartbeat = http_request_json(&requests[3]);
    assert_eq!(heartbeat["last_backfill_window_days"], 0);
    assert!(heartbeat["last_scan_finished_at"].is_null());
    assert!(heartbeat.get("manifest").is_none());
}

#[test]
fn replay_manifest_folds_only_entities_inside_the_negotiated_semantic_window() {
    let inside = "a".repeat(64);
    let replay_only = "b".repeat(64);
    let mut index = ScanIndex::default();
    index
        .file_snapshot_fingerprints
        .insert("inside.jsonl".to_string(), BTreeSet::from([inside.clone()]));
    index.file_snapshot_fingerprints.insert(
        "replay-only.jsonl".to_string(),
        BTreeSet::from([replay_only.clone()]),
    );
    index.snapshot_activity_at = crate::snapshots::SharedMap::from([
        (inside, Some("2026-08-29T00:00:00Z".to_string())),
        (replay_only, Some("2025-08-29T00:00:00Z".to_string())),
    ]);
    let (window_start, window_end) =
        snapshot_manifest_window("2026-08-30T12:00:00Z", 183).expect("manifest window");

    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let manifest = index
            .manifest_for_window(source, &window_start, &window_end)
            .expect("source-generic semantic manifest");
        assert_eq!(manifest.entity_count, 1);
        assert_eq!(snapshot_manifest_window_days(&manifest).unwrap(), 183);
    }
}

#[test]
fn invalid_or_future_receipt_window_hints_fail_closed() {
    assert_eq!(validated_receipt_window_days(0).unwrap(), 0);
    assert!(snapshot_manifest_window("2026-08-30T12:00:00Z", 0).is_err());
    assert_eq!(validated_receipt_window_days(1).unwrap(), 1);
    assert_eq!(validated_receipt_window_days(183).unwrap(), 183);
    assert!(validated_receipt_window_days(184).is_err());
    assert!(validated_receipt_window_days(u64::MAX).is_err());
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set_path(key: &'static str, value: &Path) -> Self {
        Self::set_os(key, value.as_os_str().to_os_string())
    }

    fn set_str(key: &'static str, value: &str) -> Self {
        Self::set_os(key, std::ffi::OsString::from(value))
    }

    fn set_os(key: &'static str, value: std::ffi::OsString) -> Self {
        let previous = std::env::var_os(key);
        unsafe { std::env::set_var(key, value) };
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            unsafe { std::env::set_var(self.key, previous) };
        } else {
            unsafe { std::env::remove_var(self.key) };
        }
    }
}

fn test_dir(name: &str) -> PathBuf {
    crate::test_scratch::unique_path(&format!("ottto-{name}"))
}

fn test_agent_status(source: SourceKind) -> AgentStatusSnapshot {
    AgentStatusSnapshot {
        source,
        status: AgentStatusState::Available,
        collection_method: AgentStatusCollectionMethod::ManualFallback,
        captured_at: "2026-06-01T10:00:00Z".to_string(),
        expires_at: "2026-06-01T10:15:00Z".to_string(),
        account: None,
        model: None,
        quota_windows: Vec::new(),
        credit_balances: Vec::new(),
        context: None,
        capabilities: Vec::new(),
        plan_observations: Vec::new(),
        diagnostics: Vec::new(),
        runtime_defaults: None,
    }
}

fn test_agent_account(account_hash: &str, organization_hash: &str) -> AgentAccountStatus {
    AgentAccountStatus {
        login_state: AgentLoginState::SignedIn,
        provider: Some("anthropic".to_string()),
        auth_method: Some("oauth".to_string()),
        email: None,
        account_id: None,
        organization_id: None,
        organization_label: None,
        plan_type: Some("max".to_string()),
        subscription_product: Some("claude_max".to_string()),
        billing_channel: Some("subscription".to_string()),
        subscription_period_start: None,
        subscription_period_end: None,
        subscription_period_last_checked_at: None,
        account_identifier_hash: Some(account_hash.to_string()),
        organization_identifier_hash: Some(organization_hash.to_string()),
        superseded_account_identifier_hash: None,
        superseded_organization_identifier_hash: None,
        credential_fingerprint_hash: None,
        billing_identity_evidence: Some("provider_account_id".to_string()),
        claude_quota_access_state: None,
        claude_anchor_durability: None,
        claude_anchor_health: None,
        billing_identity_confidence: AgentStatusConfidence::High,
        confidence: AgentStatusConfidence::High,
    }
}

/// Run a test body on a thread sized like a production scan worker. Debug
/// (opt-level 0) frames on the native scan path can exceed the default 2 MiB
/// test thread;
/// `scan_worker_stack_margin_receipt` remains the production stack guard.
pub(super) fn run_on_scan_worker_stack<T: Send>(body: impl FnOnce() -> T + Send) -> T {
    run_on_scan_worker_stack_with_size(SNAPSHOT_SYNC_WORKER_STACK_BYTES, body)
}

pub(super) fn run_on_scan_worker_stack_with_size<T: Send>(
    stack_bytes: usize,
    body: impl FnOnce() -> T + Send,
) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(
                std::thread::current()
                    .name()
                    .unwrap_or("test-scan-worker")
                    .to_string(),
            )
            .stack_size(stack_bytes)
            .spawn_scoped(scope, body)
            .expect("spawn test scan worker")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn test_daemon(machine_id: &str) -> LocalDaemon {
    LocalDaemon::new(
        MachineIdentity {
            machine_id: machine_id.to_string(),
            installation_id: "install_test".to_string(),
            display_name: "Test Mac".to_string(),
            hostname: "test-mac.local".to_string(),
            os: OperatingSystem::Macos,
            arch: "arm64".to_string(),
            local_platform_version: "0.1.35".to_string(),
            hardware_uuid: None,
            account_scope: None,
        },
        ControlToken::new("token").expect("valid token"),
        "2026-06-16T10:00:00Z",
    )
}
