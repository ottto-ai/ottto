// Real prepare/scanner/finish/HTTP/ACK/index-save paths. Targets never receive
// hand-injected watcher hints. Only the scanner page cap and process restart
// are synthetic; filesystem discovery and bytes remain production code.
fn index_path(home: &AckFinishHome) -> PathBuf {
    let namespace = snapshot_upload_destination_namespace(&home.device, "device-secret");
    snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(&home.support, SnapshotSource::ClaudeCode), &namespace,
    ))
}
fn project(home: &AckFinishHome) -> PathBuf {
    home.fixture.home.join(".claude/projects/-synthetic-repo")
}
fn seed_deferred(home: &AckFinishHome, add: bool) {
    let path = index_path(home);
    let mut value = serde_json::to_value(ScanIndex::load(&path).unwrap_or_default()).unwrap();
    for n in 0..65 {
        let root = format!("20000000-0000-4000-8000-{n:012}");
        if add {
            value["claude_usage_family_pending"][&root] = serde_json::json!({
                "census_window_end":"2026-01-01T00:00:00Z", "member_request_id_hashes":{},
                "member_occurrences":{}, "invalid":false
            });
        } else {
            value["claude_usage_family_pending"].as_object_mut().unwrap().remove(&root);
        }
    }
    let mut index: ScanIndex = serde_json::from_value(value).unwrap();
    index.save(&path).unwrap();
}
fn prepare(home: &mut AckFinishHome) -> (SourcePreparation, ScanIndex, SourceScanResult) {
    home.cadence.next_due_cycle();
    let frame = crate::agent_status_refresh::with_test_collection(AckFinishHome::collection(), || {
        prepare_sync_source(&home.client, &home.device, "device-secret", SnapshotSource::ClaudeCode,
            "otm_test", &home.fixture.home, &home.support, &home.daemon, &mut home.transport,
            home.daemon.snapshot_scan_account_witness().unwrap(), false)
    }).unwrap().expect("due production preparation");
    collect_native_preparation_with_rotation(frame, false)
}
fn write_target(home: &AckFinishHome, root: &str) -> PathBuf {
    let path = project(home).join(format!("{root}.jsonl"));
    std::fs::write(&path, format!("{}\n", serde_json::json!({
        "timestamp":current_rfc3339(), "type":"assistant", "sessionId":root,
        "requestId":"missed-request", "message":{"id":"missed-message", "model":"claude-haiku-4-5",
        "usage":{"input_tokens":7,"output_tokens":3}}
    }))).unwrap();
    path
}
fn saved(home: &AckFinishHome) -> ScanIndex { ScanIndex::load(&index_path(home)).unwrap() }
fn assert_settled(home: &AckFinishHome, server: &AckScriptedServer, root: &str) {
    let offers = server.offered.lock().unwrap();
    let body = offers.iter().rev().find(|body| body["source_session_id"] == root).expect("actual POST of target");
    assert!(saved(home).accepted_snapshot_fingerprint_recorded(body["snapshot_fingerprint"].as_str().unwrap()),
        "actual ACK settled in the saved index");
}

fn recover_missed_file(overflow: bool) {
    const TARGET: &str = "c3333333-3333-4333-8333-333333333333";
    const PASSES: usize = 16;
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    seed_deferred(&home, true);
    let (p, i, s) = prepare(&mut home);
    home.finish(p, i, s).unwrap();
    let initial = serde_json::to_value(saved(&home)).unwrap();
    let window = initial["traversal"]["census_window_end"].clone();
    let unchanged = project(&home).join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    // A directory wider than one metadata page proves the durable offset
    // resumes rather than repeatedly reading its first 512 entries.
    for n in 0..1025 { std::fs::write(project(&home).join(format!("metadata-{n:04}.txt")), "").unwrap(); }
    if overflow {
        for n in 0..4096 {
            crate::snapshot_watcher::hint_snapshot_path_for_test(SnapshotSource::ClaudeCode,
                project(&home).join(format!("lost-{n:04}.txt")));
        }
    }
    write_target(&home, TARGET); // stopped daemon / during overflow, no target hint
    if overflow {
        crate::snapshot_watcher::hint_snapshot_path_for_test(SnapshotSource::ClaudeCode, project(&home).join("overflow.txt"));
    } else {
        // Retain a same-context non-window carry from a prior daemon process.
        // Losing this optional certificate must not clear files or restart a
        // parked traversal. Missing/mismatched/full-window origins stay BASE.
        let mut checkpoint = serde_json::to_value(saved(&home)).unwrap();
        checkpoint["claude_stale_family_carry"] = serde_json::json!({
            "roots":[IDENTITY_PIPELINE_ROOT],
            "origin":{"context_fingerprint":checkpoint["traversal"]["context_fingerprint"],
                "process":0,"full_rearm_window":false}
        });
        let mut parked: ScanIndex = serde_json::from_value(checkpoint).unwrap();
        parked.save(&index_path(&home)).unwrap();
        home.daemon = test_daemon("otm_test");
        crate::snapshots::forget_parked_rewalk_process_for_test();
    }
    let mut saw_cursor = false;
    let mut found = false;
    for pass in 1..=PASSES {
        crate::snapshots::parked_native_opens_for_test();
        let ((p, i, s), lines) = crate::local_resource_diagnostics::capture(|| prepare(&mut home));
        assert!(!s.census_complete);
        let opened = crate::snapshots::parked_native_opens_for_test();
        assert!(!opened.contains(&unchanged), "zero opens/bytes for unchanged transcript on pass {pass}");
        assert!(lines.iter().all(|line| line["stage"] != "bounded_traversal_transition"
            || line["counts"]["event"] != "starting"), "no traversal-start or stale-pending re-arm");
        for line in lines.iter().filter(|line| line["stage"] == "parked_rewalk") {
            assert!(line["counts"]["entries"].as_u64().unwrap() <= 512);
            assert!(line["counts"]["dirs"].as_u64().unwrap() <= 8);
        }
        home.finish(p, i, s).unwrap();
        let value = serde_json::to_value(saved(&home)).unwrap();
        assert_eq!(value["traversal"]["census_window_end"], window);
        saw_cursor |= value["traversal"]["reconciliation_after"].as_str()
            .is_some_and(|value| value.starts_with("\0parked_rewalk:"));
        found |= server.offered.lock().unwrap().iter().any(|body| body["source_session_id"] == TARGET);
    }
    assert!(saw_cursor, "wide directory resumed through the existing persisted cursor");
    assert!(found, "missed target uploaded within {PASSES} passes");
    assert_settled(&home, &server, TARGET);
    assert!(cached_source_manifest(&snapshot_upload_destination_namespace(&home.device, "device-secret"), SnapshotSource::ClaudeCode).is_none());
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn parked_restart_discovers_unhinted_file_with_zero_unchanged_reads() { recover_missed_file(false); }

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn parked_overflow_recovers_unhinted_file_within_sixteen_passes_without_rearm() { recover_missed_file(true); }

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn earlier_partial_page_reoffers_and_settles_after_restart_before_parked_terminal() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    write_target(&home, "c3333333-3333-4333-8333-333333333333");
    seed_deferred(&home, true);
    crate::snapshots::with_parked_page_limit_for_test(1, || {
        let (p, i, s) = prepare(&mut home);
        assert!(!s.census_complete);
        assert!(i.claude_terminal_fold_deferred().is_none(), "EARLIER nonterminal page");
        server.script.lock().unwrap().push_back(AckScriptedPost::UnretriedServerError);
        assert!(home.finish(p, i, s).is_err());
        let failed = server.offered.lock().unwrap()[0].clone();
        let checkpoint = serde_json::to_value(saved(&home)).unwrap();
        assert!(!checkpoint["traversal"]["pending_candidates"].as_array().unwrap().is_empty());
        home.daemon = test_daemon("otm_test");
        crate::snapshots::forget_parked_rewalk_process_for_test();
        let mut deferred = false;
        for _ in 0..8 {
            let (p, i, s) = prepare(&mut home);
            deferred |= i.claude_terminal_fold_deferred().is_some();
            home.finish(p, i, s).unwrap();
        }
        assert!(deferred);
        assert!(server.offered.lock().unwrap().iter().filter(|body|
            body["snapshot_fingerprint"] == failed["snapshot_fingerprint"]).count() >= 2);
        assert!(saved(&home).accepted_snapshot_fingerprint_recorded(failed["snapshot_fingerprint"].as_str().unwrap()));
    });
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn refused_removal_revalidates_after_reload_and_manifest_excludes_deleted_file() {
    const VICTIM: &str = "c3333333-3333-4333-8333-333333333333";
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    let victim = write_target(&home, VICTIM);
    let (p, i, s) = prepare(&mut home);
    home.finish(p, i, s).unwrap();
    assert_settled(&home, &server, VICTIM);
    seed_deferred(&home, true);
    crate::snapshots::with_parked_page_limit_for_test(1, || {
        let (p, i, s) = prepare(&mut home);
        assert!(!s.census_complete);
        home.finish(p, i, s).unwrap();
        // The victim is already in the ordinary directory census queue. No
        // watcher injection is needed to exercise the refused-removal path.
        std::fs::remove_file(&victim).unwrap();
        let (p, i, s) = prepare(&mut home);
        assert!(i.claude_terminal_fold_deferred().is_some());
        home.finish(p, i, s).unwrap();
    });
    let value = serde_json::to_value(saved(&home)).unwrap();
    assert!(value["files"].as_object().unwrap().contains_key(victim.to_str().unwrap()), "refusal never commits removal");
    assert!(value["traversal"]["pending_candidates"].as_array().unwrap().iter()
        .any(|entry| entry["path"] == victim.to_str().unwrap()), "removal demand saved");
    seed_deferred(&home, false); // synthetic over-budget debt no longer owed
    home.daemon = test_daemon("otm_test");
    crate::snapshots::forget_parked_rewalk_process_for_test();
    for _ in 0..8 {
        let (p, i, s) = prepare(&mut home);
        home.finish(p, i, s).unwrap();
        if cached_source_manifest(&snapshot_upload_destination_namespace(&home.device, "device-secret"), SnapshotSource::ClaudeCode).is_some() { break; }
    }
    let value = serde_json::to_value(saved(&home)).unwrap();
    assert!(!value["files"].as_object().unwrap().contains_key(victim.to_str().unwrap()));
    let manifest = cached_source_manifest(&snapshot_upload_destination_namespace(&home.device, "device-secret"), SnapshotSource::ClaudeCode).expect("admitted complete manifest");
    assert_eq!(manifest.entity_count, 1, "the previously uploaded deleted entity is excluded");
}

fn write_pair(home: &AckFinishHome, root: &str) {
    use sha2::{Digest, Sha256};
    let (api, trace) = crate::claude_local_otel::terminal_sidecar_paths_for_test(&home.support, root);
    std::fs::create_dir_all(api.parent().unwrap()).unwrap();
    std::fs::create_dir_all(trace.parent().unwrap()).unwrap();
    let mut apis = String::new();
    let mut traces = String::new();
    for n in 1..=2 {
        let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(180 - n)).format(&Rfc3339).unwrap();
        let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
            capture_revision:"claude_api_request:v2".into(), session_id:root.into(), request_id:format!("req_{n}"),
            client_request_id:format!("client-{n}"), observed_at:at.clone(), model:"claude-haiku-4-5".into(),
            effort:"high".into(), query_source:"user".into(), app_version:"2.1.310".into(),
            event_sequence:Some(n as u64), cost_usd_micros:Some(100), input_tokens:10 * n as u64,
            output_tokens:n as u64, request_count:1, ..Default::default()
        };
        api.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&api).unwrap()));
        apis += &(serde_json::to_string(&api).unwrap() + "\n");
        let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
            capture_revision:"claude_llm_request_ownership:v1".into(), session_id:root.into(), request_id:format!("req_{n}"),
            client_request_id:format!("client-{n}"), observed_at:at, ..Default::default()
        };
        trace.fingerprint = format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(&trace).unwrap()));
        traces += &(serde_json::to_string(&trace).unwrap() + "\n");
    }
    std::fs::write(api, apis).unwrap();
    std::fs::write(trace, traces).unwrap();
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn off_page_open_error_keeps_incomplete_page_history_upload_and_settlement() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    std::fs::create_dir_all(home.support.join("snapshots")).unwrap();
    std::fs::write(home.support.join("snapshots/claude_code-reemission-exclusions.txt"), "# synthetic\n").unwrap();
    let off = "20000000-0000-4000-8000-000000000001";
    let off_path = write_target(&home, off);
    crate::snapshots::with_max_gated_claude_revision(1, || {
        let _base = crate::snapshots::claude_request_money::e2::GateForTest::off();
        let (p, i, s) = prepare(&mut home);
        home.finish(p, i, s).unwrap();
    });
    let root_path = project(&home).join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    // Upgrade only the off-page family while the healthy target is protected.
    // Both bodies/ACKs come from real finish, rather than forged index tuples.
    use sha2::{Digest, Sha256};
    std::fs::write(home.support.join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes()))).unwrap();
    write_pair(&home, off);
    crate::snapshots::with_max_gated_claude_revision(3, || {
        crate::snapshots::claude_request_money::e2::with_enabled(|| {
            let (p, i, s) = prepare(&mut home);
            home.finish(p, i, s).unwrap();
        });
    });
    let prior = serde_json::to_value(saved(&home)).unwrap();
    assert!(prior["files"][root_path.to_str().unwrap()]["effective_upload_body_witness_revision"].as_u64().unwrap() < 3);
    assert_eq!(prior["files"][off_path.to_str().unwrap()]["effective_upload_body_witness_revision"], 3);
    let off_body = prior["files"][off_path.to_str().unwrap()]["last_upload_body_witness"].clone();
    std::fs::write(home.support.join("snapshots/claude_code-reemission-exclusions.txt"), "# synthetic\n").unwrap();
    let before = server.offered.lock().unwrap().len();
    let mut value = serde_json::to_value(saved(&home)).unwrap();
    value["claude_usage_family_pending"][off] = serde_json::json!({"census_window_end":"2026-01-01T00:00:00Z",
        "member_request_id_hashes":{},"member_occurrences":{},"invalid":false});
    let mut index: ScanIndex = serde_json::from_value(value).unwrap();
    index.save(&index_path(&home)).unwrap();
    write_pair(&home, IDENTITY_PIPELINE_ROOT);
    let (api, _) = crate::claude_local_otel::terminal_sidecar_paths_for_test(&home.support, off);
    let off_pending = serde_json::to_value(saved(&home)).unwrap()["claude_usage_family_pending"][off].clone();
    crate::snapshots::with_max_gated_claude_revision(3, || {
        crate::snapshots::claude_request_money::e2::with_enabled(|| {
            crate::snapshots::with_staged_births_for_test(
                BTreeMap::from([(root_path.to_string_lossy().into_owned(), 1)]), || {
                    let (p, mut i, mut s) = prepare(&mut home);
                    assert!(i.claude_terminal_effects_staged());
                    assert!(i.claude_terminal_fold_deferred().is_none());
                    assert!(!s.snapshots.is_empty());
                    assert!(s.snapshots.iter().all(|body| body.source_session_id != off), "failed family is truly off-page");
                    i.mark_bounded_sweep_unsettled();
                    s.census_complete = false; // legitimate earlier-page settlement veto
                    let _hook = crate::claude_local_otel::terminal_off_page_open_failure_for_test(api);
                    home.finish(p, i, s).unwrap();
                });
        });
    });
    let stats = TERMINAL_FIXTURE_STATS.with(|slot| slot.take().unwrap());
    assert!(!stats.effort_evidence_load_failed, "off-page strict error cannot fail the page map");
    assert!(server.offered.lock().unwrap().len() > before, "owed current-page history actually uploaded");
    assert_settled(&home, &server, IDENTITY_PIPELINE_ROOT);
    let value = serde_json::to_value(saved(&home)).unwrap();
    assert_eq!(value["files"][root_path.to_str().unwrap()]["effective_upload_body_witness_revision"], 3);
    assert_eq!(value["files"][off_path.to_str().unwrap()]["last_upload_body_witness"], off_body);
    assert_eq!(value["claude_usage_family_pending"][off], off_pending, "retained failed family stays owed");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn below_allowance_trace_growth_never_freezes_failed_generation_as_complete() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    write_pair(&home, IDENTITY_PIPELINE_ROOT);
    crate::snapshots::claude_request_money::e2::with_enabled(|| {
        let (p, i, s) = prepare(&mut home);
        assert!(i.claude_terminal_effects_staged());
        let _hook = crate::claude_local_otel::terminal_growth_hook_for_test(true, |path| {
            use std::io::Write;
            std::fs::OpenOptions::new().append(true).open(path).unwrap().write_all(b"\n").unwrap();
        });
        home.finish(p, i, s).unwrap();
    });
    let stats = TERMINAL_FIXTURE_STATS.with(|slot| slot.take().unwrap());
    assert!(stats.terminal_fold_deferred.is_none(), "mutation stays below allowance");
    assert_eq!(stats.trace_incomplete_root_count, 1);
    assert!(server.offered.lock().unwrap().iter().all(|body| body["telemetry_owned_complete"] != true));
}


#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn below_allowance_unknown_api_generation_remains_family_incomplete() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    write_pair(&home, IDENTITY_PIPELINE_ROOT);
    crate::snapshots::claude_request_money::e2::with_enabled(|| {
        let (p, i, s) = prepare(&mut home);
        let _unknown = crate::claude_local_otel::unknown_api_generation_for_test();
        home.finish(p, i, s).unwrap();
    });
    let stats = TERMINAL_FIXTURE_STATS.with(|slot| slot.take().unwrap());
    assert!(stats.terminal_fold_deferred.is_none());
    assert_eq!(stats.api_incomplete_root_count, 1);
    assert!(server.offered.lock().unwrap().iter().all(|body| body["telemetry_owned_complete"] != true));
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn deferred_terminal_alarm_counts_offers_across_multiple_metadata_pages() {
    let server = AckScriptedServer::new();
    let mut home = AckFinishHome::new(&server);
    seed_deferred(&home, true);
    // Initialize the diagnostic as after a successful terminal offer.
    ScanIndex::default().note_claude_terminal_fold_offer(false);
    for n in 0..1025 { std::fs::write(project(&home).join(format!("alarm-{n:04}.txt")), "").unwrap(); }
    let mut offers = Vec::new();
    let mut ordinary_pages = 0;
    for _ in 0..16 {
        let (p, i, s) = prepare(&mut home);
        let terminal = i.claude_terminal_fold_deferred().is_some();
        let (result, lines) = crate::local_resource_diagnostics::capture(|| home.finish(p, i, s));
        result.unwrap();
        let count = lines.iter().find(|line| line["stage"] == "terminal_fold_deferred_consecutive");
        if terminal {
            offers.push(count.expect("terminal counter")["counts"]["passes"].as_u64().unwrap());
            if offers.len() == 3 { break; }
            // A real overflow requests a multi-page metadata sweep without
            // restarting the process or its global terminal-offer counter.
            for n in 0..4097 {
                crate::snapshot_watcher::hint_snapshot_path_for_test(SnapshotSource::ClaudeCode,
                    project(&home).join(format!("lost-alarm-{n:04}.txt")));
            }
        } else {
            ordinary_pages += 1;
            assert!(count.is_none(), "ordinary pages neither count nor reset");
        }
    }
    assert!(ordinary_pages >= 2);
    assert_eq!(offers, [1, 2, 3], "third deferred TERMINAL offer reaches the alarm despite intervening pages");
}
