use super::*;

/// [money] R1 on the real prepare/finish: a confirmed same-account re-login
/// installs device B with an alias to device A's namespace. The next cycle,
/// in a restarted daemon, keeps A's index and ACK ledger: it offers no
/// accepted body, reads no transcript byte and still sends B's terminal
/// report. An appended request uploads only that session's new revision,
/// whose money exceeds the accepted one by exactly the appended suffix.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn relogin_alias_keeps_accepted_history_without_a_reread() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::snapshots::sampled_scan::transition_fixture::observe_consumed;
    forget_carried_namespaces_for_test(&["relogin-device-a", "relogin-device-b"]);
    let fixture = IdentityPipelineHome::new();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("relogin-support");
    let secrets = fixture.base.join("relogin-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device_a = LocalDeviceBinding {
        device_id: "relogin-device-a".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["claude_code".into()],
    };
    FileDeviceStore::default().save(&device_a).unwrap();
    std::fs::write(secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT), "secret-a").unwrap();
    write_native_bootstrap_sidecars(&fixture, &support);
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
        setup_snapshot_index: None,
    };
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    // One cycle in a fresh daemon and client: what it offered and where.
    let mut cycle = |device: &LocalDeviceBinding, secret: &str| {
        cadence.next_due_cycle();
        server.offered.lock().unwrap().clear();
        let reports = server.terminal.lock().unwrap().len();
        let client = SnapshotApiClient::new(server.url.clone());
        let daemon = test_daemon("otm_test");
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
            prepare_sync_source(
                &client,
                device,
                secret,
                SnapshotSource::ClaudeCode,
                "otm_test",
                &fixture.home,
                &support,
                &daemon,
                &mut transport,
                daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("due preparation");
        let (preparation, index, scan) = collect_preparation_with_rotation(frame);
        let paths = (
            preparation.index_path.clone(),
            preparation.upload_progress_path.clone(),
        );
        crate::agent_status_refresh::with_test_collection(collection(), || {
            finish_sync_source(
                preparation,
                index,
                scan,
                &client,
                device,
                secret,
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
        let offered = server.offered.lock().unwrap().clone();
        assert_eq!(server.terminal.lock().unwrap().len(), reports + 1);
        (offered, paths)
    };

    let ((offered, (index_path, progress_path)), read) =
        observe_consumed(|| cycle(&device_a, "secret-a"));
    assert!(read > 0, "positive control: cycle 1 reads the transcript");
    assert_eq!(offered.len(), 1, "first cycle uploads the session");
    let money = |body: &serde_json::Value| {
        ["input_tokens", "output_tokens", "cache_read_tokens"]
            .map(|field| body[field].as_u64().unwrap())
    };
    let accepted_money = money(&offered[0]);
    let accepted = offered[0]["snapshot_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(ScanIndex::load(&index_path)
        .unwrap()
        .accepted_snapshot_fingerprint_recorded(&accepted));
    let namespace = snapshot_upload_destination_namespace(&device_a, "secret-a");
    let ledger = || {
        SnapshotUploadProgress::load(
            &progress_path,
            &namespace,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap()
    };
    let before = ledger();

    // Promotion writes the successor with the carried namespace.
    let device_b = LocalDeviceBinding {
        device_id: "relogin-device-b".into(),
        ..device_a.clone()
    };
    assert_ne!(
        snapshot_destination_namespace(&device_b, "secret-b", None),
        namespace,
        "without the alias the successor would start a fresh index"
    );
    FileDeviceStore::default()
        .save_with_credential_generation(&ottto_core::LocalDeviceCredentialBinding {
            device: device_b.clone(),
            credential_generation: 2,
            continuity: ottto_core::DeviceCredentialContinuity {
                owner: None,
                snapshot_namespace: Some(ottto_core::SnapshotNamespaceAlias {
                    namespace: namespace.clone(),
                    secret_commitment_sha256: crate::control::secret_sha256("secret-b"),
                }),
            },
        })
        .unwrap();
    std::fs::write(secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT), "secret-b").unwrap();
    // The restarted daemon's loader carries the namespace with the credential.
    let (device, secret) = crate::snapshot_client::load_snapshot_device_credentials().unwrap();
    assert_eq!(device, device_b);

    let ((offered, paths), read) = observe_consumed(|| cycle(&device, &secret));
    assert_eq!(read, 0, "the quiet restart reads no transcript byte");
    assert!(offered.is_empty(), "no accepted history is offered again");
    assert_eq!(paths, (index_path.clone(), progress_path.clone()));
    assert!(ScanIndex::load(&index_path)
        .unwrap()
        .accepted_snapshot_fingerprint_recorded(&accepted));
    assert_eq!(ledger().accepted_fingerprints, before.accepted_fingerprints);

    // Only real new activity is uploaded, as the same session's next revision.
    let transcript = fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(30))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let line = serde_json::json!({"timestamp": at, "type": "assistant",
        "sessionId": IDENTITY_PIPELINE_ROOT, "requestId": "req_3", "message": {"id": "m3",
        "model": "claude-haiku-4-5", "usage": {"input_tokens": 30, "output_tokens": 3}}});
    std::fs::OpenOptions::new()
        .append(true)
        .open(transcript)
        .unwrap()
        .write_all(format!("{line}\n").as_bytes())
        .unwrap();
    let (offered, paths) = cycle(&device, &secret);
    assert_eq!(paths.0, index_path);
    assert_eq!(offered.len(), 1);
    assert_ne!(offered[0]["snapshot_fingerprint"], accepted.as_str());
    let suffix = [0, 1, 2].map(|i| money(&offered[0])[i] - accepted_money[i]);
    assert_eq!(suffix, [30, 3, 0], "exactly the appended request's money");
}

/// Characterization of today's fresh destination on A -> B -> A. The receiver
/// accepts replacements; this proves offered bodies and exact local ACK custody,
/// not the separate receiver's pricing or predecessor repository carry-forward.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn account_return_today_reinterprets_orphaned_history() {
    use crate::snapshots::sampled_scan::transition_fixture::{observe_consumed, with_scan_clock};
    use serde_json::{json, Value};
    use std::time::UNIX_EPOCH;
    if !crate::heap_layout_bound::layout_supported() || !crate::test_isolation::run_here() {
        return;
    }
    const CX: &str = "0199f7a0-0000-7000-8000-00000000c0de";
    const OLD: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba6";
    let post_cutover = OffsetDateTime::parse("2026-11-16T08:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    // Freeze the cadence's clock once; later real collection dates stay recent.
    let now = crate::scan_clock::utc_seconds().max(post_cutover);
    let at = OffsetDateTime::from_unix_timestamp(now.try_into().unwrap())
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    forget_carried_namespaces_for_test(&["return-a", "return-b", "return-a-again"]);
    let fixture = IdentityPipelineHome::new();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("return-support");
    let secrets = fixture.base.join("return-secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    let _home = EnvVarGuard::set_path("HOME", &fixture.home);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let _pi = EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &fixture.home.join(".pi/agent"));
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let project = fixture.home.join(".claude/projects/-synthetic-repo");
    let claude = project.join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let old = project.join(format!("{OLD}.jsonl"));
    let repository = fixture.home.join("vanished-repository");
    std::fs::create_dir_all(&repository).unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let write = |path: &Path, rows: Vec<Value>| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            rows.iter()
                .map(|v| v.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(now - 60))
            .unwrap();
    };
    let claude_rows = |session: &str| {
        vec![
            json!({"type":"assistant","timestamp":at,"sessionId":session,"cwd":repository,
            "requestId":format!("{session}-request"),"message":{"id":format!("{session}-response"),
                "model":"claude-haiku-4-5","usage":{"input_tokens":30,"output_tokens":3}}}),
        ]
    };
    write(&claude, claude_rows(IDENTITY_PIPELINE_ROOT));
    write(&old, claude_rows(OLD));
    write_native_bootstrap_sidecars(&fixture, &support);
    let codex = fixture
        .home
        .join(".codex/sessions")
        .join(format!("rollout-2026-11-16T08-00-00-{CX}.jsonl"));
    let usage = |input, output| {
        json!({"input_tokens":input,"output_tokens":output,
        "cached_input_tokens":0,"cache_write_input_tokens":0,"reasoning_output_tokens":0,"total_tokens":input+output})
    };
    write(
        &codex,
        vec![
            json!({"type":"session_meta","timestamp":at,"payload":{"id":CX,"timestamp":at,"source":"cli"}}),
            json!({"type":"event_msg","timestamp":at,"payload":{"type":"task_started","turn_id":"return-turn"}}),
            json!({"type":"turn_context","timestamp":at,"payload":{"turn_id":"return-turn","model":"gpt-5.2"}}),
            json!({"type":"token_usage_record","timestamp":at,"payload":{"thread_id":CX,"turn_id":"return-turn",
            "response_id":"return-response","usage":usage(1000,100),"thread_token_usage":usage(1000,100)}}),
            json!({"type":"event_msg","timestamp":at,"payload":{"type":"token_count","info":{
            "last_token_usage":usage(2000,200),"total_token_usage":usage(2000,200)}}}),
            json!({"type":"event_msg","timestamp":at,"payload":{"type":"task_complete","turn_id":"return-turn"}}),
        ],
    );
    let pi = fixture.home.join(".pi/agent/sessions/return-pi.jsonl");
    write(
        &pi,
        vec![
            json!({"type":"session","id":"return-pi","timestamp":at}),
            json!({"type":"message","message":{"role":"assistant","model":"gpt-5.4","provider":"openai",
            "timestamp":at,"responseId":"pi-response","usage":{"input":12,"output":4,"cost":{"total":0.001}}}}),
        ],
    );
    let sources = [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ];
    let (device_a, secret_a) =
        crate::control::account_return_claim_for_test("owner-a", "org-a", "return-a");
    let namespace_a = snapshot_upload_destination_namespace(&device_a, &secret_a);
    let index_path = |namespace: &str, source| {
        snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&support, source),
            namespace,
        ))
    };
    let cx_path = index_path(&namespace_a, SnapshotSource::Codex);
    let mut legacy = ScanIndex::default();
    legacy.files.insert(
        codex.to_string_lossy().into_owned(),
        serde_json::from_value(json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old",
            "last_snapshot_fingerprint":"old-ack","codex_counting_v2":false
        }))
        .unwrap(),
    );
    legacy.save(&cx_path).unwrap();
    // Like install_legacy_active: A already completed its initial Codex backfill.
    crate::backfill::update_backfill_state(&support, |state| {
        crate::backfill::mark_backfill_complete_for_destination(
            state,
            SnapshotSource::Codex,
            &namespace_a,
        );
    })
    .unwrap();
    crate::snapshots::older_build_logs_priority("return-turn");
    let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
    // Existing prepare/finish scaffold, now table-driven across the three sources.
    let mut cycle = |device: &LocalDeviceBinding, secret: &str, source: SnapshotSource| {
        cadence.next_due_cycle();
        source_cadences().lock().unwrap().remove(source.api_slug());
        source_upload_deadlines()
            .lock()
            .unwrap()
            .remove(source.api_slug());
        server.offered.lock().unwrap().clear();
        let namespace = snapshot_upload_destination_namespace(device, secret);
        crate::backfill::update_backfill_state(&support, |state| {
            state
                .first_census_ends
                .insert(format!("{namespace}:{}", source.api_slug()), at.clone());
        })
        .unwrap();
        let collection = || AgentStatusCollection {
            snapshots: vec![test_agent_status(source_kind(source))],
            source_health_snapshot: test_agent_status(source_kind(source)),
            codex_scan_homes: vec![fixture.home.join(".codex")],
            codex_home_bindings: vec![crate::agent_status::CodexHomeBinding {
                home: fixture.home.join(".codex"),
                account_identifier_hash: "a".repeat(64),
                workspace_identifier_hash: "b".repeat(64),
                auth_modified_at: UNIX_EPOCH,
            }],
            setup_snapshot_index: None,
        };
        let client = SnapshotApiClient::new(server.url.clone());
        let daemon = test_daemon("machine_test");
        let mut transport = crate::net_resilience::TransportCycleOutcome::default();
        with_scan_clock(now, || {
            observe_consumed(|| {
                let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
                    prepare_sync_source(
                        &client,
                        device,
                        secret,
                        source,
                        "machine_test",
                        &fixture.home,
                        &support,
                        &daemon,
                        &mut transport,
                        daemon.snapshot_scan_account_witness().unwrap(),
                        false,
                    )
                })
                .unwrap()
                .expect("due preparation");
                let (preparation, index, scan) = collect_preparation_with_rotation(frame);
                if namespace != namespace_a && source == SnapshotSource::ClaudeCode {
                    if !scan.snapshots.is_empty() {
                        assert_eq!(
                            scan.scanned_file_count, 1,
                            "only the recent transcript is read"
                        );
                    }
                    assert!(!index
                        .files
                        .contains_key(&old.to_string_lossy().into_owned()));
                }
                let path = preparation.index_path.clone();
                crate::agent_status_refresh::with_test_collection(collection(), || {
                    finish_sync_source(
                        preparation,
                        index,
                        scan,
                        &client,
                        device,
                        secret,
                        source,
                        "machine_test",
                        &fixture.home,
                        &support,
                        &daemon,
                        &mut transport,
                        &mut retry,
                    )
                })
                .unwrap();
                let bodies = server.offered.lock().unwrap().clone();
                let saved = ScanIndex::load(&path).unwrap();
                for body in &bodies {
                    assert!(
                        saved.accepted_snapshot_fingerprint_recorded(
                            body["snapshot_fingerprint"].as_str().unwrap()
                        ),
                        "only exact ACKs credit this destination"
                    );
                }
                bodies
            })
        })
    };
    let before = sources.map(|source| {
        let (bodies, bytes) = cycle(&device_a, &secret_a, source);
        assert!(bytes > 0);
        assert_eq!(
            bodies.len(),
            if source == SnapshotSource::ClaudeCode {
                2
            } else {
                1
            }
        );
        bodies
    });
    for source in sources {
        let (bodies, bytes) = cycle(&device_a, &secret_a, source);
        assert!(
            bodies.is_empty(),
            "intact A does not re-offer accepted money"
        );
        assert_eq!(bytes, 0, "intact A reads no unchanged transcript");
    }
    let saved = ScanIndex::load(&cx_path).unwrap();
    let entry = &saved.files[&codex.to_string_lossy().into_owned()];
    assert!(!entry.codex_counting_v2, "Legacy ACK keeps the UI counter");
    assert!(!serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"].is_null());
    let orphan = std::fs::read(&cx_path).unwrap();
    crate::snapshots::older_build_logs_expired();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(now - 61 * 86400))
        .unwrap();
    std::fs::remove_dir_all(&repository).unwrap();
    let mut returned = Vec::new();
    let mut previous_namespace = namespace_a.clone();
    for (user, org, id) in [
        ("owner-b", "org-b", "return-b"),
        ("owner-a", "org-a", "return-a-again"),
    ] {
        let (device, secret) = crate::control::account_return_claim_for_test(user, org, id);
        let namespace = snapshot_upload_destination_namespace(&device, &secret);
        // CHANGED-ON-RETURN: only the prior owner is considered; durable re-attach decision pending.
        assert_ne!(namespace, namespace_a);
        assert_ne!(namespace, previous_namespace);
        previous_namespace = namespace.clone();
        assert!(sources
            .iter()
            .all(|&source| !index_path(&namespace, source).exists()));
        returned = sources
            .map(|source| cycle(&device, &secret, source).0)
            .to_vec();
        assert!(
            returned.iter().all(|bodies| bodies.len() == 1),
            "only existing recent session keys return"
        );
        for source in sources {
            let (bodies, bytes) = cycle(&device, &secret, source);
            assert!(
                bodies.is_empty(),
                "no second offer of accepted money: {source:?}"
            );
            assert_eq!(bytes, 0, "quiet destination reads no transcript");
        }
        let returned_cx = ScanIndex::load(&index_path(&namespace, SnapshotSource::Codex)).unwrap();
        assert!(
            returned_cx.files[&codex.to_string_lossy().into_owned()].codex_counting_v2,
            "empty destination selects V2"
        );
    }
    assert_eq!(
        std::fs::read(&cx_path).unwrap(),
        orphan,
        "A's original store remains orphaned"
    );
    let counts = |body: &Value| {
        [
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
        ]
        .map(|field| {
            if field == "unattributed_total_tokens" && body.get(field).is_none() {
                0
            } else {
                body[field].as_u64().expect("wire counter is present")
            }
        })
    };
    // Each row names its current outcome; subsequent owner re-attach changes flip these deliberately.
    for (source, session, outcome, expected) in [
        // CHANGED-ON-RETURN: Legacy ACK and priority receipt are orphaned; durable re-attach decision pending.
        (
            1,
            CX,
            "CHANGED-ON-RETURN",
            Some([1000, 100, 0, 0, 0, 0, 0, 1]),
        ),
        // CHANGED-ON-RETURN: the first-read mtime gate loses correction coverage; durable re-attach decision pending.
        (0, OLD, "CHANGED-ON-RETURN", None),
        // CHANGED-ON-RETURN: the saved Git pin is orphaned; durable re-attach decision pending.
        (
            0,
            IDENTITY_PIPELINE_ROOT,
            "CHANGED-ON-RETURN",
            Some([30, 3, 0, 0, 0, 0, 0, 1]),
        ),
        // PRESERVED: Pi's reported counters and costs reconstruct from native bytes.
        (2, "return-pi", "PRESERVED", Some([12, 4, 0, 0, 0, 0, 0, 1])),
    ] {
        let prior = before[source]
            .iter()
            .find(|b| b["source_session_id"] == session)
            .expect("accepted A positive control");
        let after = returned[source]
            .iter()
            .find(|b| b["source_session_id"] == session);
        if let Some(expected) = expected {
            let after = after.expect("re-read and re-offered once in fresh A destination");
            assert_eq!(counts(after), expected, "{session}: {outcome}");
            assert_eq!(
                after["session_account_evidence"], prior["session_account_evidence"],
                "starting account binding"
            );
            for field in [
                "auth_mode",
                "billing_channel",
                "billing_provider",
                "subscription_product",
                "account_identifier_hash",
            ] {
                assert_eq!(
                    after["model_usage"][0][field], prior["model_usage"][0][field],
                    "{field}"
                );
            }
            if source == 1 {
                assert_eq!(counts(prior), [2000, 200, 0, 0, 0, 0, 0, 1]);
                assert_eq!(counts(&prior["model_usage"][0]), counts(prior));
                assert_eq!(counts(&after["model_usage"][0]), expected);
                assert_eq!(
                    prior["model_usage"][0]["selector_context"]["service_tier"],
                    "priority"
                );
                assert_ne!(
                    after["model_usage"][0]["selector_context"]["service_tier"],
                    "priority"
                );
            } else {
                assert_eq!(counts(prior), expected);
                for field in
                    crate::snapshots::sampled_scan::transition_fixture::money_oracle::FIELDS
                {
                    assert_eq!(
                        after[*field], prior[*field],
                        "{field}: priced rows and hourly cost inputs"
                    );
                }
                if source == 2 {
                    assert_eq!(after["cost"]["total_cost_usd"], "0.001");
                }
            }
            if source == 0 {
                assert!(prior["repository_hash"].is_string());
                assert!(
                    after["repository_hash"].is_null(),
                    "fresh local parse loses the Git pin"
                );
                assert_eq!(after["workspace_kind"], "unknown");
            } else {
                assert_eq!(after["repository_hash"], prior["repository_hash"]);
                assert_eq!(after["workspace_kind"], prior["workspace_kind"]);
            }
        } else {
            assert!(
                after.is_none(),
                "old accepted item is neither re-read nor re-offered"
            );
            assert_eq!(counts(prior), [30, 3, 0, 0, 0, 0, 0, 1]);
        }
        eprintln!("ACCOUNT_RETURN_ROW {session} {outcome}");
    }
}
