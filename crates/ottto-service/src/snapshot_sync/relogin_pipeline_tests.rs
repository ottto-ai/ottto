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
    // One cycle in a fresh daemon and client: what it offered and where.
    let cycle = |device: &LocalDeviceBinding, secret: &str| {
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
                device,
                secret,
                "otm_test",
                &fixture.home,
                &support,
                &daemon,
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
        SnapshotUploadProgress::load_for_index(
            &ScanIndex::load(&index_path).unwrap(),
            &index_path,
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

/// [money] Destination completion and durable namespace selection conserve the
/// three sources after a quiet account roundtrip; synthetic fixture only.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn owner_return_preserves_all_source_carry() {
    use crate::snapshots::sampled_scan::transition_fixture::{observe_consumed, with_scan_clock};
    use serde_json::{json, Value};
    use std::time::UNIX_EPOCH;
    if !crate::heap_layout_bound::layout_supported() || !crate::test_isolation::run_here() {
        return;
    }
    const AT: &str = "2026-11-16T08:00:00Z";
    const CX: &str = "0199f7a0-0000-7000-8000-00000000c0de";
    const OLD: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba6";
    let now = OffsetDateTime::parse(AT, &Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    for (third_owner, replay_bump, rollback) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (false, false, true),
    ] {
        forget_carried_namespaces_for_test(&["return-a", "return-b", "return-a-again"]);
        let fixture = IdentityPipelineHome::new();
        let cadence = IdentityPipelineCadence::new();
        let _codex_cadence = IdentityPipelineCadence::for_source("codex");
        let _pi_cadence = IdentityPipelineCadence::for_source("pi");
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
                json!({"type":"assistant","timestamp":AT,"sessionId":session,"cwd":repository,
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
                json!({"type":"session_meta","timestamp":AT,"payload":{"id":CX,"timestamp":AT,"source":"cli"}}),
                json!({"type":"event_msg","timestamp":AT,"payload":{"type":"task_started","turn_id":"return-turn"}}),
                json!({"type":"turn_context","timestamp":AT,"payload":{"turn_id":"return-turn","model":"gpt-5.2"}}),
                json!({"type":"token_usage_record","timestamp":AT,"payload":{"thread_id":CX,"turn_id":"return-turn",
            "response_id":"return-response","usage":usage(1000,100),"thread_token_usage":usage(1000,100)}}),
                json!({"type":"event_msg","timestamp":AT,"payload":{"type":"token_count","info":{
            "last_token_usage":usage(2000,200),"total_token_usage":usage(2000,200)}}}),
                json!({"type":"event_msg","timestamp":AT,"payload":{"type":"task_complete","turn_id":"return-turn"}}),
            ],
        );
        let pi = fixture.home.join(".pi/agent/sessions/return-pi.jsonl");
        write(
            &pi,
            vec![
                json!({"type":"session","id":"return-pi","timestamp":AT}),
                json!({"type":"message","message":{"role":"assistant","model":"gpt-5.4","provider":"openai",
            "timestamp":AT,"responseId":"pi-response","usage":{"input":12,"output":4,"cost":{"total":0.001}}}}),
            ],
        );
        let sources = [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ];
        let (device_a, secret_a) = {
            let device = LocalDeviceBinding {
                device_id: "return-a".into(),
                machine_id: Some("machine_test".into()),
                sources: vec!["claude_code".into(), "codex".into(), "pi".into()],
            };
            let secret = "synthetic-return-secret-a".to_string();
            crate::control::owner_return_credential_for_test(&device, &secret, "owner-a");
            (device, secret)
        };
        let namespace_a = snapshot_upload_destination_namespace(&device_a, &secret_a);
        let index_path = |namespace: &str, source| {
            snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
                &snapshot_index_path(&support, source),
                namespace,
            ))
        };
        let cx_path = index_path(&namespace_a, SnapshotSource::Codex);
        let mut legacy = ScanIndex::default();
        // Keep the Legacy entry inside the current index replay generation.
        // The first ordinary pass completes that generation in upload progress
        // and destination completion through the production writers.
        let generation = cycle_replay_generation(SnapshotSource::Codex, &namespace_a);
        legacy.prepare_historical_replay(generation.clone());
        legacy.files.insert(
            codex.to_string_lossy().into_owned(),
            serde_json::from_value(json!({
                "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old",
                "last_snapshot_fingerprint":"old-ack","codex_counting_v2":false
            }))
            .unwrap(),
        );
        legacy.save_fixture(&cx_path).unwrap();
        crate::snapshots::older_build_logs_priority("return-turn");
        // A claim switch keeps the daemon alive. Keep its physical-header cache
        // while reloading account/index state on each ordinary source pass.
        let daemon_owner = test_daemon("machine_test");
        let cycle = |device: &LocalDeviceBinding, secret: &str, source: SnapshotSource| {
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
                    .insert(format!("{namespace}:{}", source.api_slug()), AT.into());
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
            let daemon = daemon_owner
                .clone()
                .with_account(ottto_core::FileAccountStore::default().load().unwrap());
            let mut transport = crate::net_resilience::TransportCycleOutcome::default();
            with_scan_clock(now, || {
                observe_consumed(|| {
                    let frame =
                        crate::agent_status_refresh::with_test_collection(collection(), || {
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
                            device,
                            secret,
                            "machine_test",
                            &fixture.home,
                            &support,
                            &daemon,
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
        let mut before = sources.map(|source| {
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
        let uninterrupted_io = sources.map(|source| {
            let (bodies, io) =
                crate::snapshots::sampled_scan::transition_fixture::observe_codex_quiet_with_bytes(
                    || cycle(&device_a, &secret_a, source),
                );
            assert!(
                bodies.is_empty(),
                "intact A does not re-offer accepted money"
            );
            assert_eq!(io.consumed, 0, "intact A reads no unchanged transcript");
            io
        });
        let saved = ScanIndex::load(&cx_path).unwrap();
        let entry = &saved.files[&codex.to_string_lossy().into_owned()];
        assert!(entry.codex_counting_v2, "new Codex reads retain V2");
        assert!(saved.historical_replay_generation_matches(&generation));
        // The disposable progress ledger can clear after ACK handoff. Its
        // destination/replay proof survives in the authoritative index.
        assert_eq!(
            serde_json::to_value(&saved.upload_context_proof).unwrap()["replay_generation"]
                .as_str(),
            Some(generation.as_str()),
            "accepted-body proof belongs to the completed replay"
        );
        assert!(!crate::backfill::pending_backfill_sources_for_destination(
            &crate::backfill::load_backfill_state(&support),
            &namespace_a,
        )
        .contains(&SnapshotSource::Codex));
        assert!(!serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"].is_null());
        let tier = serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"].clone();
        crate::snapshots::older_build_logs_expired();
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(now - 61 * 86400))
            .unwrap();
        // A timestamp rewrite is a real changed-input cause. Settle that
        // ordinary A work before the switch, then compare a quiet return.
        // Aging the file must not masquerade as unchanged input.
        let (touched, _) = cycle(&device_a, &secret_a, SnapshotSource::ClaudeCode);
        for body in touched {
            assert_eq!(
                body["source_session_id"], OLD,
                "only the touched old file is owed"
            );
            let saved = before[0]
                .iter_mut()
                .find(|prior| prior["source_session_id"] == OLD)
                .unwrap();
            for field in crate::snapshots::sampled_scan::transition_fixture::money_oracle::FIELDS {
                assert_eq!(
                    body[*field], saved[*field],
                    "metadata touch conserves {field}"
                );
            }
            *saved = body;
        }
        let (quiet, bytes) = cycle(&device_a, &secret_a, SnapshotSource::ClaudeCode);
        assert!(quiet.is_empty());
        assert_eq!(
            bytes, 0,
            "uninterrupted A is quiet after the metadata touch"
        );
        std::fs::remove_dir_all(&repository).unwrap();
        if replay_bump {
            let source = SnapshotSource::Pi;
            let mut old = ScanIndex::load(&index_path(&namespace_a, source)).unwrap();
            old.prepare_historical_replay(format!("pi:old-revision:{namespace_a}"));
            old.save_fixture(&index_path(&namespace_a, source)).unwrap();
            crate::backfill::update_backfill_state(&support, |state| {
                state
                    .completed_destination_replays
                    .get_mut("pi")
                    .unwrap()
                    .insert(namespace_a.clone(), "old-revision".into());
            })
            .unwrap();
        }

        // Each destination completes independently; returning A must keep its
        // Legacy decision, tier receipt, old accepted file and repository binding.
        for (user, id) in [
            ("owner-b", "return-b"),
            ("owner-c", "return-c"),
            ("owner-a", "return-a-again"),
        ] {
            if user == "owner-c" && !third_owner {
                continue;
            }
            let device = LocalDeviceBinding {
                device_id: id.into(),
                ..device_a.clone()
            };
            let secret = format!("secret-{id}");
            if rollback && user == "owner-a" {
                crate::backfill::update_backfill_state(&support, |state| {
                    state.completed_destination_replays.clear()
                })
                .unwrap();
            }
            let selected = crate::control::owner_return_credential_for_test(&device, &secret, user);
            let (device, secret) =
                crate::snapshot_client::load_snapshot_device_credentials().unwrap();
            assert_eq!(
                snapshot_upload_destination_namespace(&device, &secret),
                selected
            );
            if user != "owner-a" {
                assert_ne!(selected, namespace_a);
                assert!(
                    sources
                        .iter()
                        .all(|&source| !index_path(&selected, source).exists()),
                    "no previous owner's custody inherited"
                );
                for source in sources {
                    let _ = cycle(&device, &secret, source);
                }
                continue;
            }
            assert_eq!(selected, namespace_a);
            if replay_bump {
                let source = SnapshotSource::Pi;
                let generation = cycle_replay_generation(source, &selected);
                assert_eq!(
                    generation,
                    format!(
                        "pi:{}:{selected}",
                        current_historical_replay(source).revision
                    )
                );
                let (replayed, _) = cycle(&device, &secret, source);
                assert_eq!(
                    replayed.len(),
                    1,
                    "the returning destination pays its own owed revision"
                );
                for field in
                    crate::snapshots::sampled_scan::transition_fixture::money_oracle::FIELDS
                {
                    assert_eq!(
                        replayed[0][*field], before[2][0][*field],
                        "Pi replay {field}"
                    );
                }
                let state = crate::backfill::load_backfill_state(&support);
                assert!(!crate::backfill::pending_backfill_sources_for_destination(
                    &state, &selected
                )
                .contains(&source));
                let saved = ScanIndex::load(&index_path(&selected, source)).unwrap();
                assert!(saved.historical_replay_generation_matches(&generation));
            }
            if rollback {
                for source in sources {
                    let (bodies, _) = cycle(&device, &secret, source);
                    assert!(
                        bodies.is_empty(),
                        "rollback re-walk never creates a new ACK for accepted history"
                    );
                }
            }
            for source in sources {
                let (bodies, io) =
                crate::snapshots::sampled_scan::transition_fixture::observe_codex_quiet_with_bytes(
                    || cycle(&device, &secret, source),
                );
                assert!(bodies.is_empty(), "quiet return re-offered {source:?}");
                assert_eq!(io.consumed, 0, "quiet return read {source:?}");
                let saved = ScanIndex::load(&index_path(&selected, source)).unwrap();
                let mut quiet =
                    crate::snapshots::sampled_scan::transition_fixture::RouteResult::emitted(
                        // The scan index is restored from disk on each cycle;
                        // the live daemon retains its physical header cache.
                        crate::snapshots::sampled_scan::transition_fixture::Mode::DiskRestore,
                        source,
                        Vec::new(),
                        &[],
                    );
                quiet.io = io;
                // Restarted censuses sample identity in uninterrupted A too.
                // The allowance is the independently observed control, never a
                // constant or the return's own reading; all other I/O stays zero.
                let anchors = uninterrupted_io[sources.iter().position(|s| *s == source).unwrap()]
                    .anchor_reads
                    .expect("uninterrupted anchors must be measured");
                crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_quiet_restart_with_anchor_window(&quiet, anchors);
                for prior in &before[sources.iter().position(|s| *s == source).unwrap()] {
                    assert!(saved.accepted_snapshot_fingerprint_recorded(
                        prior["snapshot_fingerprint"].as_str().unwrap()
                    ));
                }
            }
            let saved = ScanIndex::load(&cx_path).unwrap();
            let entry = &saved.files[&codex.to_string_lossy().into_owned()];
            assert!(entry.codex_counting_v2);
            assert_eq!(
                serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"],
                tier
            );
            let claude_saved =
                ScanIndex::load(&index_path(&selected, SnapshotSource::ClaudeCode)).unwrap();
            assert!(
                claude_saved
                    .files
                    .contains_key(&old.to_string_lossy().into_owned()),
                "old accepted coverage survives"
            );
            assert!(before[0]
                .iter()
                .all(|body| body["repository_hash"].is_string()));
        }
        // Deleted-store return is from a different owner. A same-owner rotation
        // must preserve main's namespace even when its store has disappeared.
        let away = LocalDeviceBinding {
            device_id: "return-b-before-loss".into(),
            ..device_a.clone()
        };
        crate::control::owner_return_credential_for_test(&away, "away-secret", "owner-b");
        // Deleted-store fallback cannot borrow ACKs or recreate the old namespace.
        std::fs::remove_dir_all(support.join("snapshots/destinations").join(&namespace_a)).unwrap();
        let fresh = LocalDeviceBinding {
            device_id: "return-a-deleted".into(),
            ..device_a.clone()
        };
        let selected =
            crate::control::owner_return_credential_for_test(&fresh, "deleted-secret", "owner-a");
        assert_ne!(selected, namespace_a);
        crate::backfill::apply_claim_backfill_policy_for_destination(
            &support,
            Some("from"),
            Some("2026-11-17T00:00:00Z"),
            "owner-a",
            Some(&selected),
        )
        .unwrap();
        let (device, secret) = crate::snapshot_client::load_snapshot_device_credentials().unwrap();
        for source in sources {
            let (bodies, _) = cycle(&device, &secret, source);
            assert!(
                bodies.is_empty(),
                "pre-cutoff store-loss fallback cannot shrink the server head"
            );
            let lost = ScanIndex::load(&index_path(&selected, source)).unwrap();
            if source == SnapshotSource::Codex {
                assert!(
                    lost.files
                        .get(&codex.to_string_lossy().into_owned())
                        .is_some_and(|entry| entry.codex_counting_v2),
                    "deleted-store fallback records the V2 interpretation residual"
                );
            }
            for prior in &before[sources.iter().position(|s| *s == source).unwrap()] {
                assert!(
                    !lost.accepted_snapshot_fingerprint_recorded(
                        prior["snapshot_fingerprint"].as_str().unwrap()
                    ),
                    "no acceptance inherited after deletion"
                );
            }
        }
    } // two- and three-owner return rows
}

/// [money] Recorded owners retain their namespace and receipts on A -> B -> A.
/// No-row owners keep the disclosed fresh-store limit; the receiver is synthetic.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn account_return_preserves_recorded_history_and_bounds_unrecorded_owners() {
    if !crate::heap_layout_bound::layout_supported() || !crate::test_isolation::run_here() {
        return;
    }
    // No-row pre-existing owners are not adopted by direct switches.
    for recorded_a in [true, false] {
        account_return_history_row(recorded_a);
    }
}

fn account_return_history_row(recorded_a: bool) {
    use crate::snapshots::sampled_scan::transition_fixture::{observe_consumed, with_scan_clock};
    use serde_json::{json, Value};
    use std::time::UNIX_EPOCH;
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
        crate::control::account_return_claim_for_test("owner-a", "org-a", "return-a", recorded_a);
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
    legacy.save_fixture(&cx_path).unwrap();
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
    let daemon_owner = test_daemon("machine_test");
    // Existing prepare/finish scaffold, now table-driven across the three sources.
    let cycle = |device: &LocalDeviceBinding, secret: &str, source: SnapshotSource| {
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
        let daemon = daemon_owner
            .clone()
            .with_account(ottto_core::FileAccountStore::default().load().unwrap());
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
                        device,
                        secret,
                        "machine_test",
                        &fixture.home,
                        &support,
                        &daemon,
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
    let mut before = sources.map(|source| {
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
    assert!(entry.codex_counting_v2, "new Codex reads retain V2");
    assert!(!serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"].is_null());
    let original_store = std::fs::read(&cx_path).unwrap();
    let tier = serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"].clone();
    crate::snapshots::older_build_logs_expired();
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(now - 61 * 86400))
        .unwrap();
    if recorded_a {
        // Settle the real timestamp edit before measuring an unchanged return.
        let (touched, _) = cycle(&device_a, &secret_a, SnapshotSource::ClaudeCode);
        for body in touched {
            assert_eq!(body["source_session_id"], OLD);
            let prior = before[0]
                .iter_mut()
                .find(|prior| prior["source_session_id"] == OLD)
                .unwrap();
            for field in crate::snapshots::sampled_scan::transition_fixture::money_oracle::FIELDS {
                assert_eq!(
                    body[*field], prior[*field],
                    "metadata touch conserves {field}"
                );
            }
            *prior = body;
        }
        let (bodies, bytes) = cycle(&device_a, &secret_a, SnapshotSource::ClaudeCode);
        assert!(bodies.is_empty());
        assert_eq!(bytes, 0);
    }
    std::fs::remove_dir_all(&repository).unwrap();
    let mut returned = Vec::new();
    let mut previous_namespace = namespace_a.clone();
    for (user, org, id) in [
        ("owner-b", "org-b", "return-b"),
        ("owner-a", "org-a", "return-a-again"),
    ] {
        let (device, secret) =
            crate::control::account_return_claim_for_test(user, org, id, recorded_a);
        let namespace = snapshot_upload_destination_namespace(&device, &secret);
        let reattached = recorded_a && user == "owner-a";
        assert_eq!(namespace == namespace_a, reattached);
        assert_ne!(namespace, previous_namespace);
        previous_namespace = namespace.clone();
        assert!(sources
            .iter()
            .all(|&source| index_path(&namespace, source).exists() == reattached));
        returned = sources
            .map(|source| cycle(&device, &secret, source).0)
            .to_vec();
        if reattached {
            assert!(
                returned.iter().all(|bodies| bodies.is_empty()),
                "no accepted history or saved Git binding is replaced on return"
            );
            let saved =
                ScanIndex::load(&index_path(&namespace, SnapshotSource::ClaudeCode)).unwrap();
            assert!(
                saved
                    .files
                    .contains_key(&old.to_string_lossy().into_owned()),
                "old accepted Claude coverage survives"
            );
        } else {
            assert!(
                returned.iter().all(|bodies| bodies.len() == 1),
                "a fresh destination keeps only existing recent session keys"
            );
        }
        for source in sources {
            let (bodies, bytes) = cycle(&device, &secret, source);
            assert!(
                bodies.is_empty(),
                "no second offer of accepted money: {source:?}"
            );
            assert_eq!(bytes, 0, "quiet destination reads no transcript");
        }
        let returned_cx = ScanIndex::load(&index_path(&namespace, SnapshotSource::Codex)).unwrap();
        let entry = &returned_cx.files[&codex.to_string_lossy().into_owned()];
        assert!(entry.codex_counting_v2);
        if reattached {
            assert_eq!(
                serde_json::to_value(entry).unwrap()["codex_applied_tier_receipt"],
                tier
            );
        }
    }
    if !recorded_a {
        assert_eq!(
            std::fs::read(&cx_path).unwrap(),
            original_store,
            "no-row pre-existing stores remain orphaned rather than being adopted"
        );
    }
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
    for (source, session, expected) in [
        (1, CX, Some([1000, 100, 0, 0, 0, 0, 0, 1])),
        (0, OLD, recorded_a.then_some([30, 3, 0, 0, 0, 0, 0, 1])),
        (0, IDENTITY_PIPELINE_ROOT, Some([30, 3, 0, 0, 0, 0, 0, 1])),
        (2, "return-pi", Some([12, 4, 0, 0, 0, 0, 0, 1])),
    ] {
        let prior = before[source]
            .iter()
            .find(|b| b["source_session_id"] == session)
            .expect("accepted A positive control");
        let after = returned[source]
            .iter()
            .find(|b| b["source_session_id"] == session);
        if let Some(expected) = expected {
            let after = if recorded_a {
                assert!(after.is_none(), "unchanged accepted body is not replaced");
                let saved = ScanIndex::load(&index_path(&namespace_a, sources[source])).unwrap();
                assert!(saved.accepted_snapshot_fingerprint_recorded(
                    prior["snapshot_fingerprint"].as_str().unwrap()
                ));
                // No replacement and the exact ACK keep this body effective.
                // The fingerprint includes repository identity and all money fields.
                prior
            } else {
                after.expect("the fresh destination offers its body")
            };
            assert_eq!(counts(after), expected, "{session}: recorded={recorded_a}");
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
                assert_eq!(counts(prior), [1000, 100, 0, 0, 0, 0, 0, 1]);
                assert_eq!(counts(&prior["model_usage"][0]), counts(prior));
                assert_eq!(counts(&after["model_usage"][0]), expected);
                assert_eq!(
                    prior["model_usage"][0]["selector_context"]["service_tier"],
                    "priority"
                );
                assert_eq!(
                    after["model_usage"][0]["selector_context"]["service_tier"] == "priority",
                    recorded_a
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
            if source == 0 && !recorded_a {
                assert!(prior["repository_hash"].is_string());
                assert!(
                    after["repository_hash"].is_null(),
                    "fresh local parse loses the Git pin"
                );
                assert_eq!(after["workspace_kind"], "unknown");
            } else {
                if source == 0 {
                    assert!(
                        after["repository_hash"].is_string(),
                        "the accepted Git pin survives"
                    );
                }
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
        eprintln!("ACCOUNT_RETURN_ROW {session} recorded={recorded_a}");
    }
}
