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
