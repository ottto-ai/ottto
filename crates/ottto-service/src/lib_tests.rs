#[cfg(test)]
mod tests {
    //! Daemon integration tests for authentication and source status.
    //! Exercises repair, verification and canonical health projections.
    //! Loaded by the crate root under the existing `tests` module.

    use super::*;
    use ottto_core::source_state_file_name;
    use ottto_core::FileSourceStateStore;
    use ottto_core::LocalConnectionBinding;
    use ottto_core::LocalDeviceBinding;
    use ottto_core::LocalSourceState;
    use ottto_core::OTTTO_KEYCHAIN_ACCOUNT;
    use ottto_core::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
    use ottto_protocol::AgentQuotaWindow;
    use ottto_protocol::AgentQuotaWindowFreshness;
    use ottto_protocol::AgentQuotaWindowStatus;
    use ottto_protocol::AgentStatusSnapshot;
    use ottto_protocol::AgentStatusState;
    use ottto_protocol::DaemonRuntimeState;
    use ottto_protocol::DaemonStatus;
    use ottto_protocol::DetectedUse;
    use ottto_protocol::DetectedUseQuotaWindowState;
    use ottto_protocol::DiagnosticsBundle;
    use ottto_protocol::DiagnosticsUploadAuthorization;
    use ottto_protocol::DiagnosticsUploadStatus;
    use ottto_protocol::HealthProblem;
    use ottto_protocol::InstallOwner;
    use ottto_protocol::LocalAccountBinding;
    use ottto_protocol::LocalAccountState;
    use ottto_protocol::LocalAccountUser;
    use ottto_protocol::LocalDeviceState;
    use ottto_protocol::LocalHealthAccountState;
    use ottto_protocol::LocalHealthAuthority;
    use ottto_protocol::LocalHealthCommandStatus;
    use ottto_protocol::LocalHealthSeverity;
    use ottto_protocol::LocalSetupRunState;
    use ottto_protocol::LocalSetupTokenState;
    use ottto_protocol::MachineIdentity;
    use ottto_protocol::PersonalMeterLocalCollectorStatus;
    use ottto_protocol::PersonalMeterLocalFreshnessStatus;
    use ottto_protocol::PersonalMeterLocalSnapshot;
    use ottto_protocol::PersonalMeterLocalValueStatus;
    use ottto_protocol::RedactedValue;
    use ottto_protocol::RedactionCategory;
    use ottto_protocol::RedactionSurface;
    use ottto_protocol::RepairAction;
    use ottto_protocol::RepairActionApproval;
    use ottto_protocol::RepairActionKind;
    use ottto_protocol::RepairApprovalSurface;
    use ottto_protocol::RepairAuthorityMode;
    use ottto_protocol::SourceHealth;
    use ottto_protocol::SourceKind;
    use ottto_protocol::SourceVerificationResult;
    use ottto_protocol::SourceVerificationStatus;
    use ottto_protocol::StableMessage;
    use ottto_protocol::StableProblemCode;
    use ottto_protocol::PROTOCOL_VERSION;
    use ottto_protocol::{
        AccountBindingState, AgentDiagnosticSeverity, AgentStatusDiagnostic,
        DetectedUseTokenSample, HealthGrade, LocalAccountOrganization, LocalHealthContractFixture,
        LocalHealthOverallState, LocalHealthSourceState, OperatingSystem, SourceConfigState,
        SourceState,
    };
    use serial_test::serial;
    use std::path::Path;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    const TOKEN: &str = "local_control_token";

    #[test]
    fn doctor_connection_binding_finding_requires_reconnect_and_clears_after_repair() {
        if !crate::test_isolation::run_here() {
            return;
        }
        let root = std::env::temp_dir().join(format!("doctor-connection-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _support = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
        let daemon = daemon().with_account(account("synthetic", "synthetic@example.invalid"));
        let finding = |status: DaemonStatus| {
            status
                .canonical_health
                .unwrap()
                .blockers
                .into_iter()
                .find(|b| b.code == "connection_binding_unreadable")
        };
        assert!(finding(daemon.status(TOKEN).unwrap()).is_none());
        for bytes in [b"invalid-json".to_vec(), vec![b' '; 64 * 1024 + 1]] {
            std::fs::write(root.join("connection.json"), bytes).unwrap();
            let status = daemon.status(TOKEN).unwrap();
            assert_eq!(
                status.canonical_health.as_ref().unwrap().overall.state,
                LocalHealthOverallState::Blocked
            );
            let problem = finding(status).expect("doctor must surface stopped uploads");
            assert_eq!(problem.severity, LocalHealthSeverity::Blocking);
            assert!(problem.clear_condition.contains("Connection binding"));
            assert!(problem
                .clear_condition
                .contains("`ottto login --claim-code <code>` to reconnect"));
            assert!(!problem.clear_condition.contains(root.to_str().unwrap()));
        }
        std::fs::remove_file(root.join("connection.json")).unwrap();
        ottto_core::FileConnectionStore::default()
            .save(&ottto_core::LocalConnectionBinding {
                setup_run_id: "synthetic".into(),
                setup_run_token_expires_at: "2099-01-01T00:00:00Z".into(),
                machine_id: None,
                claim_code: None,
                api_base_url: "https://synthetic.invalid".into(),
            })
            .unwrap();
        assert!(finding(daemon.status(TOKEN).unwrap()).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_requires_local_auth() {
        let daemon = daemon();
        assert_eq!(
            daemon.status("wrong-token"),
            Err(LocalApiError::Unauthorized)
        );
        assert!(daemon.status(TOKEN).is_ok());
    }

    #[test]
    fn control_token_refuses_an_equal_length_mismatch() {
        let token = ControlToken::new(TOKEN).unwrap();
        assert_eq!(token.authorize(TOKEN), Ok(()));
        let last = format!("{}X", &TOKEN[..TOKEN.len() - 1]);
        let first = format!("X{}", &TOKEN[1..]);
        for candidate in [last, first] {
            assert_eq!(candidate.len(), TOKEN.len());
            assert_eq!(
                token.authorize(&candidate),
                Err(LocalApiError::Unauthorized)
            );
        }
    }

    #[test]
    fn concurrent_repairs_are_locked() {
        let daemon = daemon();
        let lease = daemon
            .acquire_repair_lock(TOKEN, SourceKind::Codex)
            .expect("first repair should acquire lock");
        assert_eq!(lease.source(), &SourceKind::Codex);

        assert_eq!(
            daemon
                .acquire_repair_lock(TOKEN, SourceKind::ClaudeCode)
                .err(),
            Some(LocalApiError::RepairLocked)
        );

        let status = daemon.status(TOKEN).expect("status should succeed");
        assert_eq!(status.daemon, DaemonRuntimeState::RepairLocked);

        lease.release();
        assert!(daemon
            .acquire_repair_lock(TOKEN, SourceKind::ClaudeCode)
            .is_ok());
    }

    #[test]
    fn connected_repair_plan_limits_terminal_approval_to_setup_safe_actions() {
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(connection("setup_connected")));
        let plan = daemon
            .propose_repair(TOKEN, SourceKind::Codex, false)
            .expect("repair plan should be proposed");

        assert_eq!(
            plan.authority.mode,
            RepairAuthorityMode::ServerBackedSetupAction
        );
        assert!(plan.authority.server_backed);
        assert!(plan.authority.terminal_approval_allowed);
        assert!(plan.authority.browser_approval_required);
        assert_eq!(
            plan.authority.setup_run_id.as_deref(),
            Some("setup_connected")
        );

        let write_config = plan
            .actions
            .iter()
            .find(|action| action.action == RepairActionKind::WriteConfig)
            .expect("write config action");
        assert!(write_config.requires_approval);
        assert_eq!(
            write_config.approval.surface,
            RepairApprovalSurface::Terminal
        );
        assert!(write_config.approval.setup_safe);
        assert!(write_config.approval.server_backed);

        let rotate_secret = plan
            .actions
            .iter()
            .find(|action| action.action == RepairActionKind::RotateSecret)
            .expect("rotate secret action");
        assert_eq!(
            rotate_secret.approval.surface,
            RepairApprovalSurface::Browser
        );
        assert!(!rotate_secret.approval.setup_safe);
        assert!(!rotate_secret.approval.server_backed);

        let verify = plan
            .actions
            .iter()
            .find(|action| action.action == RepairActionKind::VerifyTelemetry)
            .expect("verify action");
        assert_eq!(verify.approval.surface, RepairApprovalSurface::None);
        assert!(verify.approval.setup_safe);
        assert!(verify.approval.server_backed);
    }

    #[test]
    fn disconnected_repair_plan_requires_browser_approval() {
        let daemon = daemon();
        let plan = daemon
            .propose_repair(TOKEN, SourceKind::Codex, false)
            .expect("repair plan should be proposed");

        assert_eq!(
            plan.authority.mode,
            RepairAuthorityMode::BrowserApprovalRequired
        );
        assert!(!plan.authority.server_backed);
        assert!(!plan.authority.terminal_approval_allowed);
        assert!(plan.authority.browser_approval_required);
        assert_eq!(plan.authority.setup_run_id, None);

        let write_config = plan
            .actions
            .iter()
            .find(|action| action.action == RepairActionKind::WriteConfig)
            .expect("write config action");
        assert_eq!(
            write_config.approval.surface,
            RepairApprovalSurface::Browser
        );
        assert!(write_config.approval.setup_safe);
        assert!(!write_config.approval.server_backed);
    }

    #[test]
    fn stale_connected_repair_authority_requires_browser_approval() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let state = daemon.state().expect("state");
        let authority = repair_authority_for_state(&state);

        assert_eq!(authority.mode, RepairAuthorityMode::BrowserApprovalRequired);
        assert!(!authority.server_backed);
        assert!(!authority.terminal_approval_allowed);
        assert!(authority.browser_approval_required);
        assert_eq!(authority.message.code, "setup_run_reconnect_required");

        let approval = setup_safe_repair_approval(&authority);
        assert_eq!(approval.surface, RepairApprovalSurface::Browser);
        assert!(approval.setup_safe);
        assert!(!approval.server_backed);
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn diagnostics_collect_includes_support_only_claude_evidence_health() {
        let support = test_scratch::ScratchDir::new("claude-diagnostics-consumer");
        let _support_guard = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _secret_guard = TestEnvVar::set(
            ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV,
            &support.join("secrets"),
        );
        let _key_guard = TestEnvVar::set(
            keychain::TELEMETRY_KEY_FILE_STORE_ENV,
            &support.join("telemetry-keys"),
        );
        let bundle = daemon().diagnostics_stub(TOKEN).unwrap();
        assert_eq!(
            diagnostic_item(&bundle, "security", "keychain_item_count"),
            Some(&RedactedValue::Number(0))
        );
        assert_eq!(
            diagnostic_item(
                &bundle,
                "claude_local_evidence",
                "complete_capture_authority"
            ),
            Some(&RedactedValue::Bool(false))
        );
        assert_eq!(
            diagnostic_item(&bundle, "claude_local_evidence", "purpose"),
            Some(&RedactedValue::String(
                "bounded_support_inspection_only".into()
            ))
        );
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(!encoded.contains(support.to_str().unwrap()));
        assert!(!bundle.upload.requested);
    }

    #[test]
    #[serial]
    fn diagnostics_stub_does_not_expose_auth() {
        let support = test_scratch::ScratchDir::new("diagnostics-redaction");
        let secrets = support.join("secrets");
        let _support_guard = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
        let _secret_guard = TestEnvVar::set(ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
        let _key_guard = TestEnvVar::set(
            keychain::TELEMETRY_KEY_FILE_STORE_ENV,
            &support.join("telemetry-keys"),
        );
        let synthetic_control_token = "synthetic-diagnostics-control-token";
        let synthetic_relay_secret = "synthetic-diagnostics-relay-secret";
        for (account, value) in [
            (OTTTO_KEYCHAIN_ACCOUNT, synthetic_control_token),
            (OTTTO_RELAY_DEVICE_SECRET_ACCOUNT, synthetic_relay_secret),
        ] {
            // Fully qualified: the trait import above is macOS-only.
            ottto_core::ControlTokenStore::save(
                &ottto_core::token_store::FileControlTokenStore::new(secrets.join(account)),
                value,
            )
            .expect("save synthetic diagnostic secret");
        }
        // A ledger the removed retained-identity path wrote is on disk.
        // Diagnostics and status must exclude its class H grain, including
        // the compact persisted form (one 73-byte proved-row record).
        let retained_hash = "0123456789abcdef".repeat(4);
        let mut ledger = snapshots::claude_request_identity::AcceptedBuckets::for_test();
        ledger.record(&serde_json::json!({
            "source_session_id":"diagnostics-retained",
            "provenance":{"collector":snapshots::claude_request_identity::COLLECTOR},
            "request_evidence":[{"identity_basis":"telemetry_login"}],
            "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z", "model_usage":[{
                "model":"claude-synthetic", "request_count":1, "evidence_ref":0,
                "account_identifier_hash":retained_hash
            }]}]
        }));
        let mut record = vec![0_u8; 40];
        record.push(1);
        record.extend(
            snapshots::claude_request_identity::digest_hex::decode::<serde::de::value::Error>(
                &retained_hash,
            )
            .unwrap(),
        );
        let compact = format!(
            "v2:{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, record)
        );
        let mut ledger_value = serde_json::to_value(&ledger).unwrap();
        for session in ledger_value.as_object_mut().unwrap().values_mut() {
            session["proved"] = serde_json::json!(compact);
        }
        let progress_path =
            support.join("snapshots/destinations/synthetic/claude-upload-progress.json");
        std::fs::create_dir_all(progress_path.parent().unwrap()).unwrap();
        std::fs::write(
            &progress_path,
            serde_json::to_vec(&serde_json::json!({
                "accepted_identity_buckets":ledger_value
            }))
            .unwrap(),
        )
        .unwrap();
        let debug = format!("{ledger:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(&retained_hash));
        // Derived array Debug would leak decimal bytes rather than hex.
        assert!(!debug.contains("[1, 35, 69, 103, 137, 171, 205, 239"));
        let daemon = daemon();
        let bundle = daemon
            .diagnostics_stub(TOKEN)
            .expect("diagnostics should succeed");
        let encoded = serde_json::to_string(&bundle).expect("diagnostics serialize");

        assert_eq!(
            diagnostic_item(&bundle, "security", "keychain_item_count"),
            Some(&RedactedValue::Number(if cfg!(target_os = "macos") {
                2
            } else {
                0
            }))
        );
        assert!(!encoded.contains(synthetic_control_token));
        assert!(!encoded.contains(synthetic_relay_secret));
        assert!(!encoded.contains(&retained_hash));
        assert!(!encoded.contains(&compact));
        let status = serde_json::to_string(&daemon.status(TOKEN).unwrap()).unwrap();
        assert!(!status.contains(&retained_hash));
        assert!(!status.contains(&compact));
        assert!(!encoded.contains(support.to_str().unwrap()));
        assert_eq!(
            diagnostic_item(&bundle, "security", "auth_header"),
            Some(&RedactedValue::String("[REDACTED]".to_string()))
        );
        assert_eq!(
            diagnostic_item(&bundle, "installation", "launch_agent_path"),
            Some(&RedactedValue::String("[path]".to_string()))
        );
        assert!(!bundle.upload.requested);
        assert_eq!(bundle.upload.status, DiagnosticsUploadStatus::LocalOnly);
        assert_eq!(
            bundle.upload.authorization,
            DiagnosticsUploadAuthorization::NotRequested
        );
        assert!(!bundle.upload.retention.accepted);
        assert!(bundle.upload.retention.text.contains("30 days"));
        assert_eq!(bundle.redaction.policy_version, 1);
        assert!(bundle
            .redaction
            .covered_surfaces
            .contains(&RedactionSurface::Diagnostics));
        assert!(bundle
            .redaction
            .covered_surfaces
            .contains(&RedactionSurface::SupportOutput));
        assert!(bundle
            .redaction
            .covered_surfaces
            .contains(&RedactionSurface::SetupError));
        assert!(bundle
            .redaction
            .redacted_categories
            .contains(&RedactionCategory::LocalPath));
        assert!(bundle
            .redaction
            .redacted_categories
            .contains(&RedactionCategory::SecretToken));
        assert!(bundle
            .redaction
            .redacted_categories
            .contains(&RedactionCategory::AccountIdentifier));
        assert!(bundle
            .redaction
            .redacted_categories
            .contains(&RedactionCategory::MachineIdentifier));
        assert!(bundle
            .redaction
            .redacted_categories
            .contains(&RedactionCategory::RawPrompt));
        assert!(bundle
            .redaction
            .redacted_fields
            .contains(&"installation.launch_agent_path".to_string()));
        assert!(bundle
            .redaction
            .redacted_fields
            .contains(&"security.auth_header".to_string()));
        assert!(!encoded.contains(TOKEN));
        assert!(!encoded.contains("/Users/"));
    }

    #[test]
    fn pending_auth_claim_for_resume_uses_daemon_stored_nonce() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");

        let resumed = daemon
            .pending_auth_claim_for_resume("claim_one")
            .expect("resume pending auth");
        assert_eq!(resumed.claim_code, "claim_one");
        assert_eq!(resumed.nonce, "nonce_one");
        assert!(matches!(
            daemon.pending_auth_claim_for_resume("claim_two"),
            Err(LocalApiError::AuthClaimMismatch)
        ));
    }

    #[test]
    fn completed_auth_claim_for_resume_requires_matching_claim_code() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete auth");

        let resumed = daemon
            .completed_auth_claim_for_resume("claim_one")
            .expect("resume completed auth")
            .expect("matching claim should be resumable");
        assert_eq!(resumed.setup_run_id, "setup_1");
        assert_eq!(
            daemon
                .completed_auth_claim_for_resume("claim_two")
                .expect("mismatch lookup"),
            None
        );
    }

    #[test]
    fn connected_account_can_refresh_same_user() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");
        assert_eq!(
            daemon
                .connection_for_authorized_client()
                .expect("connection")
                .as_ref()
                .map(|connection| connection.setup_run_id.as_str()),
            Some("setup_1")
        );

        let pending = daemon
            .begin_auth_with_claim(pending_claim("claim_two", "nonce_two"))
            .expect("start refresh auth");
        assert_eq!(pending.account.state, LocalAccountState::ClaimPending);
        assert_eq!(
            pending.account.user.as_ref().map(|user| user.id.as_str()),
            Some("user_1")
        );

        let refreshed = daemon
            .complete_auth_with_account(
                "claim_two",
                "nonce_two",
                account("user_1", "ron+fresh@example.com"),
                "setup_2".to_string(),
                "2026-05-05T10:20:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("refresh same user");
        assert_eq!(
            refreshed
                .account
                .user
                .as_ref()
                .map(|user| user.email.as_str()),
            Some("ron+fresh@example.com")
        );
        assert_eq!(
            daemon
                .connection_for_authorized_client()
                .expect("connection")
                .as_ref()
                .map(|connection| connection.setup_run_id.as_str()),
            Some("setup_2")
        );
    }

    #[test]
    fn connection_binding_is_rehydrated_from_store_after_restart() {
        let daemon = daemon();
        let connection = LocalConnectionBinding {
            setup_run_id: "setup_persisted".to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        };

        let rehydrated = daemon
            .connection_for_authorized_client_with(|| Ok(Some(connection.clone())))
            .expect("connection fallback should load");

        assert_eq!(rehydrated, Some(connection.clone()));
        assert_eq!(
            daemon
                .connection_for_authorized_client_with(|| {
                    panic!("connection should be cached after first load")
                })
                .expect("cached connection"),
            Some(connection)
        );
    }

    #[test]
    fn reset_clears_connection_binding() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete auth");
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");

        daemon
            .reset_account_for_trusted_client()
            .expect("reset account");
        assert_eq!(
            daemon
                .connection_for_authorized_client_with(|| Ok(None))
                .expect("connection cleared"),
            None
        );
        assert!(daemon.status(TOKEN).expect("status").sources.is_empty());
    }

    #[test]
    fn auth_claim_preserves_existing_source_health() {
        let daemon = daemon();
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");

        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.account.state, LocalAccountState::ClaimPending);
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
    }

    #[test]
    fn rebuild_loop_pause_is_a_server_visible_canonical_source_blocker() {
        use snapshots::{ScanIndex, SnapshotSource};
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut sibling = codex_health();
        sibling.source = SourceKind::Pi;
        sibling.descriptor = source_descriptor(&SourceKind::Pi);
        daemon
            .update_sources(TOKEN, vec![codex_health(), sibling])
            .unwrap();
        let scratch = crate::test_scratch::ScratchDir::new("rebuild-loop-source-health");
        let path = scratch.as_ref().join("index.json");
        snapshots::e2_pipeline_scan_fixture::bind_source_for_test(&path, SnapshotSource::Codex);
        snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, b"{");
        let (_, origin) = snapshots::e2_pipeline_scan_fixture::load_source_for_test(
            &path,
            SnapshotSource::Codex,
            scratch.as_ref(),
        )
        .unwrap();
        assert_eq!(origin, snapshots::ScanIndexLoadOrigin::Loaded);
        let original = b"{ ";
        snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(&path, original);
        let error = ScanIndex::load_for_snapshot_source_with_origin(
            &path,
            SnapshotSource::Codex,
            scratch.as_ref(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("scan_index_rebuild_loop"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let status = daemon.status(TOKEN).unwrap();
        let health = status.canonical_health.unwrap();
        let source = health
            .sources
            .iter()
            .find(|s| s.app == SourceKind::Codex)
            .unwrap();
        assert_eq!(source.state, LocalHealthSourceState::RepairRequired);
        assert_eq!(
            source.blocking_reason.as_deref(),
            Some("scan_index_rebuild_loop")
        );
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
        assert!(source
            .clear_condition
            .as_deref()
            .unwrap()
            .contains("never delete the index"));
        // The automatic retry time rides in the existing clear_condition:
        // 24 hours after the quarantine witness this pause read.
        let retry_at = source
            .clear_condition
            .as_deref()
            .unwrap()
            .split_once("auto_retry_at=")
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(at, _)| at)
            .expect("clear_condition names auto_retry_at");
        let retry_at =
            time::OffsetDateTime::parse(retry_at, &time::format_description::well_known::Rfc3339)
                .unwrap();
        let day_out = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        assert!((retry_at - day_out).abs() < time::Duration::minutes(5));
        assert!(health
            .blockers
            .iter()
            .any(|b| b.code == "scan_index_rebuild_loop"
                && b.clear_condition.contains("auto_retry_at=")));
        assert_eq!(
            health
                .sources
                .iter()
                .find(|s| s.app == SourceKind::Pi)
                .unwrap()
                .state,
            LocalHealthSourceState::Healthy
        );
        assert!(health
            .blockers
            .iter()
            .any(|b| b.code == "scan_index_rebuild_loop"
                && b.severity == LocalHealthSeverity::Blocking));
        assert_ne!(health.overall.state, LocalHealthOverallState::Healthy);
        // This is the same typed payload upload_local_health_projection posts.
        let wire = serde_json::to_value(&health).unwrap();
        assert!(wire["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["blocking_reason"] == "scan_index_rebuild_loop"));
        assert!(wire["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["code"] == "scan_index_rebuild_loop"));

        // Reviewed repair restores a compatible index; the next actual load
        // clears only this source's runtime pause without a daemon restart.
        std::fs::write(&path, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
        let (_, origin) = snapshots::e2_pipeline_scan_fixture::load_source_for_test(
            &path,
            SnapshotSource::Codex,
            scratch.as_ref(),
        )
        .unwrap();
        assert_eq!(origin, snapshots::ScanIndexLoadOrigin::Loaded);
        let health = daemon.status(TOKEN).unwrap().canonical_health.unwrap();
        assert!(!health
            .blockers
            .iter()
            .any(|b| b.code == "scan_index_rebuild_loop"));
        assert_eq!(
            health
                .sources
                .iter()
                .find(|s| s.app == SourceKind::Codex)
                .unwrap()
                .state,
            LocalHealthSourceState::Healthy
        );
    }

    #[test]
    fn failed_verification_uses_fresh_attempt_time() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));

        daemon
            .record_verification_result(&failed_codex_reconnect())
            .expect("record failed verification");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].state, SourceState::Failed);
        let last_verified_at = status.sources[0]
            .last_verified_at
            .as_deref()
            .expect("failed verify attempts still stamp an attempt time");
        assert_ne!(last_verified_at, "2026-05-05T10:15:00Z");
        assert_ne!(last_verified_at, "2026-05-05T09:10:00Z");

        let command = status
            .command_ledger
            .iter()
            .find(|entry| entry.action_id == "verify_codex")
            .expect("verify command ledger entry");
        assert_eq!(command.observed_at, last_verified_at);
        assert_ne!(command.observed_at, "2026-05-05T10:15:00Z");

        let event = status
            .local_health_events
            .iter()
            .find(|entry| entry.event_id.starts_with("evt_verify_codex_"))
            .expect("verify event");
        assert_eq!(event.observed_at, last_verified_at);

        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Codex)
            .expect("canonical Codex source");
        assert_eq!(source.state, LocalHealthSourceState::VerifyFailed);
        assert_eq!(source.authority_at, last_verified_at);
    }

    /// [regress] Healthy refreshes must not discard a passing Verify's timestamp.
    #[test]
    fn successful_verification_time_survives_healthy_refreshes() {
        const PASSED_AT: &str = "2026-05-05T10:20:00Z";
        for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
            for fail_first in [false, true] {
                let daemon = daemon().with_account(account("user_1", "test@example.com"));
                if fail_first {
                    let mut failed = failed_codex_reconnect();
                    failed.source = source.clone();
                    daemon.record_verification_result(&failed).unwrap();
                }
                let mut passed = verified_codex(PASSED_AT);
                passed.source = source.clone();
                daemon.record_verification_result(&passed).unwrap();
                assert_eq!(
                    daemon.status(TOKEN).unwrap().sources[0]
                        .last_verified_at
                        .as_deref(),
                    Some(PASSED_AT)
                );

                for refreshed_at in ["2026-05-05T10:30:00Z", "2026-05-05T10:40:00Z"] {
                    {
                        let mut state = daemon.inner.lock().unwrap();
                        upsert_agent_status_snapshot(
                            &mut state,
                            available_agent_status(source.clone(), refreshed_at),
                        );
                    }
                    let status = daemon.status(TOKEN).unwrap();
                    let health = &status.sources[0];
                    assert_eq!(health.state, SourceState::Healthy);
                    assert_eq!(health.last_verified_at.as_deref(), Some(PASSED_AT));
                    assert!(health.problems.is_empty());
                    let canonical = status.canonical_health.unwrap();
                    let projected = canonical
                        .sources
                        .iter()
                        .find(|row| row.app == source)
                        .unwrap();
                    assert_eq!(projected.authority, LocalHealthAuthority::Runtime);
                    assert_eq!(projected.authority_at, refreshed_at);
                }

                // A later runtime failure is not a new verification witness.
                {
                    let mut state = daemon.inner.lock().unwrap();
                    let mut snapshot =
                        available_agent_status(source.clone(), "2026-05-05T10:50:00Z");
                    snapshot.status = AgentStatusState::Error;
                    upsert_agent_status_snapshot(&mut state, snapshot);
                }
                let status = daemon.status(TOKEN).unwrap();
                assert_eq!(status.sources[0].state, SourceState::Failed);
                assert!(status.sources[0].last_verified_at.is_none());
                {
                    let mut state = daemon.inner.lock().unwrap();
                    upsert_agent_status_snapshot(
                        &mut state,
                        available_agent_status(source.clone(), "2026-05-05T11:00:00Z"),
                    );
                }
                assert_eq!(
                    daemon.status(TOKEN).unwrap().sources[0].state,
                    SourceState::Healthy
                );
            }
        }
    }

    #[test]
    fn source_update_preserves_config_drift_verification_failure() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");

        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:drifted".to_string()),
                drift: vec![ottto_protocol::ConfigDrift {
                    key: "otel.logs_endpoint".to_string(),
                    expected: RedactedValue::String("http://127.0.0.1:43119/v1/logs".to_string()),
                    observed: RedactedValue::String("http://127.0.0.1:44621/v1/logs".to_string()),
                }],
            },
            status: SourceVerificationStatus::Failed,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "config_drift".to_string(),
                text: "Codex telemetry config does not match the active Ottto relay.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record config drift verification");
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("fresh source scan should not clear verification failure");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::NeedsRepair);
        assert_eq!(status.sources[0].grade, HealthGrade::Warning);
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::ConfigDrift
        );
        assert_eq!(
            status.sources[0].recommended_actions[0].action,
            RepairActionKind::WriteConfig
        );
        assert_eq!(status.sources[0].config.drift.len(), 1);
        let health = status
            .canonical_health
            .as_ref()
            .expect("canonical health should be projected");
        assert_eq!(health.overall.state, LocalHealthOverallState::Blocked);
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("config_drift")
        );
        assert_eq!(
            health.sources[0].state,
            LocalHealthSourceState::RepairRequired
        );
        assert_eq!(
            health.sources[0].authority,
            LocalHealthAuthority::Verify,
            "current verify failure must outrank an older green source scan"
        );
        assert!(status
            .local_health_events
            .iter()
            .any(|event| event.event_type == "VerifyFailed"));
    }

    #[test]
    fn not_installed_source_does_not_degrade_overall_health() {
        // A Mac that simply does not have an agent installed is a legitimate,
        // healthy configuration: healthy verified sources plus one
        // not-installed source must project overall Healthy, not a perpetual
        // Degraded / finish_source_setup machine banner.
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));

        for source in [SourceKind::Codex, SourceKind::Pi] {
            let verified = SourceVerificationResult {
                source: source.clone(),
                config: SourceConfigState {
                    discovered: true,
                    path_hint: None,
                    fingerprint: Some("sha256:test".to_string()),
                    drift: Vec::new(),
                },
                status: SourceVerificationStatus::Verified,
                verified: true,
                records_seen: 2,
                last_record_id: Some("record_2".to_string()),
                last_received_at: Some("2026-05-05T10:15:00Z".to_string()),
                smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
                message: StableMessage {
                    code: "verified".to_string(),
                    text: "Verification passed.".to_string(),
                },
                route_results: Vec::new(),
                check: None,
            };
            daemon
                .record_verification_result(&verified)
                .expect("record verified result");
        }

        let not_installed = SourceVerificationResult {
            source: SourceKind::ClaudeCode,
            config: SourceConfigState {
                discovered: false,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Warning,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: None,
            message: StableMessage {
                code: SOURCE_NOT_INSTALLED_VERIFICATION_CODE.to_string(),
                text: "Claude Code is not installed on this Mac, so there is nothing to verify."
                    .to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };
        daemon
            .record_verification_result(&not_installed)
            .expect("record not-installed verification");

        let status = daemon.status(TOKEN).expect("status");
        let health = status
            .canonical_health
            .as_ref()
            .expect("canonical health should be projected");
        let claude = health
            .sources
            .iter()
            .find(|source| source.app == SourceKind::ClaudeCode)
            .expect("not-installed source stays listed in sources");
        assert_eq!(
            claude.state,
            LocalHealthSourceState::PendingSetup,
            "presentation state is unchanged; serving layers decide rendering"
        );
        assert_eq!(
            claude.blocking_reason.as_deref(),
            Some("source_not_installed")
        );
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::Healthy,
            "a not-installed source must not degrade the machine"
        );
        assert_eq!(health.overall.next_action, None);
    }

    #[test]
    fn cli_unavailable_verify_projects_visible_soft_warning_not_blocking() {
        // Desktop-app-only install: data/config present, CLI binary not
        // executable. The source must stay VISIBLE (unlike source_not_installed,
        // which serving layers suppress) as a soft warning, and must never
        // produce a blocking verify_failed or degrade the machine.
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));

        let cli_unavailable = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Warning,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: None,
            message: StableMessage {
                code: AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE.to_string(),
                text: "Ottto keeps syncing Codex activity from this Mac's local session data, but couldn't find the `codex` command-line tool to run a live check."
                    .to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };
        daemon
            .record_verification_result(&cli_unavailable)
            .expect("record cli-unavailable verification");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources[0].state, SourceState::NeedsConfirmation);
        assert_eq!(status.sources[0].grade, HealthGrade::Warning);
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::AgentCliUnavailable,
        );

        let health = status
            .canonical_health
            .as_ref()
            .expect("canonical health should be projected");
        let codex = health
            .sources
            .iter()
            .find(|source| source.app == SourceKind::Codex)
            .expect("cli-unavailable source stays listed in sources");
        assert_eq!(
            codex.state,
            LocalHealthSourceState::PendingSetup,
            "soft state, never verify_failed"
        );
        assert_eq!(
            codex.blocking_reason.as_deref(),
            Some("agent_cli_unavailable")
        );
        assert_ne!(
            health.overall.state,
            LocalHealthOverallState::Blocked,
            "a missing CLI for a data-present source must not block"
        );
        assert!(
            health
                .blockers
                .iter()
                .all(|blocker| blocker.owner != "source"),
            "no blocking source problem when only the CLI is unavailable"
        );
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::Healthy,
            "a cli-unavailable source must not degrade the machine"
        );
    }

    #[test]
    fn canonical_health_warns_for_recent_legacy_requests_without_port_text() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        for (now, recent) in [(1000, true), (4599, true), (4600, false)] {
            otlp_relay::legacy::with_recent_request_for_test(1000, now, || {
                let status = daemon.status(TOKEN).expect("status");
                let health = status.canonical_health.expect("canonical health");
                let finding = health
                    .blockers
                    .iter()
                    .find(|blocker| blocker.code == otlp_relay::legacy::STALE_EXPORTER_CODE);
                assert_eq!(finding.is_some(), recent);
                if recent {
                    let finding = finding.unwrap();
                    assert_eq!(finding.severity, LocalHealthSeverity::Warning);
                    assert_eq!(finding.owner, "source");
                    assert_eq!(finding.source, "runtime");
                    assert_eq!(finding.clear_condition, "Some Claude Code sessions still send telemetry to an older Ottto port; restart those Claude Code sessions.");
                    assert!(!finding.clear_condition.chars().any(|c| c.is_ascii_digit()));
                }
            });
        }
    }

    /// [regress] A standing blocker reported the read time as `since`, so
    /// every status read showed it as new.
    #[test]
    fn standing_blocker_keeps_first_seen_since_until_it_clears() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let stale_since = |status: &DaemonStatus| {
            status
                .canonical_health
                .as_ref()
                .expect("canonical health")
                .blockers
                .iter()
                .find(|blocker| blocker.code == otlp_relay::legacy::STALE_EXPORTER_CODE)
                .map(|blocker| blocker.since.clone())
        };
        let read = |now| {
            std::thread::sleep(std::time::Duration::from_millis(2));
            otlp_relay::legacy::with_recent_request_for_test(1000, now, || {
                let mut status = daemon.status(TOKEN).expect("status");
                let since = stale_since(&status);
                // A re-projection of the same status keeps it too.
                refresh_canonical_local_health(&mut status);
                assert_eq!(stale_since(&status), since);
                (since, status.generated_at)
            })
        };
        let (first, first_read) = read(1000);
        assert_eq!(first.as_deref(), Some(first_read.as_str()));
        let (second, second_read) = read(1001);
        assert_ne!(second_read, first_read);
        assert_eq!(second, first);
        assert_eq!(read(4600).0, None);
        let (again, again_read) = read(1002);
        assert_eq!(again.as_deref(), Some(again_read.as_str()));
        assert_ne!(again, first);
    }

    #[test]
    fn canonical_health_marks_protocol_mismatch_upgrade_required() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut status = daemon.status(TOKEN).expect("status");
        status.protocol_version = PROTOCOL_VERSION - 1;
        refresh_canonical_local_health(&mut status);

        let health = status.canonical_health.expect("canonical health");
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::UpgradeRequired
        );
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("protocol_mismatch")
        );
        assert!(!health.runtime.protocol_match);
    }

    #[test]
    fn canonical_health_marks_owner_drift_blocked() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut status = daemon.status(TOKEN).expect("status");
        status.service_owner.daemon_owner = InstallOwner::Homebrew;
        status.service_owner.client_owner = InstallOwner::AppBundle;
        status.service_owner.owner_drift = true;
        refresh_canonical_local_health(&mut status);

        let health = status.canonical_health.expect("canonical health");
        assert_eq!(health.overall.state, LocalHealthOverallState::Blocked);
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("owner_conflict")
        );
        assert!(health
            .blockers
            .iter()
            .any(|blocker| blocker.code == "owner_conflict"));
        assert!(health.runtime.version_match);
    }

    #[test]
    fn runtime_identity_uses_platform_version_not_internal_crate_version() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut status = daemon.status(TOKEN).expect("status");
        status.daemon_version = "0.1.0".to_string();
        status.machine.local_platform_version = "0.1.30-rc1".to_string();
        status.service_owner.daemon_owner = InstallOwner::AppBundle;

        let runtime = runtime_identity_for_status_with_installed_app_version(
            &status,
            "2026-06-15T07:00:00Z",
            "2026-06-15T08:00:00Z",
            "0.1.30-rc1",
        );

        assert_eq!(runtime.daemon_version, "0.1.30-rc1");
        assert_eq!(runtime.service_version.as_deref(), Some("0.1.30-rc1"));
        assert_eq!(runtime.app_bundle_version.as_deref(), Some("0.1.30-rc1"));
        assert!(runtime.version_match);
    }

    #[test]
    fn uploaded_runtime_identity_and_heartbeat_carry_no_executable_path_or_pid() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut status = daemon.status(TOKEN).expect("status");
        status.service_owner.daemon_owner = InstallOwner::AppBundle;

        let runtime = runtime_identity_for_status_with_installed_app_version(
            &status,
            "2026-06-15T07:00:00Z",
            "2026-06-15T08:00:00Z",
            "0.1.30-rc1",
        );
        let heartbeat = runtime_heartbeat_for_status(&status, &runtime, 7);

        assert_eq!(runtime.service_executable_path, None);
        assert_eq!(runtime.service_pid, None);
        assert_eq!(runtime.service_executable_path_class, "app_bundle_helper");
        assert_eq!(heartbeat.executable_path, "app_bundle_helper");

        let runtime_json = serde_json::to_value(&runtime).expect("runtime json");
        assert!(runtime_json.get("service_executable_path").is_none());
        assert!(runtime_json.get("service_pid").is_none());
        let exe = std::env::current_exe().expect("test executable");
        let exe = exe.display().to_string();
        for json in [
            runtime_json.to_string(),
            serde_json::to_string(&heartbeat).expect("heartbeat json"),
        ] {
            assert!(
                !json.contains(&exe),
                "uploaded JSON carries the executable path"
            );
            assert!(
                !json.contains("\"/Users/"),
                "uploaded JSON carries a home path"
            );
        }
    }

    #[test]
    fn runtime_identity_still_blocks_old_app_bundle_service() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut status = daemon.status(TOKEN).expect("status");
        status.daemon_version = "0.1.0".to_string();
        status.machine.local_platform_version = "0.1.28".to_string();
        status.service_owner.daemon_owner = InstallOwner::AppBundle;

        let runtime = runtime_identity_for_status_with_installed_app_version(
            &status,
            "2026-06-15T07:00:00Z",
            "2026-06-15T08:00:00Z",
            "0.1.30-rc1",
        );

        assert_eq!(runtime.daemon_version, "0.1.28");
        assert_eq!(runtime.app_bundle_version.as_deref(), Some("0.1.30-rc1"));
        assert!(!runtime.version_match);
    }

    #[test]
    fn relay_token_auth_failure_marks_canonical_health_reconnect_required() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));

        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");

        let health = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(
            health.account.state,
            LocalHealthAccountState::ReconnectRequired
        );
        assert_eq!(health.account.device_state, LocalDeviceState::Inactive);
        assert_eq!(
            health.account.setup_run_state,
            LocalSetupRunState::RebindRequired
        );
        assert_eq!(
            health.account.setup_token_state,
            LocalSetupTokenState::RefreshRequired
        );
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::ReconnectRequired
        );
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("auth_missing")
        );
        assert!(health
            .blockers
            .iter()
            .any(|blocker| blocker.code == "auth_missing"));
    }

    #[test]
    fn auth_rejected_status_shows_effective_reconnect_without_changing_saved_binding() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let saved = daemon.status(TOKEN).expect("status").account;
        assert_eq!(saved.state, LocalAccountState::Connected);
        assert_eq!(
            effective_account_binding(&daemon.status(TOKEN).expect("status")),
            saved
        );

        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");
        let status = daemon.status(TOKEN).expect("status");
        // Internal account gates still read the saved binding.
        assert_eq!(status.account, saved);

        let effective = effective_account_binding(&status);
        assert_eq!(effective.state, LocalAccountState::Error);
        let message = effective.message.as_ref().expect("reconnect message");
        assert_eq!(message.code, ACCOUNT_RECONNECT_REQUIRED_MESSAGE_CODE);
        assert!(message.text.contains("Sign in to Ottto again"));
        assert_eq!(effective.user, saved.user);
        assert_eq!(effective.organization, saved.organization);
        assert_eq!(effective.connected_at, saved.connected_at);
        assert_eq!(effective.can_reconnect, saved.can_reconnect);
        // Nothing was written back to the saved binding.
        assert_eq!(daemon.account_for_trusted_client().expect("account"), saved);

        // A later accepted upload clears it; the old rejection does not latch.
        daemon
            .record_local_health_upload_succeeded()
            .expect("record upload success");
        assert_eq!(
            effective_account_binding(&daemon.status(TOKEN).expect("status")),
            saved
        );
    }

    #[test]
    fn fresh_claim_is_not_rewritten_by_an_older_auth_rejection() {
        let daemon = daemon();
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");

        let status = daemon.status(TOKEN).expect("status");
        let effective = effective_account_binding(&status);
        assert_eq!(effective.state, LocalAccountState::ClaimPending);
        assert_eq!(effective, status.account);
    }

    #[test]
    fn completed_sign_in_supersedes_an_older_upload_auth_rejection() {
        // Observed 2026-11-04: the Mac's account was deleted, its local-health
        // uploads were rejected, then `ottto login` bound a new account. Status
        // kept answering reconnect_required (and the app kept "Reconnect this
        // Mac") until the next local-health upload, minutes later.
        let daemon = daemon().with_account(account("user_1", "old@example.com"));
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");
        daemon.mark_account_not_found().expect("account gone");
        daemon
            .begin_auth_with_claim(pending_claim("claim_new", "nonce_new"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_new",
                "nonce_new",
                account("user_2", "new@example.com"),
                "setup_new".to_string(),
                "2026-11-04T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete auth");

        let status = daemon.status(TOKEN).expect("status");
        let health = status.canonical_health.as_ref().expect("canonical health");
        assert_eq!(health.account.state, LocalHealthAccountState::Connected);
        assert_eq!(health.account.device_state, LocalDeviceState::Active);
        assert_eq!(health.account.setup_run_state, LocalSetupRunState::Complete);
        assert_eq!(
            health.account.setup_token_state,
            LocalSetupTokenState::Valid
        );
        assert!(!health
            .blockers
            .iter()
            .any(|blocker| blocker.code == "auth_missing"));
        assert_eq!(
            effective_account_binding(&status).state,
            LocalAccountState::Connected
        );
        assert!(!daemon
            .connected_setup_run_needs_reconnect()
            .expect("needs reconnect"));

        // The new credentials are checked again by the next upload: a fresh
        // rejection still trips the reconnect.
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record second upload failure");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(
            status
                .canonical_health
                .expect("canonical health")
                .account
                .state,
            LocalHealthAccountState::ReconnectRequired
        );
    }

    #[test]
    fn confirmed_account_switch_supersedes_an_older_upload_auth_rejection() {
        let daemon = daemon().with_account(account("user_1", "old@example.com"));
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");
        daemon
            .install_switched_account(
                account("user_2", "new@example.com"),
                "setup_new".to_string(),
                "2026-11-04T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
                "claim_new",
            )
            .expect("install switched account");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(
            status
                .canonical_health
                .expect("canonical health")
                .account
                .state,
            LocalHealthAccountState::Connected
        );
    }

    #[test]
    fn auth_rejected_upload_prevents_healthy_source_projection() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .record_verification_result(&verified_codex("2026-05-05T10:20:00Z"))
            .expect("record successful verification");
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources[0].state, SourceState::Healthy);

        let health = status.canonical_health.expect("canonical health");
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::ReconnectRequired
        );
        assert_eq!(
            health.sources[0].state,
            LocalHealthSourceState::Unknown,
            "source projection must not stay healthy while the account/device prerequisite is blocking"
        );
        assert_eq!(
            health.sources[0].blocking_reason.as_deref(),
            Some("auth_missing")
        );
        assert_eq!(health.sources[0].next_action.as_deref(), Some("sign_in"));
    }

    fn read_start(daemon: &LocalDaemon) -> SetupRunReadStart {
        daemon
            .setup_run_read_start()
            .expect("read start")
            .expect("bound setup run")
    }

    fn read_binding(setup_run_id: &str) -> LocalConnectionBinding {
        LocalConnectionBinding {
            setup_run_id: setup_run_id.to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: None,
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        }
    }

    #[test]
    fn rejected_setup_run_read_reports_run_honestly_without_blocking_uploads() {
        let run = read_binding("run_1");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(run.clone()));
        daemon
            .record_verification_result(&verified_codex("2026-05-05T10:20:00Z"))
            .expect("record successful verification");
        daemon
            .record_setup_run_read_accepted(&read_start(&daemon))
            .expect("accepted read without a prior rejection");
        assert!(latest_setup_run_read_rejection(
            &daemon.status(TOKEN).expect("status").local_health_events
        )
        .is_none());

        daemon
            .record_setup_run_ended(&run)
            .expect("record rejected read");
        daemon
            .record_setup_run_ended(&run)
            .expect("record repeated rejected read");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(
            status
                .local_health_events
                .iter()
                .filter(|event| event.event_type.starts_with("SetupRunRead"))
                .count(),
            1,
            "repeated rejected reads must not grow the event log"
        );
        let health = status.canonical_health.expect("canonical health");
        assert_eq!(health.account.state, LocalHealthAccountState::Connected);
        assert_eq!(health.account.setup_run_state, LocalSetupRunState::Rejected);
        assert_eq!(
            health.account.setup_token_state,
            LocalSetupTokenState::Expired
        );
        assert_eq!(health.account.device_state, LocalDeviceState::Active);
        let blocker = health
            .blockers
            .iter()
            .find(|blocker| blocker.code == "setup_run_rejected")
            .expect("setup run rejection is surfaced");
        assert_eq!(blocker.severity, LocalHealthSeverity::Warning);
        assert_eq!(
            health.sources[0].state,
            LocalHealthSourceState::Healthy,
            "uploads use the device credential, so a rejected read must not untrust sources"
        );

        daemon
            .record_setup_run_read_accepted(&read_start(&daemon))
            .expect("record recovered read");
        let recovered = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(
            recovered.account.setup_run_state,
            LocalSetupRunState::Complete
        );
        assert_eq!(
            recovered.account.setup_token_state,
            LocalSetupTokenState::Valid
        );
        assert!(!recovered
            .blockers
            .iter()
            .any(|blocker| blocker.code == "setup_run_rejected"));
    }

    /// Settle a device-credential answer for the active credential, as the
    /// idle check does after its request.
    fn settle_device(daemon: &LocalDaemon, refused: bool) -> bool {
        let start = daemon
            .start_credential_observation(crate::control::device_credential_epoch(), None)
            .expect("start");
        daemon.settle_device_credential_answer(&start, refused)
    }

    fn health(daemon: &LocalDaemon) -> ottto_protocol::LocalMachineHealthV1 {
        daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health")
    }

    fn has_blocker(health: &ottto_protocol::LocalMachineHealthV1, code: &str) -> bool {
        health.blockers.iter().any(|blocker| blocker.code == code)
    }

    #[test]
    #[serial]
    fn a_refused_device_credential_reads_reconnect_required_and_never_expired() {
        let run = read_binding("run_1");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(run.clone()));
        // A fresh daemon (or one just restarted) knows nothing about the
        // credential: it shows the saved state.
        assert_eq!(
            health(&daemon).account.state,
            LocalHealthAccountState::Connected
        );
        assert!(settle_device(&daemon, true));
        let device_rejected = health(&daemon);
        // Nothing this Mac sends is accepted any more, so the account reads
        // reconnect-required, as after a rejected local-health upload.
        assert_eq!(
            device_rejected.account.state,
            LocalHealthAccountState::ReconnectRequired
        );
        let effective = effective_account_binding(&daemon.status(TOKEN).expect("status"));
        assert_eq!(effective.state, LocalAccountState::Error);
        assert_eq!(
            effective.message.map(|message| message.code).as_deref(),
            Some("reconnect_required")
        );
        assert_eq!(
            device_rejected.account.setup_run_state,
            LocalSetupRunState::Unknown
        );
        assert_eq!(
            device_rejected.account.setup_token_state,
            LocalSetupTokenState::RefreshRequired
        );
        assert_eq!(
            device_rejected.account.device_state,
            LocalDeviceState::Inactive
        );
        assert!(has_blocker(&device_rejected, "device_credential_rejected"));
        assert!(!has_blocker(&device_rejected, "setup_run_rejected"));
        let reported =
            serde_json::to_string(&(&device_rejected.account, &device_rejected.blockers))
                .expect("serialize health");
        assert!(
            !reported.to_ascii_lowercase().contains("expired"),
            "{reported}"
        );
        assert!(daemon
            .connected_setup_run_needs_reconnect()
            .expect("needs reconnect"));
        assert_eq!(
            daemon.status(TOKEN).expect("status").account.state,
            LocalAccountState::Connected,
            "the saved binding is unchanged; only the reported account changes"
        );

        // An ended run is a separate fact: kept as a Warning under the
        // refusal, and shown alone once Ottto accepts the device again.
        daemon
            .record_setup_run_ended(&run)
            .expect("record ended run");
        let both = health(&daemon);
        assert_eq!(
            both.account.state,
            LocalHealthAccountState::ReconnectRequired
        );
        assert!(has_blocker(&both, "device_credential_rejected"));
        assert!(has_blocker(&both, "setup_run_rejected"));
        assert!(settle_device(&daemon, false));
        let ended = health(&daemon);
        assert_eq!(ended.account.state, LocalHealthAccountState::Connected);
        assert_eq!(ended.account.setup_run_state, LocalSetupRunState::Rejected);
        assert_eq!(
            ended.account.setup_token_state,
            LocalSetupTokenState::Expired
        );
        assert!(!has_blocker(&ended, "device_credential_rejected"));
        assert!(has_blocker(&ended, "setup_run_rejected"));
    }

    #[test]
    #[serial]
    fn device_answers_apply_in_the_order_their_requests_started() {
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(read_binding("run_1")));
        let start = |daemon: &LocalDaemon| {
            daemon
                .start_credential_observation(crate::control::device_credential_epoch(), None)
                .expect("start")
        };
        let refused = |daemon: &LocalDaemon| {
            latest_device_credential_refusal(
                &daemon.status(TOKEN).expect("status").local_health_events,
            )
            .is_some()
        };
        assert!(daemon
            .status(TOKEN)
            .expect("status")
            .local_health_events
            .is_empty());

        // A delayed usable answer loses to a newer refusal of the same kind
        // as the one already shown: the newer answer still moves the order.
        assert!(settle_device(&daemon, true));
        let delayed_usable = start(&daemon);
        let newer_refusal = start(&daemon);
        assert!(daemon.settle_device_credential_answer(&newer_refusal, true));
        assert!(!daemon.settle_device_credential_answer(&delayed_usable, false));
        assert!(refused(&daemon));

        // A delayed refusal loses to a newer usable answer.
        let delayed_refusal = start(&daemon);
        let newer_usable = start(&daemon);
        assert!(daemon.settle_device_credential_answer(&newer_usable, false));
        assert!(!daemon.settle_device_credential_answer(&delayed_refusal, true));
        assert!(!refused(&daemon));
        assert_eq!(
            health(&daemon).account.state,
            LocalHealthAccountState::Connected
        );

        // Reads never decide the device fact: a refusal that started before a
        // read succeeded (with a cached token or after a refresh) still
        // applies.
        let idle = start(&daemon);
        daemon
            .record_setup_run_read_accepted(&read_start(&daemon))
            .expect("read accepted");
        assert!(daemon.settle_device_credential_answer(&idle, true));
        assert!(refused(&daemon));

        // A sign-in starts over: the refusal is cleared, and answers that
        // started before it are dropped.
        let before_sign_in = start(&daemon);
        daemon
            .begin_auth_with_claim(pending_claim("claim_new", "nonce_new"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_new",
                "nonce_new",
                account("user_1", "ron@example.com"),
                "run_2".to_string(),
                "2026-11-04T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete auth");
        assert!(!refused(&daemon));
        assert!(!daemon.settle_device_credential_answer(&before_sign_in, true));
        assert!(!refused(&daemon));
        assert!(settle_device(&daemon, true), "a new answer still counts");
    }

    #[test]
    #[serial]
    fn an_ended_run_and_a_device_refusal_settle_independently_in_either_order() {
        for idle_first in [true, false] {
            let run = read_binding("run_1");
            let daemon = daemon()
                .with_account(account("user_1", "ron@example.com"))
                .with_connection(Some(run.clone()));
            daemon.record_setup_run_ended(&run).expect("run ended");
            assert!(settle_device(&daemon, true));
            // A read and an idle check start after both answers; their
            // results arrive in either order.
            let read = read_start(&daemon);
            let idle = daemon
                .start_credential_observation(crate::control::device_credential_epoch(), None)
                .expect("start");
            let settle_read = || {
                daemon
                    .record_setup_run_read_accepted(&read)
                    .expect("read accepted")
            };
            if idle_first {
                assert!(daemon.settle_device_credential_answer(&idle, false));
                settle_read();
            } else {
                settle_read();
                assert!(daemon.settle_device_credential_answer(&idle, false));
            }
            let recovered = health(&daemon);
            assert_eq!(recovered.account.state, LocalHealthAccountState::Connected);
            assert_eq!(
                recovered.account.setup_run_state,
                LocalSetupRunState::Complete
            );
            assert!(!has_blocker(&recovered, "setup_run_rejected"));
            assert!(!has_blocker(&recovered, "device_credential_rejected"));
        }
    }

    #[test]
    #[serial]
    fn a_usable_device_answer_never_clears_an_ended_setup_run() {
        let run = read_binding("run_1");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(run.clone()));
        daemon
            .record_setup_run_ended(&run)
            .expect("record ended run");
        // Ended, then refused, then usable: the ended run stays recorded.
        assert!(settle_device(&daemon, true));
        assert!(settle_device(&daemon, false));
        let status = daemon.status(TOKEN).expect("status");
        assert!(latest_setup_run_read_rejection(&status.local_health_events).is_some());
        let health = status.canonical_health.as_ref().expect("health");
        assert!(has_blocker(health, "setup_run_rejected"));
        assert!(daemon
            .connected_setup_run_needs_reconnect()
            .expect("needs reconnect"));
    }

    /// Answer each request on a loopback port with the next of `responses`
    /// (status line, extra headers, body), one connection each; `before`
    /// runs with the response index before each answer is written.
    fn loopback_backend(
        responses: Vec<(&'static str, &'static str, &'static str)>,
        before: impl Fn(usize) + Send + 'static,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (index, (status, headers, body)) in responses.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).expect("read request");
                    request.extend_from_slice(&buffer[..read]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    if let Some(head_end) = text.find("\r\n\r\n") {
                        let length = text[..head_end]
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        if request.len() >= head_end + 4 + length {
                            break;
                        }
                    }
                    if read == 0 {
                        break;
                    }
                }
                requests.push(String::from_utf8_lossy(&request).to_string());
                before(index);
                let response = format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
            requests
        });
        (base, server)
    }

    #[test]
    fn idle_probe_reads_only_authoritative_status_answers() {
        use crate::control::IdleProbeAnswer::{NoProof, NoRoute, Refused, Throttled, Usable};
        const JSON: &str = "Content-Type: application/json\r\n";
        let cases: Vec<(
            &'static str,
            &'static str,
            &'static str,
            crate::control::IdleProbeAnswer,
        )> = vec![
            ("200 OK", JSON, r#"{"status":"active"}"#, Usable),
            ("200 OK", JSON, r#"{"status":"expired"}"#, Usable),
            ("200 OK", JSON, r#"{"status":"revoked"}"#, Refused),
            ("200 OK", JSON, r#"{"status":"something_new"}"#, NoProof),
            (
                "200 OK",
                "Content-Type: text/html\r\n",
                "<html>sign in</html>",
                NoProof,
            ),
            (
                "401 Unauthorized",
                JSON,
                r#"{"detail":{"code":"device_credential_refused"}}"#,
                Refused,
            ),
            (
                "401 Unauthorized",
                JSON,
                r#"{"detail":"Not authenticated"}"#,
                NoProof,
            ),
            (
                "302 Found",
                "Location: https://elsewhere.example/status\r\n",
                "",
                NoProof,
            ),
            ("404 Not Found", JSON, r#"{"detail":"Not Found"}"#, NoRoute),
            ("405 Method Not Allowed", JSON, "{}", NoRoute),
            (
                "429 Too Many Requests",
                "Retry-After: 900\r\n",
                "{}",
                Throttled {
                    retry_after: Some(std::time::Duration::from_secs(900)),
                },
            ),
            (
                "503 Service Unavailable",
                "Retry-After: Wed, 21 Oct 2026 07:28:00 GMT\r\n",
                "{}",
                Throttled { retry_after: None },
            ),
        ];
        let expected = cases.iter().map(|case| case.3).collect::<Vec<_>>();
        let (base, server) = loopback_backend(
            cases
                .iter()
                .map(|(status, headers, body, _)| (*status, *headers, *body))
                .collect(),
            |_| {},
        );
        let url = format!("{base}/api/v1/telemetry/devices/device_1/status");
        for expected in expected {
            assert_eq!(
                crate::control::idle_credential_probe(&url, "device-secret"),
                expected
            );
        }
        let requests = server.join().expect("backend");
        assert!(requests.iter().all(|request| {
            request.starts_with("GET /api/v1/telemetry/devices/device_1/status ")
                && request
                    .to_ascii_lowercase()
                    .contains("x-ottto-device-secret: device-secret")
        }));
        // Nothing went to the redirect target.
        assert_eq!(requests.len(), 12);
    }

    /// A connected daemon with a device credential and setup run in scratch
    /// stores.
    struct IdleCheckFixture {
        daemon: LocalDaemon,
        device: LocalDeviceBinding,
        run: LocalConnectionBinding,
        _guards: [TestEnvVar; 2],
        _support: test_scratch::ScratchDir,
    }

    fn idle_check_fixture(name: &str) -> IdleCheckFixture {
        let support = test_scratch::ScratchDir::new(name);
        let guards = [
            TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            TestEnvVar::set(
                ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV,
                &support.join("secrets"),
            ),
        ];
        let device = LocalDeviceBinding {
            device_id: "device_1".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: Vec::new(),
        };
        crate::control::persist_relay_device_credentials(&device, "device-secret")
            .expect("save credential");
        let run = read_binding("run_1");
        ottto_core::FileConnectionStore::default()
            .save(&run)
            .expect("save connection");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(run.clone()));
        IdleCheckFixture {
            daemon,
            device,
            run,
            _guards: guards,
            _support: support,
        }
    }

    fn device_refused(daemon: &LocalDaemon) -> bool {
        latest_device_credential_refusal(&daemon.status(TOKEN).expect("status").local_health_events)
            .is_some()
    }

    #[test]
    #[serial]
    fn idle_check_reports_a_disconnected_mac_and_its_recovery() {
        use crate::control::IdleCredentialCheck::Answered;
        use crate::control::IdleProbeAnswer::{Refused, Usable};
        let fixture = idle_check_fixture("idle-check-refused");
        let mut sent = None;
        let outcome =
            crate::control::probe_idle_device_credential_with(&fixture.daemon, |url, secret| {
                sent = Some((url.to_string(), secret.to_string()));
                Refused
            });
        assert_eq!(outcome, Answered);
        assert_eq!(
            sent,
            Some((
                "https://api.ottto.net/api/v1/telemetry/devices/device_1/status".to_string(),
                "device-secret".to_string()
            ))
        );
        let refused = health(&fixture.daemon);
        assert_eq!(
            refused.account.state,
            LocalHealthAccountState::ReconnectRequired
        );
        assert!(has_blocker(&refused, "device_credential_rejected"));

        let outcome =
            crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, _| Usable);
        assert_eq!(outcome, Answered);
        assert_eq!(
            effective_account_binding(&fixture.daemon.status(TOKEN).expect("status")).state,
            LocalAccountState::Connected
        );
        assert!(!device_refused(&fixture.daemon));
    }

    #[test]
    #[serial]
    fn idle_check_records_nothing_without_proof() {
        use crate::control::IdleCredentialCheck;
        use crate::control::IdleProbeAnswer;
        let fixture = idle_check_fixture("idle-check-no-proof");
        let retry_after = Some(std::time::Duration::from_secs(30));
        for (answer, outcome) in [
            (IdleProbeAnswer::NoProof, IdleCredentialCheck::Transient),
            (IdleProbeAnswer::NoRoute, IdleCredentialCheck::NoRoute),
            (
                IdleProbeAnswer::Throttled { retry_after },
                IdleCredentialCheck::Throttled { retry_after },
            ),
        ] {
            assert_eq!(
                crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, _| answer),
                outcome
            );
        }
        let status = fixture.daemon.status(TOKEN).expect("status");
        assert!(status
            .local_health_events
            .iter()
            .all(|event| !event.event_type.starts_with("DeviceCredential")));
        assert_eq!(
            effective_account_binding(&status).state,
            LocalAccountState::Connected
        );
    }

    #[test]
    #[serial]
    fn idle_check_needs_a_connected_account_and_a_credential() {
        use crate::control::IdleCredentialCheck::Skipped;
        let fixture = idle_check_fixture("idle-check-skipped");
        let mut called = false;
        let not_connected = daemon().with_connection(Some(fixture.run.clone()));
        assert_eq!(
            crate::control::probe_idle_device_credential_with(&not_connected, |_, _| {
                called = true;
                crate::control::IdleProbeAnswer::Usable
            }),
            Skipped
        );
        ottto_core::FileDeviceStore::default()
            .reset()
            .expect("remove device");
        assert_eq!(
            crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, _| {
                called = true;
                crate::control::IdleProbeAnswer::Usable
            }),
            Skipped
        );
        assert!(
            !called,
            "nothing is sent without a connected account and credential"
        );
    }

    #[test]
    #[serial]
    fn idle_answer_for_a_credential_replaced_in_flight_is_dropped() {
        use crate::control::IdleCredentialCheck::{Answered, Transient};
        use crate::control::IdleProbeAnswer::Refused;
        let fixture = idle_check_fixture("idle-check-replaced");
        // A promotion or sign-in writes the credential after the request
        // left and before its answer is recorded.
        let outcome = crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, _| {
            crate::control::persist_relay_device_credentials(&fixture.device, "rotated")
                .expect("rotate credential");
            Refused
        });
        assert_eq!(outcome, Transient);
        assert!(!device_refused(&fixture.daemon));

        // A promotion that timed out after confirmation leaves its journal:
        // nothing is recorded until it is finished.
        let candidate = "candidate-secret";
        let journal = ottto_core::PendingDeviceCredentialPreparation {
            schema_version: 2,
            capability: "device_credential_prepare_confirm_v1".into(),
            preparation_id: "preparation-idle-check".into(),
            api_base_url: "https://api.ottto.net".into(),
            expires_at: "2026-08-01T00:00:00Z".into(),
            credential_generation: 4,
            secret_commitment_sha256: crate::control::secret_sha256(candidate),
            request_authority: None,
            device: fixture.device.clone(),
            confirmation_authorized: true,
            preconfirm_guards_passed: true,
            claim_commit: None,
            confirmed_at: Some("2026-07-31T20:00:00Z".into()),
        };
        let outcome = crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, _| {
            ottto_core::FilePendingDeviceCredentialStore::default()
                .save(&journal)
                .expect("journal");
            Refused
        });
        assert_eq!(outcome, Transient);
        assert!(!device_refused(&fixture.daemon));
        ottto_core::FilePendingDeviceCredentialStore::default()
            .reset()
            .expect("clear journal");

        // The next check sends the new credential and counts.
        let mut sent_secret = None;
        let outcome =
            crate::control::probe_idle_device_credential_with(&fixture.daemon, |_, secret| {
                sent_secret = Some(secret.to_string());
                Refused
            });
        assert_eq!(outcome, Answered);
        assert_eq!(sent_secret.as_deref(), Some("rotated"));
        assert!(device_refused(&fixture.daemon));
    }

    #[test]
    #[serial]
    fn a_credential_write_retires_device_and_upload_answers_but_keeps_the_run() {
        let fixture = idle_check_fixture("idle-check-retire");
        fixture
            .daemon
            .record_setup_run_ended(&fixture.run)
            .expect("run ended");
        assert!(settle_device(&fixture.daemon, true));
        let upload = fixture
            .daemon
            .start_credential_observation(
                crate::control::device_credential_epoch(),
                Some(fixture.run.clone()),
            )
            .expect("start upload");
        assert!(fixture.daemon.settle_local_health_upload(
            &upload,
            Err(LocalHealthUploadFailureKind::AuthRejected),
            false,
            || {}
        ));
        assert_eq!(
            health(&fixture.daemon).account.state,
            LocalHealthAccountState::ReconnectRequired
        );

        // First-app promotion (or startup recovery) writes the credential; no
        // upload has to follow for the stale answers to go.
        crate::control::persist_relay_device_credentials(&fixture.device, "promoted")
            .expect("promote");
        let status = fixture.daemon.status(TOKEN).expect("status");
        assert!(latest_device_credential_refusal(&status.local_health_events).is_none());
        assert!(latest_local_health_upload_in(&status.local_health_events).is_none());
        assert!(latest_setup_run_read_rejection(&status.local_health_events).is_some());
        let retired = status.canonical_health.expect("health");
        assert_eq!(retired.account.state, LocalHealthAccountState::Connected);
        assert_eq!(
            retired.account.setup_run_state,
            LocalSetupRunState::Rejected
        );
        assert!(!has_blocker(&retired, "device_credential_rejected"));
    }

    #[test]
    #[serial]
    fn an_accepted_upload_proves_the_device_credential() {
        let fixture = idle_check_fixture("idle-check-upload-proof");
        assert!(settle_device(&fixture.daemon, true));
        let upload = fixture
            .daemon
            .start_credential_observation(
                crate::control::device_credential_epoch(),
                Some(fixture.run.clone()),
            )
            .expect("start upload");
        assert!(fixture
            .daemon
            .settle_local_health_upload(&upload, Ok(()), false, || {}));
        assert!(!device_refused(&fixture.daemon));
        assert_eq!(
            health(&fixture.daemon).account.state,
            LocalHealthAccountState::Connected
        );
    }

    #[test]
    #[serial]
    fn a_late_upload_result_for_a_replaced_binding_changes_nothing() {
        let fixture = idle_check_fixture("idle-check-late-upload");
        let start = |fixture: &IdleCheckFixture| {
            fixture
                .daemon
                .start_credential_observation(
                    crate::control::device_credential_epoch(),
                    Some(fixture.run.clone()),
                )
                .expect("start upload")
        };
        let held = std::cell::Cell::new(false);

        // A run-only rebind while the upload was in flight.
        let success = start(&fixture);
        let failure = start(&fixture);
        ottto_core::FileConnectionStore::default()
            .save(&read_binding("run_2"))
            .expect("rebind");
        assert!(!fixture
            .daemon
            .settle_local_health_upload(&success, Ok(()), false, || held.set(true)));
        assert!(!fixture.daemon.settle_local_health_upload(
            &failure,
            Err(LocalHealthUploadFailureKind::AuthRejected),
            true,
            || held.set(true)
        ));
        ottto_core::FileConnectionStore::default()
            .save(&fixture.run)
            .expect("restore run");

        // A sign-in that wrote new credentials while the upload was in flight.
        let stale = start(&fixture);
        crate::control::persist_relay_device_credentials(&fixture.device, "signed-in")
            .expect("sign in");
        assert!(!fixture.daemon.settle_local_health_upload(
            &stale,
            Err(LocalHealthUploadFailureKind::AuthRejected),
            true,
            || held.set(true)
        ));

        assert!(!held.get(), "no hold change for a dropped result");
        let status = fixture.daemon.status(TOKEN).expect("status");
        assert!(latest_local_health_upload_in(&status.local_health_events).is_none());
        assert_eq!(status.account.state, LocalAccountState::Connected);
        assert_ne!(
            status
                .account
                .message
                .map(|message| message.code)
                .as_deref(),
            Some(ACCOUNT_NOT_FOUND_MESSAGE_CODE),
            "a stale refresh answer never marks the account gone"
        );
    }

    #[test]
    #[serial]
    fn a_refresh_minted_with_a_replaced_credential_is_not_saved() {
        let fixture = idle_check_fixture("idle-check-refresh-epoch");
        let device = fixture.device.clone();
        let (base, server) = loopback_backend(
            vec![(
                "200 OK",
                "Content-Type: application/json\r\n",
                r#"{"setup_run_token":"otsr_minted","expires_at":"2026-05-05T11:00:00Z"}"#,
            )],
            move |_| {
                // A same-run promotion commits while the refresh is in flight.
                crate::control::persist_relay_device_credentials(&device, "promoted")
                    .expect("promote");
            },
        );
        let run = LocalConnectionBinding {
            api_base_url: base,
            ..fixture.run.clone()
        };
        ottto_core::FileConnectionStore::default()
            .save(&run)
            .expect("save loopback run");
        let result = crate::control::refresh_setup_run_token_for_persisted_connection();
        server.join().expect("backend");
        assert_eq!(result, Err(LocalApiError::IdentityMutationInProgress));
        assert!(crate::control::terminal_refresh_rejection(
            &LocalApiError::IdentityMutationInProgress
        )
        .is_none());
        assert!(
            ottto_core::ControlTokenStore::load(&ottto_core::KeychainSecretStore::new(
                ottto_core::OTTTO_SETUP_RUN_TOKEN_ACCOUNT
            ))
            .is_err(),
            "the minted token is dropped"
        );
    }

    #[test]
    fn older_successful_read_cannot_clear_a_newer_same_run_rejection() {
        let run = read_binding("run_1");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(run.clone()));
        let setup_run_state = |daemon: &LocalDaemon| {
            daemon
                .status(TOKEN)
                .expect("status")
                .canonical_health
                .expect("canonical health")
                .account
                .setup_run_state
        };
        let recoveries = |daemon: &LocalDaemon| {
            daemon
                .status(TOKEN)
                .expect("status")
                .local_health_events
                .iter()
                .filter(|event| event.event_type == "SetupRunReadRecovered")
                .count()
        };

        // A slow read starts while Ottto still accepts the run. A later read
        // of the same binding is told the run ended, then the slow read's
        // success arrives: it predates that answer and must not clear it.
        let slow_read = read_start(&daemon);
        let rejected_read = read_start(&daemon);
        daemon
            .record_setup_run_ended(&rejected_read.binding)
            .expect("record rejected read");
        daemon
            .record_setup_run_read_accepted(&slow_read)
            .expect("late success of the older read");
        assert_eq!(setup_run_state(&daemon), LocalSetupRunState::Rejected);
        assert_eq!(recoveries(&daemon), 0);

        // A read that started after the rejection and succeeds recovers it.
        let started_while_rejected = read_start(&daemon);
        let recovering_read = read_start(&daemon);
        daemon
            .record_setup_run_read_accepted(&recovering_read)
            .expect("subsequent successful read");
        assert_eq!(setup_run_state(&daemon), LocalSetupRunState::Complete);
        assert_eq!(recoveries(&daemon), 1);

        // The run is rejected again with the same kind. A read that started
        // during the earlier rejection describes that one, not this one.
        daemon
            .record_setup_run_ended(&run)
            .expect("record second rejection");
        daemon
            .record_setup_run_read_accepted(&started_while_rejected)
            .expect("late success from the earlier rejection");
        assert_eq!(setup_run_state(&daemon), LocalSetupRunState::Rejected);
        assert_eq!(recoveries(&daemon), 0);

        daemon
            .record_setup_run_read_accepted(&read_start(&daemon))
            .expect("subsequent successful read");
        let recovered = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(
            recovered.account.setup_run_state,
            LocalSetupRunState::Complete
        );
        assert_eq!(recovered.account.device_state, LocalDeviceState::Active);
        assert!(!recovered.blockers.iter().any(|blocker| {
            blocker.code == "setup_run_rejected" || blocker.code == "device_credential_rejected"
        }));
        assert_eq!(recoveries(&daemon), 1);
    }

    #[test]
    fn setup_run_read_rejection_follows_the_binding_that_was_rejected() {
        let rejected = |daemon: &LocalDaemon| {
            latest_setup_run_read_rejection(
                &daemon.status(TOKEN).expect("status").local_health_events,
            )
            .is_some()
        };
        let old_run = read_binding("run_old");
        let new_run = read_binding("run_new");
        let daemon = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_connection(Some(old_run.clone()));

        daemon
            .record_setup_run_ended(&old_run)
            .expect("record rejected read");
        daemon
            .bind_setup_run_for_authorized_client(old_run.clone())
            .expect("rebind same run");
        assert!(
            rejected(&daemon),
            "the same binding is still the rejected run"
        );
        daemon
            .bind_setup_run_for_authorized_client(new_run.clone())
            .expect("bind replacement run");
        assert!(
            !rejected(&daemon),
            "a replacement run is not the rejected run"
        );
        daemon
            .record_setup_run_ended(&old_run)
            .expect("late outcome from a read of the old run");
        assert!(
            !rejected(&daemon),
            "an in-flight read of the replaced run must not reject the new run"
        );

        daemon
            .record_setup_run_ended(&new_run)
            .expect("record rejected read");
        assert!(rejected(&daemon));
        assert!(daemon
            .clear_setup_run_for_authorized_client_if_matches("run_new", "https://api.ottto.net")
            .expect("clear binding"));
        assert!(!rejected(&daemon), "a cleared binding closes its rejection");

        daemon
            .bind_setup_run_for_authorized_client(new_run.clone())
            .expect("bind run again");
        daemon
            .record_setup_run_ended(&new_run)
            .expect("record rejected read");
        daemon
            .reset_account_for_authorized_client()
            .expect("reset account");
        assert!(!rejected(&daemon), "logout closes the rejection");
    }

    #[test]
    fn backend_unreachable_upload_failure_blocks_until_success_event() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::BackendUnreachable)
            .expect("record upload failure");
        let blocked = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(blocked.account.device_state, LocalDeviceState::Unknown);
        assert_eq!(
            blocked.overall.primary_blocker.as_deref(),
            Some("backend_unreachable")
        );

        daemon
            .record_local_health_upload_succeeded()
            .expect("record upload success");
        let recovered = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(recovered.account.device_state, LocalDeviceState::Active);
        assert!(recovered
            .blockers
            .iter()
            .all(|blocker| blocker.code != "backend_unreachable"));
    }

    #[test]
    fn snapshot_sync_stall_degrades_health_until_recovery() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .record_snapshot_sync_stalled(45, Some("agent_status"))
            .expect("record sync stall");

        let stalled = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        let blocker = stalled
            .blockers
            .iter()
            .find(|blocker| blocker.code == "snapshot_sync_stalled")
            .expect("stall blocker present");
        assert_eq!(blocker.severity, LocalHealthSeverity::Warning);
        // A stall degrades the posture so the UI surfaces it, but must never
        // read as Blocked: the machine still works, freshness is dying.
        assert_eq!(stalled.overall.state, LocalHealthOverallState::Degraded);
        assert_eq!(stalled.overall.severity, LocalHealthSeverity::Warning);
        assert_eq!(
            stalled.overall.primary_blocker.as_deref(),
            Some("snapshot_sync_stalled")
        );

        daemon
            .record_snapshot_sync_recovered()
            .expect("record sync recovery");
        let recovered = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert!(recovered
            .blockers
            .iter()
            .all(|blocker| blocker.code != "snapshot_sync_stalled"));
        assert_eq!(recovered.overall.state, LocalHealthOverallState::Healthy);
    }

    #[test]
    fn snapshot_sync_stall_never_masks_a_blocking_failure() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .record_snapshot_sync_stalled(45, Some("agent_status"))
            .expect("record sync stall");
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::BackendUnreachable)
            .expect("record upload failure");

        let health = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        // Both blockers are listed, but the Blocking one owns the overall
        // posture regardless of ordering.
        assert!(health
            .blockers
            .iter()
            .any(|blocker| blocker.code == "snapshot_sync_stalled"));
        assert_eq!(health.overall.state, LocalHealthOverallState::Blocked);
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("backend_unreachable")
        );
    }

    #[test]
    fn contract_rejected_upload_failure_is_not_backend_unreachable() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::ContractRejected)
            .expect("record upload failure");

        let health = daemon
            .status(TOKEN)
            .expect("status")
            .canonical_health
            .expect("canonical health");
        assert_eq!(health.account.device_state, LocalDeviceState::Active);
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("local_health_contract_rejected")
        );
        assert!(health
            .blockers
            .iter()
            .any(|blocker| blocker.code == "local_health_contract_rejected"));
        assert!(health
            .blockers
            .iter()
            .all(|blocker| blocker.code != "backend_unreachable"));
    }

    #[test]
    fn phase_zero_red_fixtures_are_never_green() {
        let fixtures: Vec<LocalHealthContractFixture> = serde_json::from_str(include_str!(
            "../../../fixtures/local-health/contract-matrix.v1.json"
        ))
        .expect("fixtures deserialize");

        for fixture in fixtures {
            if fixture.expected.overall_state == LocalHealthOverallState::Healthy {
                continue;
            }
            assert_ne!(
                fixture.health.overall.state,
                LocalHealthOverallState::Healthy,
                "{} must not replay as healthy",
                fixture.case_id
            );
            if fixture
                .tags
                .iter()
                .any(|tag| tag == "verify" || tag == "backfill")
            {
                assert!(
                    fixture
                        .health
                        .sources
                        .iter()
                        .any(|source| source.state == LocalHealthSourceState::VerifyFailed),
                    "{} should preserve current verify failure",
                    fixture.case_id
                );
            }
        }
    }

    #[test]
    fn available_pi_route_status_clears_stale_aggregate_smoke_failure() {
        for text in [
            "No Pi model routes passed smoke verification.",
            "The provider couldn't find Pi's default model, gcp-glm / zai-org/glm-5-maas. Choose another default model in Pi, or ignore this; usage collection is not affected.",
        ] {
            available_pi_route_clears_stale_smoke_failure(text);
        }
    }

    fn available_pi_route_clears_stale_smoke_failure(text: &str) {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Pi,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Failed,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE.to_string(),
                text: text.to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };
        daemon
            .record_verification_result(&result)
            .expect("record failed Pi verification");

        {
            let mut state = daemon.inner.lock().expect("state");
            let mut snapshot = available_agent_status(SourceKind::Pi, "2026-05-05T10:20:00Z");
            snapshot.model = Some(ottto_protocol::AgentModelStatus {
                active_model: None,
                default_model: Some("zai-org/glm-5-maas".to_string()),
                provider: Some("pi".to_string()),
                available_models: vec!["zai-org/glm-5-maas".to_string()],
                available_model_details: Vec::new(),
                context_window_tokens: None,
            });
            upsert_agent_status_snapshot(&mut state, snapshot);
        }

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Pi);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
        assert!(status.sources[0].last_verified_at.is_none());
        assert!(status.sources[0].agent_status.is_some());
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Pi)
            .expect("Pi source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
    }

    /// A failed check stays failed through status passes, and clears
    /// once this Mac has an upload for that app accepted after the failure.
    #[test]
    fn accepted_upload_after_a_failed_check_clears_it() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Failed,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: None,
            message: StableMessage {
                code: "smoke_command_failed".to_string(),
                text: "Codex check failed.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };
        daemon
            .record_verification_result(&result)
            .expect("record failed verification");
        let now = OffsetDateTime::now_utc();
        let at = |offset: time::Duration| (now + offset).format(&Rfc3339).unwrap();
        let pass = |captured_at: &str| {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, captured_at),
            );
        };

        // No upload, or one accepted before the failure: still failed.
        pass(&at(time::Duration::minutes(5)));
        assert_eq!(
            daemon.status(TOKEN).unwrap().sources[0].state,
            SourceState::Failed
        );
        crate::upload_receipts::note_accepted_upload_for_test(
            SourceKind::Codex,
            &at(-time::Duration::hours(1)),
        );
        crate::upload_receipts::note_accepted_upload_for_test(
            SourceKind::ClaudeCode,
            &at(time::Duration::hours(1)),
        );
        pass(&at(time::Duration::minutes(10)));
        assert_eq!(
            daemon.status(TOKEN).unwrap().sources[0].state,
            SourceState::Failed
        );

        // Codex usage accepted after the failure clears it.
        crate::upload_receipts::note_accepted_upload_for_test(
            SourceKind::Codex,
            &at(time::Duration::hours(1)),
        );
        pass(&at(time::Duration::minutes(15)));
        let status = daemon.status(TOKEN).unwrap();
        assert_ne!(status.sources[0].state, SourceState::Failed);
        assert!(status.sources[0].problems.iter().all(|problem| {
            problem.code != ottto_protocol::StableProblemCode::TelemetryNotVerified
        }));
    }

    #[test]
    fn available_agent_status_preserves_admin_disabled_verification_policy() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Pi,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.pi/agent/settings.json".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::NoFreshTelemetry,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-09-11T06:55:00Z".to_string()),
            message: StableMessage {
                code: "telemetry_disabled_by_admin".to_string(),
                text: "Pi telemetry is turned off in this workspace. Turn telemetry on in Ottto, then retry Verify.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record admin-disabled policy");
        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Pi, "2026-09-11T07:05:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after refresh");
        let source = status.sources.first().expect("Pi source");
        assert_eq!(source.state, SourceState::NeedsConfirmation);
        assert_eq!(source.grade, HealthGrade::Warning);
        assert_eq!(
            source.problems.first().map(|problem| &problem.code),
            Some(&StableProblemCode::TelemetryDisabledByAdmin)
        );
        assert!(source.recommended_actions.is_empty());
        let health = status.canonical_health.as_ref().expect("canonical health");
        let canonical = health
            .sources
            .iter()
            .find(|source| source.app == SourceKind::Pi)
            .expect("canonical Pi source");
        assert_eq!(
            canonical.blocking_reason.as_deref(),
            Some("telemetry_disabled_by_admin")
        );
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::Healthy,
            "workspace policy belongs on the Pi row, not machine health"
        );
    }

    #[test]
    fn current_agent_status_clears_day_old_workspace_policy_warning() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut stale = codex_health();
        stale.source = SourceKind::Pi;
        stale.descriptor = source_descriptor(&SourceKind::Pi);
        stale.state = SourceState::NeedsConfirmation;
        stale.grade = HealthGrade::Warning;
        stale.last_seen_at = Some("2026-09-11T19:39:35Z".to_string());
        stale.last_verified_at = Some("2026-09-11T19:39:35Z".to_string());
        stale.problems = vec![HealthProblem {
            code: StableProblemCode::TelemetryDisabledByAdmin,
            title: "Pi data sharing is off".to_string(),
            detail: "Turn on Live telemetry for Pi, then Verify.".to_string(),
            retryable: false,
        }];
        stale.recommended_actions = Vec::new();
        daemon
            .update_sources(TOKEN, vec![stale])
            .expect("seed old workspace policy");

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Pi, "2026-09-21T12:06:33Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after current scan");
        let source = status.sources.first().expect("Pi source");
        assert_eq!(source.state, SourceState::Healthy);
        assert_eq!(source.grade, HealthGrade::Ok);
        assert!(source.last_verified_at.is_none());
        assert!(source.problems.is_empty());
        assert_eq!(
            status
                .canonical_health
                .expect("canonical health")
                .overall
                .state,
            LocalHealthOverallState::Healthy
        );
    }

    #[test]
    fn available_agent_status_clears_stale_spend_limit_failed_verification() {
        // Regression for the 2026-07 incident shape: a smoke failure carrying
        // Anthropic's "monthly spend limit" wording was recorded as a hard
        // Failed/Critical (the old keyword list missed "spend limit") and then
        // re-pinned by every refresh until a manual Verify. The detail now
        // classifies as usage-limited, so an Available agent scan clears it.
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::ClaudeCode,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Failed,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "smoke_command_failed".to_string(),
                text: "The Claude Code test run failed before Ottto could check it: You've hit your org's monthly spend limit · run [path] to raise it, or visit claude.ai/admin-settings/usage".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record failed spend-limit verification");
        let before_scan = daemon.status(TOKEN).expect("status before scan");
        assert_eq!(before_scan.sources[0].state, SourceState::Failed);
        assert_eq!(before_scan.sources[0].grade, HealthGrade::Critical);

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::ClaudeCode, "2026-05-05T10:20:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after scan");
        assert_eq!(status.sources[0].source, SourceKind::ClaudeCode);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
    }

    #[test]
    fn codex_source_off_mode_is_not_a_verification_witness_or_retry_loop() {
        let daemon = daemon().with_account(account("user_1", "test@example.com"));
        let mut result = verified_codex("2026-05-05T10:20:00Z");
        result.status = SourceVerificationStatus::Warning;
        result.verified = false;
        result.message.code = "codex_local_import".to_string();
        result.records_seen = 0;
        result.last_record_id = None;
        result.last_received_at = None;
        result.smoke_after = None;
        assert!(!verification_result_records_success(&result));
        daemon.record_verification_result(&result).unwrap();
        let status = daemon.status(TOKEN).unwrap();
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert!(status.sources[0].last_verified_at.is_none());
        assert!(status.sources[0].last_seen_at.is_none());
        assert!(status.sources[0].recommended_actions.is_empty());
        assert!(status
            .local_health_events
            .iter()
            .all(|event| !matches!(event.event_type.as_str(), "VerifyPassed" | "VerifyFailed")));
        result.config.drift.push(ottto_protocol::ConfigDrift {
            key: "codex.config_toml".into(),
            expected: RedactedValue::String("valid".into()),
            observed: RedactedValue::String("invalid".into()),
        });
        daemon.record_verification_result(&result).unwrap();
        assert_eq!(
            daemon.status(TOKEN).unwrap().sources[0].state,
            SourceState::NeedsRepair
        );
        result.config.drift.clear();
        {
            let mut state = daemon.inner.lock().unwrap();
            state.sources[0].state = SourceState::Failed;
            state.sources[0].grade = HealthGrade::Critical;
            state.sources[0].last_seen_at = Some("2026-05-05T10:00:00Z".into());
            state.sources[0].last_verified_at = Some("2026-05-05T10:01:00Z".into());
            state.sources[0].problems = vec![ottto_protocol::HealthProblem {
                code: StableProblemCode::Unknown,
                title: "Collector parse failure".into(),
                detail: "parse_error".into(),
                retryable: false,
            }];
        }
        daemon.record_verification_result(&result).unwrap();
        let status = daemon.status(TOKEN).unwrap();
        assert_eq!(status.sources[0].state, SourceState::Failed);
        assert_eq!(status.sources[0].problems[0].detail, "parse_error");
        assert_eq!(
            status.sources[0].last_seen_at.as_deref(),
            Some("2026-05-05T10:00:00Z")
        );
        assert_eq!(
            status.sources[0].last_verified_at.as_deref(),
            Some("2026-05-05T10:01:00Z")
        );
        result.message.code = "setup_run_token_expired".into();
        result.status = SourceVerificationStatus::ReconnectRequired;
        daemon.record_verification_result(&result).unwrap();
        assert_eq!(
            daemon.status(TOKEN).unwrap().sources[0].state,
            SourceState::Failed
        );
        result.status = SourceVerificationStatus::Warning;
        result.message.code = "codex_local_import".into();
        daemon.record_verification_result(&result).unwrap();
        let status = daemon.status(TOKEN).unwrap();
        assert_eq!(
            status.sources[0].state,
            SourceState::Failed,
            "readiness cannot erase prior backend auth failure"
        );
        assert!(status.sources[0]
            .problems
            .iter()
            .any(|problem| problem.code == StableProblemCode::TelemetryNotVerified));
    }

    #[test]
    fn codex_source_off_readiness_clears_resolved_source_absence() {
        let daemon = daemon().with_account(account("user_1", "test@example.com"));
        let mut result = verified_codex("2026-05-05T10:20:00Z");
        result.status = SourceVerificationStatus::Failed;
        result.verified = false;
        result.message.code = "source_not_installed".into();
        result.records_seen = 0;
        result.last_record_id = None;
        result.last_received_at = None;
        result.smoke_after = None;
        daemon.record_verification_result(&result).unwrap();
        assert_eq!(
            daemon.status(TOKEN).unwrap().sources[0].state,
            SourceState::NotFound
        );
        result.status = SourceVerificationStatus::Warning;
        result.message.code = "codex_local_import".into();
        daemon.record_verification_result(&result).unwrap();
        let status = daemon.status(TOKEN).unwrap();
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
    }

    #[test]
    fn warning_verification_without_success_never_projects_healthy() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Pi,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Warning,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "pi_oauth_reauth_required".to_string(),
                text: "Pi provider OAuth re-auth is required before verification can complete."
                    .to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record warning verification");
        let before_scan = daemon.status(TOKEN).expect("status before scan");
        let attempt_at = before_scan.sources[0]
            .last_verified_at
            .clone()
            .expect("warning verify attempt timestamp");
        assert_eq!(before_scan.sources[0].state, SourceState::NeedsConfirmation);

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Pi, "2026-05-05T10:40:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after scan");
        assert_eq!(status.sources[0].state, SourceState::NeedsConfirmation);
        assert_eq!(
            status.sources[0].last_verified_at.as_deref(),
            Some(attempt_at.as_str())
        );
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Pi)
            .expect("Pi source");
        assert_eq!(source.state, LocalHealthSourceState::VerifyFailed);
        assert_eq!(source.authority, LocalHealthAuthority::Verify);
        assert_eq!(
            source.blocking_reason.as_deref(),
            Some("telemetry_not_verified")
        );
    }

    #[test]
    fn pi_oauth_reauth_warning_clears_after_runtime_identity_refresh() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Pi,
            config: SourceConfigState {
                discovered: true,
                path_hint: None,
                fingerprint: None,
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Warning,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "pi_oauth_reauth_required".to_string(),
                text: "Re-sign in to the Pi provider, then re-run Verify -- Ottto can't re-mint a rotating provider OAuth token."
                    .to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record warning verification");
        let before_scan = daemon.status(TOKEN).expect("status before scan");
        assert_eq!(before_scan.sources[0].state, SourceState::NeedsConfirmation);

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                pi_subscription_oauth_agent_status("2026-05-05T10:40:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after scan");
        let pi = status
            .sources
            .iter()
            .find(|source| source.source == SourceKind::Pi)
            .expect("Pi source");
        assert_eq!(pi.state, SourceState::Healthy);
        assert_eq!(pi.grade, HealthGrade::Ok);
        assert!(pi.last_verified_at.is_none());
        assert!(pi.problems.is_empty());
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Pi)
            .expect("Pi source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
        assert!(source.blocking_reason.is_none());
    }

    #[test]
    fn claude_oauth_reconnect_is_source_scoped_and_prioritizes_provider_sign_in() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");
        let result = SourceVerificationResult {
            source: SourceKind::ClaudeCode,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.claude/settings.json".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: vec![ottto_protocol::ConfigDrift {
                    key: "otel_headers".to_string(),
                    expected: RedactedValue::String("current".to_string()),
                    observed: RedactedValue::String("stale".to_string()),
                }],
            },
            status: SourceVerificationStatus::ReconnectRequired,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-09-14T12:00:00Z".to_string()),
            message: StableMessage {
                code: CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE.to_string(),
                text: "Claude Code sign-in expired. Ottto itself is still connected.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record Claude reconnect result");
        let status = daemon.status(TOKEN).expect("status");
        let source = status
            .sources
            .iter()
            .find(|source| source.source == SourceKind::ClaudeCode)
            .expect("Claude source");

        assert_eq!(status.account.state, LocalAccountState::Connected);
        assert_eq!(source.state, SourceState::Failed);
        assert_eq!(source.recommended_actions.len(), 1);
        assert_eq!(
            source.recommended_actions[0].action,
            RepairActionKind::ReauthProvider
        );
        assert!(source.recommended_actions[0].title.contains("Claude Code"));
    }

    #[test]
    fn account_not_connected_verification_does_not_create_source_failure() {
        let daemon = daemon();
        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::AccountNotConnected,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: None,
            message: StableMessage {
                code: "account_not_connected".to_string(),
                text: "Use Sign in in the Ottto app, then try verifying again.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        };

        daemon
            .record_verification_result(&result)
            .expect("record account result");
        let status = daemon.status(TOKEN).expect("status");
        assert!(status.sources.is_empty());
    }

    #[test]
    fn connected_account_requires_reset_for_different_user() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");

        daemon
            .begin_auth_with_claim(pending_claim("claim_two", "nonce_two"))
            .expect("start second auth");
        let err = daemon
            .complete_auth_with_account(
                "claim_two",
                "nonce_two",
                account("user_2", "other@example.com"),
                "setup_2".to_string(),
                "2026-05-05T10:20:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect_err("different account requires reset");
        assert_eq!(err, LocalApiError::AccountResetRequired);
        assert_eq!(
            daemon.status(TOKEN).expect("status").account.state,
            LocalAccountState::ResetRequired
        );
    }

    fn staged_switch(claim_code: &str, user_id: &str, email: &str) -> StagedAccountSwitch {
        StagedAccountSwitch {
            claim_code: claim_code.to_string(),
            new_account: account(user_id, email),
            setup_run_id: format!("setup_{claim_code}"),
            setup_run_token: "token_secret".to_string(),
            setup_run_token_expires_at: "2026-05-05T11:00:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            relay_device: None,
            relay_device_secret: None,
            relay_device_credential_preparation_id: None,
            backfill_policy: None,
            backfill_cutoff_at: None,
        }
    }

    #[test]
    fn claim_for_different_user_stages_switch_candidate() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");

        daemon
            .begin_auth_with_claim(pending_claim("claim_two", "nonce_two"))
            .expect("start second auth");
        let candidate = daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_2",
                "other@example.com",
            ))
            .expect("stage")
            .expect("mismatch stages a candidate");
        assert_eq!(candidate.current_user_email, "ron@example.com");
        assert_eq!(candidate.new_user_email, "other@example.com");
        assert_eq!(candidate.claim_code, "claim_two");

        // Old-client compatibility: the binding shows the long-standing
        // reset-required state + message code.
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.account.state, LocalAccountState::ResetRequired);
        assert_eq!(
            status.account.message.as_ref().map(|m| m.code.as_str()),
            Some("account_reset_required")
        );
        // The pending claim is consumed (the backend completion is single-use).
        assert_eq!(
            daemon
                .pending_auth_claim_for_resume("claim_two")
                .expect_err("claim consumed"),
            LocalApiError::NoPendingAuthClaim
        );
    }

    #[test]
    fn confirmed_switch_installs_new_account_in_one_transition() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");
        daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_2",
                "other@example.com",
            ))
            .expect("stage")
            .expect("candidate");

        // Wrong claim code cannot consume the staged switch.
        assert!(daemon.take_staged_account_switch("claim_other").is_err());

        let staged = daemon
            .take_staged_account_switch("claim_two")
            .expect("take staged switch");
        let response = daemon
            .install_switched_account(
                staged.new_account.clone(),
                staged.setup_run_id.clone(),
                staged.setup_run_token_expires_at.clone(),
                staged.machine_id.clone(),
                &staged.claim_code,
            )
            .expect("install switched account");
        assert_eq!(
            response.account.user.as_ref().map(|u| u.email.as_str()),
            Some("other@example.com")
        );
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.account.state, LocalAccountState::Connected);
        assert_eq!(
            status.account.user.as_ref().map(|u| u.id.as_str()),
            Some("user_2")
        );
        // Consumed: a second confirm is rejected.
        assert!(daemon.take_staged_account_switch("claim_two").is_err());
    }

    #[test]
    fn same_user_claim_does_not_stage_switch() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");
        let candidate = daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_1",
                "ron@example.com",
            ))
            .expect("stage");
        assert!(candidate.is_none());
    }

    #[test]
    fn account_not_found_binding_accepts_fresh_claim_by_any_user() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");

        daemon.mark_account_not_found().expect("mark not found");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.account.state, LocalAccountState::Error);
        assert_eq!(
            status.account.message.as_ref().map(|m| m.code.as_str()),
            Some(ACCOUNT_NOT_FOUND_MESSAGE_CODE)
        );
        // Last-known user retained for display.
        assert_eq!(
            status.account.user.as_ref().map(|u| u.email.as_str()),
            Some("ron@example.com")
        );

        // No switch staging: the mismatch is waived because the old account is
        // gone…
        let candidate = daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_2",
                "other@example.com",
            ))
            .expect("stage");
        assert!(candidate.is_none());

        // …and a full completion by a DIFFERENT user proceeds as a fresh
        // first claim (no reset ceremony).
        daemon
            .begin_auth_with_claim(pending_claim("claim_two", "nonce_two"))
            .expect("start second auth");
        let response = daemon
            .complete_auth_with_account(
                "claim_two",
                "nonce_two",
                account("user_2", "other@example.com"),
                "setup_2".to_string(),
                "2026-05-05T10:20:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("fresh claim after account deletion");
        assert_eq!(
            response.account.user.as_ref().map(|u| u.id.as_str()),
            Some("user_2")
        );
        assert_eq!(
            daemon.status(TOKEN).expect("status").account.state,
            LocalAccountState::Connected
        );
    }

    #[test]
    fn fresh_claim_supersedes_staged_switch() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");
        daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_2",
                "other@example.com",
            ))
            .expect("stage")
            .expect("candidate");
        daemon
            .begin_auth_with_claim(pending_claim("claim_three", "nonce_three"))
            .expect("fresh claim");
        assert!(daemon.take_staged_account_switch("claim_two").is_err());
    }

    #[test]
    fn reset_clears_staged_switch() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete first auth");
        daemon
            .stage_account_switch_if_user_mismatch(staged_switch(
                "claim_two",
                "user_2",
                "other@example.com",
            ))
            .expect("stage")
            .expect("candidate");
        daemon.reset_account_for_authorized_client().expect("reset");
        assert!(daemon.take_staged_account_switch("claim_two").is_err());
    }

    #[test]
    fn pending_auth_claim_snapshot_reflects_in_flight_claim() {
        let daemon = daemon();
        assert!(daemon
            .pending_auth_claim_snapshot()
            .expect("snapshot")
            .is_none());
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        let (claim, account) = daemon
            .pending_auth_claim_snapshot()
            .expect("snapshot")
            .expect("claim in flight");
        assert_eq!(claim.claim_code, "claim_one");
        assert_eq!(account.state, LocalAccountState::ClaimPending);
    }

    #[test]
    fn pending_claim_overlay_never_hides_a_completed_local_binding() {
        let daemon = daemon();
        daemon
            .begin_auth_with_claim(pending_claim("claim_one", "nonce_one"))
            .expect("start auth");
        daemon
            .complete_auth_with_account(
                "claim_one",
                "nonce_one",
                account("user_1", "ron@example.com"),
                "setup_1".to_string(),
                "2026-05-05T10:10:00Z".to_string(),
                Some("machine_test".to_string()),
            )
            .expect("complete auth");
        {
            let mut state = daemon.state().expect("state");
            state.account.state = LocalAccountState::ClaimPending;
            state.account.message = Some(StableMessage {
                code: "claim_pending".to_string(),
                text: "Waiting for browser sign-in to finish.".to_string(),
            });
            state.pending_auth = Some(pending_claim("claim_stale", "nonce_stale"));
        }

        let visible = daemon.status(TOKEN).expect("status").account;
        assert_eq!(visible.state, LocalAccountState::Connected);
        assert_eq!(
            visible.user.as_ref().map(|user| user.id.as_str()),
            Some("user_1")
        );
        assert_eq!(
            visible
                .message
                .as_ref()
                .map(|message| message.code.as_str()),
            Some("connected")
        );
    }

    mod local_health_retention_tests {
        include!("lib_tests/local_health_retention_tests.rs");
    }

    mod scan_index_health_tests {
        use super::*;
        include!("lib_tests/scan_index_health_tests.rs");
    }

    fn daemon() -> LocalDaemon {
        LocalDaemon::new(
            MachineIdentity {
                machine_id: "machine_test".to_string(),
                installation_id: "install_test".to_string(),
                display_name: "Test Mac".to_string(),
                hostname: "test-mac.local".to_string(),
                os: OperatingSystem::Macos,
                arch: "arm64".to_string(),
                local_platform_version: "0.1.0".to_string(),
                hardware_uuid: None,
                account_scope: None,
            },
            ControlToken::new(TOKEN).expect("token should be valid"),
            "2026-05-05T09:10:00Z",
        )
    }

    fn diagnostic_item<'a>(
        bundle: &'a DiagnosticsBundle,
        section: &str,
        key: &str,
    ) -> Option<&'a RedactedValue> {
        bundle
            .sections
            .iter()
            .find(|candidate| candidate.name == section)
            .and_then(|candidate| candidate.items.get(key))
    }

    #[test]
    fn health_detected_uses_prunes_stale_cache_rows() {
        let detected = vec![
            DetectedUse {
                gateway_provider: "anthropic".to_string(),
                plan_fingerprint: None,
                account_identifier_hash: None,
                organization_identifier_hash: None,
                subscription_product: None,
                account_label: None,
                last_seen_at: "2025-10-05T13:12:31Z".to_string(),
                token_volume_recent: vec![ottto_protocol::DetectedUseTokenSample {
                    at: "2025-10-05T13:00:00Z".to_string(),
                    tokens: 15_417_886,
                }],
                quota_window_state: DetectedUseQuotaWindowState::Unknown,
                quota_used_percent: None,
                quota_resets_at: None,
            },
            DetectedUse {
                gateway_provider: "openai".to_string(),
                plan_fingerprint: Some("pro::20598".to_string()),
                account_identifier_hash: None,
                organization_identifier_hash: None,
                subscription_product: Some("pro".to_string()),
                account_label: Some("Pro".to_string()),
                last_seen_at: "2026-06-08T17:36:00Z".to_string(),
                token_volume_recent: Vec::new(),
                quota_window_state: DetectedUseQuotaWindowState::Unknown,
                quota_used_percent: None,
                quota_resets_at: None,
            },
        ];
        let now = OffsetDateTime::parse("2026-06-08T18:00:00Z", &Rfc3339).unwrap();

        let pruned = prune_detected_uses_for_health(detected, now);

        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].gateway_provider, "openai");
    }

    #[test]
    fn merge_current_plan_quota_only_touches_current_plan_destination() {
        use ottto_protocol::{
            AgentAccountStatus, AgentLoginState, AgentQuotaWindowScope,
            AgentStatusCollectionMethod, AgentStatusConfidence, DetectedUseTokenSample,
        };

        // Two historical Codex destinations: the current Personal Pro plan and a
        // Team plan billed elsewhere. Live agent status reports Pro near its
        // limit. Only the Pro entry must receive quota; Team must stay
        // Unknown/None (the current plan's quota is never smeared across
        // destinations it does not bill to).
        let mut detected = vec![
            DetectedUse {
                gateway_provider: "openai".to_string(),
                plan_fingerprint: Some("pro::20598".to_string()),
                account_identifier_hash: None,
                organization_identifier_hash: None,
                subscription_product: Some("pro".to_string()),
                account_label: Some("Pro".to_string()),
                last_seen_at: "2026-05-28T10:00:00Z".to_string(),
                token_volume_recent: vec![DetectedUseTokenSample {
                    at: "2026-05-28T09:00:00Z".to_string(),
                    tokens: 10,
                }],
                quota_window_state: DetectedUseQuotaWindowState::Unknown,
                quota_used_percent: None,
                quota_resets_at: None,
            },
            DetectedUse {
                gateway_provider: "openai".to_string(),
                plan_fingerprint: Some("team::20607".to_string()),
                account_identifier_hash: None,
                organization_identifier_hash: None,
                subscription_product: Some("team".to_string()),
                account_label: Some("Team".to_string()),
                last_seen_at: "2026-05-27T14:34:00Z".to_string(),
                token_volume_recent: Vec::new(),
                quota_window_state: DetectedUseQuotaWindowState::Unknown,
                quota_used_percent: None,
                quota_resets_at: None,
            },
        ];

        let snapshot = AgentStatusSnapshot {
            source: SourceKind::Codex,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::CliJson,
            captured_at: "2026-05-28T10:00:00Z".to_string(),
            expires_at: "2026-05-28T10:15:00Z".to_string(),
            account: Some(AgentAccountStatus {
                login_state: AgentLoginState::SignedIn,
                provider: Some("openai".to_string()),
                auth_method: Some("chatgpt".to_string()),
                email: Some("current@example.com".to_string()),
                account_id: None,
                organization_id: None,
                organization_label: None,
                plan_type: Some("pro".to_string()),
                subscription_product: Some("pro".to_string()),
                billing_channel: None,
                subscription_period_start: None,
                subscription_period_end: None,
                subscription_period_last_checked_at: None,
                account_identifier_hash: None,
                organization_identifier_hash: None,
                superseded_account_identifier_hash: None,
                superseded_organization_identifier_hash: None,
                credential_fingerprint_hash: None,
                billing_identity_evidence: None,
                claude_quota_access_state: None,
                claude_anchor_durability: None,
                claude_anchor_health: None,
                billing_identity_confidence: AgentStatusConfidence::High,
                confidence: AgentStatusConfidence::High,
            }),
            model: None,
            quota_windows: vec![
                AgentQuotaWindow {
                    name: "secondary".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::Ok,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    window_seconds: Some(604_800),
                    resets_at: Some("2026-06-01T00:00:00Z".to_string()),
                    used_percent: Some(16),
                    left_percent: Some(84),
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "primary".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::NearLimit,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    window_seconds: Some(18_000),
                    resets_at: Some("2026-05-28T15:00:00Z".to_string()),
                    used_percent: Some(92),
                    left_percent: Some(8),
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "other-desktop-account".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::RateLimited,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    account_label: Some("other@example.com".to_string()),
                    account_identifier_hash: Some("other-account-hash".to_string()),
                    organization_identifier_hash: Some("other-organization-hash".to_string()),
                    window_seconds: Some(604_800),
                    resets_at: Some("2026-06-01T00:00:00Z".to_string()),
                    used_percent: Some(100),
                    left_percent: Some(0),
                    ..Default::default()
                },
                AgentQuotaWindow {
                    name: "other-desktop-organization".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::RateLimited,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    account_label: Some("current@example.com".to_string()),
                    organization_identifier_hash: Some("other-organization-hash".to_string()),
                    window_seconds: Some(604_800),
                    used_percent: Some(100),
                    left_percent: Some(0),
                    ..Default::default()
                },
            ],
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        };

        merge_current_plan_quota(&mut detected, &snapshot);

        let pro = &detected[0];
        assert_eq!(pro.subscription_product.as_deref(), Some("pro"));
        // Most-constraining window (92%) wins → NearLimit, with its percent/reset.
        assert_eq!(
            pro.quota_window_state,
            DetectedUseQuotaWindowState::NearLimit
        );
        assert_eq!(pro.quota_used_percent, Some(92));
        assert_eq!(pro.quota_resets_at.as_deref(), Some("2026-05-28T15:00:00Z"));

        let team = &detected[1];
        assert_eq!(team.subscription_product.as_deref(), Some("team"));
        assert_eq!(
            team.quota_window_state,
            DetectedUseQuotaWindowState::Unknown
        );
        assert_eq!(team.quota_used_percent, None);
        assert_eq!(team.quota_resets_at, None);
    }

    #[test]
    fn source_first_seen_persists_across_restart_and_clears_on_reset() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-persist",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let state_file = dir.join(source_state_file_name("codex"));

        // First daemon observes Codex: it stamps and persists the first-seen
        // timestamp, and surfaces the cached reconciliation policy.
        let initial = daemon().with_source_state_dir(dir.clone());
        initial
            .record_reconciliation_enabled(SourceKind::Codex, true, 0)
            .expect("record reconciliation");
        initial
            .record_verification_result(&verified_codex("2026-05-05T10:15:00Z"))
            .expect("record verification");
        let status = initial.status(TOKEN).expect("status");
        assert_eq!(
            status.sources[0].connected_at.as_deref(),
            Some("2026-05-05T10:15:00Z")
        );
        assert_eq!(status.sources[0].reconciliation_enabled, Some(true));
        assert!(state_file.exists(), "first-seen file should be persisted");

        // A fresh daemon (simulated restart) boot-loads the persisted first-seen
        // and a later observation with a different timestamp must not overwrite
        // it. Reconciliation is in-memory only, so it resets to None.
        let restarted = daemon().with_source_state_dir(dir.clone());
        restarted
            .record_verification_result(&verified_codex("2026-05-06T08:00:00Z"))
            .expect("record verification after restart");
        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(
            status.sources[0].connected_at.as_deref(),
            Some("2026-05-05T10:15:00Z"),
            "persisted first-seen should win over a later observation"
        );
        assert_eq!(status.sources[0].reconciliation_enabled, None);

        // Account reset deletes the persisted per-source state file.
        restarted
            .reset_account_for_trusted_client()
            .expect("reset account");
        assert!(
            !state_file.exists(),
            "reset should delete the per-source state file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_verification_persists_across_restart_and_registered_seed() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-verify-failed",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let initial = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone());
        initial
            .record_verification_result(&failed_codex_reconnect())
            .expect("record failed verification");

        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources_presence(
                Some(LocalDeviceBinding {
                    device_id: "device_test".to_string(),
                    machine_id: Some("machine_test".to_string()),
                    sources: vec!["codex".to_string()],
                }),
                |_| true,
            );
        restarted
            .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
            .expect("record upload failure");

        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Failed);
        assert_eq!(status.sources[0].grade, HealthGrade::Critical);
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::TelemetryNotVerified
        );

        let health = status.canonical_health.expect("canonical health");
        assert_eq!(
            health.overall.state,
            LocalHealthOverallState::ReconnectRequired
        );
        assert_eq!(
            health.overall.primary_blocker.as_deref(),
            Some("auth_missing"),
            "backend auth can be the top blocker without hiding source failures"
        );
        assert_eq!(
            health.sources[0].state,
            LocalHealthSourceState::VerifyFailed
        );
        assert_eq!(health.sources[0].authority, LocalHealthAuthority::Verify);
        assert_eq!(
            health.sources[0].blocking_reason.as_deref(),
            Some("telemetry_not_verified")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn successful_verification_replaces_persisted_failure_after_restart() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-verify-recovered",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let initial = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone());
        initial
            .record_verification_result(&failed_codex_reconnect())
            .expect("record failed verification");

        let recovered = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone());
        recovered
            .record_verification_result(&verified_codex("2026-05-05T10:20:00Z"))
            .expect("record successful verification");

        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources_presence(
                Some(LocalDeviceBinding {
                    device_id: "device_test".to_string(),
                    machine_id: Some("machine_test".to_string()),
                    sources: vec!["codex".to_string()],
                }),
                |_| true,
            );
        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
        assert_eq!(
            status.sources[0].last_verified_at.as_deref(),
            Some("2026-05-05T10:20:00Z")
        );
        assert_eq!(
            status.canonical_health.expect("canonical health").sources[0].state,
            LocalHealthSourceState::Healthy
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registered_device_sources_seed_status_after_restart_before_scan() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-registered",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        FileSourceStateStore::new(dir.join(source_state_file_name("codex")))
            .save(&LocalSourceState {
                first_seen_at: Some("2026-05-05T10:15:00Z".to_string()),
                last_health: None,
                tracking_confirmation: None,
            })
            .expect("seed source state");

        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec![
                "codex".to_string(),
                "claude_code".to_string(),
                "unknown_source".to_string(),
            ],
        };
        // Both apps present on this Mac -> both seed as `verifying`.
        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources_presence(Some(device), |_| true);

        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 2);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Verifying);
        assert_eq!(status.sources[0].grade, HealthGrade::Unknown);
        assert_eq!(
            status.sources[0].connected_at.as_deref(),
            Some("2026-05-05T10:15:00Z")
        );
        assert!(status.sources[0].agent_status.is_none());
        assert_eq!(status.sources[1].source, SourceKind::ClaudeCode);
        assert_eq!(status.sources[1].state, SourceState::Verifying);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registered_device_source_absent_on_this_machine_is_not_seeded() {
        // The account has Claude Code registered (from another Mac), but this
        // machine never installed it. Seeding must skip it entirely so the app
        // does not show a phantom "Claude Code - needs attention" row that then
        // fails verification with "claude is not installed". Codex IS present
        // here, so it still seeds.
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-absent-claude",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("machine_test".to_string()),
            sources: vec!["codex".to_string(), "claude_code".to_string()],
        };
        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources_presence(Some(device), |source| {
                *source == SourceKind::Codex
            });

        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(
            status.sources.len(),
            1,
            "only the locally-present source seeds"
        );
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert!(
            status
                .sources
                .iter()
                .all(|source| source.source != SourceKind::ClaudeCode),
            "an app that this Mac never installed must not appear as a source"
        );

        // The absent source contributes no blocker: onboarding is not stalled.
        let health = status.canonical_health.expect("canonical health");
        assert!(
            health
                .blockers
                .iter()
                .all(|blocker| blocker.owner != "source"),
            "a not-present source must not produce a blocking source problem"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seeded_source_promotes_when_agent_status_refresh_arrives() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-source-state-test-{}-promote",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        FileSourceStateStore::new(dir.join(source_state_file_name("codex")))
            .save(&LocalSourceState {
                first_seen_at: Some("2026-05-05T10:15:00Z".to_string()),
                last_health: None,
                tracking_confirmation: None,
            })
            .expect("seed source state");

        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources_presence(
                Some(LocalDeviceBinding {
                    device_id: "device_test".to_string(),
                    machine_id: Some("machine_test".to_string()),
                    sources: vec!["codex".to_string()],
                }),
                |_| true,
            );
        let status = restarted.status(TOKEN).expect("status");
        assert_eq!(status.sources[0].state, SourceState::Verifying);
        assert_eq!(status.sources[0].grade, HealthGrade::Unknown);

        {
            let mut state = restarted.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:20:00Z"),
            );
        }

        let status = restarted.status(TOKEN).expect("status after refresh");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].last_verified_at.is_none());
        assert_eq!(
            status.sources[0].connected_at.as_deref(),
            Some("2026-05-05T10:15:00Z")
        );
        assert_eq!(
            status.sources[0].config.path_hint.as_deref(),
            Some("~/.codex/config.toml")
        );
        assert!(status.sources[0].agent_status.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registered_account_slot_warning_does_not_claim_current_login_is_missing() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut snapshot = available_agent_status(SourceKind::ClaudeCode, "2026-09-03T10:20:00Z");
        snapshot.status = AgentStatusState::Degraded;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_registered_slot_needs_attention_current_available",
            AgentDiagnosticSeverity::Warning,
            "One saved connection needs attention.",
        ));

        let state = daemon.inner.lock().expect("state");
        let health = source_health_from_agent_status(&state, snapshot);

        assert_eq!(health.state, SourceState::NeedsConfirmation);
        assert_eq!(health.grade, HealthGrade::Warning);
        assert_eq!(health.problems[0].code, StableProblemCode::SecretExpired);
        assert!(health.problems[0].title.contains("durable connections"));
        assert!(health.problems[0]
            .detail
            .contains("current login remains available"));
    }

    #[test]
    fn codex_usage_read_failure_is_a_retrying_warning_never_an_expired_secret() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut snapshot = available_agent_status(SourceKind::Codex, "2026-09-03T10:20:00Z");
        snapshot.status = AgentStatusState::Degraded;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "codex_usage_read_retrying",
            AgentDiagnosticSeverity::Warning,
            "A Codex usage check failed.",
        ));

        let state = daemon.inner.lock().expect("state");
        let health = source_health_from_agent_status(&state, snapshot);

        assert_eq!(health.state, SourceState::Healthy);
        assert_eq!(health.grade, HealthGrade::Warning);
        assert_eq!(health.problems.len(), 1);
        assert_eq!(health.problems[0].code, StableProblemCode::Unknown);
        assert_eq!(health.problems[0].title, CODEX_USAGE_READ_RETRYING_TITLE);
        assert!(health.problems[0].retryable);
        // Its own canonical reason, so the web can treat it as a soft
        // warning; the wire problem code stays `unknown`.
        assert_eq!(
            local_health_problem_code_slug(&health.problems[0]),
            "codex_usage_check_retrying"
        );
        let wire = serde_json::to_value(&health.problems[0]).expect("problem json");
        assert_eq!(wire["code"], "unknown");
    }

    #[test]
    fn registered_account_slot_warning_preserves_missing_current_login() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut snapshot = available_agent_status(SourceKind::ClaudeCode, "2026-09-03T10:20:00Z");
        snapshot.status = AgentStatusState::AuthRequired;
        snapshot.diagnostics.push(AgentStatusDiagnostic::source(
            "claude_registered_slot_needs_attention",
            AgentDiagnosticSeverity::Warning,
            "One saved connection needs attention.",
        ));

        let state = daemon.inner.lock().expect("state");
        let health = source_health_from_agent_status(&state, snapshot);

        assert_eq!(health.state, SourceState::NeedsConfirmation);
        assert_eq!(health.problems[0].code, StableProblemCode::SecretMissing);
        assert!(!health.problems[0]
            .detail
            .contains("current login remains available"));
    }

    fn paused_usage_checks_status(paused: bool) -> DaemonStatus {
        paused_usage_checks_status_for(usize::from(paused))
    }

    fn paused_usage_checks_status_for(accounts: usize) -> DaemonStatus {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut snapshot = available_agent_status(SourceKind::ClaudeCode, "2026-10-03T06:46:07Z");
        for _ in 0..accounts {
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                agent_status::CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE,
                AgentDiagnosticSeverity::Warning,
                "Claude usage checks paused for this account after the provider rejected sign-in; next automatic check 2026-10-04T05:00:00Z. Last readings stay shown until then.",
            ));
        }
        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(&mut state, snapshot);
        }
        daemon.status(TOKEN).expect("status")
    }

    #[test]
    fn paused_usage_checks_give_claude_source_an_attention_grade() {
        let status = paused_usage_checks_status(true);
        let source = &status.sources[0];
        assert_eq!(source.state, SourceState::Healthy);
        assert_eq!(source.grade, HealthGrade::Warning);
        assert_eq!(source.problems.len(), 1);
        let problem = &source.problems[0];
        assert_eq!(problem.code, StableProblemCode::Unknown);
        assert_eq!(problem.title, "Claude usage checks paused");
        assert!(problem
            .detail
            .starts_with("Claude usage checks paused for this account after the provider rejected sign-in; next automatic check 2026-10-04T05:00:00Z."));
        assert!(!problem.retryable);
        assert!(source.recommended_actions.is_empty());
        // Existing problem code on the wire, so strict older decoders keep working.
        let wire = serde_json::to_value(problem).expect("problem json");
        assert_eq!(wire["code"], "unknown");

        let canonical = status.canonical_health.as_ref().expect("canonical health");
        let canonical_source = &canonical.sources[0];
        assert_eq!(canonical_source.state, LocalHealthSourceState::Healthy);
        assert_eq!(
            canonical_source.blocking_reason.as_deref(),
            Some("usage_checks_paused")
        );
        assert!(canonical_source.next_action.is_none());
        // Not a machine blocker: overall health matches the unpaused machine.
        let healthy = paused_usage_checks_status(false);
        let healthy_canonical = healthy.canonical_health.as_ref().expect("canonical");
        assert_eq!(canonical.overall.state, healthy_canonical.overall.state);
        assert_eq!(canonical.blockers.len(), healthy_canonical.blockers.len());
    }

    /// [behaviour] One paused-usage diagnostic per account still makes one
    /// source problem; with several accounts it counts them.
    #[test]
    fn paused_usage_checks_for_two_accounts_make_one_counted_problem() {
        let status = paused_usage_checks_status_for(2);
        let problems = &status.sources[0].problems;
        assert_eq!(problems.len(), 1);
        assert_eq!(
            problems[0].detail,
            "Claude usage checks paused for 2 accounts; Ottto checks each again automatically. Last readings stay shown until then."
        );
    }

    #[test]
    fn available_agent_status_preserves_config_drift_repair_state() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        {
            let mut state = daemon.inner.lock().expect("state");
            let mut drifted = codex_health();
            drifted.state = SourceState::NeedsRepair;
            drifted.grade = HealthGrade::Warning;
            drifted.config.drift = vec![ottto_protocol::ConfigDrift {
                key: "env.OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
                expected: RedactedValue::String("https://relay.ottto.net".to_string()),
                observed: RedactedValue::String("http://localhost:4318".to_string()),
            }];
            drifted.problems = vec![HealthProblem {
                code: StableProblemCode::ConfigDrift,
                title: "Codex telemetry config drifted".to_string(),
                detail: "Use Repair in the Ottto app to update it.".to_string(),
                retryable: true,
            }];
            drifted.recommended_actions = vec![RepairAction {
                action: RepairActionKind::WriteConfig,
                title: "Repair Codex telemetry config".to_string(),
                detail: "Use Repair in the Ottto app to update it.".to_string(),
                requires_approval: true,
                destructive: false,
                approval: RepairActionApproval {
                    surface: RepairApprovalSurface::None,
                    setup_safe: true,
                    server_backed: true,
                    reason: "test repair approval".to_string(),
                },
                backup: None,
            }];
            drifted.last_verified_at = Some("2026-05-05T10:18:00Z".to_string());
            state.sources = vec![drifted];

            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:20:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after refresh");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::NeedsRepair);
        assert_eq!(status.sources[0].grade, HealthGrade::Warning);
        assert_eq!(
            status.sources[0].last_verified_at.as_deref(),
            Some("2026-05-05T10:18:00Z")
        );
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::ConfigDrift
        );
        assert_eq!(
            status.sources[0].recommended_actions[0].action,
            RepairActionKind::WriteConfig
        );
        assert_eq!(status.sources[0].config.drift.len(), 1);
        assert!(status.sources[0].agent_status.is_some());
    }

    #[test]
    fn config_repair_result_clears_cached_config_drift_repair_state() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        {
            let mut state = daemon.inner.lock().expect("state");
            let mut drifted = codex_health();
            drifted.state = SourceState::NeedsRepair;
            drifted.grade = HealthGrade::Warning;
            drifted.config.drift = vec![ottto_protocol::ConfigDrift {
                key: "env.OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
                expected: RedactedValue::String("https://relay.ottto.net".to_string()),
                observed: RedactedValue::String("http://localhost:4318".to_string()),
            }];
            drifted.problems = vec![HealthProblem {
                code: StableProblemCode::ConfigDrift,
                title: "Codex telemetry config drifted".to_string(),
                detail: "Use Repair in the Ottto app to update it.".to_string(),
                retryable: true,
            }];
            drifted.recommended_actions = vec![RepairAction {
                action: RepairActionKind::WriteConfig,
                title: "Repair Codex telemetry config".to_string(),
                detail: "Use Repair in the Ottto app to update it.".to_string(),
                requires_approval: true,
                destructive: false,
                approval: RepairActionApproval {
                    surface: RepairApprovalSurface::None,
                    setup_safe: true,
                    server_backed: true,
                    reason: "test repair approval".to_string(),
                },
                backup: None,
            }];
            state.sources = vec![drifted];
        }

        daemon
            .record_config_repair_result(
                &SourceKind::Codex,
                SourceConfigState {
                    discovered: true,
                    path_hint: Some("~/.codex/config.toml".to_string()),
                    fingerprint: Some("sha256:clean".to_string()),
                    drift: Vec::new(),
                },
            )
            .expect("record clean config repair");

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:25:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after repair");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
        assert!(status.sources[0].config.drift.is_empty());
        assert_eq!(
            status.sources[0].config.fingerprint.as_deref(),
            Some("sha256:clean")
        );
    }

    #[test]
    #[serial]
    fn telemetry_configured_reflects_keystore_or_relay_device_and_skips_pi() {
        let store_dir = std::env::temp_dir().join(format!(
            "ottto-telemetry-configured-test-{}",
            std::process::id()
        ));
        let support_dir = store_dir.join("support");
        let secret_dir = store_dir.join("secrets");
        let _ = std::fs::remove_dir_all(&store_dir);
        let _key_guard = TestEnvVar::set(keychain::TELEMETRY_KEY_FILE_STORE_ENV, &store_dir);
        let _support_guard = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secret_guard = TestEnvVar::set(ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV, &secret_dir);

        // Empty keystore/device binding: Codex / Claude are telemetry sources but
        // unconfigured; Pi has no local live-telemetry concept at all.
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::Codex),
            Some(false)
        );
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::ClaudeCode),
            Some(false)
        );
        assert_eq!(telemetry_configured_for_source(&SourceKind::Pi), None);

        // Setup-run install provisions a relay device + fallback secret rather
        // than a legacy per-source setup key. That must still count as live
        // telemetry configured for the sources included in the binding.
        ottto_core::FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["claude_code".to_string()],
            })
            .expect("save relay device binding");
        std::fs::create_dir_all(&secret_dir).expect("create secret dir");
        std::fs::write(
            secret_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device_secret_test",
        )
        .expect("save relay device secret fallback");
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::Codex),
            Some(false)
        );
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::ClaudeCode),
            Some(true)
        );

        // A legacy key cannot re-enable Codex managed telemetry.
        keychain::TelemetryKeyStore::production()
            .save(&SourceKind::Codex, "key_test", "secret")
            .expect("save telemetry key");
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::Codex),
            Some(false)
        );
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::ClaudeCode),
            Some(true)
        );

        let _ = std::fs::remove_dir_all(&store_dir);
    }

    #[test]
    fn personal_meter_local_snapshot_uses_local_evidence_not_totals() {
        let daemon = daemon();
        daemon
            .record_reconciliation_enabled(SourceKind::Codex, true, 30)
            .expect("record reconciliation");
        let mut snapshot = available_agent_status(SourceKind::Codex, "2026-05-05T10:20:00Z");
        snapshot.account = Some(ottto_protocol::AgentAccountStatus {
            login_state: ottto_protocol::AgentLoginState::SignedIn,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            email: Some("ron@example.com".to_string()),
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: Some("plus".to_string()),
            subscription_product: Some("ChatGPT Plus".to_string()),
            billing_channel: Some("chatgpt".to_string()),
            subscription_period_start: None,
            subscription_period_end: None,
            subscription_period_last_checked_at: None,
            account_identifier_hash: Some("acct_hash".to_string()),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("local_status".to_string()),
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: ottto_protocol::AgentStatusConfidence::High,
            confidence: ottto_protocol::AgentStatusConfidence::High,
        });
        snapshot.model = Some(ottto_protocol::AgentModelStatus {
            active_model: Some("gpt-5-codex".to_string()),
            default_model: None,
            provider: Some("openai".to_string()),
            available_models: Vec::new(),
            available_model_details: Vec::new(),
            context_window_tokens: None,
        });
        snapshot.quota_windows = vec![
            AgentQuotaWindow {
                name: "weekly".to_string(),
                scope: ottto_protocol::AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::Ok,
                freshness: AgentQuotaWindowFreshness::Fresh,
                account_label: Some("ron@example.com".to_string()),
                window_seconds: Some(604_800),
                started_at: Some("2026-05-04T00:00:00Z".to_string()),
                resets_at: Some("2026-05-11T00:00:00Z".to_string()),
                quota: Some(100),
                remaining: Some(42),
                used_percent: Some(58),
                left_percent: Some(42),
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "other-desktop-account".to_string(),
                scope: ottto_protocol::AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::RateLimited,
                freshness: AgentQuotaWindowFreshness::Fresh,
                account_label: Some("other@example.com".to_string()),
                account_identifier_hash: Some("other-account-hash".to_string()),
                organization_identifier_hash: Some("other-organization-hash".to_string()),
                window_seconds: Some(604_800),
                started_at: Some("2026-05-04T00:00:00Z".to_string()),
                resets_at: Some("2026-05-11T00:00:00Z".to_string()),
                quota: Some(100),
                remaining: Some(0),
                used_percent: Some(100),
                left_percent: Some(0),
                ..Default::default()
            },
            AgentQuotaWindow {
                name: "other-desktop-organization".to_string(),
                scope: ottto_protocol::AgentQuotaWindowScope::Account,
                status: AgentQuotaWindowStatus::RateLimited,
                freshness: AgentQuotaWindowFreshness::Fresh,
                account_label: Some("ron@example.com".to_string()),
                organization_identifier_hash: Some("other-organization-hash".to_string()),
                window_seconds: Some(604_800),
                used_percent: Some(100),
                left_percent: Some(0),
                ..Default::default()
            },
        ];
        snapshot.plan_observations = vec![ottto_protocol::AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: Some("2026-05-05T10:20:00Z".to_string()),
            evidence_method: Some("local_status".to_string()),
            source_session_id: None,
            provider: Some("openai".to_string()),
            billing_provider: Some("openai".to_string()),
            model_provider: Some("openai".to_string()),
            billing_channel: Some("chatgpt".to_string()),
            auth_mode: Some("oauth".to_string()),
            gateway_provider: None,
            subscription_product: Some("ChatGPT Plus".to_string()),
            plan_type: Some("plus".to_string()),
            account_label: Some("ron@example.com".to_string()),
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: Some("acct_hash".to_string()),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("local_status".to_string()),
            billing_identity_confidence: ottto_protocol::AgentStatusConfidence::High,
            confidence: ottto_protocol::AgentStatusConfidence::High,
            is_current: Some(true),
        }];

        {
            let mut state = daemon.state().expect("state");
            upsert_agent_status_snapshot(&mut state, snapshot);
            let health = state.sources.first_mut().expect("source health");
            health.collector = Some(ottto_protocol::LocalCollectorHealth {
                state: ottto_protocol::LocalCollectorState::Warm,
                last_scan_started_at: Some("2026-05-05T10:19:00Z".to_string()),
                last_scan_finished_at: Some("2026-05-05T10:19:30Z".to_string()),
                last_success_at: Some("2026-05-05T10:19:30Z".to_string()),
                last_uploaded_count: 3,
                last_scanned_session_count: 2,
                last_scanned_file_count: 2,
                last_backfill_window_days: 183,
                last_backfill_file_limit: 1_000,
                last_discovered_file_count: 2,
                last_skipped_file_count_due_to_limit: 0,
                last_scan_cap_hit: false,
                next_retry_at: None,
                collector_version: Some("local-enriched/1".to_string()),
                parser_version: Some("codex-jsonl/1".to_string()),
            });
            health.detected_uses = vec![DetectedUse {
                gateway_provider: "openai".to_string(),
                plan_fingerprint: Some("plus".to_string()),
                account_identifier_hash: Some("acct_hash".to_string()),
                organization_identifier_hash: None,
                subscription_product: Some("ChatGPT Plus".to_string()),
                account_label: Some("ron@example.com".to_string()),
                last_seen_at: "2026-05-05T10:19:30Z".to_string(),
                token_volume_recent: vec![DetectedUseTokenSample {
                    at: "2026-05-05T10:00:00Z".to_string(),
                    tokens: 4096,
                }],
                quota_window_state: DetectedUseQuotaWindowState::Ok,
                quota_used_percent: Some(58),
                quota_resets_at: Some("2026-05-11T00:00:00Z".to_string()),
            }];
        }

        let response = crate::control::handle_request(
            &daemon,
            ottto_protocol::LocalControlRequest {
                request_id: "req_meter".to_string(),
                protocol_version: PROTOCOL_VERSION,
                token: Some(TOKEN.to_string()),
                client_kind: Some(ottto_protocol::LocalClientKind::Cli),
                client_install_owner: None,
                command: ottto_protocol::LocalControlCommand::PersonalMeterLocalSnapshot {
                    source: Some(SourceKind::Codex),
                },
            },
        );

        assert!(response.ok, "response should succeed: {:?}", response.error);
        let payload: PersonalMeterLocalSnapshot =
            serde_json::from_value(response.payload.expect("personal meter payload"))
                .expect("payload should match protocol type");
        assert_eq!(payload.schema_version, "personal_meter.local_snapshot.v1");
        assert_eq!(payload.machine_id, "machine_test");
        assert_eq!(payload.sources.len(), 1);
        let source = &payload.sources[0];
        assert_eq!(source.source, SourceKind::Codex);
        assert!(!source.included_in_totals);
        assert_eq!(source.provider.as_deref(), Some("openai"));
        assert_eq!(source.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(source.plan.as_deref(), Some("ChatGPT Plus"));
        assert_eq!(
            source
                .account
                .as_ref()
                .and_then(|account| account.account_identifier_hash.as_deref()),
            Some("acct_hash")
        );
        assert_eq!(source.quota_windows.len(), 1);
        assert_eq!(
            source.freshness.status,
            PersonalMeterLocalFreshnessStatus::Fresh
        );
        assert_eq!(
            source.collector.status,
            PersonalMeterLocalCollectorStatus::Ok
        );
        assert_eq!(source.collector.last_uploaded_count, 3);
        assert_eq!(
            source.pending_local_delta.status,
            PersonalMeterLocalValueStatus::Unknown
        );
        assert!(!source.pending_local_delta.included_in_totals);
        assert_eq!(
            source.pending_local_delta.basis,
            "backend_inclusion_watermark_unavailable"
        );
        assert_eq!(source.pending_local_delta.total_tokens, None);
        assert_eq!(source.pending_local_delta.detected_use_count, 1);
        assert_eq!(
            source.pending_local_delta.recent_token_volume[0].tokens,
            4096
        );
    }

    fn available_agent_status(source: SourceKind, captured_at: &str) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            source,
            status: AgentStatusState::Available,
            collection_method: ottto_protocol::AgentStatusCollectionMethod::CliJson,
            captured_at: captured_at.to_string(),
            expires_at: "2026-05-05T10:35:00Z".to_string(),
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

    fn pi_subscription_oauth_agent_status(captured_at: &str) -> AgentStatusSnapshot {
        let mut snapshot = available_agent_status(SourceKind::Pi, captured_at);
        snapshot.model = Some(ottto_protocol::AgentModelStatus {
            active_model: Some("gpt-5.5".to_string()),
            default_model: Some("gpt-5.5".to_string()),
            provider: Some("openai-codex".to_string()),
            available_models: vec!["gpt-5.5".to_string()],
            available_model_details: vec![ottto_protocol::AgentAvailableModelStatus {
                id: "gpt-5.5".to_string(),
                provider: Some("openai-codex".to_string()),
                model_provider: Some("openai".to_string()),
                billing_provider: Some("openai".to_string()),
                billing_channel: Some("subscription".to_string()),
                auth_mode: Some("oauth".to_string()),
                gateway_provider: None,
                subscription_product: Some("chatgpt".to_string()),
                source_category: Some("chatgpt_openai_subscription".to_string()),
                account_identifier_hash: Some("acct_hash".to_string()),
                organization_identifier_hash: None,
                credential_fingerprint_hash: None,
                billing_identity_evidence: Some("provider_account_id".to_string()),
                billing_identity_confidence: ottto_protocol::AgentStatusConfidence::High,
                context_window_tokens: None,
                max_output_tokens: None,
                supports_thinking: Some(true),
                supports_images: None,
            }],
            context_window_tokens: None,
        });
        snapshot
    }

    mod tracking_confirmation_tests {
        use super::*;

        #[test]
        fn collection_status_requires_eligibility_and_resets_after_pause_and_both_policy_stops() {
            if !crate::test_isolation::run_here() {
                return;
            }
            use crate::scan_clock::with_clock;
            use ottto_protocol::SourceCollectionState::{Collecting, Stalled};
            let root = crate::test_scratch::private_dir("collection-status");
            let _support = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
            let daemon = daemon();
            for source in [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi] {
                let scan_source = snapshot_sync::snapshot_source_of_kind(&source);
                let slug = source_slug(&source).to_string();
                {
                    let mut state = daemon.state().unwrap();
                    let mut health = codex_health();
                    health.source = source.clone();
                    health.state = SourceState::Healthy;
                    health.config.discovered = false; // Installation is distinct from config.
                    state.sources = vec![health];
                    state.registered_source_grants = vec![slug.clone()];
                }
                let status = || {
                    status_from_state_with_relay_finding(&mut daemon.state().unwrap(), None)
                        .sources
                        .remove(0)
                };
                with_clock(0, || {
                    snapshot_sync::reset_collection_health(scan_source);
                    assert!(
                        status().collection.is_none(),
                        "eligible but no scan offered"
                    );
                    snapshot_sync::start_collection_health(scan_source);
                    assert_eq!(status().collection.unwrap().state, Collecting);
                    assert!(
                        daemon.state().unwrap().sources[0].collection.is_none(),
                        "response only"
                    );
                    daemon.state().unwrap().registered_source_grants.clear();
                    assert!(status().collection.is_none());
                    daemon.state().unwrap().registered_source_grants = vec![slug.clone()];
                    snapshot_sync::start_collection_health(scan_source);
                    daemon.state().unwrap().sources[0].state = SourceState::NotFound;
                    assert!(status().collection.is_none());
                    daemon.state().unwrap().sources[0].state = SourceState::Healthy;
                    snapshot_sync::start_collection_health(scan_source);
                    snapshot_sync::disable_snapshot_source(&root, scan_source).unwrap();
                    assert!(status().collection.is_none());
                    // Model a positive prepare hint that was already in flight at pause.
                    daemon
                        .record_reconciliation_enabled(source.clone(), true, 30)
                        .unwrap();
                });
                with_clock(7200, || {
                    snapshot_sync::reconnect_snapshot_source(&root, scan_source).unwrap();
                    snapshot_sync::resume_reconnected_sources(&root);
                    assert!(status().collection.is_none());
                    snapshot_sync::start_collection_health(scan_source);
                    assert_eq!(status().collection.unwrap().state, Collecting);
                });
                for (window, enabled) in [(0, true), (30, false)] {
                    with_clock(11000, || {
                        assert_eq!(status().collection.unwrap().state, Stalled)
                    });
                    daemon
                        .record_reconciliation_enabled(source.clone(), enabled, window)
                        .unwrap();
                    assert!(status().collection.is_none());
                    // A later cycle can offer a source before learning its positive hint.
                    snapshot_sync::start_collection_health(scan_source);
                    with_clock(20000, || {
                        daemon
                            .record_reconciliation_enabled(source.clone(), true, 30)
                            .unwrap();
                        assert_eq!(status().collection.unwrap().state, Collecting);
                    });
                    // Start the next scenario from the same epoch without intentional stop time.
                    with_clock(7200, || {
                        snapshot_sync::reset_collection_health(scan_source);
                        snapshot_sync::start_collection_health(scan_source);
                    });
                }
            }
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[serial]
        fn tracking_status_omits_inapplicable_episodes_without_mutating_saved_state() {
            let root = crate::test_scratch::private_dir("tracking-status-applicability");
            let _support = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
            let daemon = daemon();
            let source = SourceKind::Codex;
            let mut state = daemon.state().unwrap();
            state.sources = vec![codex_health()];
            assert!(serde_json::to_value(&state.sources[0])
                .unwrap()
                .get("tracking_confirmation")
                .is_none());
            state
                .tracking_confirmation
                .arm(&source, "2026-11-15T10:00:00Z".into(), true);
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_none()
            );
            state.registered_source_grants = vec!["codex".into()];
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_some()
            );
            state.source_reconciliation.insert("codex".into(), false);
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_none()
            );
            state.source_reconciliation.clear();
            state.sources[0].config.discovered = false;
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_some(),
                "config discovery is not installation; sources without config still confirm"
            );
            state.sources[0].config.discovered = true; // historical config is not installation
            state.sources[0].state = SourceState::NotFound;
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_none()
            );
            state.sources[0].state = SourceState::Healthy;
            crate::snapshot_sync::disable_snapshot_source(&root, snapshots::SnapshotSource::Codex)
                .unwrap();
            assert!(
                status_from_state_with_relay_finding(&mut state, None).sources[0]
                    .tracking_confirmation
                    .is_none()
            );
            assert!(
                state.tracking_confirmation.saved(&source).is_some(),
                "status is read-only"
            );
            assert!(state.sources[0].tracking_confirmation.is_none());
            drop(state);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[serial]
        fn passive_verification_cannot_confirm_but_active_smoke_can_and_episode_restarts() {
            let root = crate::test_scratch::private_dir("tracking-episode-restart");
            let _support = TestEnvVar::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root);
            let daemon = daemon().with_source_state_dir(root.join("sources"));
            let since = "2026-11-15T10:00:00Z";
            daemon.state().unwrap().registered_source_grants =
                vec!["pi".into(), "codex".into(), "claude_code".into()];
            for source in [SourceKind::Pi, SourceKind::Codex, SourceKind::ClaudeCode] {
                daemon
                    .state()
                    .unwrap()
                    .tracking_confirmation
                    .arm(&source, since.into(), true);
                let mut result = verified_codex("2026-11-15T10:01:00Z");
                result.source = source.clone();
                // Same empty config returned by Pi verification, including absent path/fingerprint.
                result.config = SourceConfigState {
                    discovered: false,
                    path_hint: None,
                    fingerprint: None,
                    drift: Vec::new(),
                };
                result.smoke_after = Some(since.into()); // passive paths also populate this
                daemon.record_verification_result(&result).unwrap();
                assert!(daemon.tracking_episode(&source).is_some());
                assert!(daemon
                    .status(TOKEN)
                    .unwrap()
                    .sources
                    .iter()
                    .find(|health| health.source == source)
                    .unwrap()
                    .tracking_confirmation
                    .is_some());
                if source == SourceKind::ClaudeCode {
                    let (generation, _) = daemon.tracking_episode(&source).unwrap();
                    daemon
                        .record_verification_result_with_tracking(
                            &result,
                            Some((generation, since)),
                        )
                        .unwrap();
                    assert!(daemon.tracking_episode(&source).is_none());
                }
            }
            let restarted = super::daemon().with_source_state_dir(root.join("sources"));
            assert!(restarted.tracking_episode(&SourceKind::Pi).is_some());
            assert!(restarted.tracking_episode(&SourceKind::Codex).is_some());
            let state = restarted.state().unwrap();
            assert_eq!(
                state
                    .tracking_confirmation
                    .saved(&SourceKind::ClaudeCode)
                    .unwrap()
                    .confirmed_at
                    .as_deref(),
                Some("2026-11-15T10:01:00Z")
            );
            assert!(state
                .sources
                .iter()
                .all(|health| health.tracking_confirmation.is_none()));
            drop(state);
            restarted.state().unwrap().clear_source_state();
            assert!(restarted.tracking_episode(&SourceKind::Pi).is_none());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    fn verified_codex(last_received_at: &str) -> SourceVerificationResult {
        SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Verified,
            verified: true,
            records_seen: 1,
            last_record_id: Some("record_1".to_string()),
            last_received_at: Some(last_received_at.to_string()),
            smoke_after: None,
            message: StableMessage {
                code: "verified".to_string(),
                text: "Codex verification passed.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        }
    }

    fn failed_codex_reconnect() -> SourceVerificationResult {
        SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::ReconnectRequired,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: Some("2026-05-05T10:15:00Z".to_string()),
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "setup_run_token_invalid".to_string(),
                text: "Use Sign in in the Ottto app to refresh it.".to_string(),
            },
            route_results: Vec::new(),
            check: None,
        }
    }

    /// Minimal scoped env-var guard for the `#[serial]` telemetry test; restores
    /// the previous value (or removes the var) on drop.
    struct TestEnvVar {
        key: &'static str,
        previous: Option<String>,
    }

    impl TestEnvVar {
        fn set(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for TestEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn codex_health() -> SourceHealth {
        SourceHealth {
            source: SourceKind::Codex,
            descriptor: source_descriptor(&SourceKind::Codex),
            state: SourceState::Healthy,
            grade: HealthGrade::Ok,
            account_binding: AccountBindingState {
                expected_account_id: Some("acct_test".to_string()),
                observed_account_id: Some("acct_test".to_string()),
                matched: Some(true),
            },
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            collector: None,
            agent_status: None,
            plan_observations: Vec::new(),
            detected_uses: Vec::new(),
            active_session_reconciliation: None,
            collection: None,
            tracking_confirmation: None,
            last_seen_at: Some("2026-05-05T09:09:00Z".to_string()),
            last_verified_at: Some("2026-05-05T09:09:30Z".to_string()),
            problems: Vec::new(),
            recommended_actions: Vec::new(),
            connected_at: Some("2026-05-05T09:00:00Z".to_string()),
            telemetry_configured: Some(true),
            reconciliation_enabled: Some(true),
            source_paused: false,
        }
    }

    fn pending_claim(claim_code: &str, nonce: &str) -> PendingAuthClaim {
        PendingAuthClaim {
            claim_code: claim_code.to_string(),
            claim_token: format!("{claim_code}_token"),
            nonce: nonce.to_string(),
            claim_url: format!("https://ottto.net/setup/claim?code={claim_code}&nonce={nonce}"),
            expires_at: "2026-05-05T10:00:00Z".to_string(),
        }
    }

    fn account(user_id: &str, email: &str) -> LocalAccountBinding {
        LocalAccountBinding {
            state: LocalAccountState::Connected,
            user: Some(LocalAccountUser {
                id: user_id.to_string(),
                email: email.to_string(),
                display_name: Some("Alex".to_string()),
            }),
            organization: Some(LocalAccountOrganization {
                id: "org_1".to_string(),
                name: "Ottto".to_string(),
            }),
            connected_at: Some("2026-05-05T10:00:00Z".to_string()),
            last_refreshed_at: Some("2026-05-05T10:00:00Z".to_string()),
            message: Some(StableMessage {
                code: "connected".to_string(),
                text: "This Mac is connected to Ottto.".to_string(),
            }),
            can_reconnect: None,
        }
    }

    fn connection(setup_run_id: &str) -> LocalConnectionBinding {
        LocalConnectionBinding {
            setup_run_id: setup_run_id.to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        }
    }
}
