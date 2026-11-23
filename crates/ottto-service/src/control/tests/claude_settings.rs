//! Default Claude settings writer: what it keeps, what it migrates, and how
//! Enable and Fix report a kept root.
use super::*;
use crate::agent_configs::claude_managed_settings::Outcome;

fn relay_env(port: u16) -> serde_json::Map<String, serde_json::Value> {
    claude_code_relay_env_with_base(&test_machine(), &format!("http://127.0.0.1:{port}"))
        .into_iter()
        .map(|(key, value)| (key.to_owned(), json!(value)))
        .collect()
}

fn write_default(path: &Path, support: &Path, clear_opt_out: bool) -> ConfigPatchResult {
    patch_claude_code_settings_at_with_relay_base(
        path,
        &test_machine(),
        support,
        "http://127.0.0.1:48123",
        clear_opt_out,
    )
    .unwrap()
}

/// [behaviour] An opt-out or an external exporter keeps the telemetry env as
/// it was and reports why, while the status line wrapper is still installed.
/// A linked settings file is never written.
#[test]
fn default_settings_keep_optout_external_exporter_and_linked_file() {
    let root = control_test_root("claude-settings-kept");
    let path = root.join("settings.json");
    let support = root.join("support");
    for (body, clear, kept) in [
        (
            r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"false"}}"#,
            false,
            Outcome::OptedOut,
        ),
        (
            r#"{"env":{"OTEL_LOGS_EXPORTER":"none"}}"#,
            false,
            Outcome::OptedOut,
        ),
        (
            r#"{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example"},"statusLine":{"type":"command","command":"user-status"}}"#,
            false,
            Outcome::ExternalTelemetry,
        ),
        // Enable clears an opt-out but never adopts an external exporter.
        (
            r#"{"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"0","OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"https://collector.example/v1/logs"}}"#,
            true,
            Outcome::ExternalTelemetry,
        ),
    ] {
        fs::write(&path, body).unwrap();
        assert_eq!(write_default(&path, &support, clear).kept, Some(kept));
        let before: serde_json::Value = serde_json::from_str(body).unwrap();
        let after: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(after["env"], before["env"]);
        assert_eq!(
            after["statusLine"]["command"],
            expected_claude_statusline_command(&support)
        );
        assert!(claude_statusline_wrapper_path(&support).is_file());
    }
    let target = root.join("linked-target.json");
    fs::write(&target, "{}").unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(
        write_default(&path, &support, false).kept,
        Some(Outcome::Linked)
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "{}");
    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] Missing, partial, stale-port, "true"-flag, Ottto's earlier
/// direct-to-cloud, over-1-MiB and linked-directory settings all get the
/// relay env; user keys stay.
#[test]
fn default_settings_write_relay_env_over_ottto_and_partial_shapes() {
    let root = control_test_root("claude-settings-written");
    let path = root.join("settings.json");
    let support = root.join("support");
    let mut stale = relay_env(48122);
    stale.insert("USER_FLAG".into(), json!("keep"));
    let mut truthy = relay_env(48123);
    truthy.insert("CLAUDE_CODE_ENABLE_TELEMETRY".into(), json!("true"));
    truthy.insert("USER_FLAG".into(), json!("keep"));
    for (body, clear) in [
        (None, false),
        (
            Some(json!({"env":{"CLAUDE_CODE_ENABLE_TELEMETRY":"0","USER_FLAG":"keep"}})),
            true,
        ),
        (
            Some(
                json!({"env":{"OTEL_EXPORTER_OTLP_HEADERS":"X-Ottto-Local-Relay=claude_code","USER_FLAG":"keep"}}),
            ),
            false,
        ),
        (Some(json!({ "env": stale })), false),
        (Some(json!({ "env": truthy })), false),
        (
            Some(json!({"env":{
                "CLAUDE_CODE_ENABLE_TELEMETRY":"1",
                "OTEL_METRICS_EXPORTER":"otlp",
                "OTEL_LOGS_EXPORTER":"otlp",
                "OTEL_EXPORTER_OTLP_PROTOCOL":"http/protobuf",
                "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"https://api.ottto.net/v1/metrics",
                "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT":"https://api.ottto.net/v1/logs",
                "OTEL_EXPORTER_OTLP_HEADERS":"X-API-Key=otel_redacted",
                "OTEL_RESOURCE_ATTRIBUTES":"service.name=claude-code,enduser.id=usr_test",
                "USER_FLAG":"keep"}})),
            false,
        ),
        (
            Some(json!({"padding": "x".repeat(1024 * 1024 + 1), "env":{"USER_FLAG":"keep"}})),
            false,
        ),
    ] {
        let _ = fs::remove_file(&path);
        if let Some(body) = &body {
            fs::write(&path, serde_json::to_vec(body).unwrap()).unwrap();
        }
        let result = write_default(&path, &support, clear);
        assert_eq!((result.changed, result.kept), (true, None));
        let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let env = written["env"].as_object().unwrap();
        for (key, value) in relay_env(48123) {
            assert_eq!(env.get(&key), Some(&value), "{key}");
        }
        assert_eq!(env.contains_key("USER_FLAG"), body.is_some());
        assert_eq!(
            written.get("padding"),
            body.as_ref().and_then(|body| body.get("padding"))
        );
    }
    // The user's root may sit behind a directory link.
    let alias = root.with_extension("alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    fs::write(&path, "{}").unwrap();
    let result = write_default(&alias.join("settings.json"), &support, false);
    assert_eq!((result.changed, result.kept), (true, None));
    let _ = fs::remove_file(alias);
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] With an external exporter, Enable fails with the reason before
/// writing any shell env, and Fix reports the same reason.
#[test]
#[serial]
fn enable_and_fix_report_kept_default_settings() {
    let _lock = lock_backend_test_env();
    let root = control_test_root("claude-settings-kept-enable-fix");
    create_control_test_dir(&root.join(".claude"));
    let _home = EnvVarGuard::set_path("HOME", &root);
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &root.join("support"));
    let _patch = EnvVarGuard::remove("OTTTO_PATCH_CLAUDE_CODE_DISABLED");
    fs::write(
        root.join(".claude/settings.json"),
        r#"{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"https://collector.example"}}"#,
    )
    .unwrap();
    let reason = claude_settings_kept_reason(Outcome::ExternalTelemetry).1;
    assert_eq!(
        apply_telemetry_config(&daemon(), &SourceKind::ClaudeCode),
        Err(LocalApiError::LocalOperationFailed(reason.to_string()))
    );
    assert!(!root.join(".ottto/claude-telemetry.env").exists());
    assert!(!root.join(".zshrc").exists());
    let response = handle_request(
        &daemon(),
        LocalControlRequest {
            request_id: "req_fix_claude_kept".to_string(),
            protocol_version: PROTOCOL_VERSION,
            token: Some("token".to_string()),
            client_kind: Some(LocalClientKind::Cli),
            client_install_owner: None,
            command: LocalControlCommand::Repair {
                source: SourceKind::ClaudeCode,
                dry_run: false,
            },
        },
    );
    assert!(response.ok, "{response:?}");
    let plan: RepairPlan =
        serde_json::from_value(response.payload.expect("payload")).expect("repair plan");
    assert_eq!(plan.status, RepairPlanStatus::Failed);
    assert_eq!(plan.actions[0].detail, reason);
    let _ = fs::remove_dir_all(root);
}
