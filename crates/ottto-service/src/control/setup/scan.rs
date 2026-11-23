//! setup scan for local control.

use crate::control::api_url_with_base;
use crate::control::attach_setup_run_by_claim_code;
use crate::control::auth_reset;
use crate::control::backend_post_json;
use crate::control::backend_post_json_with_timeout;
use crate::control::claude_code_telemetry_config_installed;
use crate::control::claude_managed_config_preview;
use crate::control::codex_config_state_at;
use crate::control::codex_managed_config_preview;
use crate::control::current_rfc3339;
use crate::control::default_support_dir;
use crate::control::executable_exists;
use crate::control::home_path;
use crate::control::json;
use crate::control::lock_setup_run_binding;
use crate::control::operating_system_slug;
use crate::control::process_setup_actions_with_status;
use crate::control::read_optional_to_string;
use crate::control::refresh_setup_run_token_via_device_secret;
use crate::control::request_snapshot_sync_after_device_registration;
use crate::control::request_snapshot_sync_after_setup_actions;
use crate::control::require_authorized_local_client;
use crate::control::rfc3339_after_minutes;
use crate::control::setup_result_from_detail;
use crate::control::setup_run_request_with_refresh_mut;
use crate::control::setup_run_token_for_connection;
use crate::control::setup_source_paused;
use crate::control::snapshot_device_credentials_include_source;
use crate::control::source_patch_disabled;
use crate::control::source_slug;
use crate::control::status_for;
use crate::control::terminal_refresh_rejection;
#[cfg(test)]
use crate::control::tests;
use crate::control::validated_api_base_url;
use crate::control::BTreeMap;
use crate::control::ControlTokenStore;
use crate::control::FileConnectionStore;
use crate::control::FileDeviceStore;
use crate::control::KeychainSecretStore;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::LocalDaemon;
use crate::control::MachineIdentity;
use crate::control::OrStatePoisoned;
use crate::control::Path;
use crate::control::RequestAuthorization;
use crate::control::SetupRunActionApiResponse;
use crate::control::SetupRunCredentials;
use crate::control::SetupRunDetailApiResponse;
use crate::control::SetupScanPayload;
use crate::control::SetupScanSource;
use crate::control::SourceKind;
use crate::control::AGENT_STATUS_SNAPSHOT_TTL_MINUTES;
use crate::control::OTTTO_CLIENT_NAME;
use crate::control::OTTTO_SETUP_RUN_TOKEN_ACCOUNT;
use crate::control::PROTOCOL_VERSION;
use crate::control::SETUP_SCAN;
use crate::control::SETUP_SCAN_RESULT_HTTP_TIMEOUT;

pub(in crate::control) fn setup_run(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    sources: Vec<SourceKind>,
    claim_code: Option<String>,
    setup_run_id: Option<String>,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let _attempt = SETUP_SCAN.lock().unwrap_or_else(|p| p.into_inner());
    let status = status_for(daemon, authorization)?;
    crate::snapshot_sync::reset_relay_authorization_backoff();
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let mut setup_run_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
        .load()
        .ok();
    let claim_code_provided = claim_code
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    let requested_setup_run_id = setup_run_id.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    if status.account.state == LocalAccountState::Connected
        && status.account.user.is_some()
        && !claim_code_provided
        && requested_setup_run_id.is_none()
    {
        let mut setup_run_id = connection
            .as_ref()
            .map(|binding| binding.setup_run_id.clone());
        if let Some(binding) = connection.as_ref() {
            // An explicit sign-in on a Mac that looks connected confirms the
            // binding once with the device credential. Only an authoritative
            // terminal refresh answer ends it: the existing local-only reset
            // keeps the prior device proof, and `NeedsUserAction` sends the
            // caller to a fresh browser claim. The ended run is never revived;
            // any other failure keeps the binding and the no-op answer.
            match refresh_setup_run_token_via_device_secret(&binding.api_base_url, binding) {
                Ok(refreshed) => setup_run_id = Some(refreshed.connection.setup_run_id),
                Err(error) if terminal_refresh_rejection(&error).is_some() => {
                    // Only the binding Ottto just answered for is cleared:
                    // `auth_reset` rechecks it under the identity lifecycle
                    // lock, so a binding attached meanwhile is left alone.
                    auth_reset(daemon, authorization, true, false, Some(binding))?;
                    return Err(LocalApiError::SetupRunConnectionMissing);
                }
                Err(_) => {}
            }
        }
        return Ok(json!({
            "status": "completed",
            "already_connected": true,
            "setup_run_id": setup_run_id,
            "claim_code_provided": false,
            "source_count": 0,
            "detected_sources": [],
            "next_question": null,
            "next_action": null,
            "setup_claim_url": null,
            "actions": [],
            "message": "This Mac is already connected. No new setup claim was created.",
        }));
    }

    if let Some(code) = claim_code
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let attached = attach_setup_run_by_claim_code(&api_base_url, code, &status.machine)?;
        let binding = LocalConnectionBinding {
            setup_run_id: attached.setup_run_id.clone(),
            setup_run_token_expires_at: attached.expires_at.clone(),
            machine_id: attached.run.machine_id.clone(),
            claim_code: Some(code.to_string()),
            api_base_url: api_base_url.clone(),
        };
        let _binding_lock = lock_setup_run_binding();
        KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT)
            .save(&attached.setup_run_token)
            .or_state_poisoned()?;
        FileConnectionStore::default()
            .save(&binding)
            .or_state_poisoned()?;
        daemon.bind_setup_run_for_authorized_client(binding.clone())?;
        connection = Some(binding);
        setup_run_token = Some(attached.setup_run_token);
    }

    let connection = connection.ok_or(LocalApiError::SetupRunConnectionMissing)?;
    if let Some(expected_setup_run_id) = requested_setup_run_id.as_ref() {
        if expected_setup_run_id != &connection.setup_run_id {
            return Err(LocalApiError::SetupRunConnectionMismatch);
        }
    }
    let setup_run_token = setup_run_token.ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = SetupRunCredentials {
        setup_run_token,
        connection,
    };

    scan_setup_run_with_action_count(
        daemon,
        &api_base_url,
        &mut credentials,
        &status.machine,
        sources,
        claim_code_provided,
        None,
        &mut 0,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "preserves scan inputs while reporting partial action progress on errors"
)]
pub(in crate::control) fn scan_setup_run_with_action_count(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
    sources: Vec<SourceKind>,
    claim_code_provided: bool,
    expected_device: Option<&str>,
    actions_processed: &mut usize,
) -> Result<serde_json::Value, LocalApiError> {
    let scan = build_local_scan(machine, sources);
    if let Some(expected) = expected_device {
        let device = FileDeviceStore::default().load().or_state_poisoned()?;
        if device.as_ref().map(|d| d.device_id.as_str()) != Some(expected) {
            return Err(LocalApiError::SetupRunConnectionMismatch);
        }
    }
    let mut detail = match publish_scan_result(api_base_url, credentials, &scan) {
        Ok(detail) => detail,
        Err(error) if is_terminal_setup_run_scan_error(&error) => {
            clear_setup_run_connection_if_current(
                daemon,
                &credentials.connection,
                &credentials.setup_run_token,
            )?;
            return Err(LocalApiError::SetupRunConnectionMissing);
        }
        Err(error) => return Err(error),
    };
    let (action_results, _, _) = process_setup_actions_with_status(
        daemon,
        api_base_url,
        credentials,
        machine,
        actions_processed,
    )?;
    if let Some(last) = action_results.last() {
        if let Some(refreshed) = &last.detail {
            detail = refreshed.clone();
        }
    }
    request_snapshot_sync_after_setup_actions(daemon, &action_results);

    // Build the wire result with the same builder the setup-answer and
    // setup-action paths use. Previously this path inlined a byte-identical
    // `json!`, which let a field drift between the two builders; routing through
    // `setup_result_from_detail` guarantees a field threaded for one entry point
    // (e.g. `setup_claim_url`, the verify browser-approval URL) reaches them all.
    setup_result_from_detail(
        &credentials.connection,
        detail,
        claim_code_provided,
        action_results,
    )
}

pub(in crate::control) fn clear_setup_run_connection_if_current(
    daemon: &LocalDaemon,
    failed_connection: &LocalConnectionBinding,
    failed_setup_run_token: &str,
) -> Result<(), LocalApiError> {
    let _binding_lock = lock_setup_run_binding();
    let store = FileConnectionStore::default();
    let persisted = store.load().or_state_poisoned()?;
    if persisted
        .as_ref()
        .is_some_and(|binding| setup_run_binding_matches(binding, failed_connection))
    {
        store.reset().or_state_poisoned()?;
        let current_token = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).load();
        if current_token
            .as_deref()
            .is_ok_and(|token| token == failed_setup_run_token)
        {
            let _ = KeychainSecretStore::new(OTTTO_SETUP_RUN_TOKEN_ACCOUNT).delete();
        }
    }
    daemon.clear_setup_run_for_authorized_client_if_matches(
        &failed_connection.setup_run_id,
        &failed_connection.api_base_url,
    )?;
    Ok(())
}

pub(in crate::control) fn setup_run_binding_matches(
    current: &LocalConnectionBinding,
    expected: &LocalConnectionBinding,
) -> bool {
    current.setup_run_id == expected.setup_run_id && current.api_base_url == expected.api_base_url
}

/// Under the identity lifecycle lock: `expected`, when given, must still be
/// the persisted and the daemon's bound setup run. Otherwise a reattach or a
/// completed sign-in replaced it and nothing of the replacement is touched.
pub(in crate::control) fn require_setup_run_still_bound(
    daemon: &LocalDaemon,
    expected: Option<&LocalConnectionBinding>,
) -> Result<(), LocalApiError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let persisted = FileConnectionStore::default().load().or_state_poisoned()?;
    let bound = daemon.connection_for_authorized_client()?;
    if [persisted, bound].iter().all(|binding| {
        binding
            .as_ref()
            .is_some_and(|binding| setup_run_binding_matches(binding, expected))
    }) {
        Ok(())
    } else {
        Err(LocalApiError::SetupRunConnectionMissing)
    }
}

fn is_terminal_setup_run_scan_error(error: &LocalApiError) -> bool {
    let LocalApiError::Backend(details) = error else {
        return false;
    };
    if !details.endpoint.contains("/api/v1/setup-runs/")
        || !details.endpoint.contains("/local-client/scan-result")
    {
        return false;
    }
    if matches!(details.status, Some(404) | Some(410)) {
        return true;
    }
    // A setup-run token that the backend rejects cannot become valid by
    // polling harder. Clear the stale binding after the first authoritative
    // 401/403 so an unattended CLI cannot hammer an old run forever.
    matches!(details.status, Some(401) | Some(403))
}

pub(in crate::control) fn set_source_marker(
    write: fn(&Path, crate::snapshots::SnapshotSource) -> anyhow::Result<()>,
    source: &SourceKind,
) -> Result<(), LocalApiError> {
    write(
        &default_support_dir(),
        crate::snapshot_sync::snapshot_source_of_kind(source),
    )
    .or_state_poisoned()
}

pub(in crate::control) fn setup_answer(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    answer_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    // Before any connection or POST: collection stops even if the run is gone.
    if answer_type.trim() == "disable_source" {
        set_source_marker(crate::snapshot_sync::disable_snapshot_source, &source)?;
        daemon.clear_tracking_confirmation(&source)?;
    }
    let mut connection = daemon.connection_for_authorized_client()?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = setup_run_token_for_connection(&api_base_url, &connection)?;
    let answer_type = match answer_type.trim() {
        "skip_source" | "disable_source" => answer_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_answer only supports skip_source and disable_source".to_string(),
            ))
        }
    };
    let detail = save_setup_answer(&api_base_url, &mut credentials, &source, &answer_type)?;
    // `disable_source` already revoked with its pause marker.
    if source == SourceKind::ClaudeCode && answer_type == "skip_source" {
        crate::otlp_relay::legacy::revoke_now();
    }
    setup_result_from_detail(&credentials.connection, detail, false, Vec::new())
}

/// The Companion's Pause/Resume of one source on this Mac, saved to the
/// account through the relay. Nothing is deleted and nothing is re-sent.
pub(in crate::control) fn source_collection(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    enabled: bool,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let snapshot_source = crate::snapshot_sync::snapshot_source_of_kind(&source);
    let reply = save_source_collection(&source, enabled, |body| {
        // The pause marker is already durable before any observation write.
        if !enabled {
            daemon
                .clear_tracking_confirmation(&source)
                .map_err(|_| anyhow::anyhow!("tracking state unavailable"))?;
        }
        let (device, secret) = crate::snapshot_client::load_snapshot_device_credentials()?;
        let client = crate::snapshot_client::SnapshotApiClient::new(
            crate::snapshot_sync::snapshot_api_base_url()?,
        );
        let token = client.issue_relay_token(&device, &secret, snapshot_source)?;
        client.upload_source_control(&token, body)
    })?;
    if enabled {
        request_snapshot_sync_after_device_registration(daemon);
    }
    Ok(reply)
}

/// Pause stops collection before any network and stays paused if the save
/// fails. Resume writes nothing until the account accepts it, then applies
/// the reply exactly as a heartbeat's.
pub(in crate::control) fn save_source_collection(
    source: &SourceKind,
    enabled: bool,
    post: impl FnOnce(&serde_json::Value) -> anyhow::Result<serde_json::Value>,
) -> Result<serde_json::Value, LocalApiError> {
    if !enabled {
        // Also revokes Claude's legacy relay.
        set_source_marker(crate::snapshot_sync::disable_snapshot_source, source)?;
    }
    let support_dir = default_support_dir();
    let server_saved = match post(&json!({"source": source, "enabled": enabled})) {
        Ok(reply) => {
            crate::snapshot_sync::apply_source_control(&support_dir, &reply);
            true
        }
        Err(error) if enabled => {
            return Err(LocalApiError::LocalOperationFailed(format!(
                "resume was not saved: {}",
                crate::snapshot_sync::safe_error(&error)
            )))
        }
        Err(error) => {
            eprintln!(
                "source pause not saved: {}",
                crate::snapshot_sync::safe_error(&error)
            );
            false
        }
    };
    let paused = crate::snapshot_sync::source_paused(
        &support_dir,
        crate::snapshot_sync::snapshot_source_of_kind(source),
    );
    Ok(json!({"source": source, "source_paused": paused, "server_saved": server_saved}))
}

fn publish_scan_result(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    scan: &SetupScanPayload,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/scan-result",
                active.setup_run_id
            ),
        );
        backend_post_json_with_timeout(
            &url,
            scan,
            &[("X-Ottto-Setup-Run-Token", token)],
            SETUP_SCAN_RESULT_HTTP_TIMEOUT,
        )
    })
}

fn save_setup_answer(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    answer_type: &str,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let body = json!({
        "source": source_slug(source),
        "answer_type": answer_type,
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/answers",
                active.setup_run_id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

pub(in crate::control) fn queue_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    source: &SourceKind,
    action_type: &str,
) -> Result<SetupRunActionApiResponse, LocalApiError> {
    let body = json!({
        "source": source_slug(source),
        "action_type": action_type,
        "requested_by": "companion_app",
        "payload": {
            "reason": "companion_setup_continue",
        },
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/actions",
                active.setup_run_id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn setup_scan_sources(requested_sources: Vec<SourceKind>) -> Vec<SourceKind> {
    let source_filter = if requested_sources.is_empty() {
        vec![SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi]
    } else {
        requested_sources
    };
    source_filter
        .into_iter()
        .filter(|source| !setup_source_paused(source))
        .collect()
}

pub(in crate::control) fn build_local_scan(
    machine: &MachineIdentity,
    requested_sources: Vec<SourceKind>,
) -> SetupScanPayload {
    let source_filter = setup_scan_sources(requested_sources);
    let mut machine_json = BTreeMap::new();
    machine_json.insert("id".to_string(), json!(machine.machine_id));
    machine_json.insert("name".to_string(), json!(machine.display_name));
    machine_json.insert(
        "platform".to_string(),
        json!(operating_system_slug(&machine.os)),
    );
    machine_json.insert("arch".to_string(), json!(machine.arch));

    let mut companion = BTreeMap::new();
    companion.insert("client_name".to_string(), json!(OTTTO_CLIENT_NAME));
    companion.insert("protocol_version".to_string(), json!(PROTOCOL_VERSION));
    companion.insert(
        "local_platform_version".to_string(),
        json!(machine.local_platform_version),
    );
    companion.insert(
        "capabilities".to_string(),
        json!({
            "deeplink": { "registered": true },
            "setup_run": true,
            "smoke_verification": true,
        }),
    );

    let mut service = BTreeMap::new();
    service.insert("state".to_string(), json!("running"));
    service.insert("socket".to_string(), json!("available"));

    SetupScanPayload {
        machine: machine_json,
        companion,
        relay_runtime: BTreeMap::from([("state".to_string(), json!("unknown"))]),
        service,
        sources: source_filter.iter().map(scan_source).collect(),
        missing_fields: Vec::new(),
    }
}

pub(in crate::control) fn scan_source(source: &SourceKind) -> SetupScanSource {
    #[cfg(test)]
    tests::SETUP_SCAN_PROBES.with(|count| count.set(count.get() + 1));
    match source {
        SourceKind::Codex => {
            let command_found = executable_exists("codex");
            let config = home_path(".codex/config.toml");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = false;
            let local_import_ready =
                (command_found || config.exists() || home_path(".codex/sessions").exists())
                    && snapshot_device_credentials_include_source("codex")
                    && codex_config_state_at(&config, "~/.codex/config.toml", "", false)
                        .drift
                        .is_empty();
            let managed_config = codex_managed_config_preview(config_body.as_deref());
            let local_import_ready = local_import_ready && !source_patch_disabled(source);
            let mut scan_entry = setup_scan_source(
                source,
                "codex",
                command_found || config.exists() || home_path(".codex/sessions").exists(),
                command_found,
                telemetry_installed,
                if local_import_ready {
                    "healthy"
                } else {
                    "needs_repair"
                },
                BTreeMap::from([
                    ("billing_provider".to_string(), json!("openai")),
                    ("model_provider".to_string(), json!("openai")),
                    ("billing_channel".to_string(), json!("subscription")),
                    ("auth_mode".to_string(), json!("oauth")),
                ]),
            );
            scan_entry.managed_config = managed_config;
            scan_entry.local_import_ready = Some(local_import_ready);
            scan_entry.live_telemetry_required = Some(false);
            scan_entry
        }
        SourceKind::ClaudeCode => {
            let command_found = executable_exists("claude");
            let config = home_path(".claude/settings.json");
            let config_body = read_optional_to_string(&config);
            let telemetry_installed = config_body
                .as_deref()
                .is_some_and(claude_code_telemetry_config_installed);
            let managed_config = claude_managed_config_preview(config_body.as_deref());
            let mut scan_entry = setup_scan_source(
                source,
                "claude_code",
                command_found || config.exists(),
                command_found,
                telemetry_installed,
                if telemetry_installed {
                    "healthy"
                } else {
                    "needs_repair"
                },
                BTreeMap::from([
                    ("billing_provider".to_string(), json!("anthropic")),
                    ("model_provider".to_string(), json!("anthropic")),
                    ("billing_channel".to_string(), json!("subscription")),
                    ("auth_mode".to_string(), json!("oauth")),
                ]),
            );
            scan_entry.managed_config = managed_config;
            scan_entry
        }
        SourceKind::Pi => {
            let command_found = executable_exists("pi");
            let present = crate::agent_configs::detection::source_present_locally(source);
            let telemetry_installed = snapshot_device_credentials_include_source("pi");
            setup_scan_source(
                source,
                "pi",
                present,
                command_found,
                telemetry_installed,
                if telemetry_installed {
                    "healthy"
                } else if present {
                    "needs_repair"
                } else {
                    "not_found"
                },
                BTreeMap::new(),
            )
        }
    }
}

fn setup_scan_source(
    source_kind: &SourceKind,
    source: &'static str,
    detected: bool,
    installed: bool,
    telemetry_installed: bool,
    local_health: &'static str,
    attribution_guess: BTreeMap<String, serde_json::Value>,
) -> SetupScanSource {
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    SetupScanSource {
        source,
        captured_at: captured_at.clone(),
        detected,
        installed,
        telemetry_installed,
        local_health,
        missing_fields: Vec::new(),
        attribution_guess,
        agent_status: crate::agent_status_refresh::setup_snapshot(
            source_kind,
            captured_at,
            expires_at,
        ),
        managed_config: None,
        local_import_ready: None,
        live_telemetry_required: None,
    }
}
