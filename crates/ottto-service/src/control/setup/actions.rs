//! setup actions for local control.

use crate::control::api_url_with_base;
use crate::control::append_nonce_to_claim_url;
use crate::control::apply_telemetry_config;
use crate::control::auth_claim_is_expired;
use crate::control::backend_get_json;
use crate::control::backend_post_json;
use crate::control::claude_settings_kept_reason;
use crate::control::codex_config_state_at;
use crate::control::compiled_release_version;
use crate::control::confirm_device_credential_preparation;
use crate::control::control_token_validation_base_url;
use crate::control::detect_agent_installation;
use crate::control::emit_api_key_verification_marker;
use crate::control::history_load;
use crate::control::history_stores;
use crate::control::home_path;
use crate::control::json;
use crate::control::local_history_recovery_expected;
use crate::control::local_relay_base_url_for_daemon;
use crate::control::local_relay_port_for_daemon;
use crate::control::lock_setup_run_binding;
use crate::control::loopback_listener_available;
use crate::control::mark_pending_device_credential_confirmed;
use crate::control::mark_pending_device_credential_guards_passed;
use crate::control::operating_system_slug;
use crate::control::patch_claude_code_settings_with_relay_base;
use crate::control::pending_device_credential_from_preparation;
use crate::control::prepare_telemetry_device_registration;
use crate::control::promote_pending_device_credential_with_stores;
use crate::control::queue_setup_action;
use crate::control::reconcile_codex_source_off;
use crate::control::record_install_session_event;
use crate::control::recover_pending_device_credential_at_startup;
use crate::control::registration_history_choice_account;
use crate::control::registration_history_choice_required;
use crate::control::remove_telemetry_config;
use crate::control::reoffer_registration_browser_claim;
use crate::control::request_snapshot_sync_after_device_registration;
use crate::control::require_authorized_local_client;
use crate::control::require_identity_mutation_reservation;
use crate::control::require_local_control_account;
use crate::control::require_non_empty_field;
use crate::control::require_request_base_matches_binding;
use crate::control::reserve_identity_mutation;
use crate::control::run_verify_source_action;
use crate::control::set_source_marker;
use crate::control::setup_run_request_with_refresh_mut;
use crate::control::setup_run_token_for_connection;
use crate::control::setup_source_paused;
use crate::control::snapshot_device_credentials_include_source;
use crate::control::source_display_name;
use crate::control::source_from_slug;
use crate::control::source_patch_disabled;
use crate::control::source_requires_config_patch;
use crate::control::source_requires_device_registration;
use crate::control::source_slug;
use crate::control::stage_pending_device_credential;
use crate::control::status_for;
use crate::control::validate_control_token_fresh;
use crate::control::validate_control_token_with_backend;
use crate::control::validated_api_base_url;
use crate::control::AgentInstallationDetection;
use crate::control::BackendErrorDetails;
use crate::control::BackendErrorKind;
use crate::control::ControlResult;
use crate::control::ControlResultStatus;
use crate::control::FileAccountStore;
use crate::control::FileDeviceStore;
use crate::control::FilePendingDeviceCredentialStore;
use crate::control::InstallSessionApiResponse;
use crate::control::InstallSessionEvent;
use crate::control::KeychainSecretStore;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::LocalDaemon;
use crate::control::MachineIdentity;
use crate::control::RequestAuthorization;
use crate::control::SecretString;
use crate::control::SetupActionEvent;
use crate::control::SetupActionResult;
use crate::control::SetupRunActionApiResponse;
use crate::control::SetupRunAttachResponse;
use crate::control::SetupRunCredentials;
use crate::control::SetupRunDetailApiResponse;
use crate::control::SetupRunNextActionResponse;
use crate::control::SourceKind;
use crate::control::StableMessage;
use crate::control::StoredHistoryBrowserClaim;
use crate::control::TelemetryControlAction;
use crate::control::TelemetryKeyStore;
use crate::control::OTTTO_CLIENT_NAME;
use crate::control::OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT;
use crate::control::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
use crate::control::OTTTO_SERVICE_BINARY_NAME;
use crate::control::PROTOCOL_VERSION;
pub(in crate::control) mod pi_sessions;
pub(in crate::control) mod smoke;
pub(in crate::control) mod verification;

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
pub(in crate::control) fn telemetry_control(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
) -> Result<ControlResult, LocalApiError> {
    telemetry_control_with_detector(
        daemon,
        action,
        source,
        control_token,
        api_base_url,
        key_id,
        organization_id,
        otlp_endpoint,
        ingest_key,
        &detect_agent_installation,
    )
}

#[expect(clippy::too_many_arguments, reason = "12 args; no options struct yet")]
pub(in crate::control) fn telemetry_control_with_detector(
    daemon: &LocalDaemon,
    action: TelemetryControlAction,
    source: SourceKind,
    control_token: String,
    // SECURITY: the request-supplied `api_base_url` cannot freely choose where the
    // control token is validated. Token validation is the only gate protecting
    // this telemetry-config mutation against an untrusted local peer, so
    // `control_token_validation_base_url` only honors this value when it is a
    // trusted production backend (never a request-supplied loopback URL), closing
    // the bypass where a co-resident attacker points validation at their own
    // server. See that resolver for the full rationale.
    api_base_url: Option<String>,
    key_id: Option<String>,
    organization_id: Option<String>,
    otlp_endpoint: Option<String>,
    ingest_key: Option<SecretString>,
    detector: &dyn Fn(&SourceKind) -> AgentInstallationDetection,
) -> Result<ControlResult, LocalApiError> {
    let mut key_id = key_id;
    if source == SourceKind::Codex && matches!(action, TelemetryControlAction::EnableTelemetry) {
        return Err(LocalApiError::InvalidRequest(
            "Ottto Codex live telemetry is disabled; local session import remains available"
                .to_string(),
        ));
    }
    if !matches!(source, SourceKind::Codex | SourceKind::ClaudeCode) {
        return Err(LocalApiError::InvalidRequest(
            "telemetry control supports codex and claude_code only".to_string(),
        ));
    }

    let token_validation_base_url = control_token_validation_base_url(api_base_url.as_deref())?;
    validate_control_token_fresh(&control_token, &action, &source)?;

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            require_non_empty_field(key_id.as_deref(), "key_id")?;
            require_non_empty_field(organization_id.as_deref(), "organization_id")?;
            require_non_empty_field(otlp_endpoint.as_deref(), "otlp_endpoint")?;
            let Some(secret) = ingest_key.as_ref() else {
                return Err(LocalApiError::InvalidRequest(
                    "enable_telemetry requires ingest_key".to_string(),
                ));
            };
            require_non_empty_field(Some(secret.expose_secret()), "ingest_key")?;
        }
        TelemetryControlAction::DisableTelemetry => {
            // Older installs, manually repaired installs, or installs that lost the
            // key index can still have local agent config patched to the Ottto
            // relay even though there is no indexed ingest key id to revoke.
            // Disabling live telemetry must still remove that local config; key
            // deletion is best-effort and only possible when the caller knows the
            // key id.
            if key_id
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(LocalApiError::InvalidRequest(
                    "key_id must not be empty when provided".to_string(),
                ));
            }
        }
        TelemetryControlAction::Status => {}
    }

    let claims = validate_control_token_with_backend(
        &token_validation_base_url,
        &control_token,
        &action,
        &source,
    )?;
    let _binding_lock = lock_setup_run_binding();
    require_identity_mutation_reservation(None)?;
    require_local_control_account(&claims, &FileAccountStore::default(), "telemetry control")?;
    if matches!(
        action,
        TelemetryControlAction::Status | TelemetryControlAction::DisableTelemetry
    ) {
        let device = FileDeviceStore::default()
            .load()
            .map_err(|_| LocalApiError::LocalClientNotTrusted)?
            .ok_or(LocalApiError::LocalClientNotTrusted)?;
        if device.device_id.trim().is_empty()
            || claims.device_id.as_deref() != Some(device.device_id.as_str())
            || key_id != claims.key_id
        {
            return Err(LocalApiError::LocalClientNotTrusted);
        }
    }
    if let (Some(expected), Some(observed)) = (
        claims.organization_id.as_deref(),
        organization_id
            .as_deref()
            .filter(|value| !value.trim().is_empty()),
    ) {
        if expected != observed {
            return Err(LocalApiError::InvalidRequest(
                "control token organization does not match request".to_string(),
            ));
        }
    }

    let installation = match action {
        TelemetryControlAction::EnableTelemetry | TelemetryControlAction::Status => {
            Some(detector(&source))
        }
        TelemetryControlAction::DisableTelemetry => None,
    };
    if matches!(action, TelemetryControlAction::EnableTelemetry)
        && installation
            .as_ref()
            .is_some_and(|detected| !detected.installed)
    {
        return Ok(ControlResult {
            requires_restart: false,
            key_id,
            action,
            source: source.clone(),
            status: ControlResultStatus::NeedsAttention,
            message: StableMessage {
                code: "agent_not_installed".to_string(),
                text: format!(
                    "Install {} first - we'll wait.",
                    source_display_name(&source)
                ),
            },
            config_preview: None,
            installation,
        });
    }

    match &action {
        TelemetryControlAction::EnableTelemetry => {
            let key_id = key_id
                .as_deref()
                .expect("enable key_id validated before backend call");
            let secret = ingest_key
                .as_ref()
                .expect("enable ingest_key validated before backend call");
            TelemetryKeyStore::production()
                .save(&source, key_id, secret.expose_secret())
                .map_err(|error| {
                    LocalApiError::LocalOperationFailed(format!(
                        "telemetry key storage failed: {error}"
                    ))
                })?;
            if let Err(error) = apply_telemetry_config(daemon, &source) {
                let _ = TelemetryKeyStore::production().delete(&source, key_id);
                return Err(error);
            }
            let otlp_endpoint = otlp_endpoint
                .as_deref()
                .expect("enable otlp_endpoint validated before backend call");
            if let Err(error) = emit_api_key_verification_marker(
                otlp_endpoint,
                secret.expose_secret(),
                &source,
                key_id,
                organization_id.as_deref(),
            ) {
                let _ = remove_telemetry_config(daemon, &source);
                return Err(error);
            }
        }
        TelemetryControlAction::DisableTelemetry => {
            remove_telemetry_config(daemon, &source)?;
            if let Some(key_id) = key_id.as_deref() {
                TelemetryKeyStore::production()
                    .delete(&source, key_id)
                    .map_err(|error| {
                        LocalApiError::LocalOperationFailed(format!(
                            "telemetry key removal failed: {error}"
                        ))
                    })?;
            }
        }
        TelemetryControlAction::Status => {}
    }

    if matches!(action, TelemetryControlAction::Status) && key_id.is_none() {
        key_id = TelemetryKeyStore::production()
            .latest_key_id(&source)
            .map_err(|error| {
                LocalApiError::LocalOperationFailed(format!("telemetry key lookup failed: {error}"))
            })?;
    }

    let requires_restart = matches!(action, TelemetryControlAction::EnableTelemetry)
        || (source == SourceKind::Codex
            && matches!(action, TelemetryControlAction::DisableTelemetry));
    Ok(ControlResult {
        requires_restart,
        key_id,
        action,
        source,
        status: ControlResultStatus::Accepted,
        message: StableMessage {
            code: "telemetry_control_accepted".to_string(),
            text: format!("Telemetry control request accepted by {OTTTO_SERVICE_BINARY_NAME}."),
        },
        config_preview: None,
        installation,
    })
}

pub(in crate::control) fn setup_action(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    action_type: String,
    api_base_url: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let api_base_url = api_base_url.filter(|value| !value.trim().is_empty());
    let status = status_for(daemon, authorization)?;
    let mut connection = daemon.connection_for_authorized_client()?;
    require_request_base_matches_binding(
        api_base_url.as_deref(),
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str()),
    )?;
    let api_base_url = validated_api_base_url(api_base_url.as_deref().or_else(|| {
        connection
            .as_ref()
            .map(|binding| binding.api_base_url.as_str())
    }))?;
    let connection = connection
        .take()
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let mut credentials = setup_run_token_for_connection(&api_base_url, &connection)?;
    let action_type = match action_type.trim() {
        "install_source" | "verify_source" => action_type.trim().to_string(),
        _ => {
            return Err(LocalApiError::InvalidRequest(
                "setup_action only supports install_source and verify_source".to_string(),
            ))
        }
    };
    let queued = queue_setup_action(&api_base_url, &mut credentials, &source, &action_type)?;
    if action_type == "install_source" {
        set_source_marker(crate::snapshot_sync::reconnect_snapshot_source, &source)?;
    }
    let action_results =
        process_setup_actions(daemon, &api_base_url, &mut credentials, &status.machine)?;
    request_snapshot_sync_after_setup_actions(daemon, &action_results);
    let detail = action_results
        .last()
        .and_then(|result| result.detail.clone())
        .ok_or_else(|| {
            LocalApiError::InvalidRequest(
                "queued setup action did not return a setup-run detail".to_string(),
            )
        })?;
    let mut result =
        setup_result_from_detail(&credentials.connection, detail, false, action_results)?;
    // Lets the client bind a completion to the action this request queued.
    result["queued_action_id"] = json!(queued.id);
    Ok(result)
}

pub(in crate::control) fn request_snapshot_sync_after_setup_actions(
    daemon: &LocalDaemon,
    action_results: &[SetupActionResult],
) {
    let registered_device = action_results.iter().any(|result| {
        result.action_type == "install_source"
            && result.status == "succeeded"
            && result
                .source
                .as_deref()
                .and_then(source_from_slug)
                .is_some_and(|source| source_requires_device_registration(&source))
    });
    if registered_device {
        request_snapshot_sync_after_device_registration(daemon);
    }
}

pub(in crate::control) fn setup_result_from_detail(
    connection: &LocalConnectionBinding,
    detail: SetupRunDetailApiResponse,
    claim_code_provided: bool,
    action_results: Vec<SetupActionResult>,
) -> Result<serde_json::Value, LocalApiError> {
    let source_count = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .count();
    let detected_sources = detail
        .sources
        .iter()
        .filter(|source| source.detected)
        .map(|source| {
            let mut summary = json!({
                "source": source.source,
                "state": source.state,
                "readiness_percent": source.readiness_percent,
                "missing_fields": source.missing_fields,
            });
            if let Some(ready) = source.local_import_ready {
                summary["local_import_ready"] = json!(ready);
            }
            if let Some(required) = source.live_telemetry_required {
                summary["live_telemetry_required"] = json!(required);
            }
            summary
        })
        .collect::<Vec<_>>();

    let local_claim: Option<StoredHistoryBrowserClaim> =
        match history_load(history_stores().browser.as_ref()) {
            Ok(claim) => claim,
            Err(_) if !local_history_recovery_expected()? => None,
            Err(error) => return Err(error),
        };
    let local_claim_url = local_claim
        .filter(|claim| {
            claim.setup_run_id.as_deref() == Some(connection.setup_run_id.as_str())
                && claim.api_base_url == connection.api_base_url
                && !auth_claim_is_expired(&claim.claim.expires_at)
        })
        .map(|claim| {
            append_nonce_to_claim_url(&claim.claim.claim_url, claim.nonce.expose_secret())
        });
    Ok(json!({
        "status": detail.run.status,
        "setup_run_id": connection.setup_run_id,
        "claim_code_provided": claim_code_provided,
        "source_count": source_count,
        "detected_sources": detected_sources,
        "next_question": detail.next_question,
        "next_action": detail.next_action,
        "setup_claim_url": local_claim_url.or(detail.setup_claim_url),
        "actions": action_results,
    }))
}

pub(in crate::control) fn attach_setup_run_by_claim_code(
    api_base_url: &str,
    claim_code: &str,
    machine: &MachineIdentity,
) -> Result<SetupRunAttachResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!("/api/v1/setup-claims/{claim_code}/attach"),
    );
    let body = setup_run_attach_body(machine);
    backend_post_json(&url, &body, &[])
}

pub(in crate::control) fn setup_run_attach_body(machine: &MachineIdentity) -> serde_json::Value {
    json!({
        "machine_id": machine.machine_id,
        "installation_id": machine.installation_id,
        "hardware_uuid": machine.hardware_uuid,
        "account_scope": machine.account_scope,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            "local_platform_version": machine.local_platform_version,
            "capabilities": {
                "deeplink": { "registered": true },
                "setup_run": true,
                "smoke_verification": true,
            },
        },
    })
}

pub(in crate::control) fn process_setup_actions(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
) -> Result<Vec<SetupActionResult>, LocalApiError> {
    process_setup_actions_with_status(daemon, api_base_url, credentials, machine, &mut 0)
        .map(|(results, _, _)| results)
}

pub(in crate::control) fn process_setup_actions_with_status(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    machine: &MachineIdentity,
    actions_processed: &mut usize,
) -> Result<(Vec<SetupActionResult>, Option<String>, bool), LocalApiError> {
    let mut results = Vec::new();
    let mut last_run_status = None;
    for _ in 0..8 {
        let next = get_next_setup_action(api_base_url, credentials)?;
        last_run_status = next.run_status;
        let Some(action) = next.action else {
            return Ok((results, last_run_status, true));
        };
        let source_slug = action.source.clone();
        let source = source_slug.as_deref().and_then(source_from_slug);
        if source.as_ref().is_some_and(setup_source_paused) {
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                "cancelled",
                "source_paused",
                json!({ "reason": "source_paused" }),
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status: "cancelled".to_string(),
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        if let Err(error) = record_setup_action_event(
            api_base_url,
            credentials,
            &action,
            SetupActionEvent {
                event_type: "action.started",
                status: "running",
                message: "Local daemon started setup action",
                metadata: None,
            },
        ) {
            let (status, message, result) =
                setup_action_execution_error_result(&action, source.as_ref(), &error);
            let detail = complete_setup_action(
                api_base_url,
                credentials,
                &action,
                &status,
                &message,
                result,
            )?;
            results.push(SetupActionResult {
                action_id: action.id,
                action_type: action.action_type,
                source: source_slug,
                status,
                detail: Some(detail),
                verification: None,
            });
            *actions_processed += 1;
            continue;
        }
        let action_outcome = match action.action_type.as_str() {
            "install_source" => {
                run_install_source_action(daemon, api_base_url, credentials, &action, machine)
                    .map(|(status, message, result)| (status, message, result, None))
            }
            "verify_source" => {
                if let Some(source) = source.clone() {
                    crate::provider_calls::with_trigger(
                        crate::provider_calls::Trigger::Setup,
                        || {
                            run_verify_source_action(
                                daemon,
                                api_base_url,
                                credentials,
                                &action,
                                source,
                            )
                        },
                    )
                } else {
                    Ok((
                        "failed".to_string(),
                        "Setup action source was missing".to_string(),
                        json!({
                            "verified": false,
                            "error_code": "source_missing",
                            "error_message": "Setup action source was missing",
                        }),
                        None,
                    ))
                }
            }
            _ => Ok((
                "failed".to_string(),
                format!("Unsupported setup action {}", action.action_type),
                json!({
                    "error_code": "unsupported_action",
                    "error_message": format!("Unsupported setup action {}", action.action_type),
                }),
                None,
            )),
        };
        let (status, message, result, verification) = match action_outcome {
            Ok(outcome) => outcome,
            Err(error) if registration_history_choice_required(&error) => {
                reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
                results.push(SetupActionResult {
                    action_id: action.id,
                    action_type: action.action_type,
                    source: source_slug,
                    status: "running".to_string(),
                    detail: None,
                    verification: None,
                });
                *actions_processed += 1;
                break;
            }
            Err(error) => {
                let (status, message, result) =
                    setup_action_execution_error_result(&action, source.as_ref(), &error);
                (status, message, result, None)
            }
        };
        let detail = complete_setup_action(
            api_base_url,
            credentials,
            &action,
            &status,
            &message,
            result,
        )?;
        results.push(SetupActionResult {
            action_id: action.id,
            action_type: action.action_type,
            source: source_slug,
            status,
            detail: Some(detail),
            verification,
        });
        *actions_processed += 1;
    }
    // A response containing an action cannot establish that the run is idle.
    Ok((results, last_run_status, false))
}

fn setup_action_execution_error_result(
    action: &SetupRunActionApiResponse,
    source: Option<&SourceKind>,
    error: &LocalApiError,
) -> (String, String, serde_json::Value) {
    let (error_code, error_message) = setup_action_execution_error_detail(error);
    let mut result = json!({
        "action_type": action.action_type.as_str(),
        "source": action.source.as_deref().or_else(|| source.map(source_slug)),
        "verified": false,
        "error_code": error_code,
        "error_message": error_message,
    });
    if source == Some(&SourceKind::Codex) {
        result["live_telemetry_required"] = json!(false);
        result["local_import_ready"] = json!(false);
    }
    ("failed".to_string(), error_message, result)
}

pub(in crate::control) fn setup_action_execution_error_detail(
    error: &LocalApiError,
) -> (&'static str, String) {
    match error {
        LocalApiError::SetupRunConnectionMissing => (
            "setup_run_connection_missing",
            "This Mac needs an active Ottto setup flow. Start setup from the Ottto app, then retry.".to_string(),
        ),
        LocalApiError::SetupRunConnectionMismatch => (
            "setup_run_connection_mismatch",
            "This setup action belongs to a different Ottto setup run. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::TimedOut(_) => (
            "setup_action_timed_out",
            "Setup action timed out while waiting for Ottto. Check your network and retry setup.".to_string(),
        ),
        LocalApiError::NetworkUnavailable => (
            "network_unavailable",
            "Network is unavailable while running setup. Check your connection and retry setup.".to_string(),
        ),
        LocalApiError::Backend(details) => {
            if details.status == Some(401) || details.status == Some(403) {
                return (
                    "setup_action_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                );
            }
            if details.status == Some(404) {
                return (
                    "setup_run_missing",
                    "Ottto could not find this setup run. Start setup again from the Ottto app.".to_string(),
                );
            }
            match details.kind {
                BackendErrorKind::Unreachable => (
                    "backend_unreachable",
                    "Could not reach Ottto while running setup. Check your network and retry setup.".to_string(),
                ),
                BackendErrorKind::Unavailable => (
                    "backend_unavailable",
                    "Ottto was unavailable while running setup. Retry setup in a moment.".to_string(),
                ),
                BackendErrorKind::Rejected => (
                    "backend_rejected",
                    "Ottto rejected this setup action. Start setup from the Ottto app, then retry.".to_string(),
                ),
                BackendErrorKind::ResponseUnexpected => (
                    "backend_response_unexpected",
                    "Ottto returned an unexpected setup response. Retry setup in a moment.".to_string(),
                ),
            }
        }
        LocalApiError::LocalOperationFailed(_) => (
            "local_operation_failed",
            "A local setup step failed. Open Diagnostics or retry setup.".to_string(),
        ),
        LocalApiError::StatePoisoned => (
            "local_state_unavailable",
            "Local Ottto setup state is unavailable. Restart Ottto and retry setup.".to_string(),
        ),
        LocalApiError::RepairLocked => (
            "repair_locked",
            "Another Ottto repair is already running. Wait for it to finish, then retry setup.".to_string(),
        ),
        LocalApiError::ManualFenceReviewRequired => (
            "manual_fence_review_required",
            "Setup needs manual config review before it can continue.".to_string(),
        ),
        LocalApiError::CloudSessionCleanupRequired => (
            "cloud_session_cleanup_required",
            error.to_string(),
        ),
        LocalApiError::IdentityMutationInProgress => (
            "identity_mutation_in_progress",
            error.to_string(),
        ),
        LocalApiError::InvalidRequest(_) | LocalApiError::RetiredCommand(_) => (
            "invalid_setup_action",
            "Ottto could not run this setup action. Start setup again from the Ottto app.".to_string(),
        ),
        LocalApiError::Unauthorized
        | LocalApiError::LocalClientNotTrusted
        | LocalApiError::AccountResetRequired
        | LocalApiError::AccountSwitchCandidate { .. }
        | LocalApiError::EmptyControlToken
        | LocalApiError::NoPendingAuthClaim
        | LocalApiError::AuthClaimMismatch => (
            "setup_action_failed",
            "Ottto could not finish this setup action. Start setup from the Ottto app, then retry.".to_string(),
        ),
    }
}

fn get_next_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
) -> Result<SetupRunNextActionResponse, LocalApiError> {
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/next-action",
                active.setup_run_id
            ),
        );
        heartbeat_setup_run(api_base_url, active, token, "polling_next_action")?;
        backend_get_json(&url, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn heartbeat_setup_run(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    status: &str,
) -> Result<(), LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/heartbeat",
            connection.setup_run_id
        ),
    );
    let body = json!({
        "status": status,
        "metadata": {
            "client_name": OTTTO_CLIENT_NAME,
            "protocol_version": PROTOCOL_VERSION,
            // Report the live running version so the Apps surface can read it
            // from the heartbeat (the source of truth) instead of inferring it
            // from setup-scan / telemetry-device snapshots.
            "local_platform_version": compiled_release_version(),
        },
    });
    let _: serde_json::Value =
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", setup_run_token)])?;
    Ok(())
}

pub(in crate::control) fn record_setup_action_event(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    event: SetupActionEvent<'_>,
) -> Result<(), LocalApiError> {
    let body = json!({
        "event_type": event.event_type,
        "status": event.status,
        "message": event.message,
        "source": action.source,
        "metadata": event.metadata,
    });
    let _: serde_json::Value =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/actions/{}/events",
                    active.setup_run_id, action.id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    Ok(())
}

fn complete_setup_action(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    status: &str,
    message: &str,
    result: serde_json::Value,
) -> Result<SetupRunDetailApiResponse, LocalApiError> {
    let body = json!({
        "status": status,
        "message": message,
        "result": result,
    });
    setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        let url = api_url_with_base(
            api_base_url,
            &format!(
                "/api/v1/setup-runs/{}/local-client/actions/{}/complete",
                active.setup_run_id, action.id
            ),
        );
        backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
    })
}

fn run_install_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    machine: &MachineIdentity,
) -> Result<(String, String, serde_json::Value), LocalApiError> {
    let Some(source) = action.source.as_deref() else {
        return Ok((
            "failed".to_string(),
            "Install source action did not include a source".to_string(),
            json!({
            "error_code": "source_missing",
            "error_message": "Install source action did not include a source",
            }),
        ));
    };
    let body = json!({
        "action_id": action.id,
        "source": source,
        "machine_name": machine.display_name,
        "platform": operating_system_slug(&machine.os),
        "architecture": machine.arch,
        "client_name": OTTTO_CLIENT_NAME,
        "setup_origin": "companion_setup_run",
    });
    let install_session: InstallSessionApiResponse =
        setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
            let url = api_url_with_base(
                api_base_url,
                &format!(
                    "/api/v1/setup-runs/{}/local-client/install-sessions",
                    active.setup_run_id
                ),
            );
            backend_post_json(&url, &body, &[("X-Ottto-Setup-Run-Token", token)])
        })?;
    let Some(source_kind) = source_from_slug(source) else {
        return Ok((
            "failed".to_string(),
            format!("Unsupported local source: {source}"),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "error_code": "source_unsupported",
                "error_message": format!("Unsupported local source: {source}"),
            }),
        ));
    };
    if !source_requires_device_registration(&source_kind) {
        return Ok((
            "succeeded".to_string(),
            "Local source setup prepared".to_string(),
            json!({
                "install_session_id": install_session.install_session_id,
                "source": source,
                "local_changes": "prepared",
            }),
        ));
    }

    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.started",
            status: "running",
            message: &format!(
                "Registering local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: None,
        },
    )?;
    // Resolve any previously confirmed-but-not-promoted generation before
    // beginning another identity mutation. Uncertain pending state fails
    // closed; it is never overwritten by a modern-to-legacy fallback.
    recover_pending_device_credential_at_startup()?;
    if FileAccountStore::default()
        .load()
        .is_ok_and(|account| registration_history_choice_account(&account))
    {
        reoffer_registration_browser_claim(daemon, machine, api_base_url)?;
        return Err(LocalApiError::Backend(BackendErrorDetails {
            kind: BackendErrorKind::Rejected,
            endpoint: "/api/v1/telemetry/devices/registration-preparations".to_string(),
            status: Some(400),
            body_excerpt: Some("Setup claim session is pending".to_string()),
            reason_code: Some("history_choice_required".to_string()),
        }));
    }
    // Preparation is server-side non-authoritative. Hold a panic-safe local
    // reservation across prepare, local durable staging, confirm, and exact
    // promotion while leaving the lifecycle mutex free during network I/O.
    let identity_reservation = reserve_identity_mutation()?;
    let (prepared, _prior, request_authority) =
        prepare_telemetry_device_registration(api_base_url, &install_session, machine)?;
    let pending = pending_device_credential_from_preparation(
        api_base_url,
        &prepared,
        true,
        None,
        request_authority,
    )?;
    stage_pending_device_credential(&pending, &prepared.candidate_secret)?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
    }
    let pending = mark_pending_device_credential_guards_passed(
        &pending,
        &FilePendingDeviceCredentialStore::default(),
    )?;
    let confirmed = confirm_device_credential_preparation(&pending, &prepared.candidate_secret)?;
    let pending_store = FilePendingDeviceCredentialStore::default();
    let pending = mark_pending_device_credential_confirmed(
        &pending,
        &confirmed.confirmed_at,
        &pending_store,
    )?;
    {
        let _identity_lifecycle_lock = lock_setup_run_binding();
        identity_reservation.validate_locked()?;
        promote_pending_device_credential_with_stores(
            &pending,
            &prepared.candidate_secret,
            &pending_store,
            &KeychainSecretStore::new(OTTTO_PENDING_RELAY_DEVICE_SECRET_ACCOUNT),
            &FileDeviceStore::default(),
            &KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
        )?;
    }
    let device = pending.device;
    let device_id = device.device_id.clone();
    drop(identity_reservation);
    // The local device binding + secret are now durable. Wake the snapshot
    // collector before any backend completion/event call that can transiently
    // fail after registration has already succeeded.
    request_snapshot_sync_after_device_registration(daemon);
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "device.registration.completed",
            status: "succeeded",
            message: &format!(
                "Registered local {} telemetry device",
                source_display_name(&source_kind)
            ),
            metadata: Some(json!({"source": source})),
            device_id: Some(&device_id),
        },
    )?;
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: "secure_store.saved",
            status: "succeeded",
            message: "Saved local relay device secret",
            metadata: Some(json!({"source": source, "store": "keychain"})),
            device_id: Some(&device_id),
        },
    )?;

    let codex_cleanup = if source_kind == SourceKind::Codex {
        Some(reconcile_codex_source_off()?)
    } else {
        None
    };
    if source_kind == SourceKind::Codex || !source_requires_config_patch(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} does not require local OTLP config patching",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "not_required",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} local session import prepared",
            source_display_name(&source_kind)
        );
        let mut result = install_source_registration_result(
            &install_session.install_session_id,
            &device_id,
            source,
            &message,
        );
        if let Some(cleanup) = codex_cleanup {
            result["live_telemetry_required"] = json!(false);
            result["local_import_ready"] = json!(
                snapshot_device_credentials_include_source("codex")
                    && codex_config_state_at(
                        &home_path(".codex/config.toml"),
                        "~/.codex/config.toml",
                        "",
                        false
                    )
                    .drift
                    .is_empty()
                    && !source_patch_disabled(&source_kind)
            );
            result["managed_telemetry_disabled"] = json!(!source_patch_disabled(&source_kind));
            result["config_updated"] = json!(cleanup.changed);
            result["requires_restart"] = json!(cleanup.changed);
            result["message"] = json!(if cleanup.changed {
                "Codex local import prepared; restart existing Codex processes to stop managed telemetry"
            } else {
                &message
            });
        }
        return Ok(("succeeded".to_string(), message, result));
    }

    if source_patch_disabled(&source_kind) {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "config.patch.skipped",
                status: "succeeded",
                message: &format!(
                    "{} telemetry config patching is disabled by environment",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "reason": "disabled_by_env",
                })),
                device_id: Some(&device_id),
            },
        )?;
        let message = format!(
            "{} telemetry config patching skipped by environment",
            source_display_name(&source_kind)
        );
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            install_source_patch_disabled_result(
                &install_session.install_session_id,
                &device_id,
                source,
                &message,
            ),
        ));
    }

    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let relay_port = local_relay_port_for_daemon(daemon);
    let patch = match source_kind {
        SourceKind::Codex => reconcile_codex_source_off()?,
        SourceKind::ClaudeCode => {
            patch_claude_code_settings_with_relay_base(machine, &relay_base_url, false)?
        }
        SourceKind::Pi => unreachable!("Pi install actions do not patch OTLP config"),
    };
    let kept = patch.kept.map(claude_settings_kept_reason);
    let config_event_message = if let Some((_, text)) = kept {
        text.to_string()
    } else if patch.changed {
        format!(
            "Patched {} telemetry settings",
            source_display_name(&source_kind)
        )
    } else {
        format!(
            "{} telemetry settings already up to date",
            source_display_name(&source_kind)
        )
    };
    let mut metadata = json!({
        "source": source,
        "settings": match source_kind {
            SourceKind::Codex => "codex_config",
            SourceKind::ClaudeCode => "claude_settings",
            SourceKind::Pi => "none",
        },
        "changed": patch.changed,
        "created": patch.created,
        "backup_created": patch.backup_created,
        "backup_scope": "source_config",
        "restore_operation": "uninstall_restore",
    });
    if let Some((reason, _)) = kept {
        metadata["reason"] = json!(reason);
    }
    record_install_session_event(
        api_base_url,
        &install_session.install_session_id,
        &install_session.install_session_token,
        InstallSessionEvent {
            event_type: if kept.is_some() {
                "config.patch.skipped"
            } else if patch.changed {
                "config.patched"
            } else {
                "config.unchanged"
            },
            status: "succeeded",
            message: &config_event_message,
            metadata: Some(metadata),
            device_id: Some(&device_id),
        },
    )?;

    let relay_running = loopback_listener_available(relay_port);
    if relay_running {
        record_install_session_event(
            api_base_url,
            &install_session.install_session_id,
            &install_session.install_session_token,
            InstallSessionEvent {
                event_type: "relay.started",
                status: "succeeded",
                message: &format!(
                    "{} local OTLP relay is listening",
                    source_display_name(&source_kind)
                ),
                metadata: Some(json!({
                    "source": source,
                    "port": relay_port,
                })),
                device_id: Some(&device_id),
            },
        )?;
    }

    let status = if relay_running { "succeeded" } else { "failed" }.to_string();
    let message = if let Some((_, text)) = kept {
        if relay_running {
            text.to_string()
        } else {
            format!("{text} The local OTLP relay is not listening.")
        }
    } else if relay_running {
        format!(
            "{} telemetry setup installed",
            source_display_name(&source_kind)
        )
    } else {
        let config_state = if patch.changed {
            "config was written"
        } else {
            "config is unchanged"
        };
        format!(
            "{} telemetry {config_state}, but the local OTLP relay is not listening",
            source_display_name(&source_kind)
        )
    };
    Ok((
        status,
        message.clone(),
        install_source_action_result(
            &install_session.install_session_id,
            &device_id,
            source,
            relay_running,
            relay_port,
            &message,
            patch.changed,
        ),
    ))
}

pub(in crate::control) fn patch_disabled_message(source: &SourceKind) -> StableMessage {
    StableMessage {
        code: "patch_disabled".to_string(),
        text: format!(
            "{} telemetry config patching is disabled by environment; Ottto will not inspect or repair local config.",
            source_display_name(source)
        ),
    }
}

pub(in crate::control) fn install_source_registration_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "registered",
        "config_patched": false,
        "relay_required": false,
        "message": message,
    })
}

pub(in crate::control) fn install_source_action_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    relay_running: bool,
    relay_port: u16,
    message: &str,
    config_patched: bool,
) -> serde_json::Value {
    let mut result = json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "installed",
        "config_patched": config_patched,
        "relay_running": relay_running,
        "relay_port": relay_port,
        "relay_source": source,
    });
    if !relay_running {
        result["error_code"] = json!("relay_unavailable");
        result["error_message"] = json!(message);
    }
    result
}

fn install_source_patch_disabled_result(
    install_session_id: &str,
    device_id: &str,
    source: &str,
    message: &str,
) -> serde_json::Value {
    json!({
        "install_session_id": install_session_id,
        "device_id": device_id,
        "source": source,
        "local_changes": "patch_disabled",
        "config_patched": false,
        "relay_required": true,
        "message": message,
    })
}
