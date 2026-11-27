//! setup actions verification for local control.

use crate::control::api_url_with_base;
use crate::control::backend_error_indicates_account_gone;
use crate::control::backend_get_json_with_timeout;
use crate::control::current_rfc3339;
use crate::control::emit_setup_run_fast_verification_marker_with_refresh_mut;
use crate::control::empty_source_config;
use crate::control::execute_write_config_repair;
use crate::control::json;
use crate::control::new_pi_route_session_files;
use crate::control::no_fresh_telemetry_code;
use crate::control::not_installed_verification_result;
use crate::control::patch_disabled_message;
use crate::control::pi_identity_hints_for_route;
use crate::control::pi_route_is_unscoped;
use crate::control::pi_route_label;
use crate::control::pi_route_model;
use crate::control::pi_route_provider;
use crate::control::pi_route_summary_metadata;
use crate::control::pi_smoke_command;
use crate::control::prepare_pi_live_session_census;
use crate::control::read_pi_agent_auth;
use crate::control::read_pi_smoke_routes;
use crate::control::recent_pi_session_files;
use crate::control::reconcile_codex_source_off;
use crate::control::record_setup_action_event;
use crate::control::record_smoke_prompt;
use crate::control::refresh_setup_run_token_via_device_secret;
use crate::control::require_authorized_local_client;
use crate::control::run_bounded_command;
use crate::control::run_verification_smoke_prompt;
use crate::control::setup_run_request_with_refresh_mut;
use crate::control::setup_run_token_for_connection;
use crate::control::smoke_failure_verification_result;
use crate::control::smoke_failure_verification_result_with_config;
use crate::control::smoke_result_metadata;
use crate::control::snapshot_device_credentials_include_source;
use crate::control::source_binary_present;
use crate::control::source_config_state_for_daemon;
use crate::control::source_display_name;
use crate::control::source_patch_disabled;
use crate::control::source_requires_config_patch;
use crate::control::source_slug;
use crate::control::status_for;
use crate::control::telemetry_disabled_by_admin_message;
use crate::control::terminal_refresh_rejection;
use crate::control::thread;
use crate::control::url_with_query_params;
use crate::control::verification_failure_code;
use crate::control::verification_failure_message;
use crate::control::wait_for_setup_run_verification_with_refresh_mut_timeout;
use crate::control::wait_for_verification_with_refresh_mut;
use crate::control::BackendErrorDetails;
use crate::control::BackendErrorKind;
use crate::control::BillingIdentityHints;
use crate::control::Command;
use crate::control::ControlTokenStore;
use crate::control::Duration;
use crate::control::FileDeviceStore;
use crate::control::Instant;
use crate::control::KeychainSecretStore;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::LocalDaemon;
use crate::control::PiModelRoute;
use crate::control::PiSessionCensus;
use crate::control::RequestAuthorization;
use crate::control::SetupActionEvent;
use crate::control::SetupRunActionApiResponse;
use crate::control::SetupRunCredentials;
use crate::control::SetupRunVerificationFilters;
use crate::control::SetupRunVerificationResponse;
use crate::control::SetupVerificationTimeouts;
use crate::control::SmokeResult;
use crate::control::SourceConfigState;
use crate::control::SourceKind;
use crate::control::SourceRouteVerificationResult;
use crate::control::SourceVerificationCheck;
use crate::control::SourceVerificationMethod;
use crate::control::SourceVerificationResult;
use crate::control::SourceVerificationScope;
use crate::control::SourceVerificationStatus;
use crate::control::StableMessage;
use crate::control::SystemTime;
use crate::control::TerminalRefreshRejection;
use crate::control::CLAUDE_OAUTH_REAUTH_REQUIRED_CODE;
use crate::control::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
use crate::control::PI_SESSION_CENSUS_FAILED_CODE;
use crate::control::PI_SMOKE_COMMAND_TIMEOUT;
use crate::control::PI_VERIFICATION_HTTP_TIMEOUT;
use crate::control::PI_VERIFICATION_WAIT_TIMEOUT;
use crate::control::SETUP_VERIFICATION_HTTP_TIMEOUT;
use crate::control::SOURCE_NOT_INSTALLED_CODE;
use crate::control::UNIX_EPOCH;
use crate::control::VERIFICATION_POLL_INTERVAL;
use crate::PI_DEFAULT_MODEL_TEXT;

/// Status, message and backend result of a setup action, plus the
/// verification result a verify_source action computed.
pub(in crate::control) type SetupVerifyActionOutcome = (
    String,
    String,
    serde_json::Value,
    Option<SourceVerificationResult>,
);

pub(in crate::control) fn run_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
    source: SourceKind,
) -> Result<SetupVerifyActionOutcome, LocalApiError> {
    if source == SourceKind::Codex {
        reconcile_codex_source_off()?;
        let result = verify_source(daemon, &RequestAuthorization::DaemonInternal, source, false)?;
        let ready = result.message.code == "codex_local_import" && result.config.drift.is_empty();
        return Ok((
            if ready { "succeeded" } else { "failed" }.to_string(),
            result.message.text.clone(),
            json!({
                "status": verification_status_slug(&result.status), "verified": false, "records_seen": 0,
                "last_record_id": null, "last_received_at": null, "smoke_after": null,
                "local_import_ready": ready, "live_telemetry_required": false,
                "message_code": result.message.code,
                "error_code": if ready { serde_json::Value::Null } else { json!(result.message.code) },
                "error_message": if ready { serde_json::Value::Null } else { json!(result.message.text) }
            }),
            Some(result),
        ));
    }

    if !source_binary_present(&source) {
        let mut result =
            not_installed_verification_result(source.clone(), empty_source_config(&source));
        daemon.record_verification_result(&result)?;
        attach_verification_check(&mut result);
        let message = result.message.text.clone();
        return Ok((
            "succeeded".to_string(),
            message.clone(),
            json!({
                "status": verification_status_slug(&result.status),
                "verified": false,
                "records_seen": 0,
                "last_record_id": serde_json::Value::Null,
                "last_received_at": serde_json::Value::Null,
                "smoke_after": serde_json::Value::Null,
                "error_code": SOURCE_NOT_INSTALLED_CODE,
                "error_message": message,
            }),
            Some(result),
        ));
    }
    // Pi verifies its routes after the shared not-installed gate, so a Mac
    // without Pi never creates Pi directories or runs a doomed smoke.
    if source == SourceKind::Pi {
        return run_pi_verify_source_action(daemon, api_base_url, credentials, action);
    }
    let smoke_after = current_rfc3339();
    let smoke = run_verification_smoke_prompt(daemon, &source)?;
    record_setup_action_event(
        api_base_url,
        credentials,
        action,
        SetupActionEvent {
            event_type: "smoke.completed",
            status: if smoke.succeeded {
                "succeeded"
            } else {
                "warning"
            },
            message: &smoke.message,
            metadata: Some(json!({
                "source": source_slug(&source),
                "command_found": smoke.command_found,
                "exit_status": smoke.exit_status,
                "duration_ms": smoke.duration_ms,
                "diagnostic": smoke.diagnostic.clone(),
            })),
        },
    )?;
    if !smoke.succeeded {
        let mut result =
            smoke_failure_verification_result(source.clone(), &smoke, Some(smoke_after));
        daemon.record_verification_result(&result)?;
        attach_verification_check(&mut result);
        let message = result.message.text.clone();
        let action_status = match result.status {
            SourceVerificationStatus::Verified | SourceVerificationStatus::Warning => "succeeded",
            _ => "failed",
        };
        return Ok((
            action_status.to_string(),
            message.clone(),
            json!({
                "status": verification_status_slug(&result.status),
                "verified": false,
                "records_seen": 0,
                "last_record_id": serde_json::Value::Null,
                "last_received_at": serde_json::Value::Null,
                "smoke_after": result.smoke_after,
                "smoke": smoke_result_metadata(&smoke),
                "error_code": smoke.error_code.as_deref().unwrap_or("smoke_command_failed"),
                "error_message": message,
            }),
            Some(result),
        ));
    }
    let _ = emit_setup_run_fast_verification_marker_with_refresh_mut(
        api_base_url,
        credentials,
        &source,
        "setup_action_verify",
    );
    let verification =
        wait_for_verification_with_refresh_mut(api_base_url, credentials, &source, &smoke_after)?;
    let failure_code = verification_failure_code(&source, &smoke, &verification);
    let verification_message = if verification.verified {
        format!("{} verification passed.", source_display_name(&source))
    } else {
        verification_failure_message(
            &source,
            &smoke,
            &failure_code,
            verification.clear_condition.as_deref(),
        )
    };
    let mut result = verification_result(
        source.clone(),
        if verification.verified {
            SourceVerificationStatus::Verified
        } else {
            SourceVerificationStatus::NoFreshTelemetry
        },
        verification.verified,
        verification.records_seen,
        verification.last_record_id.clone(),
        verification.last_received_at.clone(),
        Some(verification.smoke_after.clone()),
        if verification.verified {
            "verified"
        } else {
            &failure_code
        },
        &verification_message,
    );
    daemon.record_verification_result(&result)?;
    attach_verification_check(&mut result);
    let status = if verification.verified {
        "succeeded"
    } else {
        "failed"
    };
    let message = result.message.text.clone();
    Ok((
        status.to_string(),
        message,
        json!({
            "verified": verification.verified,
            "records_seen": verification.records_seen,
            "last_record_id": verification.last_record_id,
            "last_received_at": verification.last_received_at,
            "smoke_after": verification.smoke_after,
            "smoke": smoke_result_metadata(&smoke),
            "error_code": if verification.verified { serde_json::Value::Null } else { json!(failure_code) },
            "error_message": if verification.verified { serde_json::Value::Null } else { json!(result.message.text) },
        }),
        Some(result),
    ))
}

fn run_pi_verify_source_action(
    daemon: &LocalDaemon,
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    action: &SetupRunActionApiResponse,
) -> Result<SetupVerifyActionOutcome, LocalApiError> {
    let mut result = run_pi_route_verification_with_credentials(api_base_url, credentials, None)?;
    record_setup_action_event(
        api_base_url,
        credentials,
        action,
        SetupActionEvent {
            event_type: "smoke.completed",
            status: if result.status == SourceVerificationStatus::Verified {
                "succeeded"
            } else if result.status == SourceVerificationStatus::Warning {
                "warning"
            } else {
                "failed"
            },
            message: &result.message.text,
            metadata: Some(pi_route_summary_metadata(&result)),
        },
    )?;
    daemon.record_verification_result(&result)?;
    let message = result.message.text.clone();
    let routes_total = result.route_results.len();
    let routes_verified = result
        .route_results
        .iter()
        .filter(|route| route.verified)
        .count();
    let routes_failed = routes_total.saturating_sub(routes_verified);
    // A Warning (partial-verified, or all routes awaiting a provider re-sign-in)
    // is a non-fatal completion: the run should advance and the source settle to
    // "warning"/needs-attention, not a hard "failed" that blocks. Only a real
    // smoke Failed maps the action to "failed".
    let action_status = match result.status {
        SourceVerificationStatus::Verified | SourceVerificationStatus::Warning => "succeeded",
        _ => "failed",
    };
    let backend_result = json!({
        "status": verification_status_slug(&result.status),
        "verified": result.verified,
        "records_seen": result.records_seen,
        "last_record_id": result.last_record_id,
        "last_received_at": result.last_received_at,
        "smoke_after": result.smoke_after,
        "route_results": result.route_results,
        "routes_total": routes_total,
        "routes_verified": routes_verified,
        "routes_failed": routes_failed,
        "error_code": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(result.message.code) },
        "error_message": if result.status == SourceVerificationStatus::Verified { serde_json::Value::Null } else { json!(message) },
    });
    // Classify after building the backend payload so its bytes are unchanged.
    attach_verification_check(&mut result);
    Ok((
        action_status.to_string(),
        message,
        backend_result,
        Some(result),
    ))
}

pub(in crate::control) fn codex_local_import_verification(
    config: SourceConfigState,
) -> SourceVerificationResult {
    verification_result_with_config(SourceKind::Codex, config, SourceVerificationStatus::Warning, false, 0, None, None, None,
        "codex_local_import", "Codex uses local session import. Live telemetry is disabled; this check does not prove an upload. Restart existing Codex processes after configuration cleanup and check collector status for import progress.")
}

pub(in crate::control) fn verify_source(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    repair: bool,
) -> Result<SourceVerificationResult, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    let mut result = verify_source_unchecked(daemon, authorization, source, repair)?;
    attach_verification_check(&mut result);
    Ok(result)
}

fn verify_source_unchecked(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    repair: bool,
) -> Result<SourceVerificationResult, LocalApiError> {
    let tracking_generation = daemon
        .tracking_episode(&source)
        .map(|(generation, _)| generation);
    let mut config = source_config_state_for_daemon(daemon, &source)?;
    if source_requires_config_patch(&source) && source_patch_disabled(&source) {
        let message = patch_disabled_message(&source);
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::Warning,
            false,
            0,
            None,
            None,
            None,
            "patch_disabled",
            &message.text,
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    if source_requires_config_patch(&source) && !config.drift.is_empty() {
        if repair {
            execute_write_config_repair(daemon, authorization, &source)?;
            config = source_config_state_for_daemon(daemon, &source)?;
        }
        if !config.drift.is_empty() && source != SourceKind::ClaudeCode {
            let result = config_drift_verification_result(source, config, repair);
            daemon.record_verification_result(&result)?;
            return Ok(result);
        }
    }

    let status = status_for(daemon, authorization)?;
    let recoverable_pending_account =
        status.account.state == LocalAccountState::ClaimPending && status.account.user.is_some();
    if status.account.state != LocalAccountState::Connected
        && (source == SourceKind::Codex || !recoverable_pending_account)
    {
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::AccountNotConnected,
            false,
            0,
            None,
            None,
            None,
            "account_not_connected",
            "This Mac isn't connected to Ottto yet. Use Sign in in the Ottto app, then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let Some(connection) = daemon.connection_for_authorized_client()? else {
        let result = verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            None,
            "reconnect_required",
            "This Mac needs a fresh Ottto sign-in. Use Sign in in the Ottto app, then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    };

    if source == SourceKind::Codex {
        let result = if !snapshot_device_credentials_include_source("codex") {
            verification_result_with_config(source, config, SourceVerificationStatus::Warning, false,
                0, None, None, None, "relay_device_not_provisioned",
                "Codex local import needs this Mac's source registration. Finish setup in Ottto, then check again.")
        } else if source_binary_present(&source) {
            codex_local_import_verification(config)
        } else {
            not_installed_verification_result(source, config)
        };
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let mut setup_credentials = match setup_run_token_for_connection(
        &connection.api_base_url,
        &connection,
    ) {
        Ok(credentials) => {
            if recoverable_pending_account {
                daemon.clear_recoverable_pending_auth_for_authorized_client()?;
            }
            credentials
        }
        Err(error) => {
            // A refresh failure proving the bound account was deleted
            // server-side frees the binding for a fresh first claim by any
            // user instead of dead-ending on reconnect/reset ceremony.
            if backend_error_indicates_account_gone(&error) {
                let _ = daemon.mark_account_not_found();
            }
            record_verify_refresh_rejection(daemon, &connection, &error);
            let result = verification_result_with_config(
                    source,
                    config,
                    SourceVerificationStatus::ReconnectRequired,
                    false,
                    0,
                    None,
                    None,
                    None,
                    "setup_run_token_missing",
                    "This Mac's local Ottto connection needs a fresh sign-in. Use Sign in in the Ottto app, then try verifying again.",
                );
            daemon.record_verification_result(&result)?;
            return Ok(result);
        }
    };
    let api_base_url = setup_credentials.connection.api_base_url.clone();

    // Before anything else: if the source CLI is genuinely not installed on this
    // Mac, there is nothing to smoke. Running the smoke anyway returns
    // "not installed or not executable", which the health projection renders as
    // a BLOCKING telemetry failure and stalls onboarding on a machine that never
    // had the app. Report a clean, non-blocking not-installed result instead.
    if !source_binary_present(&source) {
        let result = not_installed_verification_result(source.clone(), config);
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    if source == SourceKind::Pi {
        let connection = setup_credentials.connection.clone();
        let pi_token = setup_credentials.setup_run_token.clone();
        let result = match run_pi_route_verification(
            &api_base_url,
            &connection,
            &pi_token,
            tracking_generation.map(|generation| (daemon, generation)),
        ) {
            Ok(result) => result,
            Err(LocalApiError::Backend(details)) if details.status == Some(401) => {
                // Token expired mid-Pi-verify. Try a single refresh + retry.
                match refresh_setup_run_token_via_device_secret(&api_base_url, &connection) {
                    Ok(refreshed) => match run_pi_route_verification(
                        &api_base_url,
                        &refreshed.connection,
                        &refreshed.setup_run_token,
                        tracking_generation.map(|generation| (daemon, generation)),
                    ) {
                        Ok(retry) => retry,
                        Err(err) => verification_result_for_backend_error_with_config(
                            source.clone(),
                            empty_source_config(&source),
                            None,
                            &err,
                        ),
                    },
                    Err(err) => verification_result_for_backend_error_with_config(
                        source.clone(),
                        empty_source_config(&source),
                        None,
                        &err,
                    ),
                }
            }
            Err(other) => verification_result_for_backend_error_with_config(
                source.clone(),
                empty_source_config(&source),
                None,
                &other,
            ),
        };
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    // Codex/Claude verification proves telemetry by polling the backend for
    // records that the LOCAL OTLP relay forwards, and that forward requires the
    // relay device binding + relay-device-secret. On a freshly-claimed Mac those
    // are provisioned by the setup-run install action — not by claim completion,
    // and not by `ottto fix` (which only patches the agent's OTLP config) — so
    // within that window the relay drops every exported record (502) and the
    // backend poll returns 0. Running a smoke anyway and reporting
    // `no_fresh_telemetry` mis-attributes "telemetry transport is still being
    // set up" to "the agent produced no telemetry", which is what made a fresh
    // install fail to verify Codex even though the smoke ran and `fix` reported
    // success. Detect the missing provisioning up front and return an accurate,
    // actionable status instead of running a doomed smoke.
    if !relay_device_is_provisioned() {
        let result = verification_result_with_config(
            source.clone(),
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            None,
            "relay_device_not_provisioned",
            "This Mac just connected and is still finishing telemetry setup. Open the Ottto app to finish setup (or wait a moment), then try verifying again.",
        );
        daemon.record_verification_result(&result)?;
        return Ok(result);
    }

    let smoke_after = current_rfc3339();
    let smoke = run_verification_smoke_prompt(daemon, &source)?;
    let result = if !smoke.succeeded
        && smoke.error_code.as_deref() == Some(CLAUDE_OAUTH_REAUTH_REQUIRED_CODE)
    {
        smoke_failure_verification_result_with_config(
            source.clone(),
            config,
            &smoke,
            Some(smoke_after.clone()),
        )
    } else if !config.drift.is_empty() {
        // Claude auth is a higher-priority source blocker than telemetry config
        // drift. Run the smoke first so an expired provider session gets the
        // source-scoped sign-in action; otherwise preserve the normal Repair
        // guidance for the outstanding drift.
        config_drift_verification_result(source.clone(), config, repair)
    } else if !smoke.succeeded {
        smoke_failure_verification_result_with_config(
            source.clone(),
            config,
            &smoke,
            Some(smoke_after.clone()),
        )
    } else {
        let _ = emit_setup_run_fast_verification_marker_with_refresh_mut(
            &api_base_url,
            &mut setup_credentials,
            &source,
            "manual_verify",
        );
        match wait_for_verification_with_refresh_mut(
            &api_base_url,
            &mut setup_credentials,
            &source,
            &smoke_after,
        ) {
            Ok(response) if response.verified => verification_result_with_config(
                source.clone(),
                config,
                SourceVerificationStatus::Verified,
                true,
                response.records_seen,
                response.last_record_id,
                response.last_received_at,
                Some(response.smoke_after),
                "verified",
                &format!("{} verification passed.", source_display_name(&source)),
            ),
            Ok(response) => {
                let failure_code = verification_failure_code(&source, &smoke, &response);
                let failure_message = verification_failure_message(
                    &source,
                    &smoke,
                    &failure_code,
                    response.clear_condition.as_deref(),
                );
                verification_result_with_config(
                    source.clone(),
                    config,
                    SourceVerificationStatus::NoFreshTelemetry,
                    false,
                    response.records_seen,
                    response.last_record_id,
                    response.last_received_at,
                    Some(response.smoke_after),
                    &failure_code,
                    &failure_message,
                )
            }
            Err(error) => {
                record_verify_refresh_rejection(daemon, &connection, &error);
                verification_result_for_backend_error_with_config(
                    source,
                    config,
                    Some(smoke_after.clone()),
                    &error,
                )
            }
        }
    };
    daemon.record_verification_result_with_tracking(
        &result,
        tracking_generation.map(|generation| (generation, smoke_after.as_str())),
    )?;
    Ok(result)
}

/// Record an authoritative "run ended" refresh answer met during Verify, the
/// same way agent reads do (`observe_setup_run_read`), so local health stops
/// reporting the dead run as complete and Sign-in may reconnect this Mac.
/// Anything else, a refused device credential included, says nothing about
/// the run and is ignored; an outcome for a since-replaced binding is dropped
/// by the daemon.
fn record_verify_refresh_rejection(
    daemon: &LocalDaemon,
    binding: &LocalConnectionBinding,
    error: &LocalApiError,
) {
    if terminal_refresh_rejection(error) == Some(TerminalRefreshRejection::SetupRunEnded) {
        let _ = daemon.record_setup_run_ended(binding);
    }
}

/// True when the local OTLP relay can actually forward telemetry to the backend
/// — i.e. both the relay device binding (`FileDeviceStore`) and the
/// relay-device-secret exist. Mirrors
/// `snapshot_client::load_snapshot_device_credentials`. On a freshly-claimed Mac
/// these are provisioned asynchronously by the setup-run install action, so a
/// Codex/Claude verify uses this to avoid running a doomed smoke and reporting
/// `no_fresh_telemetry` while telemetry transport is still being set up.
fn relay_device_is_provisioned() -> bool {
    matches!(FileDeviceStore::default().load(), Ok(Some(_)))
        && KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
            .load()
            .is_ok()
}

fn run_pi_route_verification(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    tracking: Option<(&LocalDaemon, u64)>,
) -> Result<SourceVerificationResult, LocalApiError> {
    let mut credentials = SetupRunCredentials {
        setup_run_token: setup_run_token.to_string(),
        connection: connection.clone(),
    };
    run_pi_route_verification_with_credentials(api_base_url, &mut credentials, tracking)
}

fn run_pi_route_verification_with_credentials(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    tracking: Option<(&LocalDaemon, u64)>,
) -> Result<SourceVerificationResult, LocalApiError> {
    let mut routes = read_pi_smoke_routes();
    if routes.is_empty() {
        routes.push(PiModelRoute {
            provider: "default".to_string(),
            model: "default".to_string(),
            thinking_level: None,
            classification: crate::agent_status::PiRouteClassification {
                model_provider: None,
                billing_provider: None,
                billing_channel: None,
                auth_mode: None,
                gateway_provider: None,
                subscription_product: None,
                source_category: Some("unknown".to_string()),
            },
        });
    }

    let mut route_results = Vec::new();
    for route in &routes {
        route_results.push(run_one_pi_route_verification(
            api_base_url,
            credentials,
            route,
            tracking,
        ));
    }
    Ok(pi_route_aggregate_result(route_results))
}

pub(in crate::control) fn run_one_pi_route_verification(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    route: &PiModelRoute,
    tracking: Option<(&LocalDaemon, u64)>,
) -> SourceRouteVerificationResult {
    // A subscription-OAuth route (openai-codex / anthropic / github-copilot)
    // authenticates via a single-use *rotating* refresh token that Ottto must not
    // consume. Running a live `pi` smoke would burn that token (the provider then
    // returns 401 refresh_token_reused — which also breaks the agent's own CLI),
    // and Ottto cannot re-mint it. So verify these routes PASSIVELY from telemetry
    // the local_sessions collector already uploaded, and surface an actionable
    // re-auth Warning (not a hard smoke Failed) when none is fresh. Non-OAuth
    // routes (api_key / gateway / service_account) still run a live smoke.
    if route_is_subscription_oauth(route) {
        return verify_pi_subscription_oauth_route_passively(api_base_url, credentials, route);
    }

    // The direct Pi import endpoint is retired, so Verify no longer uploads the
    // smoke transcript. The post-smoke census already ran through the held
    // pre-smoke root; a new local session without matching backend usage
    // settles as the existing local-only Warning, never as an upload success.
    let (_, smoke_after, smoke) = match run_pi_route_pre_smoke(route) {
        Ok(ready) => ready,
        Err(failed) => return *failed,
    };
    if !smoke.succeeded {
        return pi_route_result_from_smoke(route, &smoke, Some(smoke_after));
    }

    let filters = if pi_route_is_unscoped(route) {
        None
    } else {
        Some(SetupRunVerificationFilters {
            model: Some(route.model.clone()),
            model_provider: route.classification.model_provider.clone(),
            billing_provider: route.classification.billing_provider.clone(),
        })
    };
    let result = match wait_for_setup_run_verification_with_refresh_mut_timeout(
        api_base_url,
        credentials,
        &SourceKind::Pi,
        &smoke_after,
        filters.as_ref(),
        SetupVerificationTimeouts {
            wait: PI_VERIFICATION_WAIT_TIMEOUT,
            request: PI_VERIFICATION_HTTP_TIMEOUT,
        },
    ) {
        Ok(verification) => pi_route_result_from_verification(route, &smoke, verification),
        Err(error) => {
            pi_route_result_from_backend_error(route, &smoke, Some(smoke_after.clone()), &error)
        }
    };
    // Only this execution path ran a smoke and polled its own records. Passive
    // routes return above, even though they also populate smoke_after.
    if let Some((daemon, generation)) = tracking {
        let evidence = pi_route_aggregate_result(vec![result.clone()]);
        let _ = daemon.confirm_tracking_smoke(&evidence, generation, &smoke_after);
    }
    result
}

pub(in crate::control) fn run_pi_route_pre_smoke(
    route: &PiModelRoute,
) -> Result<(PiSessionCensus, String, SmokeResult), Box<SourceRouteVerificationResult>> {
    run_pi_route_pre_smoke_with(
        route,
        prepare_pi_live_session_census,
        run_pi_route_smoke_prompt,
    )
}

pub(in crate::control) fn run_pi_route_pre_smoke_with<Prepare, RunSmoke>(
    route: &PiModelRoute,
    prepare: Prepare,
    run_smoke: RunSmoke,
) -> Result<(PiSessionCensus, String, SmokeResult), Box<SourceRouteVerificationResult>>
where
    Prepare: FnOnce() -> Result<PiSessionCensus, LocalApiError>,
    RunSmoke: FnOnce(&PiModelRoute) -> SmokeResult,
{
    let before_session_census = match prepare() {
        Ok(census) => census,
        Err(_) => {
            eprintln!("Pi route pre-smoke session safety check failed.");
            return Err(Box::new(pi_route_pre_smoke_census_failure(route)));
        }
    };
    let smoke_after = current_rfc3339();
    let mut smoke = run_smoke(route);
    if !smoke.succeeded {
        // A failed command is already terminal for this route. Its generic
        // pathname count is not authoritative and a second filesystem error
        // must not replace the real smoke diagnostic.
        smoke.local_session_observed = None;
        return Ok((before_session_census, smoke_after, smoke));
    }
    // Live route Verify owns a held pre-smoke root descriptor, so only a post-smoke
    // difference derived through that same descriptor can authorize local-only
    // success. A replaced/unreadable root fails before backend polling instead
    // of reclassifying another directory's pre-existing transcripts as smoke
    // evidence.
    let local_session_observed = match new_pi_route_session_files(&before_session_census) {
        Ok(files) => !files.is_empty(),
        Err(_) => {
            eprintln!("Pi route post-smoke session safety check failed.");
            return Err(Box::new(pi_route_post_smoke_census_failure(
                route,
                &smoke,
                smoke_after,
            )));
        }
    };
    smoke.local_session_observed = Some(local_session_observed);
    Ok((before_session_census, smoke_after, smoke))
}

/// Every Pi route result's route classification and billing identity hints,
/// with the no-evidence defaults most results share: failed, nothing seen, no
/// command run. Callers override only the fields that differ.
fn pi_route_result_base(route: &PiModelRoute) -> SourceRouteVerificationResult {
    let identity = pi_route_billing_identity_hints(route);
    SourceRouteVerificationResult {
        provider: pi_route_provider(route),
        model: pi_route_model(route),
        model_provider: route.classification.model_provider.clone(),
        billing_provider: route.classification.billing_provider.clone(),
        billing_channel: route.classification.billing_channel.clone(),
        auth_mode: route.classification.auth_mode.clone(),
        gateway_provider: route.classification.gateway_provider.clone(),
        subscription_product: route.classification.subscription_product.clone(),
        source_category: route.classification.source_category.clone(),
        account_identifier_hash: identity.account_identifier_hash,
        organization_identifier_hash: identity.organization_identifier_hash,
        credential_fingerprint_hash: identity.credential_fingerprint_hash,
        billing_identity_evidence: identity.billing_identity_evidence,
        billing_identity_confidence: identity.billing_identity_confidence,
        status: SourceVerificationStatus::Failed,
        verified: false,
        records_seen: 0,
        last_record_id: None,
        last_received_at: None,
        smoke_after: None,
        command_found: false,
        command_succeeded: false,
        exit_status: None,
        duration_ms: 0,
        diagnostic: None,
        error_code: None,
        local_session_observed: None,
        message: StableMessage {
            code: String::new(),
            text: String::new(),
        },
        check: None,
    }
}

fn pi_route_pre_smoke_census_failure(route: &PiModelRoute) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        error_code: Some(PI_SESSION_CENSUS_FAILED_CODE.to_string()),
        message: StableMessage {
            code: PI_SESSION_CENSUS_FAILED_CODE.to_string(),
            text: format!(
                "Pi route {} could not run a smoke because Ottto could not safely establish a complete local session baseline. Check that Pi's sessions directory is a real, readable directory, then retry Verify.",
                pi_route_label(route)
            ),
        },
        ..base
    }
}

fn pi_route_post_smoke_census_failure(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: String,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        smoke_after: Some(smoke_after),
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(PI_SESSION_CENSUS_FAILED_CODE.to_string()),
        message: StableMessage {
            code: PI_SESSION_CENSUS_FAILED_CODE.to_string(),
            text: format!(
                "Pi route {} completed smoke, but Ottto could not safely establish complete post-smoke local session evidence. No local session evidence was accepted; check that Pi's sessions directory is a real, readable directory, then retry Verify.",
                pi_route_label(route)
            ),
        },
        ..base
    }
}

/// error_code (and aggregate code) for a Pi route that has no fresh telemetry and
/// authenticates via a rotating provider OAuth token Ottto can't re-mint: the
/// recovery is a provider re-sign-in (`ottto fix --app pi` yields the steps).
pub(in crate::control) const PI_OAUTH_REAUTH_CODE: &str = "pi_oauth_reauth_required";

/// Pi is accepted through local session/route evidence for now. Live telemetry
/// matching is intentionally not a hard acceptance gate until the Pi live
/// ingestion path is productized again.
pub(in crate::control) const PI_LOCAL_ONLY_CODE: &str = "pi_local_only";

/// How far back to look for already-uploaded telemetry when verifying a
/// subscription-OAuth Pi route passively (we don't run a live smoke, so we treat
/// recent observed usage as the verification signal).
const PI_PASSIVE_LOOKBACK_HOURS: u32 = 6;

/// True for a Pi route whose provider OAuth token rotates on use (subscription
/// auth_mode=oauth: openai-codex / anthropic / github-copilot). These must not be
/// live-smoked.
fn route_is_subscription_oauth(route: &PiModelRoute) -> bool {
    is_subscription_oauth(
        route.classification.auth_mode.as_deref(),
        route.classification.billing_channel.as_deref(),
    )
}

fn is_subscription_oauth(auth_mode: Option<&str>, billing_channel: Option<&str>) -> bool {
    auth_mode == Some("oauth") && billing_channel == Some("subscription")
}

/// `now - hours` as an RFC3339 UTC timestamp (mirrors `current_rfc3339`'s
/// `/bin/date` approach). Falls back to "now" on failure, which simply tightens
/// the passive lookback (safe — it requires fresher telemetry).
fn rfc3339_hours_ago(hours: u32) -> String {
    Command::new("/bin/date")
        .args(["-u", &format!("-v-{hours}H"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(current_rfc3339)
}

/// Verify a subscription-OAuth Pi route without a live smoke: query the backend
/// for recently-observed usage for this route (model/provider filtered) over
/// a passive lookback window. Fresh usage -> Verified; fresh local route/account
/// evidence -> local-only verified Warning; none -> an actionable re-auth
/// Warning (never a hard smoke failure); backend error -> error result.
fn verify_pi_subscription_oauth_route_passively(
    api_base_url: &str,
    credentials: &mut SetupRunCredentials,
    route: &PiModelRoute,
) -> SourceRouteVerificationResult {
    let lookback = rfc3339_hours_ago(PI_PASSIVE_LOOKBACK_HOURS);
    // Recent local Pi sessions count as local route evidence so a valid OAuth
    // route with fresh local use is not mislabeled `pi_oauth_reauth_required`.
    // Only file presence and mtime are read; nothing is uploaded because the
    // direct Pi import endpoint is retired. The mtime bound matches the passive
    // lookback window. Non-fatal on error.
    let local_evidence_since = SystemTime::now()
        .checked_sub(Duration::from_secs(
            u64::from(PI_PASSIVE_LOOKBACK_HOURS) * 3600,
        ))
        .unwrap_or(UNIX_EPOCH);
    let recent_session_files = match recent_pi_session_files(local_evidence_since) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("Pi passive route session discovery failed (non-fatal): {error}");
            None
        }
    };
    let recent_local_session_observed = recent_session_files
        .as_ref()
        .is_some_and(|files| !files.is_empty());
    let local_session_observed = Some(recent_local_session_observed);
    let local_evidence_observed = pi_route_has_local_verification_evidence(
        &pi_route_billing_identity_hints(route),
        recent_local_session_observed,
    );
    let filters = if pi_route_is_unscoped(route) {
        None
    } else {
        Some(SetupRunVerificationFilters {
            model: Some(route.model.clone()),
            model_provider: route.classification.model_provider.clone(),
            billing_provider: route.classification.billing_provider.clone(),
        })
    };
    // A single query is enough: no smoke runs, so polling for 60s can't make new
    // records appear — they either already exist in the lookback window or not.
    match setup_run_request_with_refresh_mut(api_base_url, credentials, |active, token| {
        get_setup_run_verification_with_base(
            api_base_url,
            active,
            token,
            &SourceKind::Pi,
            &lookback,
            filters.as_ref(),
        )
    }) {
        Ok(verification) if verification.verified => pi_route_passive_result(
            route,
            SourceVerificationStatus::Verified,
            true,
            verification.records_seen,
            verification.last_record_id,
            verification.last_received_at,
            Some(lookback),
            None,
            format!(
                "Pi route {} verification passed from recent usage.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Ok(_) if local_evidence_observed => pi_route_passive_result(
            route,
            SourceVerificationStatus::Warning,
            true,
            0,
            None,
            None,
            Some(lookback),
            Some(PI_LOCAL_ONLY_CODE.to_string()),
            format!(
                "Verified Pi route {} from local route/account evidence. Pi is local-only for this rotating-OAuth route; live telemetry matching is not required.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Ok(_) => pi_route_passive_result(
            route,
            SourceVerificationStatus::Warning,
            false,
            0,
            None,
            None,
            Some(lookback),
            Some(PI_OAUTH_REAUTH_CODE.to_string()),
            format!(
                "Pi route {} needs a provider re-sign-in: no recent matching usage, and Ottto can't live-probe this route. Run `ottto fix --app pi` for recovery steps.",
                pi_route_label(route)
            ),
            local_session_observed,
        ),
        Err(error) => pi_route_result_from_backend_error(
            route,
            &pi_passive_placeholder_smoke(local_session_observed),
            Some(lookback),
            &error,
        ),
    }
}

/// A non-run `SmokeResult` placeholder for the passive verify path (no live `pi`
/// smoke was executed) so we can reuse the existing backend-error result builder.
fn pi_passive_placeholder_smoke(local_session_observed: Option<bool>) -> SmokeResult {
    SmokeResult {
        command_found: true,
        succeeded: false,
        exit_status: None,
        duration_ms: 0,
        message: "Checked recent Pi usage; no live smoke was run for this rotating-OAuth route."
            .to_string(),
        diagnostic: None,
        error_code: Some(PI_OAUTH_REAUTH_CODE.to_string()),
        local_session_observed,
    }
}

/// Build a route result for the passive (no-live-smoke) verification path.
#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
pub(in crate::control) fn pi_route_passive_result(
    route: &PiModelRoute,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    error_code: Option<String>,
    text: String,
    local_session_observed: Option<bool>,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    let code = error_code.clone().unwrap_or_else(|| "verified".to_string());
    SourceRouteVerificationResult {
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        command_found: true,
        error_code,
        local_session_observed,
        message: StableMessage { code, text },
        ..base
    }
}

/// The live route smoke. Its local session evidence comes only from the held
/// root's pre/post census, so the command itself counts nothing.
pub(in crate::control) fn run_pi_route_smoke_prompt(route: &PiModelRoute) -> SmokeResult {
    let command = pi_smoke_command(Some(route));
    let result = run_bounded_command(
        command.program,
        &command.args,
        PI_SMOKE_COMMAND_TIMEOUT,
        "Pi",
    );
    // Every route smoke is a real model request, so each one is logged; a
    // provider other than OpenAI or Anthropic is logged as unknown.
    let provider = match route.classification.model_provider.as_deref() {
        Some("openai") => crate::provider_calls::Provider::Openai,
        Some("anthropic") => crate::provider_calls::Provider::Anthropic,
        _ => crate::provider_calls::Provider::Unknown,
    };
    record_smoke_prompt(
        provider,
        crate::provider_calls::CallKind::PiSmokePrompt,
        pi_route_billing_identity_hints(route).account_identifier_hash,
        &result,
    );
    result
}

fn pi_route_billing_identity_hints(route: &PiModelRoute) -> BillingIdentityHints {
    let auth = read_pi_agent_auth();
    pi_identity_hints_for_route(auth.as_ref(), route)
}

pub(in crate::control) fn pi_route_has_local_verification_evidence(
    identity: &BillingIdentityHints,
    recent_local_session_observed: bool,
) -> bool {
    recent_local_session_observed
        || identity.billing_identity_evidence.is_some()
        || identity.account_identifier_hash.is_some()
        || identity.organization_identifier_hash.is_some()
        || identity.credential_fingerprint_hash.is_some()
}

/// Pi Verify checks only the saved default model. When its provider answered
/// that the model was not found, name it and say what to do; every other
/// failure keeps the generic text (the Companion keys its repair tone on it).
fn pi_route_failed_text(route_results: &[SourceRouteVerificationResult]) -> String {
    const GENERIC: &str = "No Pi model routes passed smoke verification.";
    let [route] = route_results else {
        return GENERIC.to_string();
    };
    let (Some(provider), Some(model)) = (route.provider.as_deref(), route.model.as_deref()) else {
        return GENERIC.to_string();
    };
    let model_not_found = route.diagnostic.as_deref().is_some_and(|diagnostic| {
        let diagnostic = diagnostic.to_ascii_lowercase();
        diagnostic.contains("404")
            && diagnostic.contains("model")
            && diagnostic.contains("not found")
            && !diagnostic.contains("endpoint")
    });
    if !model_not_found {
        return GENERIC.to_string();
    }
    format!(
        "The provider couldn't find {PI_DEFAULT_MODEL_TEXT}, {provider} / {model}. Choose another default model in Pi, or ignore this; usage collection is not affected."
    )
}

pub(in crate::control) fn pi_route_result_from_smoke(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        smoke_after,
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(
            smoke
                .error_code
                .clone()
                .unwrap_or_else(|| "smoke_command_failed".to_string()),
        ),
        local_session_observed: smoke.local_session_observed,
        message: StableMessage {
            code: smoke
                .error_code
                .clone()
                .unwrap_or_else(|| "smoke_command_failed".to_string()),
            text: format!(
                "Pi route {} failed smoke: {}",
                pi_route_label(route),
                smoke.message
            ),
        },
        ..base
    }
}

pub(in crate::control) fn pi_route_result_from_verification(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    verification: SetupRunVerificationResponse,
) -> SourceRouteVerificationResult {
    let base = pi_route_result_base(route);
    let local_only_verified = !verification.verified && smoke.local_session_observed == Some(true);
    let status = if verification.verified {
        SourceVerificationStatus::Verified
    } else if local_only_verified {
        SourceVerificationStatus::Warning
    } else {
        SourceVerificationStatus::NoFreshTelemetry
    };
    let code = if verification.verified {
        "verified".to_string()
    } else if local_only_verified {
        PI_LOCAL_ONLY_CODE.to_string()
    } else {
        no_fresh_telemetry_code(&SourceKind::Pi, smoke).to_string()
    };
    let text = if verification.verified {
        format!("Pi route {} verification passed.", pi_route_label(route))
    } else if local_only_verified {
        format!(
            "Pi route {} created a local session. Ottto is treating Pi as local-only; live telemetry is not required for this route.",
            pi_route_label(route)
        )
    } else {
        format!(
            "Pi route {} completed smoke, but Ottto did not receive matching usage.",
            pi_route_label(route)
        )
    };
    SourceRouteVerificationResult {
        status,
        verified: verification.verified || local_only_verified,
        records_seen: verification.records_seen,
        last_record_id: verification.last_record_id,
        last_received_at: verification.last_received_at,
        smoke_after: Some(verification.smoke_after),
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: if verification.verified {
            None
        } else {
            Some(code.clone())
        },
        local_session_observed: smoke.local_session_observed,
        message: StableMessage { code, text },
        ..base
    }
}

pub(in crate::control) fn pi_route_result_from_backend_error(
    route: &PiModelRoute,
    smoke: &SmokeResult,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceRouteVerificationResult {
    let source_result =
        verification_result_for_backend_error(SourceKind::Pi, smoke_after.clone(), error);
    let base = pi_route_result_base(route);
    SourceRouteVerificationResult {
        status: source_result.status,
        smoke_after,
        command_found: smoke.command_found,
        command_succeeded: smoke.succeeded,
        exit_status: smoke.exit_status,
        duration_ms: smoke.duration_ms.try_into().unwrap_or(u64::MAX),
        diagnostic: smoke.diagnostic.clone(),
        error_code: Some(source_result.message.code.clone()),
        local_session_observed: smoke.local_session_observed,
        message: StableMessage {
            code: source_result.message.code,
            text: format!(
                "Pi route {} could not be verified: {}",
                pi_route_label(route),
                source_result.message.text
            ),
        },
        ..base
    }
}

pub(in crate::control) fn pi_route_aggregate_result(
    route_results: Vec<SourceRouteVerificationResult>,
) -> SourceVerificationResult {
    let total = route_results.len();
    let live_passed = route_results
        .iter()
        .filter(|route| route.verified && route.status == SourceVerificationStatus::Verified)
        .count();
    let local_only_passed = route_results
        .iter()
        .filter(|route| {
            route.verified
                && route.status == SourceVerificationStatus::Warning
                && route.error_code.as_deref() == Some(PI_LOCAL_ONLY_CODE)
        })
        .count();
    // A route awaiting a provider re-sign-in is a soft, actionable Warning — not a
    // hard smoke failure — even though it isn't verified: Ottto deliberately did
    // not (and can't safely) live-probe a rotating-OAuth route, so "no fresh
    // telemetry yet" must not aggregate to Failed.
    let reauth_pending = route_results
        .iter()
        .filter(|route| {
            !route.verified && route.error_code.as_deref() == Some(PI_OAUTH_REAUTH_CODE)
        })
        .count();
    let hard_failed = total
        .saturating_sub(live_passed)
        .saturating_sub(local_only_passed)
        .saturating_sub(reauth_pending);
    let status = if total > 0 && live_passed == total {
        SourceVerificationStatus::Verified
    } else if total > 0 && hard_failed == 0 {
        // Everything is live-verified, local-only verified, and/or awaiting re-auth.
        SourceVerificationStatus::Warning
    } else if live_passed > 0 || local_only_passed > 0 || reauth_pending > 0 {
        SourceVerificationStatus::Warning
    } else {
        SourceVerificationStatus::Failed
    };
    let all_reauth_pending =
        live_passed == 0 && local_only_passed == 0 && hard_failed == 0 && reauth_pending > 0;
    let all_local_only =
        live_passed == 0 && local_only_passed > 0 && hard_failed == 0 && reauth_pending == 0;
    let all_census_failed = total > 0
        && route_results
            .iter()
            .all(|route| route.error_code.as_deref() == Some(PI_SESSION_CENSUS_FAILED_CODE));
    let all_telemetry_disabled = total > 0
        && route_results
            .iter()
            .all(|route| route.error_code.as_deref() == Some("telemetry_disabled_by_admin"));
    let status = if all_telemetry_disabled {
        SourceVerificationStatus::NoFreshTelemetry
    } else {
        status
    };
    let (code, text): (&str, String) = match status {
        SourceVerificationStatus::Verified => {
            ("verified", format!("Verified {total} Pi model routes."))
        }
        SourceVerificationStatus::Warning if all_local_only => (
            PI_LOCAL_ONLY_CODE,
            format!(
                "Verified {local_only_passed} Pi model route(s) from local session evidence. Pi is local-only; live telemetry is not required."
            ),
        ),
        SourceVerificationStatus::Warning if all_reauth_pending => (
            PI_OAUTH_REAUTH_CODE,
            "Re-sign in to the Pi provider, then re-run Verify — Ottto can't re-mint a rotating provider OAuth token."
                .to_string(),
        ),
        SourceVerificationStatus::Warning => (
            "pi_route_warnings",
            if live_passed > 0 || local_only_passed > 0 {
                format!(
                    "Verified {live_passed} live and {local_only_passed} local-only of {total} Pi model routes; review the remaining routes."
                )
            } else {
                format!(
                    "Pi has {total} model routes awaiting review; re-sign in if a provider asks."
                )
            },
        ),
        SourceVerificationStatus::Failed if all_census_failed => (
            PI_SESSION_CENSUS_FAILED_CODE,
            "Pi verification could not safely establish complete local session evidence before or after smoke. No local session evidence was accepted; check that Pi's sessions directory is a real, readable directory, then retry Verify."
                .to_string(),
        ),
        SourceVerificationStatus::NoFreshTelemetry if all_telemetry_disabled => (
            "telemetry_disabled_by_admin",
            telemetry_disabled_by_admin_message(&SourceKind::Pi),
        ),
        _ => ("pi_route_smoke_failed", pi_route_failed_text(&route_results)),
    };
    let last_route = route_results
        .iter()
        .filter(|route| route.last_received_at.is_some())
        .max_by_key(|route| route.last_received_at.as_deref().unwrap_or(""));
    SourceVerificationResult {
        source: SourceKind::Pi,
        config: empty_source_config(&SourceKind::Pi),
        status,
        verified: live_passed > 0 || local_only_passed > 0,
        records_seen: route_results.iter().map(|route| route.records_seen).sum(),
        last_record_id: last_route.and_then(|route| route.last_record_id.clone()),
        last_received_at: last_route.and_then(|route| route.last_received_at.clone()),
        smoke_after: route_results
            .iter()
            .filter_map(|route| route.smoke_after.clone())
            .min(),
        message: StableMessage {
            code: code.to_string(),
            text,
        },
        route_results,
        check: None,
    }
}

fn config_drift_verification_result(
    source: SourceKind,
    config: SourceConfigState,
    repair_requested: bool,
) -> SourceVerificationResult {
    if source == SourceKind::Codex
        && config
            .drift
            .iter()
            .any(|drift| drift.key == "codex.config_toml")
    {
        return verification_result_with_config(source, config, SourceVerificationStatus::Failed,
            false, 0, None, None, None, "manual_fence_review_required",
            "Codex configuration needs manual review. Ottto left it unchanged. Review the Ottto telemetry entries and fence markers in ~/.codex/config.toml, then run Verify again.");
    }
    let missing = !config.discovered
        || config
            .drift
            .iter()
            .any(|drift| drift.key.ends_with("config_file"));
    let code = if repair_requested {
        "config_drift_after_repair"
    } else if missing {
        "config_missing"
    } else {
        "config_drift"
    };
    let text = if repair_requested {
        format!(
            "{} telemetry config still does not match the active Ottto relay after repair.",
            source_display_name(&source)
        )
    } else if missing {
        format!(
            "{} telemetry config is missing. Use Repair in the Ottto app to update it, then run Verify again.",
            source_display_name(&source)
        )
    } else {
        format!(
            "{} telemetry config does not match the active Ottto relay. Use Repair in the Ottto app to update it, then run Verify again.",
            source_display_name(&source)
        )
    };
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Failed,
        false,
        0,
        None,
        None,
        None,
        code,
        &text,
    )
}

pub(in crate::control) fn verification_result_for_backend_error(
    source: SourceKind,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    verification_result_for_backend_error_with_config(source, config, smoke_after, error)
}

fn verification_result_for_backend_error_with_config(
    source: SourceKind,
    config: SourceConfigState,
    smoke_after: Option<String>,
    error: &LocalApiError,
) -> SourceVerificationResult {
    if matches!(error, LocalApiError::SetupRunConnectionMissing) {
        return verification_result_with_config(
            source,
            config,
            SourceVerificationStatus::ReconnectRequired,
            false,
            0,
            None,
            None,
            smoke_after,
            "setup_run_connection_missing",
            "This Mac needs a fresh Ottto sign-in. Use Sign in in the Ottto app, then try verifying again.",
        );
    }
    if let LocalApiError::Backend(details) = error {
        if is_telemetry_disabled_by_admin_error(error) {
            return verification_result_with_config(
                source.clone(),
                config,
                SourceVerificationStatus::NoFreshTelemetry,
                false,
                0,
                None,
                None,
                smoke_after,
                "telemetry_disabled_by_admin",
                &telemetry_disabled_by_admin_message(&source),
            );
        }
        if details.status == Some(401) {
            let expired = details
                .body_excerpt
                .as_deref()
                .is_some_and(|body| body.to_ascii_lowercase().contains("expired"));
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::ReconnectRequired,
                false,
                0,
                None,
                None,
                smoke_after,
                if expired {
                    "setup_run_token_expired"
                } else {
                    "setup_run_token_invalid"
                },
                "Your Ottto session has expired. Use Sign in in the Ottto app, then try verifying again.",
            );
        }
        if details.status == Some(404) {
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::ReconnectRequired,
                false,
                0,
                None,
                None,
                smoke_after,
                "setup_run_missing",
                "We can't find an active Ottto session for this Mac. Use Sign in in the Ottto app, then try verifying again.",
            );
        }
        if details.kind == BackendErrorKind::Rejected {
            return verification_result_with_config(
                source,
                config,
                SourceVerificationStatus::Failed,
                false,
                0,
                None,
                None,
                smoke_after,
                "verification_service_rejected",
                "Ottto couldn't verify this source. Use Sign in in the Ottto app to refresh your session, then try again.",
            );
        }
    }
    verification_result_with_config(
        source,
        config,
        SourceVerificationStatus::Failed,
        false,
        0,
        None,
        None,
        smoke_after,
        "verification_service_unavailable",
        "Could not reach Ottto verification. Check your network and retry.",
    )
}

pub(in crate::control) fn is_telemetry_disabled_by_admin_error(error: &LocalApiError) -> bool {
    matches!(
        error,
        LocalApiError::Backend(details)
            if details.status == Some(403)
                && backend_error_has_detail_code(details, "telemetry_disabled_by_admin")
    )
}

fn backend_error_has_detail_code(details: &BackendErrorDetails, code: &str) -> bool {
    let Some(body) = details.body_excerpt.as_deref() else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(detail) = value.get("detail") else {
        return false;
    };
    detail.as_str() == Some(code)
        || detail.get("code").and_then(serde_json::Value::as_str) == Some(code)
}

pub(in crate::control) fn no_fresh_telemetry_message(
    source: &SourceKind,
    smoke: &SmokeResult,
) -> String {
    if source == &SourceKind::Pi && smoke.local_session_observed == Some(true) {
        return "Pi created a local session, but Ottto did not receive a matching verification signal for this setup run. Check the backend binding and local upload path, then retry Verify.".to_string();
    }
    if source == &SourceKind::Pi {
        return "Pi smoke completed, but no new local Pi session file was observed and Ottto did not receive matching usage. Check the configured Pi provider route, then retry Verify.".to_string();
    }
    format!(
        "Ottto did not receive a fresh {} verification signal after the smoke session. Check that {} setup is connected, then retry Verify.",
        source_display_name(source),
        source_display_name(source),
    )
}

fn get_setup_run_verification_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    get_setup_run_verification_with_base_timeout(
        api_base_url,
        connection,
        setup_run_token,
        source,
        smoke_after,
        filters,
        SETUP_VERIFICATION_HTTP_TIMEOUT,
    )
}

pub(in crate::control) fn get_setup_run_verification_with_base_timeout(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    request_timeout: Duration,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/verification",
            connection.setup_run_id
        ),
    );
    let mut params = vec![
        ("source", source_slug(source).to_string()),
        ("smoke_after", smoke_after.to_string()),
    ];
    if let Some(filters) = filters {
        if let Some(model) = filters.model.as_deref() {
            params.push(("model", model.to_string()));
        }
        if let Some(model_provider) = filters.model_provider.as_deref() {
            params.push(("model_provider", model_provider.to_string()));
        }
        if let Some(billing_provider) = filters.billing_provider.as_deref() {
            params.push(("billing_provider", billing_provider.to_string()));
        }
    }
    // `source` and `smoke_after` are always present, so the query is never empty.
    let url = url_with_query_params(url, params);
    backend_get_json_with_timeout(
        &url,
        &[("X-Ottto-Setup-Run-Token", setup_run_token)],
        request_timeout,
    )
}

pub(in crate::control) fn wait_for_setup_run_verification_with_base_timeout(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: &SourceKind,
    smoke_after: &str,
    filters: Option<&SetupRunVerificationFilters>,
    timeouts: SetupVerificationTimeouts,
) -> Result<SetupRunVerificationResponse, LocalApiError> {
    let start = Instant::now();
    loop {
        let response = get_setup_run_verification_with_base_timeout(
            api_base_url,
            connection,
            setup_run_token,
            source,
            smoke_after,
            filters,
            timeouts.request,
        )?;
        if response.verified || start.elapsed() >= timeouts.wait {
            return Ok(response);
        }
        thread::sleep(VERIFICATION_POLL_INTERVAL);
    }
}

#[expect(clippy::too_many_arguments, reason = "9 args; no options struct yet")]
pub(in crate::control) fn verification_result(
    source: SourceKind,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    code: &str,
    text: &str,
) -> SourceVerificationResult {
    let config = empty_source_config(&source);
    verification_result_with_config(
        source,
        config,
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        code,
        text,
    )
}

#[expect(clippy::too_many_arguments, reason = "10 args; no options struct yet")]
pub(in crate::control) fn verification_result_with_config(
    source: SourceKind,
    config: SourceConfigState,
    status: SourceVerificationStatus,
    verified: bool,
    records_seen: u64,
    last_record_id: Option<String>,
    last_received_at: Option<String>,
    smoke_after: Option<String>,
    code: &str,
    text: &str,
) -> SourceVerificationResult {
    SourceVerificationResult {
        source,
        config,
        status,
        verified,
        records_seen,
        last_record_id,
        last_received_at,
        smoke_after,
        message: StableMessage {
            code: code.to_string(),
            text: text.to_string(),
        },
        route_results: Vec::new(),
        check: None,
    }
}

/// Record what kind of check produced `result` and what it established, from
/// the result alone. A positive scope needs a Verified/Warning status, and no
/// scope names an account: nothing in a result binds accepted usage to one.
pub(in crate::control) fn attach_verification_check(result: &mut SourceVerificationResult) {
    let positive_status = matches!(
        result.status,
        SourceVerificationStatus::Verified | SourceVerificationStatus::Warning
    );
    let check = match result.source {
        SourceKind::Codex => SourceVerificationCheck {
            method: Some(SourceVerificationMethod::ConfigurationCheck),
            scope: if positive_status
                && !result.verified
                && result.message.code == "codex_local_import"
                && result.config.drift.is_empty()
            {
                SourceVerificationScope::Configuration
            } else {
                SourceVerificationScope::NotEstablished
            },
        },
        SourceKind::ClaudeCode => SourceVerificationCheck {
            method: Some(SourceVerificationMethod::LivePrompt),
            scope: if result.verified && result.status == SourceVerificationStatus::Verified {
                SourceVerificationScope::UsageReceived
            } else {
                SourceVerificationScope::NotEstablished
            },
        },
        SourceKind::Pi => {
            for route in &mut result.route_results {
                route.check = Some(pi_route_verification_check(route));
            }
            let checks = result
                .route_results
                .iter()
                .filter_map(|route| route.check.as_ref())
                .collect::<Vec<_>>();
            let method = checks.first().and_then(|first| {
                if checks.iter().all(|check| check.method == first.method) {
                    first.method
                } else {
                    Some(SourceVerificationMethod::Mixed)
                }
            });
            let all =
                |scope: SourceVerificationScope| checks.iter().all(|check| check.scope == scope);
            let established = checks
                .iter()
                .filter(|check| check.scope != SourceVerificationScope::NotEstablished)
                .count();
            let scope = if !positive_status || established == 0 {
                SourceVerificationScope::NotEstablished
            } else if all(SourceVerificationScope::UsageReceived) {
                SourceVerificationScope::UsageReceived
            } else if all(SourceVerificationScope::LocalEvidence) {
                SourceVerificationScope::LocalEvidence
            } else {
                SourceVerificationScope::Partial
            };
            SourceVerificationCheck { method, scope }
        }
    };
    result.check = Some(check);
}

/// Same route split as Verify's dispatch and the aggregate's route counting.
fn pi_route_verification_check(route: &SourceRouteVerificationResult) -> SourceVerificationCheck {
    let passive =
        is_subscription_oauth(route.auth_mode.as_deref(), route.billing_channel.as_deref());
    SourceVerificationCheck {
        method: Some(if passive {
            SourceVerificationMethod::PassiveRecentUsage
        } else {
            SourceVerificationMethod::LivePrompt
        }),
        scope: if !route.verified {
            SourceVerificationScope::NotEstablished
        } else if route.status == SourceVerificationStatus::Verified {
            SourceVerificationScope::UsageReceived
        } else if route.status == SourceVerificationStatus::Warning
            && route.error_code.as_deref() == Some(PI_LOCAL_ONLY_CODE)
        {
            SourceVerificationScope::LocalEvidence
        } else {
            SourceVerificationScope::NotEstablished
        },
    }
}

pub(in crate::control) fn verification_status_slug(
    status: &SourceVerificationStatus,
) -> &'static str {
    match status {
        SourceVerificationStatus::Verified => "verified",
        SourceVerificationStatus::Warning => "warning",
        SourceVerificationStatus::NoFreshTelemetry => "no_fresh_telemetry",
        SourceVerificationStatus::AccountNotConnected => "account_not_connected",
        SourceVerificationStatus::ReconnectRequired => "reconnect_required",
        SourceVerificationStatus::Failed => "failed",
    }
}
