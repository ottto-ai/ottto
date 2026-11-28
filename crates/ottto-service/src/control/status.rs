//! status for local control.

use crate::control::agent_read_with_refresh;
use crate::control::api_url_with_base;
use crate::control::approved_managed_claude_relay_env;
use crate::control::backend_get_agent_read_json;
use crate::control::compiled_build_id;
use crate::control::compiled_release_channel;
use crate::control::compiled_release_version;
use crate::control::default_support_dir;
use crate::control::form_url_encode;
use crate::control::home_path;
use crate::control::install_owner_for_path;
use crate::control::local_lifecycle_home_dir;
use crate::control::local_relay_base_url_for_daemon;
use crate::control::lock_managed_claude_settings;
use crate::control::refresh_setup_run_token_via_device_secret;
use crate::control::release_channel_from_str;
use crate::control::repair_claude_statusline_for_refresh_at;
use crate::control::repair_registered_managed_claude_relay_settings_locked;
use crate::control::require_authorized_local_client;
use crate::control::setup_run_token_for_connection;
use crate::control::source_patch_disabled;
use crate::control::terminal_refresh_rejection;
use crate::control::thread;
use crate::control::validated_api_base_url;
use crate::control::AgentContextQuery;
use crate::control::AgentCostsQuery;
use crate::control::AgentProviderImpactQuery;
use crate::control::AgentRecommendationsQuery;
use crate::control::AgentSessionsQuery;
use crate::control::AgentStatusSnapshot;
use crate::control::Command;
use crate::control::Duration;
use crate::control::InstallOwner;
use crate::control::LocalAccountBinding;
use crate::control::LocalAccountState;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::LocalDaemon;
use crate::control::PathBuf;
use crate::control::ReleaseChannel;
use crate::control::ReleaseManifest;
use crate::control::RequestAuthorization;
use crate::control::ServiceOwnerState;
use crate::control::SetupRunReadStart;
use crate::control::SourceKind;
use crate::control::SourceVerificationResult;
use crate::control::SourceVerificationStatus;
use crate::control::SystemTime;
use crate::control::TerminalRefreshRejection;
use crate::control::UpdateGate;
use crate::control::UpdateState;
use crate::control::UpdateStatus;
use crate::control::AGENT_STATUS_SNAPSHOT_TTL_MINUTES;
use crate::control::PROTOCOL_VERSION;
use crate::control::UNIX_EPOCH;

pub(super) fn status_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<ottto_protocol::DaemonStatus, LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => daemon.status(token),
        RequestAuthorization::TrustedCompanionApp | RequestAuthorization::DaemonInternal => {
            daemon.status_for_trusted_client()
        }
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }
}

pub(super) fn verification_result_should_refresh_agent_status(
    result: &SourceVerificationResult,
) -> bool {
    (matches!(result.status, SourceVerificationStatus::NoFreshTelemetry)
        && result.message.code != "telemetry_disabled_by_admin")
        || (matches!(result.status, SourceVerificationStatus::Failed)
            && matches!(
                result.message.code.as_str(),
                "smoke_timeout" | "verification_service_unavailable"
            ))
}

pub(super) fn account_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
) -> Result<LocalAccountBinding, LocalApiError> {
    // The `account` command answers with the effective account, like `status`.
    status_for(daemon, authorization).map(|status| crate::effective_account_binding(&status))
}

pub(super) fn agent_context(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentContextQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto context",
        |api_base_url, connection| agent_context_url(api_base_url, connection, &query),
    )
}

pub(super) fn agent_costs(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentCostsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto costs",
        |api_base_url, connection| agent_costs_url(api_base_url, connection, &query),
    )
}

pub(super) fn agent_sessions(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentSessionsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    reject_timezone_override(query.timezone.as_deref())?;
    observe_agent_read(
        daemon,
        authorization,
        "ottto sessions",
        |api_base_url, connection| agent_sessions_url(api_base_url, connection, &query),
    )
}

pub(super) fn agent_recommendations(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentRecommendationsQuery,
) -> Result<serde_json::Value, LocalApiError> {
    observe_agent_read(
        daemon,
        authorization,
        "ottto recommendations",
        |api_base_url, connection| agent_recommendations_url(api_base_url, connection, &query),
    )
}

pub(super) fn agent_provider_impact(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    query: AgentProviderImpactQuery,
) -> Result<serde_json::Value, LocalApiError> {
    observe_agent_read(
        daemon,
        authorization,
        "ottto provider-impact",
        |api_base_url, connection| agent_provider_impact_url(api_base_url, connection, &query),
    )
}

/// One observed agent read: the setup-run binding and its observation come
/// from `observe_setup_run_read`, the request from `agent_read_with_refresh`.
fn observe_agent_read(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
    read_url: impl Fn(&str, &LocalConnectionBinding) -> String,
) -> Result<serde_json::Value, LocalApiError> {
    observe_setup_run_read(
        daemon,
        authorization,
        command,
        |api_base_url, connection, setup_run_token| {
            agent_read_with_refresh(api_base_url, connection, setup_run_token, &read_url)
        },
    )
}

pub(super) const TIMEZONE_OVERRIDE_UNSUPPORTED: &str =
    "--timezone is not supported. Ottto uses the timezone saved in your account settings for calendar windows.";

/// Calendar windows follow the account's saved timezone; Ottto rejects an
/// explicit `timezone=` query, so refuse it locally with that reason instead
/// of forwarding a request that can only fail.
fn reject_timezone_override(timezone: Option<&str>) -> Result<(), LocalApiError> {
    if timezone.is_some_and(|value| !value.trim().is_empty()) {
        return Err(LocalApiError::InvalidRequest(
            TIMEZONE_OVERRIDE_UNSUPPORTED.to_string(),
        ));
    }
    Ok(())
}

/// Run one setup-run agent read and record whether Ottto still accepts this
/// Mac's setup run, so local status stops reporting a rejected run as
/// complete. Only an authoritative terminal answer from the device-secret
/// refresh counts (`terminal_refresh_rejection`): every read path propagates
/// that refresh error unchanged, so it is the read's final error. A read 401,
/// a 401 retried after a successful refresh, an unrecognized refresh detail,
/// and network, timeout or other backend failures say nothing about the run
/// and leave the recorded state unchanged. A successful read clears it.
/// Reads run concurrently with setup and sign-in, so the outcome is recorded
/// against exactly the binding this read used, and dropped by the daemon if
/// that binding has since been replaced. Reads of one binding also run
/// concurrently with each other, so a success clears only the rejection that
/// was already recorded when this read started, never a newer one.
fn observe_setup_run_read<T>(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
    read: impl FnOnce(&str, &LocalConnectionBinding, &str) -> Result<T, LocalApiError>,
) -> Result<T, LocalApiError> {
    let (api_base_url, start) = setup_run_agent_read_binding(daemon, authorization, command)?;
    let result =
        setup_run_token_for_connection(&api_base_url, &start.binding).and_then(|credentials| {
            read(
                &api_base_url,
                &credentials.connection,
                &credentials.setup_run_token,
            )
        });
    match &result {
        Ok(_) => {
            let _ = daemon.record_setup_run_read_accepted(&start);
        }
        Err(error) => {
            if let Some(rejection) = terminal_refresh_rejection(error) {
                let _ = daemon.record_setup_run_read_rejected(&start.binding, rejection);
            }
        }
    }
    result
}

/// The device credential check for a Mac with no enabled app. Uploads and
/// local-health passes need an app's relay token, so without one nothing tells
/// this Mac that Ottto disconnected it. The heartbeat thread calls this every
/// `IDLE_CREDENTIAL_CHECK_INTERVAL` while no app is enabled, and after the
/// Mac wakes from sleep.
///
/// The check is one read-only `GET /api/v1/telemetry/devices/{id}/status` with
/// this Mac's device id and secret: no source, usage or local data, nothing
/// written on either side, no token. Only an authoritative answer is recorded,
/// the same way as for agent reads: a refused credential marks the setup run
/// rejected with a refused device (`account` and `status` then read
/// reconnect-required), and a usable one clears an earlier device refusal
/// (never a "setup run ended" rejection, which the device answer can't
/// prove anything about). No
/// answer (network, 429, 5xx, an older server without the route) changes
/// nothing.
/// Returns the answer when the check ran, `None` when it was skipped.
pub(crate) fn probe_idle_device_credential(
    daemon: &LocalDaemon,
) -> Option<crate::control::IdleCredentialAnswer> {
    probe_idle_device_credential_with(daemon, crate::control::idle_device_credential_answer)
}

pub(crate) fn probe_idle_device_credential_with(
    daemon: &LocalDaemon,
    check: impl FnOnce(&str) -> crate::control::IdleCredentialAnswer,
) -> Option<crate::control::IdleCredentialAnswer> {
    use crate::control::IdleCredentialAnswer;
    let connected = daemon
        .status_for_trusted_client()
        .is_ok_and(|status| status.account.state == LocalAccountState::Connected);
    if !connected {
        return None;
    }
    let Ok(Some(start)) = daemon.setup_run_read_start() else {
        return None;
    };
    let answer = check(&start.binding.api_base_url);
    match answer {
        IdleCredentialAnswer::Usable => {
            let _ = daemon.record_device_credential_accepted(&start);
        }
        IdleCredentialAnswer::Refused => {
            let _ = daemon.record_setup_run_read_rejected(
                &start.binding,
                TerminalRefreshRejection::DeviceRejected,
            );
        }
        IdleCredentialAnswer::NoProof => {}
    }
    Some(answer)
}

/// `ottto cloud status`: read-only connector status through the setup-run
/// bridge, plus whether this service serves the Mac app's signer. Attempt-specific status and
/// Bedrock setup use the cloud-connect control commands.
pub(super) fn cloud_status(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: Option<String>,
) -> Result<serde_json::Value, LocalApiError> {
    validate_cloud_status_source(source.as_deref())?;
    let (mut status, web) = observe_setup_run_read(
        daemon,
        authorization,
        "ottto cloud",
        |api_base_url, connection, setup_run_token| {
            let web = crate::control::cloud_connect::paired_connect_url(api_base_url);
            match cloud_status_with_base(
                api_base_url,
                connection,
                setup_run_token,
                source.as_deref(),
            ) {
                Ok(value) => Ok(value),
                Err(LocalApiError::Backend(ref details)) if details.status == Some(401) => {
                    let refreshed =
                        refresh_setup_run_token_via_device_secret(api_base_url, connection)?;
                    cloud_status_with_base(
                        api_base_url,
                        &refreshed.connection,
                        &refreshed.setup_run_token,
                        source.as_deref(),
                    )
                }
                Err(error) => Err(error),
            }
            .map(|value| (value, web))
        },
    )?;
    // The connections link names the web origin compiled for this API, never the server's own.
    crate::control::cloud_connect::set_connect_url(&mut status, web);
    if let Some(status) = status.as_object_mut() {
        let signer = if crate::control::cloud_connect::signer_available() {
            "available"
        } else {
            "unavailable"
        };
        status.insert("signer".to_string(), serde_json::Value::from(signer));
    }
    Ok(status)
}

pub(super) fn validate_cloud_status_source(source: Option<&str>) -> Result<(), LocalApiError> {
    if source.is_some_and(|source| !matches!(source, "bedrock" | "vertex")) {
        return Err(LocalApiError::InvalidRequest(
            "cloud source must be bedrock or vertex".to_string(),
        ));
    }
    Ok(())
}

fn cloud_status_with_base(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    setup_run_token: &str,
    source: Option<&str>,
) -> Result<serde_json::Value, LocalApiError> {
    let header = [("X-Ottto-Setup-Run-Token", setup_run_token)];
    let suffix = source
        .map(|source| format!("?source={}", form_url_encode(source)))
        .unwrap_or_default();
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/cloud/status{suffix}",
            connection.setup_run_id
        ),
    );
    backend_get_agent_read_json(&url, &header)
}

fn setup_run_agent_read_binding(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    command: &str,
) -> Result<(String, SetupRunReadStart), LocalApiError> {
    let status = status_for(daemon, authorization)?;
    if status.account.state != LocalAccountState::Connected {
        return Err(LocalApiError::InvalidRequest(format!(
            "{command} requires this Mac to be connected to Ottto"
        )));
    }
    let start = daemon
        .setup_run_read_start()?
        .ok_or(LocalApiError::SetupRunConnectionMissing)?;
    let api_base_url = validated_api_base_url(Some(start.binding.api_base_url.as_str()))?;
    Ok((api_base_url, start))
}

pub(super) fn local_lifecycle_home() -> Result<PathBuf, LocalApiError> {
    local_lifecycle_home_dir()
        .map_err(|error| LocalApiError::LocalOperationFailed(error.to_string()))
}

pub(super) fn refresh_agent_status_for(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: Option<SourceKind>,
) -> Result<Vec<ottto_protocol::AgentStatusSnapshot>, LocalApiError> {
    require_authorized_local_client(daemon, authorization)?;
    reconcile_agent_status_config_for_refresh(daemon, source.as_ref())?;
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    let snapshots = match authorization {
        RequestAuthorization::Token(token) => {
            daemon.refresh_agent_status(token, source, captured_at, expires_at)
        }
        RequestAuthorization::TrustedCompanionApp | RequestAuthorization::DaemonInternal => {
            daemon.refresh_agent_status_for_trusted_client(source, captured_at, expires_at)
        }
        RequestAuthorization::Untrusted => Err(LocalApiError::LocalClientNotTrusted),
    }?;
    if !crate::agent_status_refresh::active() {
        upload_agent_status_snapshots_in_background(snapshots.clone());
    }
    Ok(snapshots)
}

/// Explicit quota refresh (a user's Refresh action) of every account of the
/// source(s). Codex homes are read here, each at most once a minute (one
/// `codex app-server` run per home, up to its timeout, before the reply).
/// Claude accounts are marked for the collection that follows, whose usage
/// gate reads them at most once a minute and keeps every hold, breaker and
/// Retry-After; the lane's next own pass answers a mark that collection
/// missed (one already in flight).
pub(super) fn request_explicit_quota_refresh(source: Option<&SourceKind>) {
    if source.map_or(true, |source| source == &SourceKind::ClaudeCode) {
        crate::agent_status::request_claude_explicit_refresh();
        crate::agent_status_refresh::request(&SourceKind::ClaudeCode);
    }
    if source.map_or(true, |source| source == &SourceKind::Codex) {
        let outcome = crate::agent_status::refresh_codex_quota_now();
        eprintln!(
            "explicit Codex quota refresh: read={} rate_limited={}",
            outcome.read, outcome.rate_limited
        );
    }
}

fn reconcile_agent_status_config_for_refresh(
    daemon: &LocalDaemon,
    source: Option<&SourceKind>,
) -> Result<(), LocalApiError> {
    if source.is_some_and(|source| source != &SourceKind::ClaudeCode) {
        return Ok(());
    }
    reconcile_claude_statusline_for_agent_status_refresh(daemon)
}

fn reconcile_claude_statusline_for_agent_status_refresh(
    daemon: &LocalDaemon,
) -> Result<(), LocalApiError> {
    if source_patch_disabled(&SourceKind::ClaudeCode)
        || !crate::agent_configs::detection::source_present_locally(&SourceKind::ClaudeCode)
    {
        return Ok(());
    }
    let machine = daemon.status_for_trusted_client()?.machine;
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let support_dir = default_support_dir();
    let settings_path = home_path(".claude/settings.json");
    let _settings_guard = lock_managed_claude_settings();
    let managed_approval_before_repair = match approved_managed_claude_relay_env() {
        Ok(env) => env.is_some(),
        Err(error) => {
            eprintln!("managed Claude settings repair skipped: {error}");
            false
        }
    };
    let _ = repair_claude_statusline_for_refresh_at(
        &settings_path,
        &machine,
        &support_dir,
        &relay_base_url,
    )?;
    if managed_approval_before_repair {
        if let Err(error) = repair_registered_managed_claude_relay_settings_locked() {
            eprintln!("managed Claude settings repair skipped: {error}");
        }
    }
    Ok(())
}

pub(super) fn upload_agent_status_snapshots_in_background(snapshots: Vec<AgentStatusSnapshot>) {
    let spawn_result = thread::Builder::new()
        .name("ottto-agent-status-upload".to_string())
        .spawn(move || {
            if let Err(error) = crate::snapshot_sync::upload_agent_status_snapshots(&snapshots) {
                eprintln!(
                    "manual agent status upload skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("manual agent status upload skipped: {error}");
    }
}

pub(super) fn check_update_state() -> UpdateState {
    let current_version = compiled_release_version();
    let local_channel = local_release_channel();
    let checked_at = Some(current_rfc3339());
    let build_id = compiled_build_id();
    let install_owner = detect_install_owner();

    let manifest_url = std::env::var("OTTTO_RELEASE_MANIFEST_URL")
        .unwrap_or_else(|_| default_release_manifest_url(&local_channel));
    let manifest = crate::retry_tls::agent()
        .get(&manifest_url)
        .set("Accept", "application/json")
        .timeout(Duration::from_secs(5))
        .call()
        .ok()
        .and_then(|response| response.into_json::<ReleaseManifest>().ok());

    let Some(manifest) = manifest else {
        return UpdateState {
            current_version,
            latest_version: None,
            channel: local_channel,
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: None,
            min_protocol_version: None,
            checked_at,
            reason: Some("release manifest was unavailable".to_string()),
            download_url: None,
            build_id,
            update_command: None,
            update_instructions: None,
            release_notes: None,
        };
    };

    update_state_from_manifest(
        manifest,
        current_version,
        local_channel,
        checked_at,
        build_id,
        install_owner,
    )
}

pub(super) fn update_state_from_manifest(
    manifest: ReleaseManifest,
    current_version: String,
    local_channel: ReleaseChannel,
    checked_at: Option<String>,
    build_id: Option<String>,
    install_owner: InstallOwner,
) -> UpdateState {
    if let Some(reason) = release_manifest_metadata_error(&manifest) {
        // Never offer a download link from metadata that failed validation.
        let download_url = None;
        let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
        return UpdateState {
            current_version,
            latest_version: Some(manifest.version),
            channel: local_channel,
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: Some(manifest.min_supported_version),
            min_protocol_version: Some(manifest.min_protocol_version),
            checked_at,
            reason: Some(reason),
            download_url,
            build_id: build_id.or(Some(manifest.commit)),
            update_command: None,
            update_instructions: None,
            release_notes,
        };
    }

    if manifest.channel != local_channel {
        let download_url = app_download_url(&manifest);
        let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
        let latest_version = manifest.version.clone();
        let manifest_channel = manifest.channel.clone();
        return UpdateState {
            current_version,
            latest_version: Some(latest_version),
            channel: local_channel.clone(),
            status: UpdateStatus::Unknown,
            gate: UpdateGate::Unknown,
            install_owner,
            min_supported_version: Some(manifest.min_supported_version),
            min_protocol_version: Some(manifest.min_protocol_version),
            checked_at,
            reason: Some(format!(
                "local {local_channel:?} build cannot be compared to {manifest_channel:?} release metadata"
            )),
            download_url,
            build_id: build_id.or(Some(manifest.commit)),
            update_command: None,
            update_instructions: None,
            release_notes,
        };
    }

    let manifest_tuple = version_tuple(&manifest.version);
    let current_tuple = version_tuple(&current_version);
    // Pre-release channels (dev/preview) ship versions like `0.1.0-dev-AAAA`. The
    // semver tuple collapses every dev build to (0,1,0), so we also compare the
    // recorded git commit when the tuple is equal. Without this, every dev user
    // is told they are current even when a newer build sits in the manifest.
    let build_differs = build_id
        .as_ref()
        .map_or(current_version != manifest.version, |local| {
            !commits_equivalent(local, &manifest.commit)
        });
    let update_available =
        manifest_tuple > current_tuple || (manifest_tuple == current_tuple && build_differs);
    let below_min_supported = current_tuple < version_tuple(&manifest.min_supported_version);
    let protocol_incompatible = PROTOCOL_VERSION < manifest.min_protocol_version;
    let gate = if below_min_supported || protocol_incompatible {
        UpdateGate::HardBlock
    } else if update_available {
        UpdateGate::SoftWarn
    } else {
        UpdateGate::Current
    };
    let update_required = !matches!(gate, UpdateGate::Current);
    let download_url = app_download_url(&manifest);
    let reason = if protocol_incompatible {
        Some(format!(
            "release requires local protocol v{}; this build supports v{}",
            manifest.min_protocol_version, PROTOCOL_VERSION
        ))
    } else if below_min_supported {
        Some(format!(
            "current version is below the minimum supported version {}",
            manifest.min_supported_version
        ))
    } else if update_available {
        if manifest_tuple > current_tuple {
            Some("A newer Ottto app is available.".to_string())
        } else {
            Some(format!(
                "A newer Ottto app build is available ({})",
                manifest.commit
            ))
        }
    } else {
        Some("You are running the latest available version.".to_string())
    };
    let (update_command, update_instructions) = if update_required {
        update_route_for_owner(install_owner, &manifest.supported_install_owners)
    } else {
        (None, None)
    };
    let release_notes = normalized_release_notes(manifest.release_notes.as_deref());
    UpdateState {
        current_version,
        latest_version: Some(manifest.version),
        channel: local_channel,
        status: if update_required {
            UpdateStatus::UpdateAvailable
        } else {
            UpdateStatus::Current
        },
        gate,
        install_owner,
        min_supported_version: Some(manifest.min_supported_version),
        min_protocol_version: Some(manifest.min_protocol_version),
        checked_at,
        reason,
        download_url,
        build_id: build_id.or(Some(manifest.commit)),
        update_command,
        update_instructions,
        release_notes,
    }
}

fn normalized_release_notes(release_notes: Option<&str>) -> Option<String> {
    release_notes
        .map(str::trim)
        .filter(|notes| !notes.is_empty())
        .map(ToOwned::to_owned)
}

fn release_manifest_metadata_error(manifest: &ReleaseManifest) -> Option<String> {
    if manifest.schema_version != 1 {
        return Some(format!(
            "unsupported release manifest schema_version {}",
            manifest.schema_version
        ));
    }
    if manifest.product != "ottto-local-platform" {
        return Some(format!(
            "unexpected release manifest product {}",
            manifest.product
        ));
    }
    if manifest.min_supported_version.trim().is_empty() {
        return Some("release manifest is missing min_supported_version".to_string());
    }
    if manifest.min_protocol_version == 0 {
        return Some("release manifest has invalid min_protocol_version".to_string());
    }
    if manifest.supported_install_owners.is_empty() {
        return Some("release manifest must list supported install owners".to_string());
    }
    if manifest.rollback.strategy != "channel_latest_pointer" {
        return Some(
            "release manifest is missing channel_latest_pointer rollback metadata".to_string(),
        );
    }
    if manifest.rollback.immutable_prefix.trim().is_empty()
        || !valid_update_manifest_url(&manifest.rollback.immutable_prefix)
    {
        return Some("release manifest has invalid rollback immutable_prefix".to_string());
    }
    if manifest.rollback.latest_manifest_url.trim().is_empty()
        || !valid_update_manifest_url(&manifest.rollback.latest_manifest_url)
        || !manifest
            .rollback
            .latest_manifest_url
            .ends_with("/release-manifest.json")
    {
        return Some("release manifest has invalid rollback latest_manifest_url".to_string());
    }
    if !manifest.rollback.preserve_failed_version {
        return Some(
            "release manifest rollback must preserve failed versioned artifacts".to_string(),
        );
    }
    if manifest.artifacts.is_empty() {
        return Some("release manifest has no artifacts".to_string());
    }
    let immutable_prefix = format!(
        "{}/",
        manifest.rollback.immutable_prefix.trim_end_matches('/')
    );
    if manifest.artifacts.iter().any(|artifact| {
        !artifact.url.starts_with(&immutable_prefix) || !valid_update_manifest_url(&artifact.url)
    }) {
        return Some(
            "release manifest artifact URL is outside rollback immutable_prefix".to_string(),
        );
    }
    None
}

/// Release metadata may point only at the Ottto install host over HTTPS, or,
/// when a developer set `OTTTO_RELEASE_MANIFEST_URL`, at that URL's origin.
fn valid_update_manifest_url(url: &str) -> bool {
    let developer_override = std::env::var("OTTTO_RELEASE_MANIFEST_URL").ok();
    trusted_release_url(url, developer_override.as_deref())
}

const RELEASE_ORIGIN: &str = "https://install.ottto.net";

pub(super) fn trusted_release_url(url: &str, developer_override: Option<&str>) -> bool {
    let Some(origin) = release_url_origin(url) else {
        return false;
    };
    origin.eq_ignore_ascii_case(RELEASE_ORIGIN)
        || developer_override
            .and_then(release_url_origin)
            .is_some_and(|allowed| origin.eq_ignore_ascii_case(allowed))
}

/// `scheme://authority` of an http(s) URL. `None` for any other scheme, an
/// empty authority, or one with user info or a backslash.
fn release_url_origin(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return None;
    }
    Some(&url[..url.len() - rest.len() + authority_len])
}

fn update_route_for_owner(
    install_owner: InstallOwner,
    supported_install_owners: &[InstallOwner],
) -> (Option<String>, Option<String>) {
    if !install_owner_supported(install_owner, supported_install_owners) {
        return (
            None,
            Some(format!(
                "This release manifest does not advertise an update route for {} installs. Install the latest Ottto local platform from the Apps page.",
                install_owner_label(install_owner)
            )),
        );
    }

    match install_owner {
        InstallOwner::Homebrew => (
            Some("brew update && brew upgrade ottto".to_string()),
            Some("Update this Homebrew-managed install with brew.".to_string()),
        ),
        InstallOwner::HostedInstaller => (
            Some("curl -fsSL https://ottto.net/install.sh | bash".to_string()),
            Some(
                "Update this hosted-installer install by rerunning the Ottto installer."
                    .to_string(),
            ),
        ),
        InstallOwner::AppBundle => (
            None,
            Some(
                "Update this app-bundled install by installing the latest Ottto.app release."
                    .to_string(),
            ),
        ),
        InstallOwner::Dev => (
            None,
            Some(
                "Dev-owned installs must be updated with an explicit developer command."
                    .to_string(),
            ),
        ),
        InstallOwner::Unknown => (
            None,
            Some("Install the latest Ottto local platform from the Apps page.".to_string()),
        ),
    }
}

fn install_owner_supported(
    install_owner: InstallOwner,
    supported_install_owners: &[InstallOwner],
) -> bool {
    install_owner == InstallOwner::Unknown || supported_install_owners.contains(&install_owner)
}

fn install_owner_label(install_owner: InstallOwner) -> &'static str {
    match install_owner {
        InstallOwner::Homebrew => "Homebrew",
        InstallOwner::HostedInstaller => "hosted-installer",
        InstallOwner::AppBundle => "app-bundled",
        InstallOwner::Dev => "dev",
        InstallOwner::Unknown => "unknown-owner",
    }
}

/// Doctor's check for a second Ottto install variant. Ottto has two: the app
/// (its bundle runs the daemon) and the headless Homebrew formula. Both use
/// launchd label `net.ottto.service` and one LaunchAgent file, so one runs per
/// Mac and the app wins. Doctor only: it lists two Cellar folders and
/// checks that a few paths exist; it reads no file.
///
/// - `formula_next_to_app`: the daemon belongs to the app and a formula is
///   also installed. `brew services start`, `restart` or `run` for ottto
///   would point the app's job at the formula, and `stop` would unload it.
/// - `homebrew_service_with_app`: the daemon is the formula's and an app
///   bundle is installed. The app should run the service.
/// - `system_service`: a root LaunchDaemon (`sudo brew services start`) is
///   registered next to this user's daemon.
pub(super) fn install_variant_conflict(owner: InstallOwner) -> Option<serde_json::Value> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let mut apps = vec![std::path::PathBuf::from("/Applications/Ottto.app")];
    if let Some(home) = &home {
        apps.push(home.join("Applications").join("Ottto.app"));
    }
    install_variant_conflict_in(
        owner,
        &[
            std::path::Path::new("/opt/homebrew/Cellar/ottto"),
            std::path::Path::new("/usr/local/Cellar/ottto"),
        ],
        &apps,
        std::path::Path::new("/Library/LaunchDaemons/net.ottto.service.plist"),
    )
}

pub(super) fn install_variant_conflict_in(
    owner: InstallOwner,
    cellars: &[&std::path::Path],
    apps: &[std::path::PathBuf],
    system_plist: &std::path::Path,
) -> Option<serde_json::Value> {
    let mut versions = cellars
        .iter()
        .filter_map(|cellar| std::fs::read_dir(cellar).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|version| {
            !version.is_empty()
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
        .collect::<Vec<_>>();
    versions.sort();
    versions.dedup();
    let app = apps.iter().find(|app| {
        app.join("Contents")
            .join("Helpers")
            .join("ottto-service")
            .is_file()
    });
    let system_service = system_plist.exists();
    let kind = match owner {
        InstallOwner::AppBundle if !versions.is_empty() => "formula_next_to_app",
        InstallOwner::Homebrew if app.is_some() => "homebrew_service_with_app",
        _ if system_service => "system_service",
        _ => return None,
    };
    Some(serde_json::json!({
        "kind": kind,
        "versions": versions,
        "daemon_version": compiled_release_version(),
        "app_installed": app.is_some(),
        "system_service": system_service,
    }))
}

pub(super) fn detect_install_owner() -> InstallOwner {
    std::env::current_exe()
        .ok()
        .as_deref()
        .map(install_owner_for_path)
        .unwrap_or(InstallOwner::Unknown)
}

/// Best-effort: surface the AI-generated machine icon (persisted by the snapshot
/// sync from the backend response) on `status.machine.icon_url`, so the Companion
/// footer matches the web /apps machine identity. Any failure leaves it unset and
/// the app falls back to its procedural glyph.
pub(super) fn inject_machine_icon(status_value: &mut serde_json::Value) {
    apply_machine_icon(status_value, load_persisted_machine_icon());
}

pub(super) fn apply_machine_icon(
    status_value: &mut serde_json::Value,
    icon: Option<(String, String)>,
) {
    let Some((icon_machine_id, icon_url)) = icon else {
        return;
    };
    if icon_url.is_empty() {
        return;
    }
    let Some(machine) = status_value
        .get_mut("machine")
        .and_then(|m| m.as_object_mut())
    else {
        return;
    };
    let matches =
        machine.get("machine_id").and_then(|v| v.as_str()) == Some(icon_machine_id.as_str());
    if matches {
        machine.insert("icon_url".to_string(), serde_json::Value::String(icon_url));
    }
}

fn load_persisted_machine_icon() -> Option<(String, String)> {
    let path = ottto_core::default_support_dir().join("machine_icon.json");
    let raw = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let machine_id = value.get("machine_id")?.as_str()?.to_string();
    let icon_url = value.get("icon_url")?.as_str()?.to_string();
    Some((machine_id, icon_url))
}

pub(super) fn service_owner_state(client_owner: InstallOwner) -> ServiceOwnerState {
    service_owner_state_with(
        client_owner,
        crate::macos_service::inspect_launch_agent_owner,
    )
}

/// The ordinary status request's owner state: the launchd job probe may be
/// reused for up to 60 s while launchd runs this process as the job.
pub(super) fn cached_service_owner_state(client_owner: InstallOwner) -> ServiceOwnerState {
    service_owner_state_with(
        client_owner,
        crate::macos_service::inspect_launch_agent_owner_for_status,
    )
}

fn service_owner_state_with(
    client_owner: InstallOwner,
    inspect: fn(
        &std::path::Path,
        Option<&std::path::Path>,
    ) -> crate::macos_service::LaunchAgentOwnerState,
) -> ServiceOwnerState {
    let daemon_owner = detect_install_owner();
    let owner_state = local_lifecycle_home_dir().ok().map(|home| {
        let plist_path = crate::macos_service::launch_agent_path(&home);
        inspect(&plist_path, std::env::current_exe().ok().as_deref())
    });
    let (plist_owner, loaded_owner, plist_exists, launchd_loaded, mut owner_drift) =
        if let Some(owner_state) = owner_state {
            (
                owner_state.plist_owner,
                owner_state.loaded_owner,
                owner_state.plist_exists,
                owner_state.loaded,
                owner_state.owner_drift,
            )
        } else {
            (
                InstallOwner::Unknown,
                InstallOwner::Unknown,
                false,
                false,
                false,
            )
        };

    owner_drift |= client_owner_conflict(client_owner, daemon_owner)
        || client_owner_conflict(client_owner, plist_owner)
        || client_owner_conflict(client_owner, loaded_owner);

    ServiceOwnerState {
        daemon_owner,
        plist_owner,
        loaded_owner,
        client_owner,
        owner_drift,
        plist_exists,
        launchd_loaded,
        repair_command: owner_repair_command(preferred_repair_owner(
            client_owner,
            loaded_owner,
            plist_owner,
            daemon_owner,
        ))
        .map(ToString::to_string),
        detail: Some(owner_state_detail(owner_drift, client_owner, daemon_owner)),
    }
}

pub(super) fn client_owner_conflict(
    client_owner: InstallOwner,
    service_owner: InstallOwner,
) -> bool {
    if client_owner == InstallOwner::Unknown || service_owner == InstallOwner::Unknown {
        return false;
    }
    if client_owner == service_owner {
        return false;
    }
    // The signed app bundle is also the supported UI for a Homebrew-owned
    // daemon. Client/service packaging can differ without service drift; the
    // launchd/plist/loaded owners still decide whether mutation is safe.
    //
    // A Homebrew `ottto` reading an app-owned daemon is the normal state after
    // a Homebrew serve hands over to Ottto.app with the formula still
    // installed. Doctor's `install_variants` names that copy and how to remove
    // it; any Homebrew attempt to rewrite the job is still refused by the
    // launch agent owner check unless it passes `--migrate-owner`.
    if matches!(
        (client_owner, service_owner),
        (InstallOwner::AppBundle, InstallOwner::HostedInstaller)
            | (InstallOwner::AppBundle, InstallOwner::Homebrew)
            | (InstallOwner::HostedInstaller, InstallOwner::AppBundle)
            | (InstallOwner::Homebrew, InstallOwner::AppBundle)
    ) {
        return false;
    }
    true
}

fn preferred_repair_owner(
    client_owner: InstallOwner,
    loaded_owner: InstallOwner,
    plist_owner: InstallOwner,
    daemon_owner: InstallOwner,
) -> InstallOwner {
    for owner in [loaded_owner, plist_owner, daemon_owner, client_owner] {
        if owner != InstallOwner::Unknown {
            return owner;
        }
    }
    InstallOwner::Unknown
}

fn owner_repair_command(owner: InstallOwner) -> Option<&'static str> {
    match owner {
        InstallOwner::Homebrew => Some("brew services restart ottto"),
        InstallOwner::HostedInstaller => Some("rerun the Ottto installer"),
        InstallOwner::AppBundle => Some("quit and relaunch the Ottto app"),
        InstallOwner::Dev => Some("run the explicit dev repair command"),
        InstallOwner::Unknown => None,
    }
}

fn owner_state_detail(
    owner_drift: bool,
    client_owner: InstallOwner,
    daemon_owner: InstallOwner,
) -> String {
    if owner_drift {
        return format!(
            "LaunchAgent owner drift detected between {} client and {} daemon.",
            install_owner_label(client_owner),
            install_owner_label(daemon_owner)
        );
    }
    format!(
        "LaunchAgent owner is {}.",
        install_owner_label(daemon_owner)
    )
}

pub(super) fn commits_equivalent(local: &str, remote: &str) -> bool {
    if local == remote {
        return true;
    }
    let min_len = local.len().min(remote.len()).min(40);
    if min_len < 7 {
        return false;
    }
    local[..min_len].eq_ignore_ascii_case(&remote[..min_len])
}

fn local_release_channel() -> ReleaseChannel {
    std::env::var("OTTTO_RELEASE_CHANNEL")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| release_channel_from_str(&value))
        .unwrap_or_else(compiled_release_channel)
}

fn default_release_manifest_url(channel: &ReleaseChannel) -> String {
    format!(
        "https://install.ottto.net/ottto-local-platform/releases/{}/latest/release-manifest.json",
        release_channel_slug(channel)
    )
}

fn release_channel_slug(channel: &ReleaseChannel) -> &'static str {
    match channel {
        ReleaseChannel::Dev => "dev",
        ReleaseChannel::Preview => "preview",
        ReleaseChannel::StableCandidate => "stable-candidate",
        ReleaseChannel::Stable => "stable",
    }
}

fn app_download_url(manifest: &ReleaseManifest) -> Option<String> {
    manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == "macos_app"
                && artifact.platform == "macos"
                && (artifact.arch == std::env::consts::ARCH || artifact.arch == "universal")
        })
        .map(|artifact| artifact.url.clone())
}

pub(super) fn version_tuple(value: &str) -> (u64, u64, u64) {
    let mut parts = value
        .split('-')
        .next()
        .unwrap_or(value)
        .split('.')
        .filter_map(|part| part.parse::<u64>().ok());
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

pub(super) fn operating_system_slug(os: &ottto_protocol::OperatingSystem) -> &'static str {
    match os {
        ottto_protocol::OperatingSystem::Macos => "macos",
        ottto_protocol::OperatingSystem::Windows => "windows",
        ottto_protocol::OperatingSystem::Linux => "linux",
        ottto_protocol::OperatingSystem::Unknown => "unknown",
    }
}

pub(super) fn source_from_slug(source: &str) -> Option<SourceKind> {
    match source {
        "codex" => Some(SourceKind::Codex),
        "claude_code" | "claude-code" => Some(SourceKind::ClaudeCode),
        "pi" => Some(SourceKind::Pi),
        _ => None,
    }
}

pub(super) fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

pub(super) fn current_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub(super) fn rfc3339_after_minutes(minutes: u64) -> Option<String> {
    let macos = Command::new("/bin/date")
        .args(["-u", &format!("-v+{minutes}M"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if macos.is_some() {
        return macos;
    }
    Command::new("/bin/date")
        .args([
            "-u",
            "-d",
            &format!("+{minutes} minutes"),
            "+%Y-%m-%dT%H:%M:%SZ",
        ])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn agent_context_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentContextQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/agent-context",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(days) = query.days {
        params.push(("days", days.to_string()));
    }
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    if let Some(max_tokens) = query.max_tokens {
        params.push(("max_tokens", max_tokens.to_string()));
    }
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    url_with_query_params(url, params)
}

pub(super) fn agent_costs_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentCostsQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/costs",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(days) = query.days {
        params.push(("days", days.to_string()));
    }
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    push_non_empty_query(&mut params, "bucket", query.bucket.as_deref());
    push_non_empty_query(&mut params, "mode", query.mode.as_deref());
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    push_non_empty_query(&mut params, "dimensions", query.dimensions.as_deref());
    if query.daily {
        params.push(("daily", "true".to_string()));
    }
    url_with_query_params(url, params)
}

fn agent_sessions_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentSessionsQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/sessions",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    if let Some(limit) = query.limit {
        params.push(("limit", limit.to_string()));
    }
    push_non_empty_query(&mut params, "cursor", query.cursor.as_deref());
    push_non_empty_query(&mut params, "range", query.range.as_deref());
    push_non_empty_query(&mut params, "start_date", query.start_date.as_deref());
    push_non_empty_query(&mut params, "end_date", query.end_date.as_deref());
    push_non_empty_query(&mut params, "source", query.source.as_deref());
    push_non_empty_query(&mut params, "model", query.model.as_deref());
    push_non_empty_query(
        &mut params,
        "billing_provider",
        query.billing_provider.as_deref(),
    );
    push_non_empty_query(
        &mut params,
        "billing_channel",
        query.billing_channel.as_deref(),
    );
    push_non_empty_query(&mut params, "machine_id", query.machine_id.as_deref());
    push_non_empty_query(
        &mut params,
        "source_plan_profile_id",
        query.source_plan_profile_id.as_deref(),
    );
    push_non_empty_query(&mut params, "min_cost", query.min_cost.as_deref());
    push_non_empty_query(&mut params, "max_cost", query.max_cost.as_deref());
    push_non_empty_query(&mut params, "sort_by", query.sort_by.as_deref());
    push_non_empty_query(&mut params, "sort_dir", query.sort_dir.as_deref());
    push_non_empty_query(&mut params, "search", query.search.as_deref());
    if query.all_machines {
        params.push(("all_machines", "true".to_string()));
    }
    url_with_query_params(url, params)
}

fn agent_recommendations_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    _query: &AgentRecommendationsQuery,
) -> String {
    api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/recommendations",
            connection.setup_run_id
        ),
    )
}

fn agent_provider_impact_url(
    api_base_url: &str,
    connection: &LocalConnectionBinding,
    query: &AgentProviderImpactQuery,
) -> String {
    let url = api_url_with_base(
        api_base_url,
        &format!(
            "/api/v1/setup-runs/{}/local-client/provider-impact",
            connection.setup_run_id
        ),
    );
    let mut params = Vec::new();
    push_non_empty_query(&mut params, "date_from", query.date_from.as_deref());
    push_non_empty_query(&mut params, "date_to", query.date_to.as_deref());
    push_non_empty_query(&mut params, "provider", query.provider.as_deref());
    push_non_empty_query(&mut params, "app", query.app.as_deref());
    push_non_empty_query(&mut params, "kind", query.kind.as_deref());
    push_non_empty_query(&mut params, "confidence", query.confidence.as_deref());
    push_non_empty_query(
        &mut params,
        "impact_priority",
        query.impact_priority.as_deref(),
    );
    push_non_empty_query(&mut params, "status", query.status.as_deref());
    push_non_empty_query(&mut params, "q", query.q.as_deref());
    if let Some(limit) = query.limit {
        params.push(("limit", limit.to_string()));
    }
    url_with_query_params(url, params)
}

pub(super) fn url_with_query_params(url: String, params: Vec<(&'static str, String)>) -> String {
    if params.is_empty() {
        return url;
    }
    let query_string = params
        .into_iter()
        .map(|(key, value)| format!("{}={}", form_url_encode(key), form_url_encode(&value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{url}?{query_string}")
}

fn push_non_empty_query(
    params: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        params.push((key, value.to_string()));
    }
}

pub(super) fn source_slug(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "codex",
        SourceKind::ClaudeCode => "claude_code",
        SourceKind::Pi => "pi",
    }
}

pub(super) fn source_display_name(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "Codex",
        SourceKind::ClaudeCode => "Claude Code",
        SourceKind::Pi => "Pi",
    }
}
