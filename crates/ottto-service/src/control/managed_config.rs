//! managed config for local control.

use crate::control::approved_managed_claude_relay_endpoint;
use crate::control::codex_toml;
use crate::control::current_rfc3339;
use crate::control::default_support_dir;
use crate::control::disable_managed_claude_relay_settings;
use crate::control::fs;
use crate::control::io;
use crate::control::json;
use crate::control::lock_managed_claude_settings;
use crate::control::patch_disabled_message;
use crate::control::repair_registered_managed_claude_relay_settings_locked;
use crate::control::source_display_name;
use crate::control::source_slug;
use crate::control::AgentConfigError;
use crate::control::AtomicU64;
use crate::control::ConfigDrift;
use crate::control::Digest;
use crate::control::DocumentMut;
use crate::control::Duration;
use crate::control::IpAddr;
use crate::control::Ipv4Addr;
use crate::control::Item;
use crate::control::LocalApiError;
use crate::control::LocalDaemon;
use crate::control::MachineIdentity;
use crate::control::Mutex;
#[cfg(unix)]
use crate::control::OpenOptionsExt;
use crate::control::OrStatePoisoned;
use crate::control::Ordering;
use crate::control::Path;
use crate::control::PathBuf;
#[cfg(unix)]
use crate::control::PermissionsExt;
use crate::control::RedactedValue;
use crate::control::RepairAction;
use crate::control::RepairActionApproval;
use crate::control::RepairActionKind;
use crate::control::RepairApprovalSurface;
use crate::control::RepairPlan;
use crate::control::RepairPlanStatus;
use crate::control::RequestAuthorization;
use crate::control::Sha256;
use crate::control::SocketAddr;
use crate::control::SourceConfigState;
use crate::control::SourceKind;
use crate::control::StableMessage;
use crate::control::SystemTime;
use crate::control::TcpStream;
use crate::control::TelemetryKeyStore;
use crate::control::UninstallExecutionResult;
use crate::control::MAX_CONFIG_BACKUPS_PER_SOURCE;
use crate::control::OTTTO_CONFIG_BACKUP_RETENTION_ENV;
use crate::control::UNIX_EPOCH;

pub(super) fn apply_telemetry_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(source) {
        return Ok(ConfigPatchResult::default());
    }
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            // Explicit, backend-authorized enable also clears the default
            // JSON opt-out written by disable. Per-root user opt-outs and
            // external exporters survive. Telemetry lives in settings.json
            // only: enable also removes the old shell env file and its
            // `~/.zshrc` line.
            let settings =
                patch_claude_code_settings_with_relay_base(&machine, &relay_base_url, true)?;
            if let Some(kept) = settings.kept {
                return Err(LocalApiError::LocalOperationFailed(
                    claude_settings_kept_reason(kept).1.to_string(),
                ));
            }
            // Cleaning up the old shell line never blocks enabling telemetry.
            let mut patch = remove_claude_code_env().unwrap_or_else(|_| {
                eprintln!("old Claude shell telemetry cleanup needs review; telemetry is enabled");
                ConfigPatchResult::default()
            });
            patch.changed |= settings.changed;
            Ok(patch)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "telemetry control does not patch Pi local config".to_string(),
        )),
    }
}

pub(super) fn remove_telemetry_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let _ = daemon.status_for_trusted_client()?;
            let changed = disable_managed_claude_relay_settings()?;
            // Cleaning up the old shell line never blocks disabling telemetry.
            let mut patch = remove_claude_code_env().unwrap_or_else(|_| {
                eprintln!("old Claude shell telemetry cleanup needs review; telemetry is disabled");
                ConfigPatchResult::default()
            });
            patch.changed |= changed;
            Ok(patch)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "telemetry control does not patch Pi local config".to_string(),
        )),
    }
}

pub(super) fn repair_source(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    dry_run: bool,
) -> Result<RepairPlan, LocalApiError> {
    let plan = propose_repair_plan(daemon, authorization, source.clone(), dry_run)?;
    if dry_run {
        return Ok(plan);
    }
    crate::snapshot_sync::reset_relay_authorization_backoff();
    if let Some(plan) = scan_index_rebuild_override_repair(daemon, authorization, &source, &plan) {
        daemon.arm_tracking_confirmation(&source, &plan)?;
        return Ok(plan);
    }

    // Pi has no local telemetry config to patch; its failure mode is an
    // expired/consumed provider OAuth credential that only a provider re-sign-in
    // can fix (Ottto can't re-mint the rotating token). Offer that actionable
    // recovery instead of a dead "blocked, no actions" response. Build the plan
    // before the WriteConfig-only retain below would strip everything.
    if matches!(source, SourceKind::Pi) {
        let plan = build_pi_reauth_repair_plan(plan);
        daemon.arm_tracking_confirmation(&source, &plan)?;
        return Ok(plan);
    }

    let mut plan = plan;
    plan.actions
        .retain(|action| action.action == RepairActionKind::WriteConfig);

    if !source_requires_config_patch(&source) {
        plan.status = RepairPlanStatus::Blocked;
        plan.authority.message = StableMessage {
            code: "config_repair_not_supported".to_string(),
            text: format!(
                "{} does not support local config repair.",
                source_display_name(&source)
            ),
        };
        plan.actions.clear();
        return Ok(plan);
    }

    if source_patch_disabled(&source) {
        plan.status = RepairPlanStatus::Blocked;
        plan.authority.message = patch_disabled_message(&source);
        plan.actions.clear();
        return Ok(plan);
    }

    let before = source_config_state_for_daemon(daemon, &source)?;
    let patch = if before.drift.is_empty() {
        ConfigPatchResult::default()
    } else {
        execute_write_config_repair(daemon, authorization, &source)?
    };
    let after = source_config_state_for_daemon(daemon, &source)?;
    if after.drift.is_empty() {
        daemon.record_config_repair_result(&source, after.clone())?;
    }

    plan.status = if after.drift.is_empty() {
        RepairPlanStatus::Succeeded
    } else {
        RepairPlanStatus::Failed
    };
    if let Some(action) = plan.actions.first_mut() {
        action.detail = if after.drift.is_empty() {
            if patch.changed {
                format!(
                    "{} telemetry config was repaired through ottto-service.",
                    source_display_name(&source)
                )
            } else {
                format!(
                    "{} local source config already matched its collection policy.",
                    source_display_name(&source)
                )
            }
        } else if let Some(kept) = patch.kept {
            claude_settings_kept_reason(kept).1.to_string()
        } else {
            format!(
                "{} telemetry config still has drift after repair.",
                source_display_name(&source)
            )
        };
    }
    daemon.arm_tracking_confirmation(&source, &plan)?;
    Ok(plan)
}

/// User Repair override of the 24-hour scan-index rebuild-loop guard.
///
/// Origin: only the companion's Repair button counts. It sends a token-less
/// `repair` (`dry_run: false`) as `client_kind: companion_app`, which
/// `request_authorization` grants as `TrustedCompanionApp` only for a
/// same-uid, Developer ID-signed Companion peer; the CLI (`ottto fix`) and
/// agents present the control token. Verify, including `repair: true`, never
/// reaches `repair_source`, and automatic retries are loads, not commands.
/// A source the guard is not pausing takes the ordinary Repair path.
pub(super) fn scan_index_rebuild_override_repair(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: &SourceKind,
    plan: &RepairPlan,
) -> Option<RepairPlan> {
    if *authorization != RequestAuthorization::TrustedCompanionApp {
        return None;
    }
    let snapshot_source = crate::snapshot_sync::snapshot_source_of_kind(source);
    let outcome = crate::snapshots::arm_scan_index_rebuild_manual_override(
        snapshot_source,
        SystemTime::now(),
    );
    let retry = crate::snapshots::scan_index_rebuild_auto_retry_at(snapshot_source)
        .map(|at| format!(" Ottto retries by itself at {at}."))
        .unwrap_or_default();
    let mut plan = plan.clone();
    plan.actions.clear();
    match outcome {
        crate::snapshots::ScanIndexRebuildOverride::NotPaused => return None,
        crate::snapshots::ScanIndexRebuildOverride::Armed => {
            plan.status = RepairPlanStatus::Running;
            plan.authority.message = StableMessage {
                code: "scan_index_rebuild_override_armed".to_string(),
                text: format!(
                    "{} local record will be rebuilt on the next sync; older sessions are re-checked slowly.",
                    source_display_name(source)
                ),
            };
            // Run that sync now instead of waiting for the next cycle.
            #[cfg(not(test))]
            if let Err(error) =
                crate::snapshot_sync::spawn_one_shot_local_snapshot_sync(daemon.clone())
            {
                eprintln!(
                    "local snapshot sync after user Repair override unavailable: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            #[cfg(test)]
            let _ = daemon;
        }
        crate::snapshots::ScanIndexRebuildOverride::IdentityUnrecoverable => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: crate::snapshots::SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE
                    .to_string(),
                text: format!(
                    "{} local record is too damaged for Repair to rebuild safely.{retry}",
                    source_display_name(source)
                ),
            };
        }
        crate::snapshots::ScanIndexRebuildOverride::Refused(code) => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: code.to_string(),
                text: format!("Repair could not safely recover the local record. The source stays paused and its files are kept.{retry}"),
            };
        }
        crate::snapshots::ScanIndexRebuildOverride::Cooldown => {
            plan.status = RepairPlanStatus::Blocked;
            plan.authority.message = StableMessage {
                code: crate::snapshots::SCAN_INDEX_REBUILD_OVERRIDE_COOLDOWN_CODE.to_string(),
                text: format!(
                    "Repair was already used for this source in the last 24 hours.{retry}"
                ),
            };
        }
    }
    Some(plan)
}

/// Build an actionable Pi recovery plan: a manual provider re-sign-in (which the
/// daemon cannot perform — it can't re-mint a provider's rotating OAuth token)
/// plus next-session confirmation, instead of the dead `config_repair_not_supported`
/// "blocked, no actions" response. Reuses the authority already computed by
/// `propose_repair_plan` so terminal/browser approval semantics are preserved.
fn build_pi_reauth_repair_plan(mut plan: RepairPlan) -> RepairPlan {
    plan.status = RepairPlanStatus::Proposed;
    plan.authority.message = StableMessage {
        code: "pi_provider_reauth_required".to_string(),
        text: "Pi reported an expired provider sign-in. Re-sign in to the failing provider in Pi, then start a session so Ottto can confirm tracking. Test tracking is optional.".to_string(),
    };
    let approval = RepairActionApproval {
        surface: RepairApprovalSurface::None,
        setup_safe: true,
        server_backed: false,
        reason:
            "Re-authenticating a provider in Pi is a manual local action; Ottto only guides it."
                .to_string(),
    };
    plan.actions = vec![
        RepairAction {
            action: RepairActionKind::ReauthProvider,
            title: "Re-sign in to the Pi provider".to_string(),
            detail: "Run `pi` and re-authenticate the failing provider (e.g. openai-codex), then start a session so Ottto can confirm tracking. Ottto can't re-mint the provider's rotating OAuth token for you.".to_string(),
            requires_approval: false,
            destructive: false,
            approval: approval.clone(),
            backup: None,
        },
        RepairAction {
            action: RepairActionKind::VerifyTelemetry,
            title: "Test Pi tracking (optional)".to_string(),
            detail: "Ottto confirms tracking after it collects your next session. You can also run Test tracking; this optional check may use recent activity.".to_string(),
            requires_approval: false,
            destructive: false,
            approval,
            backup: None,
        },
    ];
    plan
}

pub(super) fn propose_repair_plan(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: SourceKind,
    dry_run: bool,
) -> Result<RepairPlan, LocalApiError> {
    match authorization {
        RequestAuthorization::Token(token) => daemon.propose_repair(token, source, dry_run),
        RequestAuthorization::TrustedCompanionApp => {
            daemon.propose_repair_for_trusted_client(source, dry_run)
        }
        RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
            Err(LocalApiError::LocalClientNotTrusted)
        }
    }
}

pub(super) fn execute_write_config_repair(
    daemon: &LocalDaemon,
    authorization: &RequestAuthorization,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(source) {
        return Err(LocalApiError::InvalidRequest(format!(
            "{} telemetry config patching is disabled by environment",
            source_display_name(source)
        )));
    }
    let _lease = match authorization {
        RequestAuthorization::Token(token) => daemon.acquire_repair_lock(token, source.clone())?,
        RequestAuthorization::TrustedCompanionApp => {
            daemon.acquire_repair_lock_for_trusted_client(source.clone())?
        }
        RequestAuthorization::Untrusted | RequestAuthorization::DaemonInternal => {
            return Err(LocalApiError::LocalClientNotTrusted)
        }
    };
    repair_source_config(daemon, source)
}

pub(super) fn repair_source_config(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<ConfigPatchResult, LocalApiError> {
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    match source {
        SourceKind::Codex => reconcile_codex_source_off(),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            patch_claude_code_settings_with_relay_base(&machine, &relay_base_url, false)
        }
        SourceKind::Pi => Err(LocalApiError::InvalidRequest(
            "Pi does not support local config repair".to_string(),
        )),
    }
}

pub(super) fn sweep_telemetry_keys_for_uninstall(result: &mut UninstallExecutionResult) {
    match TelemetryKeyStore::production().sweep_all() {
        Ok(sweep) => {
            result.removed_paths.extend(
                sweep
                    .removed
                    .iter()
                    .map(|reference| format!("keychain://{}", reference.target())),
            );
            result.missing_paths.extend(
                sweep
                    .missing
                    .iter()
                    .map(|reference| format!("keychain://{}", reference.target())),
            );
            result.removed_paths.extend(
                sweep
                    .removed_unindexed_services
                    .iter()
                    .map(|target| format!("keychain://{target}")),
            );
            result.warnings.extend(sweep.warnings);
        }
        Err(error) => {
            result.status = "uninstall_incomplete".to_string();
            result
                .failed_operations
                .push(format!("remove telemetry keychain items: {error}"));
        }
    }
}

pub(super) fn request_snapshot_sync_after_device_registration(daemon: &LocalDaemon) {
    if let Err(error) = crate::snapshot_sync::spawn_one_shot_local_snapshot_sync(daemon.clone()) {
        eprintln!(
            "local snapshot sync after setup unavailable: {}",
            crate::snapshot_sync::safe_error(&error)
        );
    }
}

pub(super) fn source_requires_device_registration(source_kind: &SourceKind) -> bool {
    matches!(
        source_kind,
        SourceKind::Codex | SourceKind::ClaudeCode | SourceKind::Pi
    )
}

pub(super) fn source_requires_config_patch(source_kind: &SourceKind) -> bool {
    matches!(source_kind, SourceKind::Codex | SourceKind::ClaudeCode)
}

pub(super) fn source_patch_env_token(source_kind: &SourceKind) -> Option<&'static str> {
    match source_kind {
        SourceKind::Codex => Some("CODEX"),
        SourceKind::ClaudeCode => Some("CLAUDE_CODE"),
        SourceKind::Pi => None,
    }
}

pub(super) fn setup_source_paused(source: &SourceKind) -> bool {
    source_patch_disabled(source)
        || crate::snapshot_sync::source_paused(
            &default_support_dir(),
            crate::snapshot_sync::snapshot_source_of_kind(source),
        )
}

pub(super) fn source_patch_disabled(source_kind: &SourceKind) -> bool {
    let Some(token) = source_patch_env_token(source_kind) else {
        return false;
    };
    let key = format!("OTTTO_PATCH_{token}_DISABLED");
    std::env::var(&key)
        .ok()
        .is_some_and(|value| env_value_truthy(&value))
}

fn env_value_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(super) fn source_config_state_for_daemon(
    daemon: &LocalDaemon,
    source: &SourceKind,
) -> Result<SourceConfigState, LocalApiError> {
    let relay_base_url = local_relay_base_url_for_daemon(daemon);
    let patch_disabled = source_patch_disabled(source);
    Ok(match source {
        SourceKind::Codex => codex_config_state_at(
            &home_path(".codex/config.toml"),
            "~/.codex/config.toml",
            &relay_base_url,
            patch_disabled,
        ),
        SourceKind::ClaudeCode => {
            let machine = daemon.status_for_trusted_client()?.machine;
            let support_dir = default_support_dir();
            claude_code_settings_config_state_at(
                &home_path(".claude/settings.json"),
                "~/.claude/settings.json",
                &machine,
                &relay_base_url,
                &support_dir,
                patch_disabled,
            )
        }
        SourceKind::Pi => empty_source_config(source),
    })
}

pub(super) fn empty_source_config(source: &SourceKind) -> SourceConfigState {
    SourceConfigState {
        discovered: false,
        path_hint: match source {
            SourceKind::Codex => Some("~/.codex/config.toml".to_string()),
            SourceKind::ClaudeCode => Some("~/.claude/settings.json".to_string()),
            SourceKind::Pi => None,
        },
        fingerprint: None,
        drift: Vec::new(),
    }
}

pub(super) fn codex_config_state_at(
    path: &Path,
    path_hint: &str,
    _relay_base_url: &str,
    patch_disabled: bool,
) -> SourceConfigState {
    let bytes = fs::read(path);
    let (discovered, fingerprint, drift) = match bytes {
        Err(error) if error.kind() == io::ErrorKind::NotFound => (false, None, Vec::new()),
        Err(_) => (
            false,
            None,
            vec![config_drift("codex.config_file", "readable", "unreadable")],
        ),
        Ok(bytes) => {
            let drift = match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|body| codex_source_off_body(body).ok().map(|next| (body, next)))
            {
                Some((body, next)) if body == next => Vec::new(),
                Some(_) => vec![config_drift(
                    "codex.ottto_exporters",
                    "disabled",
                    "configured",
                )],
                None => vec![config_drift(
                    "codex.config_toml",
                    "valid_unambiguous",
                    "needs_review",
                )],
            };
            (true, Some(config_fingerprint(&bytes)), drift)
        }
    };
    SourceConfigState {
        discovered,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift: if patch_disabled { Vec::new() } else { drift },
    }
}

pub(super) fn claude_code_settings_config_state_at(
    path: &Path,
    path_hint: &str,
    machine: &MachineIdentity,
    relay_base_url: &str,
    support_dir: &Path,
    patch_disabled: bool,
) -> SourceConfigState {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return SourceConfigState {
                discovered: false,
                path_hint: Some(path_hint.to_string()),
                fingerprint: None,
                drift: if patch_disabled {
                    Vec::new()
                } else {
                    vec![config_drift(
                        "claude_code.settings_file",
                        "present",
                        "missing",
                    )]
                },
            };
        }
        Err(_) => {
            return SourceConfigState {
                discovered: false,
                path_hint: Some(path_hint.to_string()),
                fingerprint: None,
                drift: if patch_disabled {
                    Vec::new()
                } else {
                    vec![config_drift(
                        "claude_code.settings_file",
                        "readable",
                        "unreadable",
                    )]
                },
            };
        }
    };
    let fingerprint = Some(config_fingerprint(&bytes));
    if patch_disabled {
        return SourceConfigState {
            discovered: true,
            path_hint: Some(path_hint.to_string()),
            fingerprint,
            drift: Vec::new(),
        };
    }
    let mut drift = Vec::new();
    let settings = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value.is_object() => value,
        Ok(_) => {
            drift.push(config_drift(
                "claude_code.settings_json",
                "object",
                "non_object",
            ));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
        Err(_) => {
            drift.push(config_drift(
                "claude_code.settings_json",
                "valid",
                "invalid",
            ));
            return SourceConfigState {
                discovered: true,
                path_hint: Some(path_hint.to_string()),
                fingerprint,
                drift,
            };
        }
    };
    let env = settings.get("env").and_then(|value| value.as_object());
    for (key, expected) in claude_code_relay_env_with_base(machine, relay_base_url) {
        let observed = env
            .and_then(|env| env.get(key))
            .and_then(|value| value.as_str());
        if observed != Some(expected.as_str()) {
            drift.push(config_drift(
                format!("env.{key}"),
                expected,
                observed.unwrap_or("missing"),
            ));
        }
    }
    let statusline_command = settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str());
    if let Some(command_drift) = claude_statusline_command_drift(statusline_command, support_dir) {
        drift.push(command_drift);
    } else if let Some(wrapper_drift) = claude_statusline_wrapper_drift(support_dir) {
        drift.push(wrapper_drift);
    }
    SourceConfigState {
        discovered: true,
        path_hint: Some(path_hint.to_string()),
        fingerprint,
        drift,
    }
}

fn config_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

pub(super) fn config_drift(
    key: impl Into<String>,
    expected: impl Into<String>,
    observed: impl Into<String>,
) -> ConfigDrift {
    ConfigDrift {
        key: key.into(),
        expected: RedactedValue::String(expected.into()),
        observed: RedactedValue::String(observed.into()),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConfigPatchResult {
    pub(super) changed: bool,
    pub(super) created: bool,
    pub(super) backup_created: bool,
    /// Claude settings left untouched because the user opted out or exports
    /// telemetry elsewhere.
    pub(super) kept: Option<crate::agent_configs::claude_managed_settings::Outcome>,
}

pub(super) fn local_relay_base_url_for_daemon(daemon: &LocalDaemon) -> String {
    crate::otlp_relay::local_relay_base_url_for_port(local_relay_port_for_daemon(daemon))
}

/// The port settings writers record. Only a relay bound and serving right now
/// (Connected) supplies its live port. While unbound or mid-rebind the
/// endpoint settings already approve stays, so a transient never moves it.
pub(super) fn local_relay_port_for_daemon(daemon: &LocalDaemon) -> u16 {
    daemon
        .status_for_trusted_client()
        .ok()
        .filter(|status| status.relay.state == ottto_protocol::RelayRuntimeState::Connected)
        .and_then(|status| status.relay.endpoint)
        .as_deref()
        .and_then(crate::otlp_relay::local_relay_port_from_endpoint)
        .or_else(|| {
            approved_managed_claude_relay_endpoint()
                .ok()
                .flatten()
                .as_deref()
                .and_then(crate::otlp_relay::local_relay_port_from_endpoint)
        })
        .unwrap_or(crate::otlp_relay::LOCAL_RELAY_DEFAULT_PORT)
}

/// Upgrade reconciliation is local and never reads credentials or contacts a provider.
pub fn reconcile_codex_source_off_at_startup() -> Result<bool, LocalApiError> {
    reconcile_codex_source_off().map(|result| result.changed)
}

pub(super) fn reconcile_codex_source_off() -> Result<ConfigPatchResult, LocalApiError> {
    if source_patch_disabled(&SourceKind::Codex) {
        return Ok(ConfigPatchResult::default());
    }
    reconcile_codex_source_off_at(&home_path(".codex/config.toml"), &default_support_dir())
}

static CODEX_CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());

static CODEX_CONFIG_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) fn reconcile_codex_source_off_at(
    path: &Path,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    let _write_guard = CODEX_CONFIG_WRITE_LOCK.lock().or_state_poisoned()?;
    let existing = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ConfigPatchResult::default())
        }
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    let next = codex_source_off_body(&existing)?;
    if next == existing {
        return Ok(ConfigPatchResult::default());
    }
    let backup_created = backup_existing_config(SourceKind::Codex, path, backup_root)?.is_some();
    if fs::read_to_string(path).or_state_poisoned()? != existing {
        return Err(LocalApiError::InvalidRequest(
            "Codex config changed during telemetry cleanup; retry after the edit finishes"
                .to_string(),
        ));
    }
    write_codex_source_off_body(path, &existing, &next)?;
    Ok(ConfigPatchResult {
        changed: true,
        created: false,
        backup_created,
        kept: None,
    })
}

pub(super) fn write_codex_source_off_body(
    path: &Path,
    expected: &str,
    next: &str,
) -> Result<(), LocalApiError> {
    use std::io::Write;
    let sequence = CODEX_CONFIG_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp.codex-off.{}.{sequence}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| {
        let mut file = options.open(&temp).or_state_poisoned()?;
        let permissions = fs::metadata(path).or_state_poisoned()?.permissions();
        fs::set_permissions(&temp, permissions).or_state_poisoned()?;
        file.write_all(next.as_bytes()).or_state_poisoned()?;
        file.sync_all().or_state_poisoned()?;
        if fs::read_to_string(path).or_state_poisoned()? != expected {
            return Err(LocalApiError::InvalidRequest(
                "Codex config changed during cleanup; retry after the edit finishes".into(),
            ));
        }
        fs::rename(&temp, path).or_state_poisoned()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Only an Ottto header AND a loopback signal destination establish ownership.
/// External exporters and unrelated table fields survive, including inside a fence.
pub(super) fn codex_source_off_body(existing: &str) -> Result<String, LocalApiError> {
    let fence = codex_toml::source_off_fence(existing, codex_exporter_relay_port)
        .map_err(|_| LocalApiError::ManualFenceReviewRequired)?;
    if let codex_toml::SourceOffFence::Recovered(next) = &fence {
        return Ok(next.clone());
    }
    let mut document = existing.parse::<DocumentMut>().or_state_poisoned()?;
    let Some(otel) = document.get_mut("otel").and_then(Item::as_table_like_mut) else {
        return Ok(existing.to_string());
    };
    let changed = remove_owned_codex_exporters(otel);
    if !changed {
        return Ok(existing.to_string());
    }
    // A legacy fence containing only the generated telemetry fields can go away
    // entirely. Mixed/user-edited fences keep their remaining contents.
    if let codex_toml::SourceOffFence::Complete { start, end } = fence {
        let fenced_body = &existing[start.end..end.start];
        if let Ok(mut fenced) = fenced_body.parse::<DocumentMut>() {
            if let Some(table) = fenced.get_mut("otel").and_then(Item::as_table_like_mut) {
                remove_owned_codex_exporters(table);
                let generated_only = table.iter().all(|(key, value)| match key {
                    "environment" => value.as_str() == Some("prod"),
                    "log_user_prompt" => value.as_bool() == Some(false),
                    _ => false,
                }) && fenced.iter().count() == 1;
                let full_table_generated_only =
                    document["otel"].as_table_like().is_some_and(|table| {
                        table.iter().all(|(key, value)| match key {
                            "environment" => value.as_str() == Some("prod"),
                            "log_user_prompt" => value.as_bool() == Some(false),
                            _ => false,
                        })
                    });
                if generated_only && full_table_generated_only {
                    let mut next = existing.to_string();
                    next.replace_range(start.start..end.end, "");
                    let mut remaining = next.parse::<DocumentMut>().or_state_poisoned()?;
                    if let Some(otel) = remaining.get_mut("otel").and_then(Item::as_table_like_mut)
                    {
                        if remove_owned_codex_exporters(otel) {
                            return Ok(remaining.to_string());
                        }
                    }
                    return Ok(next);
                }
            }
        }
    }
    Ok(document.to_string())
}

fn remove_owned_codex_exporters(otel: &mut dyn toml_edit::TableLike) -> bool {
    let mut changed = false;
    for (key, signal) in [
        ("exporter", "logs"),
        ("trace_exporter", "traces"),
        ("metrics_exporter", "metrics"),
    ] {
        if codex_exporter_relay_port(otel, key, signal).is_some() {
            let exporter = otel
                .get_mut(key)
                .and_then(Item::as_table_like_mut)
                .expect("owned exporter table");
            exporter.remove("otlp-http");
            if exporter.is_empty() {
                otel.remove(key);
            }
            changed = true;
        }
    }
    changed
}

#[cfg(test)]
pub(super) fn patch_codex_config_at(
    path: &Path,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    patch_codex_config_at_with_relay_base(
        path,
        backup_root,
        &crate::otlp_relay::default_local_relay_base_url(),
    )
}

// Historical enabled configuration is a fixture, never a production policy.
#[cfg(test)]
fn patch_codex_config_at_with_relay_base(
    path: &Path,
    backup_root: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    let body = render_codex_relay_toml_block_for_base(relay_base_url);
    let backup_created = backup_existing_config(SourceKind::Codex, path, backup_root)?.is_some();
    let write = codex_toml::upsert_fence(path, &body).map_err(agent_config_error)?;
    Ok(ConfigPatchResult {
        changed: write.changed,
        created: write.created,
        backup_created,
        kept: None,
    })
}

#[cfg(test)]
pub(super) fn render_codex_relay_toml_block_for_base(relay_base_url: &str) -> String {
    let relay_header = crate::otlp_relay::LOCAL_RELAY_HEADER;
    let relay_source = crate::otlp_relay::CODEX_RELAY_SOURCE;
    let relay_base_url = relay_base_url.trim_end_matches('/');
    [
        "otel.environment = \"prod\"".to_string(),
        "otel.log_user_prompt = false".to_string(),
        format!(
            "otel.exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/logs\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
        format!(
            "otel.trace_exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/traces\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
        format!(
            "otel.metrics_exporter.\"otlp-http\" = {{ endpoint = \"{relay_base_url}/v1/metrics\", protocol = \"binary\", headers = {{ \"{relay_header}\" = \"{relay_source}\" }} }}"
        ),
    ]
    .join("\n")
}

/// `clear_opt_out` only for the explicit source Enable; every other caller
/// leaves an opt-out or external exporter in place and reports it.
pub(super) fn patch_claude_code_settings_with_relay_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
    clear_opt_out: bool,
) -> Result<ConfigPatchResult, LocalApiError> {
    let _settings_guard = lock_managed_claude_settings();
    let backup_root = default_support_dir();
    let mut patch = patch_claude_code_settings_at_with_relay_base(
        &home_path(".claude/settings.json"),
        machine,
        &backup_root,
        relay_base_url,
        clear_opt_out,
    )?;
    patch.changed |= repair_registered_managed_claude_relay_settings_locked()?;
    Ok(patch)
}

pub(super) fn repair_claude_statusline_for_refresh_at(
    path: &Path,
    machine: &MachineIdentity,
    support_dir: &Path,
    relay_base_url: &str,
) -> Result<ConfigPatchResult, LocalApiError> {
    if !claude_statusline_refresh_repair_needed(path, support_dir) {
        return Ok(ConfigPatchResult::default());
    }
    patch_claude_code_settings_at_with_relay_base(path, machine, support_dir, relay_base_url, false)
}

pub(super) fn claude_statusline_refresh_repair_needed(path: &Path, support_dir: &Path) -> bool {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    let settings = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) if value.is_object() => value,
        _ => return false,
    };
    let has_telemetry_settings = settings
        .get("env")
        .and_then(|env| env.as_object())
        .is_some_and(|env| {
            env.keys().any(|key| {
                key.starts_with("OTEL_")
                    || matches!(
                        key.as_str(),
                        "CLAUDE_CODE_ENABLE_TELEMETRY"
                            | "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA"
                            | "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS"
                    )
            })
        });
    if has_telemetry_settings
        && std::str::from_utf8(&bytes)
            .ok()
            .and_then(crate::agent_configs::claude_managed_settings::approved_relay_port)
            .is_none()
    {
        return false;
    }
    if [
        "CLAUDE_CODE_ENABLE_TELEMETRY",
        "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    ]
    .iter()
    .any(|key| {
        settings
            .get("env")
            .and_then(|env| env.get(*key))
            .is_some_and(|enabled| enabled != "1")
    }) {
        return false;
    }
    let statusline = settings
        .get("statusLine")
        .and_then(|value| value.as_object());
    if statusline
        .and_then(|statusline| statusline.get("type"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value != "command")
    {
        return false;
    }
    let command = statusline
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match command {
        None => true,
        Some(command) if is_ottto_statusline_command(command) => {
            command != expected_claude_statusline_command(support_dir).as_str()
                || claude_statusline_wrapper_drift(support_dir).is_some()
        }
        Some(_) => false,
    }
}

/// Upgrade cleanup: Claude Code telemetry now lives only in settings.json, so
/// the old `~/.ottto/claude-telemetry.env` file and its fenced `~/.zshrc` line
/// are removed. Local only; user lines outside Ottto's fence are kept.
pub fn remove_claude_shell_env_at_startup() -> Result<bool, LocalApiError> {
    if source_patch_disabled(&SourceKind::ClaudeCode) {
        return Ok(false);
    }
    remove_claude_code_env().map(|result| result.changed)
}

/// The `~/.zshrc` line older versions wrote inside Ottto's fence.
const LEGACY_CLAUDE_SHELL_LINE: &str =
    r#"[ -f "$HOME/.ottto/claude-telemetry.env" ] && . "$HOME/.ottto/claude-telemetry.env""#;

fn remove_claude_code_env() -> Result<ConfigPatchResult, LocalApiError> {
    // Without a real home directory there is nothing of ours to clean up;
    // never fall back to the temp directory here.
    let Some(home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute() && home.is_dir())
    else {
        return Ok(ConfigPatchResult::default());
    };
    remove_claude_code_env_at(
        &home.join(".ottto/claude-telemetry.env"),
        &home.join(".zshrc"),
    )
}

/// Removes the old Claude telemetry env file and its fenced `~/.zshrc` line,
/// only when both hold exactly what Ottto wrote: the fence in `~/.zshrc` holds
/// only the old source line, and the env file's fence holds only exports of
/// Ottto's own telemetry keys. Both files are checked, with the same fence
/// parser removal uses, before either changes. Anything else (a linked file
/// or folder, extra lines, a broken fence) is left untouched for review.
pub(super) fn remove_claude_code_env_at(
    env_path: &Path,
    shell_rc_path: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    let shell = checked_legacy_body(shell_rc_path, |inner| {
        let lines = inner
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        lines == [LEGACY_CLAUDE_SHELL_LINE]
    })?;
    // Every mention of the env file must be the fenced line Ottto wrote;
    // otherwise removing the env file would leave a dangling source line.
    let mentions = |body: &str| body.matches(".ottto/claude-telemetry.env").count();
    let shell_mentions = fs::read_to_string(shell_rc_path).map_or(0, |body| mentions(&body));
    if shell_mentions != mentions(LEGACY_CLAUDE_SHELL_LINE) * usize::from(shell.is_some()) {
        return Err(LocalApiError::ManualFenceReviewRequired);
    }
    // The env file's folder must be a real folder, not a link elsewhere.
    if let Some(folder) = env_path.parent() {
        match fs::symlink_metadata(folder) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(LocalApiError::ManualFenceReviewRequired),
        }
    }
    let env = checked_legacy_body(env_path, legacy_env_is_ottto_owned)?;
    let env_changed = match env.as_deref() {
        Some(body) => {
            crate::agent_configs::fence::remove_fence_checked(env_path, body)
                .map_err(agent_config_error)?
                .changed
        }
        None => false,
    };
    let shell_changed = match shell.as_deref() {
        Some(body) => {
            crate::agent_configs::fence::remove_fence_checked(shell_rc_path, body)
                .map_err(agent_config_error)?
                .changed
        }
        None => false,
    };
    let removed_empty_env = env_changed
        && fs::read_to_string(env_path).is_ok_and(|body| body.trim().is_empty())
        && fs::remove_file(env_path).is_ok();
    Ok(ConfigPatchResult {
        changed: env_changed || shell_changed || removed_empty_env,
        created: false,
        backup_created: false,
        kept: None,
    })
}

/// The old env file's fence holds exactly Ottto's relay env, as older
/// versions wrote it: one `export KEY='value'` line per Ottto telemetry key,
/// nothing else, every value the one Ottto generates and all three endpoints
/// on one port the relay itself could have chosen (the rule settings.json
/// uses, `approved_relay_port`, plus the relay's candidate ports). A user's
/// own key, value or collector is not Ottto's.
fn legacy_env_is_ottto_owned(inner: &str) -> bool {
    let mut env = serde_json::Map::new();
    for line in inner.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((key, quoted)) = line
            .strip_prefix("export ")
            .and_then(|assignment| assignment.split_once('='))
        else {
            return false;
        };
        let Some(value) = quoted
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .filter(|value| !value.contains('\''))
        else {
            return false;
        };
        if !crate::agent_configs::claude_managed_settings::MANAGED_KEYS.contains(&key)
            || env
                .insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                )
                .is_some()
        {
            return false;
        }
    }
    if env.len() != crate::agent_configs::claude_managed_settings::MANAGED_KEYS.len() {
        return false;
    }
    let Some(port) = crate::agent_configs::claude_managed_settings::approved_relay_port(
        &serde_json::json!({ "env": env }).to_string(),
    ) else {
        return false;
    };
    // The shared port must be one the relay itself could have chosen for this
    // user (its own candidate rule). A user's own local collector is not.
    crate::otlp_relay::is_candidate_relay_port(port)
}

/// The whole contents of `path` when it is a regular file whose single Ottto
/// fence passes `owned`, or `None` when the file is missing or has no fence.
/// A linked or unreadable file, a broken fence or a fence `owned` rejects is
/// an error, so nothing is changed.
fn checked_legacy_body(
    path: &Path,
    owned: impl Fn(&str) -> bool,
) -> Result<Option<String>, LocalApiError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LocalApiError::ManualFenceReviewRequired),
    };
    if !metadata.file_type().is_file() {
        return Err(LocalApiError::ManualFenceReviewRequired);
    }
    let body = fs::read_to_string(path).map_err(|_| LocalApiError::ManualFenceReviewRequired)?;
    match crate::agent_configs::fence::fence_inner(&body, path) {
        Ok(None) => Ok(None),
        Ok(Some(inner)) if owned(inner) => Ok(Some(body)),
        Ok(Some(_)) | Err(_) => Err(LocalApiError::ManualFenceReviewRequired),
    }
}

fn agent_config_error(error: AgentConfigError) -> LocalApiError {
    match error {
        AgentConfigError::AmbiguousFence { .. } => LocalApiError::ManualFenceReviewRequired,
        _ => LocalApiError::LocalOperationFailed(error.to_string()),
    }
}

#[cfg(test)]
pub(super) fn patch_claude_code_settings_at(
    path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
) -> Result<ConfigPatchResult, LocalApiError> {
    patch_claude_code_settings_at_with_relay_base(
        path,
        machine,
        backup_root,
        &crate::otlp_relay::default_local_relay_base_url(),
        false,
    )
}

pub(super) fn patch_claude_code_settings_at_with_relay_base(
    path: &Path,
    machine: &MachineIdentity,
    backup_root: &Path,
    relay_base_url: &str,
    clear_opt_out: bool,
) -> Result<ConfigPatchResult, LocalApiError> {
    use crate::agent_configs::claude_managed_settings::{reconcile_default, Outcome};
    let created = !path.exists();
    let root = path.parent().ok_or(LocalApiError::StatePoisoned)?;
    let (mut wrapper_changed, mut backup_created) = (false, false);
    let (written, kept) = reconcile_default(
        root,
        &claude_code_relay_env_with_base(machine, relay_base_url),
        clear_opt_out,
        |settings| {
            wrapper_changed = point_claude_statusline_at_wrapper(settings, backup_root)
                .map_err(io::Error::other)?;
            Ok(())
        },
        || {
            backup_created = backup_existing_config(SourceKind::ClaudeCode, path, backup_root)
                .map_err(io::Error::other)?
                .is_some();
            Ok(())
        },
    )
    .map_err(|error| {
        LocalApiError::LocalOperationFailed(format!(
            "Claude Code settings could not be safely updated: {error}"
        ))
    })?;
    let written = written == Outcome::Changed;
    Ok(ConfigPatchResult {
        changed: written || wrapper_changed,
        created: created && written,
        backup_created,
        kept,
    })
}

/// Route the settings status line through Ottto's wrapper, delegating to the
/// user's own command, and refresh the wrapper. Returns whether it changed.
fn point_claude_statusline_at_wrapper(
    settings: &mut serde_json::Value,
    backup_root: &Path,
) -> Result<bool, LocalApiError> {
    let delegated_statusline = match existing_claude_statusline_command(settings) {
        Some(command) => Some(command),
        None => existing_claude_statusline_wrapper_delegated_command(backup_root)?,
    };
    let object = settings
        .as_object_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    let statusline_script = claude_statusline_wrapper_path(backup_root);
    let statusline_value = object.entry("statusLine").or_insert_with(|| json!({}));
    if !statusline_value.is_object() {
        *statusline_value = json!({});
    }
    let statusline = statusline_value
        .as_object_mut()
        .ok_or(LocalApiError::StatePoisoned)?;
    statusline.insert(
        "type".to_string(),
        serde_json::Value::String("command".to_string()),
    );
    statusline.insert(
        "command".to_string(),
        serde_json::Value::String(shell_quote_path(&statusline_script)),
    );
    let (_statusline_script, wrapper_changed) =
        write_claude_statusline_wrapper(backup_root, delegated_statusline.as_deref())?;
    Ok(wrapper_changed)
}

/// Stable reason code and user text for Claude settings Ottto left untouched.
pub(super) fn claude_settings_kept_reason(
    kept: crate::agent_configs::claude_managed_settings::Outcome,
) -> (&'static str, &'static str) {
    use crate::agent_configs::claude_managed_settings::Outcome;
    match kept {
        Outcome::OptedOut => (
            "opted_out",
            "Claude Code settings turn telemetry off, so Ottto left their telemetry settings unchanged.",
        ),
        Outcome::Linked => (
            "linked_settings",
            "Claude Code settings.json is a link or not a regular file, so Ottto left it unchanged.",
        ),
        _ => (
            "external_telemetry",
            "Claude Code settings send telemetry to another collector, so Ottto left their telemetry settings unchanged.",
        ),
    }
}

fn existing_claude_statusline_command(settings: &serde_json::Value) -> Option<String> {
    let command = settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .filter(|statusline| {
            statusline
                .get("type")
                .and_then(|value| value.as_str())
                .map_or(true, |value| value == "command")
        })
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if is_ottto_statusline_command(command) {
        return None;
    }
    Some(command.to_string())
}

fn is_ottto_statusline_command(command: &str) -> bool {
    command.contains("claude-code-statusline")
}

pub(super) fn claude_statusline_wrapper_path(support_dir: &Path) -> PathBuf {
    support_dir.join("claude-code-statusline.sh")
}

pub(super) fn expected_claude_statusline_command(support_dir: &Path) -> String {
    shell_quote_path(&claude_statusline_wrapper_path(support_dir))
}

fn claude_statusline_command_drift(
    command: Option<&str>,
    support_dir: &Path,
) -> Option<ConfigDrift> {
    let expected = expected_claude_statusline_command(support_dir);
    let observed = command.map(str::trim).filter(|value| !value.is_empty());
    match observed {
        Some(command) if command == expected => None,
        Some(command) if is_ottto_statusline_command(command) => {
            Some(config_drift("statusLine.command", expected, command))
        }
        Some(command) => Some(config_drift(
            "statusLine.command",
            "ottto claude-code-statusline wrapper",
            command,
        )),
        None => Some(config_drift(
            "statusLine.command",
            "ottto claude-code-statusline wrapper",
            "missing",
        )),
    }
}

fn claude_statusline_wrapper_drift(support_dir: &Path) -> Option<ConfigDrift> {
    let path = claude_statusline_wrapper_path(support_dir);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "missing",
            ));
        }
        Err(_) => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "unreadable",
            ));
        }
    };
    if !metadata.is_file() {
        return Some(config_drift(
            "statusLine.wrapper",
            "executable current ottto statusLine wrapper",
            "not_file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Some(config_drift(
            "statusLine.wrapper",
            "executable current ottto statusLine wrapper",
            "not_executable",
        ));
    }
    let body = match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(_) => {
            return Some(config_drift(
                "statusLine.wrapper",
                "executable current ottto statusLine wrapper",
                "unreadable",
            ));
        }
    };
    let delegated_command = body
        .lines()
        .find_map(|line| line.strip_prefix("ORIGINAL_STATUSLINE="))
        .and_then(parse_shell_single_quoted_assignment)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let expected =
        render_claude_statusline_wrapper(&preferred_ottto_cli_path(), delegated_command.as_deref());
    if body != expected {
        return Some(config_drift(
            "statusLine.wrapper",
            "current ottto statusLine wrapper",
            "stale",
        ));
    }
    None
}

fn claude_statusline_wrapper_ready(support_dir: &Path) -> bool {
    claude_statusline_wrapper_drift(support_dir).is_none()
}

fn existing_claude_statusline_wrapper_delegated_command(
    support_dir: &Path,
) -> Result<Option<String>, LocalApiError> {
    let path = claude_statusline_wrapper_path(support_dir);
    let body = match fs::read_to_string(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(LocalApiError::StatePoisoned),
    };
    Ok(body
        .lines()
        .find_map(|line| line.strip_prefix("ORIGINAL_STATUSLINE="))
        .and_then(parse_shell_single_quoted_assignment)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn parse_shell_single_quoted_assignment(value: &str) -> Option<String> {
    let inner = value.trim().strip_prefix('\'')?.strip_suffix('\'')?;
    Some(inner.replace("'\"'\"'", "'"))
}

fn write_claude_statusline_wrapper(
    support_dir: &Path,
    delegated_command: Option<&str>,
) -> Result<(PathBuf, bool), LocalApiError> {
    fs::create_dir_all(support_dir).or_state_poisoned()?;
    let path = claude_statusline_wrapper_path(support_dir);
    let cli_path = preferred_ottto_cli_path();
    let script = render_claude_statusline_wrapper(&cli_path, delegated_command);
    match fs::read_to_string(&path) {
        Ok(existing) if existing == script => return Ok((path, false)),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(LocalApiError::StatePoisoned),
    }
    let tmp_path = path.with_extension(format!("sh.tmp.{}", std::process::id()));
    fs::write(&tmp_path, script).or_state_poisoned()?;
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(&tmp_path, permissions).or_state_poisoned()?;
    }
    fs::rename(&tmp_path, &path).or_state_poisoned()?;
    Ok((path, true))
}

pub(super) fn preferred_ottto_cli_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("ottto"));
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".ottto/bin/ottto"));
    }
    if let Some(path) = crate::command_env::executable_path("ottto") {
        candidates.push(path);
    }
    candidates
        .into_iter()
        .find(|path| path.exists() && path.is_file())
}

fn render_claude_statusline_wrapper(
    cli_path: &Option<PathBuf>,
    delegated_command: Option<&str>,
) -> String {
    let cli_assignment = cli_path
        .as_ref()
        .map(|path| shell_single_quote(&path.display().to_string()))
        .unwrap_or_else(|| "''".to_string());
    let delegated_assignment = delegated_command
        .map(shell_single_quote)
        .unwrap_or_else(|| "''".to_string());
    format!(
        r#"#!/bin/sh
input="$(cat)"
OTTTO_CLI={cli_assignment}
ORIGINAL_STATUSLINE={delegated_assignment}

if [ -n "$OTTTO_CLI" ] && [ -x "$OTTTO_CLI" ]; then
  printf '%s' "$input" | "$OTTTO_CLI" claude-code-statusline >/dev/null 2>&1 || true
else
  printf '%s' "$input" | ottto claude-code-statusline >/dev/null 2>&1 || true
fi

if [ -n "$ORIGINAL_STATUSLINE" ]; then
  printf '%s' "$input" | sh -c "$ORIGINAL_STATUSLINE"
fi
"#
    )
}

fn shell_quote_path(path: &Path) -> String {
    shell_single_quote(&path.display().to_string())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigBackupResult {
    backup_id: String,
}

fn backup_existing_config(
    source: SourceKind,
    path: &Path,
    backup_root: &Path,
) -> Result<Option<ConfigBackupResult>, LocalApiError> {
    if !path.exists() {
        return Ok(None);
    }
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .or_state_poisoned()?
        .as_millis();
    let backup_id = format!("{}_config_{millis}", source_slug(&source));
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("backup");
    let backup_dir = backup_root
        .join("config-backups")
        .join(source_slug(&source));
    fs::create_dir_all(&backup_dir).or_state_poisoned()?;
    fs::copy(path, backup_dir.join(format!("{backup_id}.{extension}"))).or_state_poisoned()?;
    prune_config_backups(&backup_dir, config_backup_retention_limit())?;
    Ok(Some(ConfigBackupResult { backup_id }))
}

pub(super) fn config_backup_retention_limit() -> usize {
    std::env::var(OTTTO_CONFIG_BACKUP_RETENTION_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(MAX_CONFIG_BACKUPS_PER_SOURCE)
}

pub(super) fn prune_config_backups(backup_dir: &Path, keep: usize) -> Result<(), LocalApiError> {
    let mut entries = fs::read_dir(backup_dir)
        .or_state_poisoned()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some(ConfigBackupEntry {
                rank_millis: config_backup_rank_millis(&path, &metadata),
                path,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .rank_millis
            .cmp(&left.rank_millis)
            .then_with(|| right.path.cmp(&left.path))
    });
    for entry in entries.into_iter().skip(keep) {
        if let Err(error) = fs::remove_file(&entry.path) {
            eprintln!(
                "Failed to prune old config backup {}: {error}",
                entry.path.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ConfigBackupEntry {
    rank_millis: Option<u128>,
    path: PathBuf,
}

fn config_backup_rank_millis(path: &Path, metadata: &fs::Metadata) -> Option<u128> {
    let file_name = path.file_name()?.to_str()?;
    if let Some((_prefix, suffix)) = file_name.split_once("_config_") {
        let timestamp = suffix.split('.').next().unwrap_or("");
        return timestamp.parse::<u128>().ok();
    }
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
}

pub(super) fn claude_code_relay_env_with_base(
    machine: &MachineIdentity,
    relay_base_url: &str,
) -> Vec<(&'static str, String)> {
    claude_code_relay_env_for_machine_id(&machine.machine_id, relay_base_url)
}

pub(super) fn claude_code_relay_env_for_machine_id(
    machine_id: &str,
    relay_base_url: &str,
) -> Vec<(&'static str, String)> {
    let relay_base = relay_base_url.trim_end_matches('/');
    vec![
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".to_string()),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1".to_string()),
        ("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS", "10000".to_string()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_string()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_string()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_string()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_string()),
        // The local reducer consumes Claude's exact per-request api_request logs.
        // Keep metrics/traces protobuf while making only the logs signal safely
        // inspectable without persisting raw OTLP payloads.
        ("OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "http/json".to_string()),
        (
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            format!("{relay_base}/v1/metrics"),
        ),
        (
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            format!("{relay_base}/v1/logs"),
        ),
        (
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            format!("{relay_base}/v1/traces"),
        ),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Ottto-Local-Relay=claude_code".to_string(),
        ),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            format!(
                "service.name=claude-code,ottto.source=claude_code,ottto.machine_id={machine_id}"
            ),
        ),
    ]
}

const MANAGED_CONFIG_PREVIEW_MAX_LINES: usize = 40;

const MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH: usize = 240;

/// Mask token-shaped content in one managed-config line. Never trusts a
/// specific format: long opaque character runs, anything after "bearer", and
/// values of secret-bearing keys (key/token/secret/header/authorization) are
/// all replaced. The backend re-sanitizes on ingest as defense-in-depth.
fn redact_managed_config_line(line: &str) -> String {
    let mut redacted = String::new();
    let mut token = String::new();
    fn flush(token: &mut String, out: &mut String) {
        // Long opaque runs are masked, but pure UPPER_SNAKE runs are env-key
        // names (OTEL_EXPORTER_OTLP_LOGS_ENDPOINT is 32 chars), not secrets.
        let looks_like_env_key = token
            .chars()
            .all(|character| character.is_ascii_uppercase() || character == '_');
        if token.len() >= 32 && !looks_like_env_key {
            out.push_str("…redacted…");
        } else {
            out.push_str(token);
        }
        token.clear();
    }
    for character in line.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '_' | '-') {
            token.push(character);
        } else {
            flush(&mut token, &mut redacted);
            redacted.push(character);
        }
    }
    flush(&mut token, &mut redacted);

    let lowered = redacted.to_ascii_lowercase();
    if let Some(index) = lowered.find("bearer") {
        redacted.truncate(index + "bearer".len());
        redacted.push_str(" …redacted…");
    }
    if let Some(delimiter_index) = redacted.find(['=', ':']) {
        let key = redacted[..delimiter_index].to_ascii_lowercase();
        if ["key", "token", "secret", "header", "authorization"]
            .iter()
            .any(|marker| key.contains(marker))
        {
            let delimiter = redacted[delimiter_index..].chars().next().unwrap_or('=');
            redacted = format!("{}{delimiter} …redacted…", &redacted[..delimiter_index]);
        }
    }
    redacted
}

/// Redacted preview of the Ottto-managed fence region for the scan payload.
/// `path_label` is a home-relative label ("~/.codex/config.toml") so machine
/// user names never leave the device. Returns `None` when the file is
/// missing or holds no complete fence.
/// Ottto-managed env keys in `~/.claude/settings.json`, in write order (see
/// `claude_code_relay_env_with_base`). Claude Code's config is JSON, so the
/// fence-based extractor can never apply; the preview instead renders the
/// managed keys as they actually exist on disk.
const CLAUDE_MANAGED_ENV_KEYS: [&str; 13] = [
    "CLAUDE_CODE_ENABLE_TELEMETRY",
    "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
    "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS",
    "OTEL_METRICS_EXPORTER",
    "OTEL_LOGS_EXPORTER",
    "OTEL_TRACES_EXPORTER",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_RESOURCE_ATTRIBUTES",
];

/// Redacted preview of the Ottto-managed env keys inside
/// `~/.claude/settings.json`. Reports what is really on disk (never the
/// template): only keys present in the file appear, and values ride through
/// the same redaction as the fence path. Returns `None` when the file is
/// missing, unparseable, or holds none of the managed keys.
pub(super) fn claude_managed_config_preview(body: Option<&str>) -> Option<serde_json::Value> {
    let body = body?;
    let settings: serde_json::Value = serde_json::from_str(body).ok()?;
    let env = settings.get("env")?.as_object()?;
    let mut lines: Vec<String> = Vec::new();
    for key in CLAUDE_MANAGED_ENV_KEYS {
        let Some(value) = env.get(key) else {
            continue;
        };
        let rendered = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let line: String = format!("{key} = \"{rendered}\"")
            .chars()
            .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
            .collect();
        lines.push(redact_managed_config_line(&line));
    }
    if lines.is_empty() {
        return None;
    }
    Some(json!({
        "path": "~/.claude/settings.json",
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": lines,
    }))
}

/// Redacted preview of the Ottto-managed region in `~/.codex/config.toml`.
/// Handles both on-disk shapes: the legacy `# ottto:start/end` fenced block,
/// and the current unfenced managed `otel` table (dotted `otel.*` keys or
/// `[otel]`/`[otel.*]` sections) that `patch_existing_codex_otel_table`
/// maintains. Returns `None` when the file is missing or holds no managed
/// region.
pub(super) fn codex_managed_config_preview(body: Option<&str>) -> Option<serde_json::Value> {
    let body = body?;
    if let Some(preview) = managed_config_preview("~/.codex/config.toml", Some(body)) {
        return Some(preview);
    }
    let mut lines: Vec<String> = Vec::new();
    let mut inside_otel_section = false;
    for line in body.lines() {
        if lines.len() >= MANAGED_CONFIG_PREVIEW_MAX_LINES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .trim_matches('"');
            inside_otel_section = name == "otel" || name.starts_with("otel.");
            if !inside_otel_section {
                continue;
            }
        } else if !inside_otel_section && !trimmed.starts_with("otel.") {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let capped: String = line
            .chars()
            .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
            .collect();
        lines.push(redact_managed_config_line(&capped));
    }
    if lines.is_empty() {
        return None;
    }
    Some(json!({
        "path": "~/.codex/config.toml",
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": lines,
    }))
}

pub(super) fn managed_config_preview(
    path_label: &str,
    body: Option<&str>,
) -> Option<serde_json::Value> {
    let body = body?;
    let lines = crate::agent_configs::fence::extract_fence_lines(body)?;
    let redacted: Vec<String> = lines
        .iter()
        .take(MANAGED_CONFIG_PREVIEW_MAX_LINES)
        .map(|line| {
            let capped: String = line
                .chars()
                .take(MANAGED_CONFIG_PREVIEW_MAX_LINE_LENGTH)
                .collect();
            redact_managed_config_line(&capped)
        })
        .collect();
    Some(json!({
        "path": path_label,
        "exists": true,
        "captured_at": current_rfc3339(),
        "lines": redacted,
    }))
}

pub(super) fn read_optional_to_string(path: &PathBuf) -> Option<String> {
    fs::read_to_string(path).ok()
}

#[cfg(test)]
pub(super) fn codex_config_has_relay_otel(body: &str) -> bool {
    codex_config_relay_port(body).is_some()
}

#[cfg(test)]
fn codex_config_relay_port(body: &str) -> Option<u16> {
    let Ok(document) = body.parse::<DocumentMut>() else {
        return None;
    };
    let otel = document.get("otel").and_then(Item::as_table)?;
    let prompt_logging_disabled = otel
        .get("log_user_prompt")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        == Some(false);
    if !prompt_logging_disabled {
        return None;
    }
    let logs = codex_exporter_relay_port(otel, "exporter", "logs")?;
    let traces = codex_exporter_relay_port(otel, "trace_exporter", "traces")?;
    let metrics = codex_exporter_relay_port(otel, "metrics_exporter", "metrics")?;
    if logs == traces && traces == metrics {
        Some(logs)
    } else {
        None
    }
}

fn codex_exporter_relay_port(
    otel: &dyn toml_edit::TableLike,
    exporter_key: &str,
    signal: &str,
) -> Option<u16> {
    let otlp_http = otel
        .get(exporter_key)
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("otlp-http"))
        .and_then(Item::as_table_like)?;
    let endpoint = otlp_http
        .get("endpoint")
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())?;
    let suffix = format!("/v1/{signal}");
    if !endpoint.ends_with(&suffix) {
        return None;
    }
    let relay_base_url = endpoint.strip_suffix(&suffix)?;
    let relay_port = crate::otlp_relay::local_relay_port_from_endpoint(relay_base_url)?;
    let headers = otlp_http.get("headers").and_then(Item::as_table_like)?;
    if headers
        .get(crate::otlp_relay::LOCAL_RELAY_HEADER)
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())
        == Some(crate::otlp_relay::CODEX_RELAY_SOURCE)
    {
        Some(relay_port)
    } else {
        None
    }
}

pub(super) fn claude_code_telemetry_config_installed(body: &str) -> bool {
    let relay_port = claude_code_settings_relay_port(body);
    claude_code_settings_has_relay_env(body)
        && claude_code_settings_has_statusline_helper(body)
        && claude_statusline_wrapper_ready(&default_support_dir())
        && relay_port.is_some_and(loopback_listener_available)
        && snapshot_device_credentials_include_source(crate::otlp_relay::CLAUDE_CODE_RELAY_SOURCE)
}

pub(super) fn snapshot_device_credentials_include_source(source: &str) -> bool {
    crate::snapshot_client::load_snapshot_device_credentials()
        .ok()
        .is_some_and(|(device, secret)| {
            if source == "codex" && (device.device_id.trim().is_empty() || secret.trim().is_empty())
            {
                return false;
            }
            device
                .sources
                .iter()
                .any(|configured_source| configured_source == source)
        })
}

pub(super) fn claude_code_settings_has_relay_env(body: &str) -> bool {
    claude_code_settings_relay_port(body).is_some()
}

fn claude_code_settings_relay_port(body: &str) -> Option<u16> {
    let Ok(settings) = serde_json::from_str::<serde_json::Value>(body) else {
        return None;
    };
    let env = settings.get("env").and_then(|value| value.as_object())?;

    let metrics_endpoint = env
        .get("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let logs_endpoint = env
        .get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let traces_endpoint = env
        .get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .and_then(|value| value.as_str())?;
    let metrics_port = relay_port_from_signal_endpoint(metrics_endpoint, "metrics")?;
    let logs_port = relay_port_from_signal_endpoint(logs_endpoint, "logs")?;
    let traces_port = relay_port_from_signal_endpoint(traces_endpoint, "traces")?;
    if metrics_port != logs_port || logs_port != traces_port {
        return None;
    }

    let expected = [
        ("CLAUDE_CODE_ENABLE_TELEMETRY", "1".to_string()),
        ("CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "1".to_string()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_string()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_string()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_string()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_string()),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            "X-Ottto-Local-Relay=claude_code".to_string(),
        ),
    ];
    for (key, expected_value) in expected {
        if env.get(key).and_then(|value| value.as_str()) != Some(expected_value.as_str()) {
            return None;
        }
    }
    let metadata_valid = env
        .get("CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS")
        .and_then(|value| value.as_str())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|timeout| timeout >= 10000)
        && env
            .get("OTEL_RESOURCE_ATTRIBUTES")
            .and_then(|value| value.as_str())
            .is_some_and(|attributes| {
                attributes.contains("service.name=claude-code")
                    && attributes.contains("ottto.source=claude_code")
                    && attributes.contains("ottto.machine_id=")
            });
    if metadata_valid {
        Some(metrics_port)
    } else {
        None
    }
}

fn relay_port_from_signal_endpoint(endpoint: &str, signal: &str) -> Option<u16> {
    let suffix = format!("/v1/{signal}");
    if !endpoint.ends_with(&suffix) {
        return None;
    }
    crate::otlp_relay::local_relay_port_from_endpoint(endpoint.strip_suffix(&suffix)?)
}

pub(super) fn claude_code_settings_has_statusline_helper(body: &str) -> bool {
    let Ok(settings) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    settings
        .get("statusLine")
        .and_then(|value| value.as_object())
        .and_then(|statusline| statusline.get("command"))
        .and_then(|value| value.as_str())
        .is_some_and(is_ottto_statusline_command)
}

pub(super) fn loopback_listener_available(port: u16) -> bool {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok()
}

pub(super) fn home_path(relative: &str) -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(relative)
}

pub(super) fn executable_exists(program: &str) -> bool {
    crate::command_env::executable_path(program).is_some()
}
