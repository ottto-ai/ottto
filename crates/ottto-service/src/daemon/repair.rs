//! Daemon repair leases, approval plans and local diagnostics.
//! Owns repair locking and the support-only diagnostics projection.
//! Called by local control through the root LocalDaemon API.

use crate::app_bundle_version;
use crate::claude_local_otel;
use crate::macos_service;
use crate::source_display_name;
use crate::source_slug;
use crate::DaemonState;
use crate::LocalApiError;
use crate::LocalDaemon;
use ottto_core::compiled_release_version;
use ottto_core::default_support_dir;
use ottto_core::launch_agent_path;
use ottto_core::launchd_target;
use ottto_core::local_lifecycle_home_dir;
#[cfg(target_os = "macos")]
use ottto_core::ControlTokenStore;
#[cfg(target_os = "macos")]
use ottto_core::KeychainSecretStore;
use ottto_core::RedactionPolicy;
use ottto_core::OTTTO_KEYCHAIN_ACCOUNT;
use ottto_core::OTTTO_RELAY_DEVICE_SECRET_ACCOUNT;
use ottto_core::OTTTO_SERVICE_BINARY_NAME;
use ottto_core::OTTTO_SETUP_RUN_TOKEN_ACCOUNT;
use ottto_protocol::DaemonRuntimeState;
use ottto_protocol::DiagnosticsBundle;
use ottto_protocol::DiagnosticsRetentionDisclosure;
use ottto_protocol::DiagnosticsSection;
use ottto_protocol::DiagnosticsUploadAuthorization;
use ottto_protocol::DiagnosticsUploadReport;
use ottto_protocol::DiagnosticsUploadStatus;
use ottto_protocol::EventStatus;
use ottto_protocol::LocalAccountState;
use ottto_protocol::RedactedValue;
use ottto_protocol::RedactionCategory;
use ottto_protocol::RedactionReport;
use ottto_protocol::RedactionSurface;
use ottto_protocol::RepairAction;
use ottto_protocol::RepairActionApproval;
use ottto_protocol::RepairActionKind;
use ottto_protocol::RepairApprovalSurface;
use ottto_protocol::RepairAuthority;
use ottto_protocol::RepairAuthorityMode;
use ottto_protocol::RepairBackupMetadata;
use ottto_protocol::RepairBackupScope;
use ottto_protocol::RepairPlan;
use ottto_protocol::RepairPlanStatus;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceOperation;
use ottto_protocol::StableMessage;
use ottto_protocol::DIAGNOSTICS_RETENTION_DISCLOSURE;
use ottto_protocol::PROTOCOL_VERSION;
use std::collections::BTreeMap;
use std::process::Command;
use std::process::Stdio;

impl LocalDaemon {
    pub fn acquire_repair_lock(
        &self,
        token: &str,
        source: SourceKind,
    ) -> Result<RepairLease, LocalApiError> {
        self.control_token.authorize(token)?;
        self.acquire_repair_lock_authorized(source)
    }

    pub fn acquire_repair_lock_for_trusted_client(
        &self,
        source: SourceKind,
    ) -> Result<RepairLease, LocalApiError> {
        self.acquire_repair_lock_authorized(source)
    }

    fn acquire_repair_lock_authorized(
        &self,
        source: SourceKind,
    ) -> Result<RepairLease, LocalApiError> {
        let mut state = self.state()?;
        if state.repair_locked {
            return Err(LocalApiError::RepairLocked);
        }
        state.repair_locked = true;
        Ok(RepairLease {
            daemon: self.clone(),
            source,
            released: false,
        })
    }

    pub fn propose_repair(
        &self,
        token: &str,
        source: SourceKind,
        dry_run: bool,
    ) -> Result<RepairPlan, LocalApiError> {
        self.control_token.authorize(token)?;
        self.propose_repair_authorized(source, dry_run)
    }

    pub fn propose_repair_for_trusted_client(
        &self,
        source: SourceKind,
        dry_run: bool,
    ) -> Result<RepairPlan, LocalApiError> {
        self.propose_repair_authorized(source, dry_run)
    }

    fn propose_repair_authorized(
        &self,
        source: SourceKind,
        dry_run: bool,
    ) -> Result<RepairPlan, LocalApiError> {
        let _lease = self.acquire_repair_lock_authorized(source.clone())?;
        let should_load_connection = {
            let state = self.state()?;
            state.account.state == LocalAccountState::Connected && state.connection.is_none()
        };
        if should_load_connection {
            let _ = self.connection_for_authorized_client()?;
        }
        let shell_finding = self.shell_profile_finding(&source)?;
        let state = self.state()?;
        let mut authority = repair_authority_for_state(&state);
        if let Some(problem) = shell_finding {
            authority.message.text.push(' ');
            authority.message.text.push_str(&problem.detail);
        }
        Ok(RepairPlan {
            plan_id: format!("repair_{}", source_slug(&source)),
            machine_id: state.machine.machine_id.clone(),
            source: source.clone(),
            dry_run,
            status: RepairPlanStatus::Proposed,
            authority: authority.clone(),
            actions: vec![
                RepairAction {
                    action: RepairActionKind::WriteConfig,
                    title: format!("Back up and repair {} config", source_display_name(&source)),
                    detail:
                        "Create ottto-service-owned backup metadata before writing telemetry config."
                            .to_string(),
                    requires_approval: true,
                    destructive: false,
                    approval: setup_safe_repair_approval(&authority),
                    backup: Some(config_backup_metadata(&source, false, None, None)),
                },
                RepairAction {
                    action: RepairActionKind::RotateSecret,
                    title: "Rotate local telemetry key".to_string(),
                    detail: "Request a fresh source-scoped key and write it through ottto-service."
                        .to_string(),
                    requires_approval: true,
                    destructive: false,
                    approval: browser_repair_approval(
                        false,
                        "Credential rotation changes source-scoped auth material and must be approved in Ottto.",
                    ),
                    backup: None,
                },
                RepairAction {
                    action: RepairActionKind::VerifyTelemetry,
                    title: "Verify setup".to_string(),
                    detail: "Run source verification after local config is written.".to_string(),
                    requires_approval: false,
                    destructive: false,
                    approval: no_repair_approval(
                        true,
                        authority.server_backed,
                        "Verification only reads local state and publishes setup status.",
                    ),
                    backup: None,
                },
            ],
            created_at: state.now.clone(),
        })
    }

    pub fn diagnostics_stub(&self, token: &str) -> Result<DiagnosticsBundle, LocalApiError> {
        self.control_token.authorize(token)?;
        self.diagnostics_stub_authorized()
    }

    pub fn diagnostics_stub_for_trusted_client(&self) -> Result<DiagnosticsBundle, LocalApiError> {
        self.diagnostics_stub_authorized()
    }

    fn diagnostics_stub_authorized(&self) -> Result<DiagnosticsBundle, LocalApiError> {
        let status = self.status_for_authorized_client()?;
        let home = local_lifecycle_home_dir().ok();
        let launch_agent_path_value = if home.is_some() { "[path]" } else { "unknown" };
        let launch_agent_loaded = launchd_service_loaded();
        let current_exe = std::env::current_exe().ok();
        let owner_state = home.as_ref().map(|home| {
            let plist_path = macos_service::launch_agent_path(home);
            macos_service::inspect_launch_agent_owner(&plist_path, current_exe.as_deref())
        });
        let launch_agent_path_exists = home
            .as_ref()
            .map(|home| launch_agent_path(home).exists())
            .unwrap_or(false);
        let launch_agent_path_drift = launch_agent_loaded && !launch_agent_path_exists;
        let owner_drift = owner_state
            .as_ref()
            .map(|state| state.owner_drift)
            .unwrap_or(false);
        let keychain_item_count = local_secret_presence_count();
        let current_version = compiled_release_version();
        let version_mismatch =
            status.protocol_version != PROTOCOL_VERSION || status.daemon_version != current_version;
        let stale_registrations = if launch_agent_path_drift {
            vec![launchd_target()]
        } else {
            Vec::new()
        };

        let mut runtime = BTreeMap::new();
        runtime.insert(
            "daemon_state".to_string(),
            RedactedValue::String(format!("{:?}", status.daemon)),
        );
        runtime.insert(
            "daemon_running".to_string(),
            RedactedValue::Bool(status.daemon == DaemonRuntimeState::Running),
        );
        runtime.insert("socket_reachable".to_string(), RedactedValue::Bool(true));
        runtime.insert(
            "xpc_reachable".to_string(),
            RedactedValue::Bool(launch_agent_loaded),
        );
        runtime.insert(
            "source_count".to_string(),
            RedactedValue::Number(status.sources.len() as i64),
        );

        let mut versions = BTreeMap::new();
        versions.insert(
            "app_version".to_string(),
            RedactedValue::String(app_bundle_version::diagnostics_app_version(
                current_exe.as_deref(),
                home.as_deref(),
            )),
        );
        versions.insert(
            "cli_version".to_string(),
            RedactedValue::String(current_version),
        );
        versions.insert(
            "daemon_version".to_string(),
            RedactedValue::String(status.daemon_version.clone()),
        );
        versions.insert(
            "protocol_version".to_string(),
            RedactedValue::Number(status.protocol_version as i64),
        );
        versions.insert(
            "build_id".to_string(),
            RedactedValue::String(option_env!("GIT_COMMIT").unwrap_or("dev").to_string()),
        );
        versions.insert(
            "version_mismatch".to_string(),
            RedactedValue::Bool(version_mismatch),
        );

        let mut installation = BTreeMap::new();
        installation.insert(
            "launch_agent_loaded".to_string(),
            RedactedValue::Bool(launch_agent_loaded),
        );
        installation.insert(
            "launch_agent_path".to_string(),
            RedactedValue::String(launch_agent_path_value.to_string()),
        );
        installation.insert(
            "launch_agent_path_drift".to_string(),
            RedactedValue::Bool(launch_agent_path_drift),
        );
        installation.insert(
            "daemon_owner".to_string(),
            RedactedValue::String(
                current_exe
                    .as_deref()
                    .map(ottto_core::install_owner_for_path)
                    .map(macos_service::install_owner_label)
                    .unwrap_or("unknown-owner")
                    .to_string(),
            ),
        );
        installation.insert(
            "plist_owner".to_string(),
            RedactedValue::String(
                owner_state
                    .as_ref()
                    .map(|state| macos_service::install_owner_label(state.plist_owner))
                    .unwrap_or("unknown-owner")
                    .to_string(),
            ),
        );
        installation.insert(
            "loaded_owner".to_string(),
            RedactedValue::String(
                owner_state
                    .as_ref()
                    .map(|state| macos_service::install_owner_label(state.loaded_owner))
                    .unwrap_or("unknown-owner")
                    .to_string(),
            ),
        );
        installation.insert("owner_drift".to_string(), RedactedValue::Bool(owner_drift));
        installation.insert(
            "repair_command".to_string(),
            RedactedValue::String(
                owner_state
                    .as_ref()
                    .and_then(|state| {
                        let owner = if state.loaded_owner != ottto_protocol::InstallOwner::Unknown {
                            state.loaded_owner
                        } else {
                            state.plist_owner
                        };
                        match owner {
                            ottto_protocol::InstallOwner::Homebrew => {
                                Some("brew services restart ottto")
                            }
                            ottto_protocol::InstallOwner::HostedInstaller => {
                                Some("rerun the Ottto installer")
                            }
                            ottto_protocol::InstallOwner::AppBundle => {
                                Some("quit and relaunch the Ottto app")
                            }
                            ottto_protocol::InstallOwner::Dev => {
                                Some("run the explicit dev repair command")
                            }
                            ottto_protocol::InstallOwner::Unknown => None,
                        }
                    })
                    .unwrap_or("inspect LaunchAgent owner")
                    .to_string(),
            ),
        );
        installation.insert(
            "stale_registrations".to_string(),
            redacted_string_list(stale_registrations),
        );
        installation.insert(
            "manifest_hash_status".to_string(),
            RedactedValue::String("unknown".to_string()),
        );
        installation.insert(
            "manifest_hash_mismatch".to_string(),
            RedactedValue::Bool(false),
        );

        let mut repair = BTreeMap::new();
        repair.insert(
            "safe_repair_actions".to_string(),
            redacted_string_list(vec![
                "repair_source_config".to_string(),
                "collect_diagnostics".to_string(),
                "uninstall_plan".to_string(),
                "uninstall_execute_confirmed".to_string(),
            ]),
        );
        repair.insert(
            "repair_backup_metadata".to_string(),
            repair_backup_diagnostics(),
        );

        let mut security = BTreeMap::new();
        security.insert(
            "keychain_item_count".to_string(),
            RedactedValue::Number(keychain_item_count),
        );
        security.insert(
            "auth_header".to_string(),
            RedactedValue::String("[REDACTED]".to_string()),
        );

        Ok(DiagnosticsBundle {
            bundle_id: diagnostics_bundle_id(&status.generated_at),
            machine_id: status.machine.machine_id.clone(),
            created_at: status.generated_at.clone(),
            upload: diagnostics_local_only_upload_report(),
            redaction: diagnostics_redaction_report(),
            sections: vec![
                diagnostics_section("runtime", runtime),
                diagnostics_section("versions", versions),
                diagnostics_section("installation", installation),
                diagnostics_section("repair", repair),
                diagnostics_section("security", security),
                #[cfg(unix)]
                diagnostics_section(
                    "claude_local_evidence",
                    claude_local_otel::support_health::diagnostics_items(
                        &default_support_dir(),
                        &status.relay,
                    ),
                ),
            ],
        })
    }

    fn release_repair_lock(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.repair_locked = false;
        }
    }
}

fn launchd_service_loaded() -> bool {
    if std::env::consts::OS != "macos" {
        return false;
    }
    Command::new("/bin/launchctl")
        .arg("print")
        .arg(launchd_target())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn local_secret_presence_count() -> i64 {
    [
        OTTTO_KEYCHAIN_ACCOUNT,
        OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
        OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    ]
    .iter()
    .filter(|account| KeychainSecretStore::new(account).load().is_ok())
    .count() as i64
}

#[cfg(not(target_os = "macos"))]
fn local_secret_presence_count() -> i64 {
    let _ = (
        OTTTO_KEYCHAIN_ACCOUNT,
        OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
        OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    );
    0
}

fn redacted_string_list(values: Vec<String>) -> RedactedValue {
    RedactedValue::List(values.into_iter().map(RedactedValue::String).collect())
}

fn diagnostics_section(
    name: impl Into<String>,
    items: BTreeMap<String, RedactedValue>,
) -> DiagnosticsSection {
    DiagnosticsSection {
        name: name.into(),
        status: EventStatus::Succeeded,
        items,
    }
}

fn diagnostics_bundle_id(created_at: &str) -> String {
    let compact = created_at
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if compact.is_empty() {
        "diag_local".to_string()
    } else {
        format!("diag_{compact}")
    }
}

pub fn diagnostics_local_only_upload_report() -> DiagnosticsUploadReport {
    DiagnosticsUploadReport {
        requested: false,
        status: DiagnosticsUploadStatus::LocalOnly,
        approval_required: true,
        approved: false,
        retention: DiagnosticsRetentionDisclosure {
            accepted: false,
            text: DIAGNOSTICS_RETENTION_DISCLOSURE.to_string(),
        },
        authorization: DiagnosticsUploadAuthorization::NotRequested,
        support_claim_provided: false,
        upload_id: None,
        uploaded_at: None,
    }
}

fn diagnostics_redaction_report() -> RedactionReport {
    RedactionReport {
        policy_version: RedactionPolicy::default().policy_version,
        covered_surfaces: vec![
            RedactionSurface::Diagnostics,
            RedactionSurface::SupportOutput,
            RedactionSurface::AgentOutput,
            RedactionSurface::SetupError,
            RedactionSurface::CommandOutput,
        ],
        redacted_categories: vec![
            RedactionCategory::LocalPath,
            RedactionCategory::SecretToken,
            RedactionCategory::AccountIdentifier,
            RedactionCategory::MachineIdentifier,
            RedactionCategory::RawPrompt,
            RedactionCategory::CommandOutput,
        ],
        redacted_fields: vec![
            "installation.launch_agent_path".to_string(),
            "security.auth_header".to_string(),
        ],
        preserved_fields: vec![
            "bundle_id".to_string(),
            "machine_id".to_string(),
            "created_at".to_string(),
            "runtime.daemon_state".to_string(),
            "runtime.daemon_running".to_string(),
            "runtime.socket_reachable".to_string(),
            "runtime.xpc_reachable".to_string(),
            "runtime.source_count".to_string(),
            "versions.cli_version".to_string(),
            "versions.daemon_version".to_string(),
            "versions.protocol_version".to_string(),
            "installation.launch_agent_loaded".to_string(),
            "installation.launch_agent_path_drift".to_string(),
            "installation.stale_registrations".to_string(),
            "repair.safe_repair_actions".to_string(),
            "repair.repair_backup_metadata".to_string(),
            "security.keychain_item_count".to_string(),
        ],
    }
}

fn repair_backup_diagnostics() -> RedactedValue {
    RedactedValue::Object(BTreeMap::from([
        ("required".to_string(), RedactedValue::Bool(true)),
        ("restore_available".to_string(), RedactedValue::Bool(false)),
        (
            "restore_operation".to_string(),
            RedactedValue::String("uninstall_restore".to_string()),
        ),
        (
            "cloud_credentials_untouched".to_string(),
            RedactedValue::Bool(true),
        ),
    ]))
}

#[derive(Debug)]
pub struct RepairLease {
    daemon: LocalDaemon,
    source: SourceKind,
    released: bool,
}

impl RepairLease {
    pub fn source(&self) -> &SourceKind {
        &self.source
    }

    pub fn release(mut self) {
        if !self.released {
            self.daemon.release_repair_lock();
            self.released = true;
        }
    }
}

impl Drop for RepairLease {
    fn drop(&mut self) {
        if !self.released {
            self.daemon.release_repair_lock();
            self.released = true;
        }
    }
}

pub(crate) fn config_backup_metadata(
    source: &SourceKind,
    restore_available: bool,
    backup_id: Option<String>,
    target_fingerprint: Option<String>,
) -> RepairBackupMetadata {
    RepairBackupMetadata {
        scope: RepairBackupScope::SourceConfig,
        required: true,
        restore_available,
        backup_id,
        target_fingerprint,
        restore_operation: Some(SourceOperation::UninstallRestore),
        detail: Some(format!(
            "{} config changes must be reversible through {OTTTO_SERVICE_BINARY_NAME}.",
            source_display_name(source)
        )),
    }
}

pub(crate) fn repair_authority_for_state(state: &DaemonState) -> RepairAuthority {
    if state.account.state != LocalAccountState::Connected {
        return RepairAuthority {
            mode: RepairAuthorityMode::BrowserApprovalRequired,
            server_backed: false,
            terminal_approval_allowed: false,
            browser_approval_required: true,
            setup_run_id: None,
            message: StableMessage {
                code: "account_not_connected".to_string(),
                text: "Sign in to Ottto in your browser before approving repair actions."
                    .to_string(),
            },
        };
    }

    let Some(connection) = state.connection.as_ref() else {
        return RepairAuthority {
            mode: RepairAuthorityMode::BrowserApprovalRequired,
            server_backed: false,
            terminal_approval_allowed: false,
            browser_approval_required: true,
            setup_run_id: None,
            message: StableMessage {
                code: "setup_run_reconnect_required".to_string(),
                text: "This Mac has no active Ottto setup binding. Start setup from the Ottto app before approving repair actions."
                    .to_string(),
            },
        };
    };

    RepairAuthority {
        mode: RepairAuthorityMode::ServerBackedSetupAction,
        server_backed: true,
        terminal_approval_allowed: true,
        browser_approval_required: true,
        setup_run_id: Some(connection.setup_run_id.clone()),
        message: StableMessage {
            code: "server_backed_setup_repair".to_string(),
            text: "Setup-safe repairs can be approved in this terminal through the active Ottto setup run; credential rotation still requires browser approval."
                .to_string(),
        },
    }
}

pub(crate) fn setup_safe_repair_approval(authority: &RepairAuthority) -> RepairActionApproval {
    if authority.server_backed && authority.terminal_approval_allowed {
        return RepairActionApproval {
            surface: RepairApprovalSurface::Terminal,
            setup_safe: true,
            server_backed: true,
            reason: "This setup-safe config repair is tied to an active Ottto setup run."
                .to_string(),
        };
    }

    browser_repair_approval(
        true,
        "Setup repair needs browser approval until this Mac is connected to an active Ottto setup run.",
    )
}

fn browser_repair_approval(setup_safe: bool, reason: &str) -> RepairActionApproval {
    RepairActionApproval {
        surface: RepairApprovalSurface::Browser,
        setup_safe,
        server_backed: false,
        reason: reason.to_string(),
    }
}

pub(crate) fn no_repair_approval(
    setup_safe: bool,
    server_backed: bool,
    reason: &str,
) -> RepairActionApproval {
    RepairActionApproval {
        surface: RepairApprovalSurface::None,
        setup_safe,
        server_backed,
        reason: reason.to_string(),
    }
}
