pub mod adaptive_collector;
pub mod agent_configs;
pub mod agent_status;
pub mod backfill;
pub(crate) mod command_env;
pub mod control;
pub mod detected_uses;
pub mod keychain;
pub mod macos_service;
pub mod otlp_relay;
pub mod snapshot_client;
pub mod snapshot_sync;
pub mod snapshot_watcher;
pub mod snapshots;
#[cfg(unix)]
pub mod unix_socket;
pub mod xpc_mach;

use ottto_core::{
    default_connection_api_base_url, default_support_dir, empty_status, launch_agent_path,
    launchd_target, local_lifecycle_home_dir, FileConnectionStore, LocalConnectionBinding,
    RedactionPolicy, OTTTO_KEYCHAIN_ACCOUNT, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
    OTTTO_SERVICE_BINARY_NAME, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
};
#[cfg(target_os = "macos")]
use ottto_core::{ControlTokenStore, KeychainSecretStore};
use ottto_protocol::{
    AccountBindingState, AgentQuotaWindow, AgentQuotaWindowFreshness, AgentQuotaWindowStatus,
    AgentStatusSnapshot, AgentStatusState, AuthCompleteResponse, AuthResetResponse,
    AuthStartResponse, CollectorDataSourceKind, CollectorDefaultState, CollectorDescriptor,
    CollectorRiskClass, ConnectorMaturity, ConnectorReviewTier, DaemonRuntimeState, DaemonStatus,
    DetectedUse, DetectedUseQuotaWindowState, DiagnosticsBundle, DiagnosticsRetentionDisclosure,
    DiagnosticsSection, DiagnosticsUploadAuthorization, DiagnosticsUploadReport,
    DiagnosticsUploadStatus, EventStatus, HealthGrade, HealthProblem, LocalAccountBinding,
    LocalAccountState, LocalAccountUser, MachineIdentity, RedactedValue, RedactionCategory,
    RedactionReport, RedactionSurface, RelayRuntimeState, RelayState, RepairAction,
    RepairActionApproval, RepairActionKind, RepairApprovalSurface, RepairAuthority,
    RepairAuthorityMode, RepairBackupMetadata, RepairBackupScope, RepairPlan, RepairPlanStatus,
    SourceConfigState, SourceDescriptor, SourceHealth, SourceKind, SourceOperation,
    SourceOperationDescriptor, SourceOperationState, SourceState, SourceStateOwner,
    SourceVerificationResult, SourceVerificationStatus, StableMessage, StableProblemCode,
    DIAGNOSTICS_RETENTION_DISCLOSURE, PROTOCOL_VERSION,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendErrorKind {
    Unreachable,
    Rejected,
    Unavailable,
    ResponseUnexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendErrorDetails {
    pub kind: BackendErrorKind,
    pub endpoint: String,
    pub status: Option<u16>,
    pub body_excerpt: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalApiError {
    #[error("local daemon authentication failed")]
    Unauthorized,
    #[error("another repair is already running")]
    RepairLocked,
    #[error("daemon state lock is poisoned")]
    StatePoisoned,
    #[error("control token cannot be empty")]
    EmptyControlToken,
    #[error("local client is not trusted")]
    LocalClientNotTrusted,
    #[error(
        "this Mac is connected to a different Ottto account; reset local account binding first"
    )]
    AccountResetRequired,
    #[error("no pending Ottto sign-in claim")]
    NoPendingAuthClaim,
    #[error("Ottto sign-in claim does not match this local session")]
    AuthClaimMismatch,
    #[error("setup-run connection is missing")]
    SetupRunConnectionMissing,
    #[error("this Mac is attached to a different setup run; open the Ottto app from Ottto")]
    SetupRunConnectionMismatch,
    #[error("invalid local control request: {0}")]
    InvalidRequest(String),
    #[error("Ottto found a manually edited managed fence and needs you to review it.")]
    ManualFenceReviewRequired,
    #[error("local operation failed: {0}")]
    LocalOperationFailed(String),
    #[error("network unavailable")]
    NetworkUnavailable,
    #[error("operation timed out: {0}")]
    TimedOut(String),
    #[error("backend request failed: {0:?}")]
    Backend(BackendErrorDetails),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlToken(String);

impl ControlToken {
    pub fn new(value: impl Into<String>) -> Result<Self, LocalApiError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(LocalApiError::EmptyControlToken);
        }
        Ok(Self(value))
    }

    fn authorize(&self, candidate: &str) -> Result<(), LocalApiError> {
        if self.0 == candidate {
            Ok(())
        } else {
            Err(LocalApiError::Unauthorized)
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalDaemon {
    inner: Arc<Mutex<DaemonState>>,
    control_token: ControlToken,
}

#[derive(Debug, Clone)]
struct DaemonState {
    machine: MachineIdentity,
    relay: RelayState,
    sources: Vec<SourceHealth>,
    account: LocalAccountBinding,
    connection: Option<LocalConnectionBinding>,
    pending_auth: Option<PendingAuthClaim>,
    repair_locked: bool,
    running: bool,
    now: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthClaim {
    pub claim_code: String,
    pub claim_token: String,
    pub nonce: String,
    pub claim_url: String,
    pub expires_at: String,
}

impl LocalDaemon {
    pub fn new(
        machine: MachineIdentity,
        control_token: ControlToken,
        now: impl Into<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonState {
                machine,
                relay: RelayState {
                    state: RelayRuntimeState::Unknown,
                    endpoint: None,
                    last_connected_at: None,
                    last_error: None,
                },
                sources: Vec::new(),
                account: LocalAccountBinding::not_connected(),
                connection: None,
                pending_auth: None,
                repair_locked: false,
                running: true,
                now: now.into(),
            })),
            control_token,
        }
    }

    pub fn with_account(self, account: LocalAccountBinding) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            state.account = account;
        }
        self
    }

    pub fn with_connection(self, connection: Option<LocalConnectionBinding>) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            state.connection = connection;
        }
        self
    }

    pub fn status(&self, token: &str) -> Result<DaemonStatus, LocalApiError> {
        self.control_token.authorize(token)?;
        self.status_for_authorized_client()
    }

    pub fn status_for_trusted_client(&self) -> Result<DaemonStatus, LocalApiError> {
        self.status_for_authorized_client()
    }

    pub fn account_for_trusted_client(&self) -> Result<LocalAccountBinding, LocalApiError> {
        let state = self.state()?;
        Ok(state.account.clone())
    }

    fn status_for_authorized_client(&self) -> Result<DaemonStatus, LocalApiError> {
        let state = self.state()?;
        Ok(status_from_state(&state))
    }

    pub fn begin_auth_with_claim(
        &self,
        claim: PendingAuthClaim,
    ) -> Result<AuthStartResponse, LocalApiError> {
        let mut state = self.state()?;
        let previous_account = state.account.clone();
        state.pending_auth = Some(claim.clone());
        state.sources.clear();
        state.account = LocalAccountBinding {
            state: LocalAccountState::ClaimPending,
            user: previous_account.user,
            organization: previous_account.organization,
            connected_at: previous_account.connected_at,
            last_refreshed_at: Some(state.now.clone()),
            message: Some(StableMessage {
                code: "claim_pending".to_string(),
                text: "Waiting for browser sign-in to finish.".to_string(),
            }),
        };
        Ok(AuthStartResponse {
            account: state.account.clone(),
            claim_code: claim.claim_code,
            claim_url: claim.claim_url,
            nonce: claim.nonce,
            expires_at: claim.expires_at,
        })
    }

    pub fn pending_auth_claim(
        &self,
        claim_code: &str,
        nonce: &str,
    ) -> Result<PendingAuthClaim, LocalApiError> {
        let state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code || claim.nonce != nonce {
            return Err(LocalApiError::AuthClaimMismatch);
        }
        Ok(claim.clone())
    }

    pub fn complete_auth_with_account(
        &self,
        claim_code: &str,
        nonce: &str,
        account: LocalAccountBinding,
        setup_run_id: String,
        setup_run_token_expires_at: String,
        machine_id: Option<String>,
    ) -> Result<AuthCompleteResponse, LocalApiError> {
        let mut state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code || claim.nonce != nonce {
            return Err(LocalApiError::AuthClaimMismatch);
        }
        if let Some(existing_user) = bound_user(&state.account) {
            if let Some(new_user) = bound_user(&account) {
                if existing_user.id != new_user.id {
                    state.account.state = LocalAccountState::ResetRequired;
                    state.account.message = Some(StableMessage {
                        code: "account_reset_required".to_string(),
                        text: "This Mac is connected to a different Ottto account.".to_string(),
                    });
                    return Err(LocalApiError::AccountResetRequired);
                }
            }
        }
        state.pending_auth = None;
        state.connection = Some(LocalConnectionBinding {
            setup_run_id: setup_run_id.clone(),
            setup_run_token_expires_at: setup_run_token_expires_at.clone(),
            machine_id: machine_id.clone(),
            api_base_url: default_connection_api_base_url(),
        });
        state.account = account.clone();
        Ok(AuthCompleteResponse {
            account,
            setup_run_id,
            setup_run_token_expires_at,
            machine_id,
        })
    }

    pub fn reset_account_for_trusted_client(&self) -> Result<AuthResetResponse, LocalApiError> {
        self.reset_account_for_authorized_client()
    }

    pub fn reset_account_for_authorized_client(&self) -> Result<AuthResetResponse, LocalApiError> {
        let mut state = self.state()?;
        let removed_account = if state.account.state == LocalAccountState::NotConnected {
            None
        } else {
            Some(state.account.clone())
        };
        state.account = LocalAccountBinding::not_connected();
        state.connection = None;
        state.pending_auth = None;
        state.sources.clear();
        Ok(AuthResetResponse {
            account: state.account.clone(),
            removed_account,
            local_only: true,
            cloud_disconnected: false,
            setup_run_id: None,
            disconnected_at: None,
            message: StableMessage {
                code: "disconnected".to_string(),
                text: "This Mac is disconnected from Ottto.".to_string(),
            },
        })
    }

    pub fn update_sources(
        &self,
        token: &str,
        sources: Vec<SourceHealth>,
    ) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        let mut state = self.state()?;
        state.sources = sources;
        Ok(())
    }

    pub fn connection_for_authorized_client(
        &self,
    ) -> Result<Option<LocalConnectionBinding>, LocalApiError> {
        self.connection_for_authorized_client_with(|| {
            FileConnectionStore::default()
                .load()
                .map_err(|_| LocalApiError::StatePoisoned)
        })
    }

    fn connection_for_authorized_client_with<F>(
        &self,
        load_connection: F,
    ) -> Result<Option<LocalConnectionBinding>, LocalApiError>
    where
        F: FnOnce() -> Result<Option<LocalConnectionBinding>, LocalApiError>,
    {
        let mut state = self.state()?;
        if state.connection.is_none() {
            if let Some(connection) = load_connection()? {
                state.connection = Some(connection);
            }
        }
        Ok(state.connection.clone())
    }

    pub fn bind_setup_run_for_authorized_client(
        &self,
        connection: LocalConnectionBinding,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state.connection = Some(connection);
        Ok(())
    }

    pub fn record_verification_result(
        &self,
        result: &SourceVerificationResult,
    ) -> Result<(), LocalApiError> {
        if matches!(
            result.status,
            SourceVerificationStatus::AccountNotConnected
                | SourceVerificationStatus::ReconnectRequired
        ) {
            return Ok(());
        }
        let mut state = self.state()?;
        let health = source_health_from_verification(&state, result);
        if let Some(existing) = state
            .sources
            .iter_mut()
            .find(|health| health.source == result.source)
        {
            *existing = health;
        } else {
            state.sources.push(health);
        }
        Ok(())
    }

    pub fn refresh_agent_status(
        &self,
        token: &str,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        self.control_token.authorize(token)?;
        self.refresh_agent_status_authorized(source, captured_at, expires_at)
    }

    pub fn refresh_agent_status_for_trusted_client(
        &self,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        self.refresh_agent_status_authorized(source, captured_at, expires_at)
    }

    fn refresh_agent_status_authorized(
        &self,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        let sources = match source {
            Some(source) => vec![source],
            None => vec![SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi],
        };
        let snapshots = sources
            .iter()
            .map(|source| {
                agent_status::collect_agent_status(source, captured_at.clone(), expires_at.clone())
            })
            .collect::<Vec<_>>();
        let mut state = self.state()?;
        for snapshot in snapshots.iter().cloned() {
            upsert_agent_status_snapshot(&mut state, snapshot);
        }
        Ok(snapshots)
    }

    pub fn set_relay_state(&self, token: &str, relay: RelayState) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        self.set_relay_state_authorized(relay)
    }

    pub fn set_relay_state_for_trusted_client(
        &self,
        relay: RelayState,
    ) -> Result<(), LocalApiError> {
        self.set_relay_state_authorized(relay)
    }

    fn set_relay_state_authorized(&self, relay: RelayState) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state.relay = relay;
        Ok(())
    }

    pub fn stop(&self, token: &str) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        self.stop_authorized()
    }

    pub fn stop_for_trusted_client(&self) -> Result<(), LocalApiError> {
        self.stop_authorized()
    }

    fn stop_authorized(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state.running = false;
        Ok(())
    }

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
        let state = self.state()?;
        let authority = repair_authority_for_state(&state);
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
                    title: "Verify fresh telemetry".to_string(),
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
        let version_mismatch = status.protocol_version != PROTOCOL_VERSION
            || status.daemon_version != env!("CARGO_PKG_VERSION");
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
            RedactedValue::String("unknown".to_string()),
        );
        versions.insert(
            "cli_version".to_string(),
            RedactedValue::String(env!("CARGO_PKG_VERSION").to_string()),
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
            ],
        })
    }

    fn state(&self) -> Result<MutexGuard<'_, DaemonState>, LocalApiError> {
        self.inner.lock().map_err(|_| LocalApiError::StatePoisoned)
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

fn status_from_state(state: &DaemonState) -> DaemonStatus {
    let mut status = empty_status(state.machine.clone(), current_rfc3339_timestamp());
    status.account = state.account.clone();
    status.daemon = if !state.running {
        DaemonRuntimeState::Unavailable
    } else if state.repair_locked {
        DaemonRuntimeState::RepairLocked
    } else {
        DaemonRuntimeState::Running
    };
    status.relay = state.relay.clone();
    status.sources = state.sources.clone();
    status
}

pub fn current_rfc3339_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn bound_user(account: &LocalAccountBinding) -> Option<&LocalAccountUser> {
    account.user.as_ref()
}

fn source_slug(source: &SourceKind) -> &'static str {
    match source {
        SourceKind::Codex => "codex",
        SourceKind::ClaudeCode => "claude_code",
        SourceKind::Pi => "pi",
    }
}

const CONNECTOR_REGISTRY_JSON: &str = include_str!(env!("OTTTO_CONNECTOR_REGISTRY_PATH"));

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorRegistry {
    schema_version: String,
    sources: Vec<RegistrySourceEntry>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySourceEntry {
    source_id: String,
    app_slug: String,
    display_name: String,
    publisher: String,
    review_tier: ConnectorReviewTier,
    maturity: ConnectorMaturity,
    operations: Vec<SourceOperation>,
    manifest_path: String,
    collectors: Vec<RegistryCollectorEntry>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryCollectorEntry {
    collector_id: String,
    display_name: String,
    operations: Vec<SourceOperation>,
    data_source_kind: CollectorDataSourceKind,
    default_state: CollectorDefaultState,
    review_tier: ConnectorReviewTier,
    maturity: ConnectorMaturity,
    risk_classes: Vec<CollectorRiskClass>,
    uploads_raw_content: bool,
    emits: Vec<String>,
    manifest_path: String,
}

fn connector_registry() -> &'static ConnectorRegistry {
    static REGISTRY: OnceLock<ConnectorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry: ConnectorRegistry = serde_json::from_str(CONNECTOR_REGISTRY_JSON)
            .expect("generated connector registry should match the local protocol");
        if registry.schema_version != "connector_registry.v1" {
            panic!(
                "unsupported generated connector registry schema version: {}",
                registry.schema_version
            );
        }
        registry
    })
}

fn registry_source(source: &SourceKind) -> &'static RegistrySourceEntry {
    let source_id = source_slug(source);
    connector_registry()
        .sources
        .iter()
        .find(|entry| entry.source_id == source_id)
        .unwrap_or_else(|| panic!("generated connector registry is missing source {source_id}"))
}

fn source_health_from_verification(
    state: &DaemonState,
    result: &SourceVerificationResult,
) -> SourceHealth {
    let user_id = state.account.user.as_ref().map(|user| user.id.clone());
    let agent_status = state
        .sources
        .iter()
        .find(|health| health.source == result.source)
        .and_then(|health| health.agent_status.clone());
    let config_has_drift = !result.config.drift.is_empty();
    let config_missing = !result.config.discovered
        || result
            .config
            .drift
            .iter()
            .any(|drift| drift.key.ends_with("config_file"));
    let patch_disabled = result.message.code == "patch_disabled";
    let (source_state, grade, problems) = if config_has_drift {
        (
            SourceState::NeedsRepair,
            HealthGrade::Warning,
            vec![HealthProblem {
                code: if config_missing {
                    StableProblemCode::ConfigMissing
                } else {
                    StableProblemCode::ConfigDrift
                },
                title: if config_missing {
                    format!(
                        "{} telemetry config is missing",
                        source_display_name(&result.source)
                    )
                } else {
                    format!(
                        "{} telemetry config drifted",
                        source_display_name(&result.source)
                    )
                },
                detail: result.message.text.clone(),
                retryable: true,
            }],
        )
    } else if patch_disabled {
        (SourceState::Healthy, HealthGrade::Ok, Vec::new())
    } else {
        match result.status {
            SourceVerificationStatus::Verified => {
                (SourceState::Healthy, HealthGrade::Ok, Vec::new())
            }
            SourceVerificationStatus::Warning => (
                SourceState::Healthy,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "Some route checks need review".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
            SourceVerificationStatus::NoFreshTelemetry => (
                SourceState::NeedsConfirmation,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "No recent telemetry found".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
            SourceVerificationStatus::AccountNotConnected
            | SourceVerificationStatus::ReconnectRequired
            | SourceVerificationStatus::Failed => (
                SourceState::Failed,
                HealthGrade::Critical,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "Verification could not complete".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
        }
    };
    let recommended_actions = if config_has_drift {
        let authority = repair_authority_for_state(state);
        vec![RepairAction {
            action: RepairActionKind::WriteConfig,
            title: format!(
                "Repair {} telemetry config",
                source_display_name(&result.source)
            ),
            detail: result.message.text.clone(),
            requires_approval: true,
            destructive: false,
            approval: setup_safe_repair_approval(&authority),
            backup: Some(config_backup_metadata(
                &result.source,
                false,
                None,
                result.config.fingerprint.clone(),
            )),
        }]
    } else if result.verified || patch_disabled {
        Vec::new()
    } else {
        vec![RepairAction {
            action: RepairActionKind::VerifyTelemetry,
            title: format!("Retry {} verification", source_display_name(&result.source)),
            detail: result.message.text.clone(),
            requires_approval: false,
            destructive: false,
            approval: no_repair_approval(
                true,
                false,
                "Retrying verification does not change local configuration.",
            ),
            backup: None,
        }]
    };

    let detected_uses = detected_uses_for_health(&result.source, agent_status.as_ref());
    SourceHealth {
        source: result.source.clone(),
        descriptor: source_descriptor(&result.source),
        state: source_state,
        grade,
        account_binding: AccountBindingState {
            expected_account_id: user_id.clone(),
            observed_account_id: user_id,
            matched: Some(state.account.state == LocalAccountState::Connected),
        },
        config: result.config.clone(),
        collector: None,
        agent_status,
        plan_observations: Vec::new(),
        detected_uses,
        last_seen_at: result.last_received_at.clone(),
        last_verified_at: if result.verified {
            result.last_received_at.clone()
        } else {
            None
        },
        problems,
        recommended_actions,
    }
}

fn upsert_agent_status_snapshot(state: &mut DaemonState, snapshot: AgentStatusSnapshot) {
    if let Some(existing) = state
        .sources
        .iter_mut()
        .find(|health| health.source == snapshot.source)
    {
        existing.agent_status = Some(snapshot.clone());
        existing.last_seen_at = Some(snapshot.captured_at.clone());
        if matches!(snapshot.status, AgentStatusState::Available) {
            existing.last_verified_at = Some(snapshot.captured_at.clone());
        }
        return;
    }
    let health = source_health_from_agent_status(state, snapshot);
    state.sources.push(health);
}

fn source_health_from_agent_status(
    state: &DaemonState,
    snapshot: AgentStatusSnapshot,
) -> SourceHealth {
    let observed_account_id = snapshot
        .account
        .as_ref()
        .and_then(|account| account.account_id.clone().or_else(|| account.email.clone()));
    let expected_account_id = state.account.user.as_ref().map(|user| user.id.clone());
    let (source_state, grade, problems) = match snapshot.status {
        AgentStatusState::Available => (SourceState::Healthy, HealthGrade::Ok, Vec::new()),
        AgentStatusState::NotInstalled => (
            SourceState::NotFound,
            HealthGrade::Unknown,
            vec![HealthProblem {
                code: StableProblemCode::SourceNotInstalled,
                title: format!("{} is not installed", source_display_name(&snapshot.source)),
                detail: "The local CLI or safe metadata was not found on this machine.".to_string(),
                retryable: false,
            }],
        ),
        AgentStatusState::Unsupported => (
            SourceState::Unsupported,
            HealthGrade::Unknown,
            vec![HealthProblem {
                code: StableProblemCode::UnsupportedPlatform,
                title: format!(
                    "{} status is unsupported",
                    source_display_name(&snapshot.source)
                ),
                detail: "This source does not expose richer local account or limit status yet."
                    .to_string(),
                retryable: false,
            }],
        ),
        AgentStatusState::AuthRequired | AgentStatusState::Degraded | AgentStatusState::Unknown => {
            (
                SourceState::NeedsConfirmation,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::SecretMissing,
                    title: format!(
                        "{} needs account confirmation",
                        source_display_name(&snapshot.source)
                    ),
                    detail:
                        "Ottto could not confirm a signed-in local account from safe CLI metadata."
                            .to_string(),
                    retryable: true,
                }],
            )
        }
        AgentStatusState::Error => (
            SourceState::Failed,
            HealthGrade::Critical,
            vec![HealthProblem {
                code: StableProblemCode::Unknown,
                title: format!(
                    "{} status collection failed",
                    source_display_name(&snapshot.source)
                ),
                detail: "Local status collection failed without exposing raw command output."
                    .to_string(),
                retryable: true,
            }],
        ),
    };
    let detected_uses = detected_uses_for_health(&snapshot.source, Some(&snapshot));
    SourceHealth {
        source: snapshot.source.clone(),
        descriptor: source_descriptor(&snapshot.source),
        state: source_state,
        grade,
        account_binding: AccountBindingState {
            expected_account_id,
            observed_account_id,
            matched: None,
        },
        config: SourceConfigState {
            discovered: !matches!(snapshot.status, AgentStatusState::NotInstalled),
            path_hint: None,
            fingerprint: None,
            drift: Vec::new(),
        },
        collector: None,
        agent_status: Some(snapshot.clone()),
        plan_observations: snapshot.plan_observations.clone(),
        detected_uses,
        last_seen_at: Some(snapshot.captured_at.clone()),
        last_verified_at: if matches!(snapshot.status, AgentStatusState::Available) {
            Some(snapshot.captured_at)
        } else {
            None
        },
        problems,
        recommended_actions: Vec::new(),
    }
}

/// Per-source detected-uses cache file:
/// `<support_dir>/detected_uses/<source slug>.json`. Written by `snapshot_sync`
/// after each scan, read here to attach to health.
fn detected_uses_cache_path(support_dir: &Path, source: &SourceKind) -> PathBuf {
    support_dir
        .join("detected_uses")
        .join(format!("{}.json", source_slug(source)))
}

/// Load the persisted detected uses for a source. A missing or unreadable cache
/// yields an empty list (graceful empty — the panel shows nothing rather than
/// erroring), as does a malformed file.
fn load_detected_uses_for_source(source: &SourceKind) -> Vec<DetectedUse> {
    let path = detected_uses_cache_path(&default_support_dir(), source);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Vec<DetectedUse>>(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Detected uses for a source's health, with live quota overlaid onto the
/// destination matching the current account's plan when `agent_status` carries
/// quota windows. Historical destinations keep `Unknown`/`None` quota.
fn detected_uses_for_health(
    source: &SourceKind,
    agent_status: Option<&AgentStatusSnapshot>,
) -> Vec<DetectedUse> {
    let mut detected = load_detected_uses_for_source(source);
    if let Some(snapshot) = agent_status {
        merge_current_plan_quota(&mut detected, snapshot);
    }
    detected
}

/// Overlay the current plan's live quota onto the detected use whose
/// `subscription_product` matches the account's plan. Other destinations are
/// left at `Unknown`/`None`: smearing the current plan's quota across
/// destinations it does not bill to would be misleading.
fn merge_current_plan_quota(detected: &mut [DetectedUse], snapshot: &AgentStatusSnapshot) {
    let Some(account) = snapshot.account.as_ref() else {
        return;
    };
    let plan_keys: Vec<String> = [
        account.plan_type.as_deref(),
        account.subscription_product.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(|value| value.trim().to_ascii_lowercase())
    .filter(|value| !value.is_empty())
    .collect();
    if plan_keys.is_empty() {
        return;
    }
    let Some(window) = pick_quota_window(&snapshot.quota_windows) else {
        return;
    };
    let (state, used_percent, resets_at) = quota_state_from_window(window);
    for entry in detected.iter_mut() {
        let matches_current = entry
            .subscription_product
            .as_deref()
            .map(|product| plan_keys.contains(&product.trim().to_ascii_lowercase()))
            .unwrap_or(false);
        if matches_current {
            entry.quota_window_state = state.clone();
            entry.quota_used_percent = used_percent;
            entry.quota_resets_at = resets_at.clone();
        }
    }
}

/// Pick the most constraining quota window: a rate-limited window first, then
/// the highest used-percent. `None` when there are no windows.
fn pick_quota_window(windows: &[AgentQuotaWindow]) -> Option<&AgentQuotaWindow> {
    windows.iter().max_by_key(|window| {
        let rate_limited = matches!(window.status, AgentQuotaWindowStatus::RateLimited);
        (rate_limited, window.used_percent.unwrap_or(0))
    })
}

/// Map a quota window to the Companion's detected-use quota state. A
/// rate-limited or stale window maps directly; otherwise used-percent decides:
/// `>= 100` exhausted, `>= 80` near limit, else ok. A window with no percent is
/// `Unknown`.
fn quota_state_from_window(
    window: &AgentQuotaWindow,
) -> (DetectedUseQuotaWindowState, Option<u8>, Option<String>) {
    let stale = matches!(window.freshness, AgentQuotaWindowFreshness::Stale)
        || matches!(window.status, AgentQuotaWindowStatus::Stale);
    let state = if matches!(window.status, AgentQuotaWindowStatus::RateLimited) {
        DetectedUseQuotaWindowState::RateLimited
    } else if stale {
        DetectedUseQuotaWindowState::Stale
    } else {
        match window.used_percent {
            Some(percent) if percent >= 100 => DetectedUseQuotaWindowState::Exhausted,
            Some(percent) if percent >= 80 => DetectedUseQuotaWindowState::NearLimit,
            Some(_) => DetectedUseQuotaWindowState::Ok,
            None => DetectedUseQuotaWindowState::Unknown,
        }
    };
    (state, window.used_percent, window.resets_at.clone())
}

fn source_descriptor(source: &SourceKind) -> SourceDescriptor {
    let registry_source = registry_source(source);
    require_local_source_operations(registry_source);
    let mut operations: Vec<SourceOperationDescriptor> = registry_source
        .operations
        .iter()
        .cloned()
        .map(source_operation)
        .collect();
    if !registry_source
        .operations
        .contains(&SourceOperation::UninstallRestore)
    {
        operations.push(source_operation(SourceOperation::UninstallRestore));
    }

    SourceDescriptor {
        source: source.clone(),
        display_name: registry_source.display_name.clone(),
        operations,
        review_tier: registry_source.review_tier.clone(),
        maturity: registry_source.maturity.clone(),
        collectors: registry_source
            .collectors
            .iter()
            .map(collector_descriptor)
            .collect(),
        local_state_owner: SourceStateOwner::LocalDaemon,
        telemetry_owner: SourceStateOwner::LocalDaemon,
        repair_owner: SourceStateOwner::LocalDaemon,
    }
}

fn require_local_source_operations(source: &RegistrySourceEntry) {
    for operation in [
        SourceOperation::Detect,
        SourceOperation::Verify,
        SourceOperation::Repair,
        SourceOperation::CollectUsage,
        SourceOperation::MonitorQuota,
        SourceOperation::UploadSnapshot,
        SourceOperation::Diagnostics,
    ] {
        if !source.operations.contains(&operation) {
            panic!(
                "generated connector registry source {} is missing required local operation {:?}",
                source.source_id, operation
            );
        }
    }
}

fn collector_descriptor(collector: &RegistryCollectorEntry) -> CollectorDescriptor {
    CollectorDescriptor {
        collector_id: collector.collector_id.clone(),
        display_name: collector.display_name.clone(),
        operations: collector.operations.clone(),
        data_source_kind: collector.data_source_kind.clone(),
        default_state: collector.default_state.clone(),
        review_tier: collector.review_tier.clone(),
        maturity: collector.maturity.clone(),
        risk_classes: collector.risk_classes.clone(),
        uploads_raw_content: collector.uploads_raw_content,
        emits: collector.emits.clone(),
    }
}

fn source_operation(operation: SourceOperation) -> SourceOperationDescriptor {
    let requires_approval = matches!(
        &operation,
        SourceOperation::Repair | SourceOperation::UninstallRestore
    );
    let reason = match &operation {
        SourceOperation::MonitorQuota => {
            Some("Quota windows are display-only plan facts and never imply spend.".to_string())
        }
        SourceOperation::UninstallRestore => Some(
            "Restore uses daemon-owned backups and avoids revoke, delete, or disconnect actions."
                .to_string(),
        ),
        _ => None,
    };

    SourceOperationDescriptor {
        operation,
        supported: true,
        state: SourceOperationState::Available,
        requires_approval,
        destructive: false,
        reason,
    }
}

fn config_backup_metadata(
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

fn repair_authority_for_state(state: &DaemonState) -> RepairAuthority {
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
                text: "This Mac has no active Ottto setup-run binding. Open ottto.net/apps in your browser to reconnect before approving repair actions."
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

fn setup_safe_repair_approval(authority: &RepairAuthority) -> RepairActionApproval {
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

fn no_repair_approval(setup_safe: bool, server_backed: bool, reason: &str) -> RepairActionApproval {
    RepairActionApproval {
        surface: RepairApprovalSurface::None,
        setup_safe,
        server_backed,
        reason: reason.to_string(),
    }
}

fn source_display_name(source: &SourceKind) -> String {
    registry_source(source).display_name.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{
        AccountBindingState, HealthGrade, LocalAccountOrganization, OperatingSystem,
        SourceConfigState, SourceState,
    };

    const TOKEN: &str = "local_control_token";

    #[test]
    fn rejects_empty_control_token() {
        assert_eq!(ControlToken::new(""), Err(LocalApiError::EmptyControlToken));
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
    fn status_reports_running_daemon() {
        let daemon = daemon();
        let status = daemon.status(TOKEN).expect("status should succeed");
        assert_eq!(status.daemon, DaemonRuntimeState::Running);
        assert_eq!(status.machine.machine_id, "machine_test");
    }

    #[test]
    fn source_descriptor_is_registry_backed() {
        let descriptor = source_descriptor(&SourceKind::Codex);

        assert_eq!(descriptor.display_name, "Codex");
        assert_eq!(descriptor.review_tier, ConnectorReviewTier::Official);
        assert_eq!(descriptor.maturity, ConnectorMaturity::Stable);
        assert_eq!(
            descriptor
                .collectors
                .iter()
                .map(|collector| collector.collector_id.as_str())
                .collect::<Vec<_>>(),
            vec!["local_sessions", "otel_config", "quota_status"]
        );
    }

    #[test]
    fn pi_descriptor_preserves_registry_usage_operations() {
        let descriptor = source_descriptor(&SourceKind::Pi);

        for operation in [
            SourceOperation::CollectUsage,
            SourceOperation::UploadSnapshot,
            SourceOperation::MonitorQuota,
        ] {
            let descriptor_operation = descriptor
                .operations
                .iter()
                .find(|candidate| candidate.operation == operation)
                .expect("registry operation should be exposed");
            assert!(descriptor_operation.supported);
            assert_eq!(descriptor_operation.state, SourceOperationState::Available);
        }
        assert_eq!(descriptor.maturity, ConnectorMaturity::Beta);
    }

    #[test]
    fn status_generated_at_uses_response_time() {
        let daemon = daemon();
        let status = daemon.status(TOKEN).expect("status should succeed");

        assert_ne!(status.generated_at, "2026-05-05T09:10:00Z");
        assert!(OffsetDateTime::parse(&status.generated_at, &Rfc3339).is_ok());
    }

    #[test]
    fn stop_marks_daemon_unavailable() {
        let daemon = daemon();
        daemon.stop(TOKEN).expect("stop should succeed");
        let status = daemon.status(TOKEN).expect("status should succeed");
        assert_eq!(status.daemon, DaemonRuntimeState::Unavailable);
    }

    #[test]
    fn relay_state_is_daemon_owned() {
        let daemon = daemon();
        daemon
            .set_relay_state(
                TOKEN,
                RelayState {
                    state: RelayRuntimeState::Connected,
                    endpoint: Some("https://relay.ottto.net/v1/local".to_string()),
                    last_connected_at: Some("2026-05-05T09:10:00Z".to_string()),
                    last_error: None,
                },
            )
            .expect("relay state should update");

        assert_eq!(
            daemon
                .status(TOKEN)
                .expect("status should succeed")
                .relay
                .state,
            RelayRuntimeState::Connected
        );
    }

    #[test]
    fn source_health_is_daemon_owned() {
        let daemon = daemon();
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");

        let status = daemon.status(TOKEN).expect("status should succeed");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
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
    fn repair_plan_uses_daemon_lock_and_releases_it() {
        let daemon = daemon();
        let plan = daemon
            .propose_repair(TOKEN, SourceKind::Codex, true)
            .expect("repair plan should be proposed");

        assert_eq!(plan.source, SourceKind::Codex);
        assert!(plan.dry_run);
        assert_eq!(plan.status, RepairPlanStatus::Proposed);
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
    fn diagnostics_stub_does_not_expose_auth() {
        let daemon = daemon();
        let bundle = daemon
            .diagnostics_stub(TOKEN)
            .expect("diagnostics should succeed");
        let encoded = serde_json::to_string(&bundle).expect("diagnostics serialize");

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
    fn verification_result_updates_source_health() {
        let daemon = daemon();
        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
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
                text: "Saw 2 recent Codex telemetry records.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record verification");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert_eq!(
            status.sources[0].last_verified_at.as_deref(),
            Some("2026-05-05T10:15:00Z")
        );
    }

    #[test]
    fn reconnect_required_verification_preserves_source_health() {
        let daemon = daemon();
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");
        let result = SourceVerificationResult {
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
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "setup_run_token_invalid".to_string(),
                text: "Open ottto.net/apps in your browser to refresh it.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record reconnect result");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
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
                email: None,
                account_id: None,
                organization_id: None,
                organization_label: None,
                plan_type: Some("pro".to_string()),
                subscription_product: Some("pro".to_string()),
                billing_channel: None,
                account_identifier_hash: None,
                organization_identifier_hash: None,
                credential_fingerprint_hash: None,
                billing_identity_evidence: None,
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
                    model: None,
                    account_label: None,
                    window_seconds: Some(604_800),
                    started_at: None,
                    resets_at: Some("2026-06-01T00:00:00Z".to_string()),
                    quota: None,
                    remaining: None,
                    used_percent: Some(16),
                    left_percent: Some(84),
                },
                AgentQuotaWindow {
                    name: "primary".to_string(),
                    scope: AgentQuotaWindowScope::Account,
                    status: AgentQuotaWindowStatus::NearLimit,
                    freshness: AgentQuotaWindowFreshness::Fresh,
                    model: None,
                    account_label: None,
                    window_seconds: Some(18_000),
                    started_at: None,
                    resets_at: Some("2026-05-28T15:00:00Z".to_string()),
                    quota: None,
                    remaining: None,
                    used_percent: Some(92),
                    left_percent: Some(8),
                },
            ],
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
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
            last_seen_at: Some("2026-05-05T09:09:00Z".to_string()),
            last_verified_at: Some("2026-05-05T09:09:30Z".to_string()),
            problems: Vec::new(),
            recommended_actions: Vec::new(),
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
                display_name: Some("Ron".to_string()),
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
        }
    }

    fn connection(setup_run_id: &str) -> LocalConnectionBinding {
        LocalConnectionBinding {
            setup_run_id: setup_run_id.to_string(),
            setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
            machine_id: Some("machine_test".to_string()),
            api_base_url: "https://api.ottto.net".to_string(),
        }
    }
}
