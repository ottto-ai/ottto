pub mod adaptive_collector;
pub mod agent_configs;
pub mod agent_status;
pub mod backfill;
pub(crate) mod command_env;
pub mod context_footprint;
pub mod control;
pub mod detected_uses;
pub mod keychain;
pub mod macos_service;
pub mod mcp_inventory;
pub mod otlp_relay;
pub mod snapshot_client;
pub mod snapshot_sync;
pub mod snapshot_watcher;
pub mod snapshots;
#[cfg(unix)]
pub mod unix_socket;
pub mod xpc_mach;

use crate::detected_uses::{prune_stale_detected_uses, DETECTED_USE_RETENTION_DAYS};
use ottto_core::{
    compiled_release_version, default_connection_api_base_url, default_support_dir, empty_status,
    launch_agent_path, launchd_target, local_lifecycle_home_dir, source_state_file_name,
    FileConnectionStore, FileSourceStateStore, LocalConnectionBinding, LocalDeviceBinding,
    LocalSourceState, RedactionPolicy, OTTTO_KEYCHAIN_ACCOUNT, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
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
    DiagnosticsUploadStatus, EventStatus, HealthGrade, HealthProblem, InstallOwner,
    LocalAccountBinding, LocalAccountState, LocalAccountUser, LocalDeviceState,
    LocalHealthAccountState, LocalHealthAccountV1, LocalHealthAuthority, LocalHealthBlockerV1,
    LocalHealthCommandResultV1, LocalHealthCommandStatus, LocalHealthEventV1,
    LocalHealthEvidenceRefV1, LocalHealthOverall, LocalHealthOverallState, LocalHealthSeverity,
    LocalHealthSourceState, LocalHealthSourceV1, LocalMachineHealthV1, LocalSetupRunState,
    LocalSetupTokenState, MachineIdentity, MachineRuntimeHeartbeatV1, OrgTelemetryControlState,
    PersonalMeterLocalAccount, PersonalMeterLocalCollector, PersonalMeterLocalCollectorStatus,
    PersonalMeterLocalDelta, PersonalMeterLocalFreshness, PersonalMeterLocalFreshnessStatus,
    PersonalMeterLocalSnapshot, PersonalMeterLocalSourceSnapshot, PersonalMeterLocalValueStatus,
    RedactedValue, RedactionCategory, RedactionReport, RedactionSurface, RelayRuntimeState,
    RelayState, RepairAction, RepairActionApproval, RepairActionKind, RepairApprovalSurface,
    RepairAuthority, RepairAuthorityMode, RepairBackupMetadata, RepairBackupScope, RepairPlan,
    RepairPlanStatus, RuntimeIdentityV1, SourceConfigState, SourceDescriptor, SourceHealth,
    SourceKind, SourceOperation, SourceOperationDescriptor, SourceOperationState, SourceState,
    SourceStateOwner, SourceVerificationResult, SourceVerificationStatus, StableMessage,
    StableProblemCode, DIAGNOSTICS_RETENTION_DISCLOSURE, PROTOCOL_VERSION,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const USAGE_LIMITED_MESSAGE_CODE: &str = "usage_limited";
const SMOKE_QUOTA_LIMITED_MESSAGE_CODE: &str = "smoke_quota_limited";
const PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE: &str = "pi_route_smoke_failed";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalHealthUploadFailureKind {
    AuthRejected,
    BackendUnreachable,
    ContractRejected,
}

#[derive(Debug, Clone)]
struct DaemonState {
    machine: MachineIdentity,
    relay: RelayState,
    sources: Vec<SourceHealth>,
    /// Real per-source first-seen timestamps, keyed by source slug. Boot-loaded
    /// from `<source_state_dir>/<slug>-state.json` and stamped on first
    /// observation; drives `SourceHealth.connected_at`.
    source_first_seen: BTreeMap<String, String>,
    /// Most recent `local_usage_reconciliation_enabled` per source slug,
    /// recorded by the snapshot-sync loop; drives
    /// `SourceHealth.reconciliation_enabled`. In-memory only (cleared on reset
    /// and restart), which the Companion tolerates as "managed by workspace".
    source_reconciliation: BTreeMap<String, bool>,
    /// Directory for the persisted per-source state files. `None` keeps
    /// source state purely in-memory (tests); production sets it via
    /// `with_source_state_dir(default_sources_dir())`.
    source_state_dir: Option<PathBuf>,
    local_health_events: Vec<LocalHealthEventV1>,
    command_ledger: Vec<LocalHealthCommandResultV1>,
    account: LocalAccountBinding,
    connection: Option<LocalConnectionBinding>,
    pending_auth: Option<PendingAuthClaim>,
    repair_locked: bool,
    running: bool,
    now: String,
}

impl DaemonState {
    fn first_seen(&self, source: &SourceKind) -> Option<String> {
        self.source_first_seen.get(source_slug(source)).cloned()
    }

    fn reconciliation_enabled(&self, source: &SourceKind) -> Option<bool> {
        self.source_reconciliation.get(source_slug(source)).copied()
    }

    /// Record the first time `source` is observed. A no-op once known, so the
    /// persisted original timestamp wins after a restart rather than being
    /// overwritten by a later re-observation. Persists to disk when a
    /// source-state dir is configured.
    fn stamp_first_seen(&mut self, source: &SourceKind, observed_at: Option<&str>) {
        let Some(observed_at) = observed_at else {
            return; // No honest timestamp to stamp yet.
        };
        let slug = source_slug(source);
        if self.source_first_seen.contains_key(slug) {
            return;
        }
        self.source_first_seen
            .insert(slug.to_string(), observed_at.to_string());
        self.persist_source_state(source);
    }

    fn persist_source_state(&self, source: &SourceKind) {
        let slug = source_slug(source);
        if let Some(dir) = self.source_state_dir.as_ref() {
            let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
            let last_health = self
                .sources
                .iter()
                .find(|health| health.source == *source)
                .cloned();
            if let Err(error) = store.save(&LocalSourceState {
                first_seen_at: self.first_seen(source),
                last_health,
            }) {
                eprintln!("failed to persist source state for {slug}: {error}");
            }
        }
    }

    /// Clear the in-memory first-seen + reconciliation maps and delete the
    /// persisted per-source state files. Called at the account reset sites so a
    /// fresh account starts with a fresh source history.
    fn clear_source_state(&mut self) {
        if let Some(dir) = self.source_state_dir.as_ref() {
            for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
                let slug = source_slug(&source);
                let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
                if let Err(error) = store.reset() {
                    eprintln!("failed to clear first-seen for {slug}: {error}");
                }
            }
        }
        self.source_first_seen.clear();
        self.source_reconciliation.clear();
    }
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
                source_first_seen: BTreeMap::new(),
                source_reconciliation: BTreeMap::new(),
                source_state_dir: None,
                local_health_events: Vec::new(),
                command_ledger: Vec::new(),
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

    /// Seed known registered sources from the persisted relay-device binding so
    /// a freshly restarted daemon never reports a connected account with zero
    /// sources while the slower agent scan is still pending. These rows are
    /// intentionally `verifying` and carry no agent snapshot; a real scan or
    /// verification result replaces them with authoritative health.
    pub fn with_registered_device_sources(self, device: Option<LocalDeviceBinding>) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            seed_registered_sources(&mut state, device.as_ref());
        }
        self
    }

    /// Enable persistence of per-source state under `dir`
    /// (`<dir>/<slug>-state.json`) and boot-load any existing files into the
    /// in-memory map/source rows. Production passes `default_sources_dir()`;
    /// constructors that omit this keep source state purely in-memory.
    pub fn with_source_state_dir(self, dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if let Ok(mut state) = self.inner.lock() {
            state.source_first_seen = load_source_first_seen(&dir);
            state.sources = load_source_health(&state, &dir);
            state.source_state_dir = Some(dir);
        }
        self
    }

    /// Record the most recent reconciliation policy for a source, learned by
    /// the snapshot-sync loop's activity hint. This is an internal,
    /// trusted-process call (no control token), mirroring how the local OTLP
    /// relay updates daemon state. Best-effort: a poisoned lock is ignored.
    pub fn record_reconciliation_enabled(
        &self,
        source: SourceKind,
        enabled: bool,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        state
            .source_reconciliation
            .insert(source_slug(&source).to_string(), enabled);
        Ok(())
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

    /// This machine's identity, for the local loopback `/whoami` probe. Exposes
    /// only non-sensitive identity (callers must not leak `hardware_uuid`).
    pub fn machine_for_trusted_client(&self) -> Result<MachineIdentity, LocalApiError> {
        let state = self.state()?;
        Ok(state.machine.clone())
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

    pub fn pending_auth_claim_for_resume(
        &self,
        claim_code: &str,
    ) -> Result<PendingAuthClaim, LocalApiError> {
        let state = self.state()?;
        let Some(claim) = &state.pending_auth else {
            return Err(LocalApiError::NoPendingAuthClaim);
        };
        if claim.claim_code != claim_code {
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
            claim_code: Some(claim_code.to_string()),
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

    pub fn completed_auth_claim_for_resume(
        &self,
        claim_code: &str,
    ) -> Result<Option<AuthCompleteResponse>, LocalApiError> {
        let state = self.state()?;
        let Some(connection) = &state.connection else {
            return Ok(None);
        };
        if connection.claim_code.as_deref() != Some(claim_code) {
            return Ok(None);
        }
        if state.account.state != LocalAccountState::Connected {
            return Ok(None);
        }
        Ok(Some(AuthCompleteResponse {
            account: state.account.clone(),
            setup_run_id: connection.setup_run_id.clone(),
            setup_run_token_expires_at: connection.setup_run_token_expires_at.clone(),
            machine_id: connection.machine_id.clone(),
        }))
    }

    pub fn clear_recoverable_pending_auth_for_authorized_client(
        &self,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if state.account.state != LocalAccountState::ClaimPending {
            return Ok(());
        }
        if state.connection.is_none() || state.account.user.is_none() {
            return Ok(());
        }
        state.pending_auth = None;
        state.account.state = LocalAccountState::Connected;
        state.account.last_refreshed_at = Some(state.now.clone());
        state.account.message = None;
        Ok(())
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
        state.clear_source_state();
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
        mut sources: Vec<SourceHealth>,
    ) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        let mut state = self.state()?;
        for refreshed in &mut sources {
            if let Some(existing) = state
                .sources
                .iter()
                .find(|health| health.source == refreshed.source)
            {
                preserve_blocking_verification_state(refreshed, existing);
            }
        }
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

    pub fn clear_setup_run_for_authorized_client_if_matches(
        &self,
        setup_run_id: &str,
        api_base_url: &str,
    ) -> Result<bool, LocalApiError> {
        let mut state = self.state()?;
        let Some(connection) = state.connection.as_ref() else {
            return Ok(false);
        };
        if connection.setup_run_id != setup_run_id || connection.api_base_url != api_base_url {
            return Ok(false);
        }
        state.connection = None;
        Ok(true)
    }

    pub fn record_verification_result(
        &self,
        result: &SourceVerificationResult,
    ) -> Result<(), LocalApiError> {
        if matches!(result.status, SourceVerificationStatus::AccountNotConnected) {
            return Ok(());
        }
        let mut state = self.state()?;
        let observed_at = current_rfc3339_timestamp();
        state.stamp_first_seen(&result.source, result.last_received_at.as_deref());
        let health = source_health_from_verification(&state, result, &observed_at);
        if let Some(existing) = state
            .sources
            .iter_mut()
            .find(|health| health.source == result.source)
        {
            *existing = health;
        } else {
            state.sources.push(health);
        }
        state.persist_source_state(&result.source);
        let sequence = next_local_health_sequence(&state);
        let machine_id = state.machine.machine_id.clone();
        let source_slug = source_slug(&result.source);
        let action_id = format!("verify_{source_slug}");
        let records_success = verification_result_records_success(result);
        state.local_health_events.push(LocalHealthEventV1 {
            event_id: format!("evt_verify_{source_slug}_{sequence}"),
            event_schema_version: "local_health_event.v1".to_string(),
            event_type: if records_success {
                "VerifyPassed".to_string()
            } else {
                "VerifyFailed".to_string()
            },
            machine_id: machine_id.clone(),
            observed_at: observed_at.clone(),
            sequence,
            authority: LocalHealthAuthority::Verify,
            source_id: Some(format!("src_{source_slug}")),
            action_id: Some(action_id.clone()),
            payload: serde_json::json!({
                "status": result.status,
                "records_seen": result.records_seen,
                "current": true
            }),
        });
        state.command_ledger.push(LocalHealthCommandResultV1 {
            action_id,
            idempotency_key: format!("verify:{machine_id}:{source_slug}"),
            command_schema_version: "local_command.v1".to_string(),
            status: if records_success {
                LocalHealthCommandStatus::Succeeded
            } else {
                LocalHealthCommandStatus::Failed
            },
            terminal: true,
            started_projection_revision: sequence.saturating_sub(1),
            completed_projection_revision: sequence,
            observed_at,
            error_code: if records_success {
                None
            } else {
                Some(result.message.code.clone())
            },
            message: Some(result.message.text.clone()),
            result: serde_json::json!({
                "source": result.source,
                "status": result.status,
                "verified": result.verified
            }),
        });
        Ok(())
    }

    pub fn record_config_repair_result(
        &self,
        source: &SourceKind,
        config: SourceConfigState,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let Some(existing) = state
            .sources
            .iter_mut()
            .find(|health| &health.source == source)
        else {
            return Ok(());
        };

        existing.config = config;
        if existing.config.drift.is_empty() {
            existing.problems.retain(|problem| {
                !matches!(
                    problem.code,
                    StableProblemCode::ConfigMissing | StableProblemCode::ConfigDrift
                )
            });
            existing
                .recommended_actions
                .retain(|action| action.action != RepairActionKind::WriteConfig);
            if existing.state == SourceState::NeedsRepair && existing.problems.is_empty() {
                existing.state = SourceState::Healthy;
                existing.grade = HealthGrade::Ok;
            }
        }
        state.persist_source_state(source);
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

    /// Reconfirm any sources still in the seeded post-restart `verifying` state
    /// (see [`Self::with_registered_device_sources`]) by running the same
    /// agent-status scan an on-demand refresh runs, promoting each to its real
    /// health. Trusted, internal call (no control token) used by the startup
    /// re-verify burst, mirroring how the snapshot-sync loop updates daemon
    /// state without a token.
    ///
    /// Deliberately conservative: a seeded row is only replaced when the scan
    /// finds the source `Available` (-> healthy). A weaker scan result right
    /// after boot is far more likely a cold-CLI transient than a real
    /// regression, so the neutral `verifying` row is left in place rather than
    /// flash a spurious attention state — a later scan, an explicit Verify, or a
    /// fresh session resolves a genuine problem. The write also re-checks that
    /// each source is still `verifying`, so a concurrent Verify/refresh result
    /// is never clobbered. Returns the number of sources still `verifying`
    /// afterward so the startup burst can stop once everything has reconfirmed.
    pub fn reconfirm_verifying_sources_for_trusted_client(
        &self,
        captured_at: String,
        expires_at: String,
    ) -> Result<usize, LocalApiError> {
        let verifying = {
            let state = self.state()?;
            if state.account.state != LocalAccountState::Connected {
                return Ok(0);
            }
            verifying_source_kinds(&state)
        };
        if verifying.is_empty() {
            return Ok(0);
        }
        let snapshots = verifying
            .iter()
            .map(|source| {
                agent_status::collect_agent_status(source, captured_at.clone(), expires_at.clone())
            })
            .collect::<Vec<_>>();
        let mut state = self.state()?;
        Ok(apply_verifying_reconfirm(&mut state, snapshots))
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

    pub fn record_local_health_upload_succeeded(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        push_local_health_upload_event(
            &mut state,
            "LocalHealthUploadSucceeded",
            "ok",
            "canonical local health uploaded to Ottto",
        );
        Ok(())
    }

    pub fn record_local_health_upload_failed(
        &self,
        kind: LocalHealthUploadFailureKind,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let (kind, message) = match kind {
            LocalHealthUploadFailureKind::AuthRejected => (
                "auth_rejected",
                "Ottto rejected this Mac's relay device credentials",
            ),
            LocalHealthUploadFailureKind::BackendUnreachable => (
                "backend_unreachable",
                "Ottto could not be reached while uploading local health",
            ),
            LocalHealthUploadFailureKind::ContractRejected => (
                "contract_rejected",
                "Ottto rejected this daemon's local health projection contract",
            ),
        };
        push_local_health_upload_event(&mut state, "LocalHealthUploadFailed", kind, message);
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
            RedactedValue::String("unknown".to_string()),
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
    status.local_health_events = state.local_health_events.clone();
    status.command_ledger = state.command_ledger.clone();
    refresh_canonical_local_health(&mut status);
    status
}

fn push_local_health_upload_event(
    state: &mut DaemonState,
    event_type: &str,
    kind: &str,
    message: &str,
) {
    let sequence = next_local_health_sequence(state);
    let observed_at = current_rfc3339_timestamp();
    state.local_health_events.push(LocalHealthEventV1 {
        event_id: format!("evt_local_health_upload_{kind}_{sequence}"),
        event_schema_version: "local_health_event.v1".to_string(),
        event_type: event_type.to_string(),
        machine_id: state.machine.machine_id.clone(),
        observed_at,
        sequence,
        authority: LocalHealthAuthority::Backend,
        source_id: None,
        action_id: None,
        payload: serde_json::json!({
            "kind": kind,
            "message": message,
            "current": true
        }),
    });
}

pub fn refresh_canonical_local_health(status: &mut DaemonStatus) {
    let observed_at = status.generated_at.clone();
    let projection_revision = next_status_projection_revision(status);
    let runtime_event = LocalHealthEventV1 {
        event_id: format!("evt_runtime_observed_{projection_revision}"),
        event_schema_version: "local_health_event.v1".to_string(),
        event_type: "MachineRuntimeObserved".to_string(),
        machine_id: status.machine.machine_id.clone(),
        observed_at: observed_at.clone(),
        sequence: projection_revision,
        authority: LocalHealthAuthority::Runtime,
        source_id: None,
        action_id: None,
        payload: serde_json::json!({
            "daemon_state": status.daemon,
            "service_owner": status.service_owner,
        }),
    };
    let mut events = status.local_health_events.clone();
    events.push(runtime_event.clone());
    let runtime = runtime_identity_for_status(status, &observed_at);
    let heartbeat = runtime_heartbeat_for_status(status, &runtime, projection_revision);
    let account = local_health_account_for_status(status);
    let mut sources = status
        .sources
        .iter()
        .map(|source| local_health_source_for_status(source, projection_revision))
        .collect::<Vec<_>>();
    apply_account_prerequisite_to_sources(&account, &mut sources);
    let blockers = local_health_blockers_for_status(status, &runtime, &account, &sources);
    let overall = local_health_overall(&blockers, &runtime, &account, &sources);
    let evidence = events
        .iter()
        .map(|event| LocalHealthEvidenceRefV1 {
            event_id: event.event_id.clone(),
            event_type: event.event_type.clone(),
            authority: event.authority.clone(),
            observed_at: event.observed_at.clone(),
            sequence: event.sequence,
        })
        .collect::<Vec<_>>();

    status.runtime_heartbeat = Some(heartbeat);
    status.local_health_events = events;
    status.canonical_health = Some(LocalMachineHealthV1 {
        schema_version: 1,
        schema_version_name: "local_machine_health.v1".to_string(),
        machine_id: status.machine.machine_id.clone(),
        device_id: None,
        org_id: status
            .account
            .organization
            .as_ref()
            .map(|organization| organization.id.clone()),
        user_id: status.account.user.as_ref().map(|user| user.id.clone()),
        revision: projection_revision,
        projection_revision,
        protocol_version: format!("local_control.v{}", status.protocol_version),
        projection_version: "health_projection.v1".to_string(),
        event_schema_version: "local_health_event.v1".to_string(),
        capabilities: local_health_capabilities(status),
        observed_at,
        computed_at: status.generated_at.clone(),
        fresh_until: status.generated_at.clone(),
        overall,
        runtime,
        account,
        sources,
        blockers,
        evidence,
    });
}

fn next_local_health_sequence(state: &DaemonState) -> u64 {
    state
        .local_health_events
        .iter()
        .map(|event| event.sequence)
        .chain(
            state
                .command_ledger
                .iter()
                .map(|result| result.completed_projection_revision),
        )
        .max()
        .unwrap_or(0)
        + 1
}

fn next_status_projection_revision(status: &DaemonStatus) -> u64 {
    status
        .local_health_events
        .iter()
        .map(|event| event.sequence)
        .chain(
            status
                .command_ledger
                .iter()
                .map(|result| result.completed_projection_revision),
        )
        .max()
        .unwrap_or(0)
        + 1
}

fn runtime_identity_for_status(status: &DaemonStatus, observed_at: &str) -> RuntimeIdentityV1 {
    runtime_identity_for_status_with_installed_app_version(
        status,
        observed_at,
        &ottto_core::compiled_release_version(),
    )
}

fn runtime_identity_for_status_with_installed_app_version(
    status: &DaemonStatus,
    observed_at: &str,
    installed_app_version: &str,
) -> RuntimeIdentityV1 {
    let executable_path = std::env::current_exe().ok();
    let install_owner = if status.service_owner.daemon_owner != InstallOwner::Unknown {
        status.service_owner.daemon_owner
    } else {
        executable_path
            .as_deref()
            .map(ottto_core::install_owner_for_path)
            .unwrap_or(InstallOwner::Unknown)
    };
    let daemon_version = service_release_version(status);
    let app_bundle_version =
        (install_owner == InstallOwner::AppBundle).then(|| installed_app_version.to_string());
    RuntimeIdentityV1 {
        install_owner,
        daemon_version: daemon_version.clone(),
        app_bundle_version: app_bundle_version.clone(),
        cli_version: Some(installed_app_version.to_string()),
        service_version: Some(daemon_version.clone()),
        service_pid: Some(std::process::id()),
        service_executable_path_class: match install_owner {
            InstallOwner::AppBundle => "app_bundle_helper",
            InstallOwner::Homebrew => "homebrew",
            InstallOwner::HostedInstaller => "hosted_installer",
            InstallOwner::Dev => "dev",
            InstallOwner::Unknown => "unknown",
        }
        .to_string(),
        service_executable_path: executable_path.map(|path| path.display().to_string()),
        service_executable_hash: None,
        launchd_label: Some(ottto_core::MACOS_LAUNCH_AGENT_LABEL.to_string()),
        launchd_loaded_program_hash: None,
        started_at: observed_at.to_string(),
        last_seen_at: observed_at.to_string(),
        boot_id: std::env::var("OTTTO_BOOT_ID").ok(),
        session_id: std::env::var("OTTTO_SESSION_ID").ok(),
        version_match: !runtime_version_mismatch(
            install_owner,
            &daemon_version,
            app_bundle_version.as_deref(),
        ),
        protocol_match: status.protocol_version == PROTOCOL_VERSION,
        schema_match: true,
    }
}

fn service_release_version(status: &DaemonStatus) -> String {
    let machine_version = status.machine.local_platform_version.trim();
    if !machine_version.is_empty() {
        return machine_version.to_string();
    }
    let update_version = status.update.current_version.trim();
    if !update_version.is_empty() {
        return update_version.to_string();
    }
    ottto_core::compiled_release_version()
}

fn runtime_version_mismatch(
    install_owner: InstallOwner,
    daemon_version: &str,
    app_bundle_version: Option<&str>,
) -> bool {
    install_owner == InstallOwner::AppBundle
        && app_bundle_version.is_some_and(|expected| daemon_version != expected)
}

fn runtime_heartbeat_for_status(
    status: &DaemonStatus,
    runtime: &RuntimeIdentityV1,
    projection_revision: u64,
) -> MachineRuntimeHeartbeatV1 {
    MachineRuntimeHeartbeatV1 {
        schema_version: "machine_runtime_heartbeat.v1".to_string(),
        machine_id: status.machine.machine_id.clone(),
        account_id: status.account.user.as_ref().map(|user| user.id.clone()),
        org_id: status
            .account
            .organization
            .as_ref()
            .map(|organization| organization.id.clone()),
        daemon_version: runtime.daemon_version.clone(),
        app_bundle_version: runtime.app_bundle_version.clone(),
        protocol_version: format!("local_control.v{}", status.protocol_version),
        health_schema_version: "local_machine_health.v1".to_string(),
        executable_path: runtime
            .service_executable_path
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        install_owner: runtime.install_owner,
        launchd_label: runtime
            .launchd_label
            .clone()
            .unwrap_or_else(|| ottto_core::MACOS_LAUNCH_AGENT_LABEL.to_string()),
        started_at: runtime.started_at.clone(),
        last_seen_at: runtime.last_seen_at.clone(),
        boot_id: runtime.boot_id.clone(),
        session_id: runtime.session_id.clone(),
        health_projection_revision: projection_revision,
        capabilities: local_health_capabilities(status),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LatestLocalHealthUpload {
    Succeeded,
    AuthRejected { observed_at: String },
    BackendUnreachable { observed_at: String },
    ContractRejected { observed_at: String },
}

fn latest_local_health_upload(status: &DaemonStatus) -> Option<LatestLocalHealthUpload> {
    status
        .local_health_events
        .iter()
        .filter(|event| {
            event.event_type == "LocalHealthUploadFailed"
                || event.event_type == "LocalHealthUploadSucceeded"
        })
        .max_by_key(|event| event.sequence)
        .and_then(|event| {
            if event.event_type == "LocalHealthUploadSucceeded" {
                return Some(LatestLocalHealthUpload::Succeeded);
            }
            let kind = event
                .payload
                .get("kind")
                .and_then(serde_json::Value::as_str)?;
            match kind {
                "auth_rejected" => Some(LatestLocalHealthUpload::AuthRejected {
                    observed_at: event.observed_at.clone(),
                }),
                "backend_unreachable" => Some(LatestLocalHealthUpload::BackendUnreachable {
                    observed_at: event.observed_at.clone(),
                }),
                "contract_rejected" => Some(LatestLocalHealthUpload::ContractRejected {
                    observed_at: event.observed_at.clone(),
                }),
                _ => None,
            }
        })
}

fn local_health_account_for_status(status: &DaemonStatus) -> LocalHealthAccountV1 {
    let (mut state, mut setup_run_state, mut setup_token_state) = match status.account.state {
        LocalAccountState::Connected => (
            LocalHealthAccountState::Connected,
            LocalSetupRunState::Complete,
            LocalSetupTokenState::Valid,
        ),
        LocalAccountState::ClaimPending => (
            LocalHealthAccountState::ClaimPending,
            LocalSetupRunState::Pending,
            LocalSetupTokenState::Unknown,
        ),
        LocalAccountState::ResetRequired | LocalAccountState::Error => (
            LocalHealthAccountState::ReconnectRequired,
            LocalSetupRunState::RebindRequired,
            LocalSetupTokenState::RefreshRequired,
        ),
        LocalAccountState::NotConnected => (
            LocalHealthAccountState::NotConnected,
            LocalSetupRunState::Unknown,
            LocalSetupTokenState::Missing,
        ),
    };
    let latest_upload = latest_local_health_upload(status);
    if matches!(
        latest_upload,
        Some(LatestLocalHealthUpload::AuthRejected { .. })
    ) && !matches!(state, LocalHealthAccountState::NotConnected)
    {
        state = LocalHealthAccountState::ReconnectRequired;
        setup_run_state = LocalSetupRunState::RebindRequired;
        setup_token_state = LocalSetupTokenState::RefreshRequired;
    }
    let device_state = match latest_upload.as_ref() {
        Some(LatestLocalHealthUpload::AuthRejected { .. }) => LocalDeviceState::Inactive,
        Some(LatestLocalHealthUpload::BackendUnreachable { .. }) => LocalDeviceState::Unknown,
        Some(LatestLocalHealthUpload::ContractRejected { .. }) => LocalDeviceState::Active,
        Some(LatestLocalHealthUpload::Succeeded) | None
            if status.daemon == DaemonRuntimeState::Unavailable =>
        {
            LocalDeviceState::StaleHeartbeat
        }
        _ => LocalDeviceState::Active,
    };
    LocalHealthAccountV1 {
        state,
        device_state,
        setup_run_state,
        setup_token_state,
        org_role: None,
        telemetry_controls: Some(OrgTelemetryControlState {
            read_only: false,
            can_mutate_sources: true,
            can_enable_telemetry: true,
            can_disable_telemetry: true,
        }),
    }
}

fn local_health_source_for_status(
    source: &SourceHealth,
    projection_revision: u64,
) -> LocalHealthSourceV1 {
    let has_verify_attention =
        source.last_verified_at.is_some() && has_verification_failure_problem(source);
    let authority = if source.last_verified_at.is_some() {
        LocalHealthAuthority::Verify
    } else {
        LocalHealthAuthority::Runtime
    };
    let state = if has_verify_attention {
        LocalHealthSourceState::VerifyFailed
    } else {
        match source.state {
            SourceState::Healthy => LocalHealthSourceState::Healthy,
            SourceState::NeedsRepair => LocalHealthSourceState::RepairRequired,
            SourceState::NeedsConfirmation => LocalHealthSourceState::PendingSetup,
            SourceState::NotFound => LocalHealthSourceState::PendingSetup,
            SourceState::Verifying => LocalHealthSourceState::Unknown,
            SourceState::Failed => LocalHealthSourceState::VerifyFailed,
            SourceState::Unsupported => LocalHealthSourceState::DisabledByPolicy,
        }
    };
    let first_problem = source.problems.first();
    let blocking_reason =
        first_problem.map(|problem| local_health_problem_code_slug(problem).to_string());
    LocalHealthSourceV1 {
        source_id: format!("src_{}", source_slug(&source.source)),
        app: source.source.clone(),
        state,
        authority,
        authority_at: source
            .last_verified_at
            .clone()
            .or_else(|| source.last_seen_at.clone())
            .or_else(|| source.connected_at.clone())
            .unwrap_or_else(current_rfc3339_timestamp),
        blocking_reason,
        clear_condition: first_problem
            .map(|problem| problem.detail.trim())
            .filter(|detail| !detail.is_empty())
            .map(str::to_string),
        next_action: source
            .recommended_actions
            .first()
            .map(|action| format!("{:?}", action.action)),
        projection_revision: projection_revision.saturating_sub(1),
    }
}

fn apply_account_prerequisite_to_sources(
    account: &LocalHealthAccountV1,
    sources: &mut [LocalHealthSourceV1],
) {
    let account_blocks_source_trust =
        matches!(
            account.state,
            LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
        ) || matches!(
            account.device_state,
            LocalDeviceState::Inactive | LocalDeviceState::StaleHeartbeat
        ) || matches!(account.setup_run_state, LocalSetupRunState::RebindRequired)
            || matches!(
                account.setup_token_state,
                LocalSetupTokenState::Missing | LocalSetupTokenState::RefreshRequired
            );
    if !account_blocks_source_trust {
        return;
    }
    for source in sources {
        if source.state != LocalHealthSourceState::Healthy {
            continue;
        }
        source.state = LocalHealthSourceState::Unknown;
        source.authority = LocalHealthAuthority::Backend;
        source.blocking_reason = Some("auth_missing".to_string());
        source.clear_condition = Some("sign in to Ottto and rebind this machine".to_string());
        source.next_action = Some("sign_in".to_string());
    }
}

fn stable_problem_code_slug(code: &StableProblemCode) -> &'static str {
    match code {
        StableProblemCode::ConfigMissing => "config_missing",
        StableProblemCode::ConfigDrift => "config_drift",
        StableProblemCode::SecretMissing => "secret_missing",
        StableProblemCode::SecretExpired => "secret_expired",
        StableProblemCode::RelayUnavailable => "relay_unavailable",
        StableProblemCode::TelemetryNotVerified => "telemetry_not_verified",
        StableProblemCode::SourceNotInstalled => "source_not_installed",
        StableProblemCode::UnsupportedPlatform => "unsupported_platform",
        StableProblemCode::Unknown => "unknown",
    }
}

fn local_health_problem_code_slug(problem: &HealthProblem) -> &'static str {
    if problem.code == StableProblemCode::TelemetryNotVerified
        && problem_detail_is_usage_limited(&problem.detail)
    {
        return "smoke_quota_limited";
    }
    stable_problem_code_slug(&problem.code)
}

fn problem_detail_is_usage_limited(detail: &str) -> bool {
    let lowered = detail.to_ascii_lowercase();
    lowered.contains("usage limit")
        || lowered.contains("weekly limit")
        || lowered.contains("rate limit")
        || lowered.contains("purchase more credits")
        || lowered.contains("quota")
}

fn local_health_blockers_for_status(
    status: &DaemonStatus,
    runtime: &RuntimeIdentityV1,
    account: &LocalHealthAccountV1,
    sources: &[LocalHealthSourceV1],
) -> Vec<LocalHealthBlockerV1> {
    let mut blockers = Vec::new();
    if !runtime.protocol_match || !runtime.schema_match {
        blockers.push(blocker(
            "protocol_mismatch",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "upgrade Ottto local runtime so protocol and health schema match",
        ));
    } else if status.service_owner.owner_drift {
        blockers.push(blocker(
            "owner_conflict",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "reconcile LaunchAgent owner before repair or upgrade",
        ));
    } else if !runtime.version_match {
        blockers.push(blocker(
            "service_outdated",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "daemon reports same version/hash as installed owner",
        ));
    }
    if account.device_state == LocalDeviceState::StaleHeartbeat {
        blockers.push(blocker(
            "stale_heartbeat",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Heartbeat,
            &status.generated_at,
            "restart ottto-service and observe a fresh heartbeat",
        ));
    }
    match latest_local_health_upload(status) {
        Some(LatestLocalHealthUpload::AuthRejected { observed_at }) => blockers.push(blocker(
            "auth_missing",
            LocalHealthSeverity::Blocking,
            "backend",
            LocalHealthAuthority::Backend,
            &observed_at,
            "rebind this Mac's relay device credentials before trusting cloud sync",
        )),
        Some(LatestLocalHealthUpload::BackendUnreachable { observed_at }) => {
            blockers.push(blocker(
                "backend_unreachable",
                LocalHealthSeverity::Blocking,
                "backend",
                LocalHealthAuthority::Backend,
                &observed_at,
                "restore network access and upload a fresh local health projection",
            ));
        }
        Some(LatestLocalHealthUpload::ContractRejected { observed_at }) => {
            blockers.push(blocker(
                "local_health_contract_rejected",
                LocalHealthSeverity::Blocking,
                "backend",
                LocalHealthAuthority::Backend,
                &observed_at,
                "upgrade Ottto or backend contract support so local health projection validates",
            ));
        }
        Some(LatestLocalHealthUpload::Succeeded) | None => {}
    }
    if matches!(
        account.state,
        LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
    ) {
        blockers.push(blocker(
            "reconnect_required",
            LocalHealthSeverity::Blocking,
            "account",
            LocalHealthAuthority::Setup,
            &status.generated_at,
            "sign in to Ottto and rebind this machine",
        ));
    }
    for source in sources {
        if matches!(
            source.state,
            LocalHealthSourceState::RepairRequired | LocalHealthSourceState::VerifyFailed
        ) {
            blockers.push(blocker(
                source.blocking_reason.as_deref().unwrap_or("config_drift"),
                LocalHealthSeverity::Blocking,
                "source",
                source.authority.clone(),
                &source.authority_at,
                source
                    .clear_condition
                    .as_deref()
                    .unwrap_or("repair the source and rerun Verify"),
            ));
        }
    }
    blockers
}

fn blocker(
    code: &str,
    severity: LocalHealthSeverity,
    owner: &str,
    source: LocalHealthAuthority,
    since: &str,
    clear_condition: &str,
) -> LocalHealthBlockerV1 {
    LocalHealthBlockerV1 {
        code: code.to_string(),
        severity,
        owner: owner.to_string(),
        source,
        since: since.to_string(),
        clear_condition: clear_condition.to_string(),
    }
}

fn local_health_overall(
    blockers: &[LocalHealthBlockerV1],
    runtime: &RuntimeIdentityV1,
    account: &LocalHealthAccountV1,
    sources: &[LocalHealthSourceV1],
) -> LocalHealthOverall {
    if !runtime.protocol_match || !runtime.schema_match {
        return LocalHealthOverall {
            state: LocalHealthOverallState::UpgradeRequired,
            primary_blocker: Some("protocol_mismatch".to_string()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("upgrade_local_runtime".to_string()),
        };
    }
    if matches!(
        account.state,
        LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
    ) {
        return LocalHealthOverall {
            state: LocalHealthOverallState::ReconnectRequired,
            primary_blocker: blockers.first().map(|blocker| blocker.code.clone()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("sign_in".to_string()),
        };
    }
    if let Some(blocker) = blockers.first() {
        return LocalHealthOverall {
            state: LocalHealthOverallState::Blocked,
            primary_blocker: Some(blocker.code.clone()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("repair_or_verify".to_string()),
        };
    }
    if sources.iter().any(|source| {
        matches!(
            source.state,
            LocalHealthSourceState::PendingSetup
                | LocalHealthSourceState::DisabledByPolicy
                | LocalHealthSourceState::Unknown
        )
    }) {
        return LocalHealthOverall {
            state: LocalHealthOverallState::Degraded,
            primary_blocker: None,
            severity: LocalHealthSeverity::Warning,
            next_action: Some("finish_source_setup".to_string()),
        };
    }
    LocalHealthOverall {
        state: LocalHealthOverallState::Healthy,
        primary_blocker: None,
        severity: LocalHealthSeverity::Info,
        next_action: None,
    }
}

fn local_health_capabilities(status: &DaemonStatus) -> Vec<String> {
    let mut capabilities = vec![
        "health.v1".to_string(),
        "service.reconcile".to_string(),
        "source.remove".to_string(),
        "backfill.v1".to_string(),
    ];
    for source in &status.sources {
        capabilities.push(format!("verify.{}", source_slug(&source.source)));
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

pub fn current_rfc3339_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn personal_meter_local_snapshot_from_status(
    status: &DaemonStatus,
    source_filter: Option<&SourceKind>,
) -> PersonalMeterLocalSnapshot {
    let sources = status
        .sources
        .iter()
        .filter(|health| {
            source_filter
                .map(|source| health.source == *source)
                .unwrap_or(true)
        })
        .map(personal_meter_source_from_health)
        .collect();

    PersonalMeterLocalSnapshot {
        schema_version: "personal_meter.local_snapshot.v1".to_string(),
        generated_at: status.generated_at.clone(),
        machine_id: status.machine.machine_id.clone(),
        sources,
    }
}

fn personal_meter_source_from_health(health: &SourceHealth) -> PersonalMeterLocalSourceSnapshot {
    let agent_status = health.agent_status.as_ref();
    let account_status = agent_status.and_then(|snapshot| snapshot.account.as_ref());
    let model_status = agent_status.and_then(|snapshot| snapshot.model.as_ref());
    let current_plan = current_plan_observation(health);

    let provider = account_status
        .and_then(|account| account.provider.clone())
        .or_else(|| model_status.and_then(|model| model.provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.billing_provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.gateway_provider.clone()))
        .or_else(|| {
            health
                .detected_uses
                .first()
                .map(|use_record| use_record.gateway_provider.clone())
        });
    let account = account_status.map(|account| PersonalMeterLocalAccount {
        login_state: account.login_state.clone(),
        label: account
            .email
            .clone()
            .or_else(|| current_plan.and_then(|plan| plan.account_label.clone()))
            .or_else(|| {
                health
                    .detected_uses
                    .first()
                    .and_then(|use_record| use_record.account_label.clone())
            }),
        account_identifier_hash: account
            .account_identifier_hash
            .clone()
            .or_else(|| current_plan.and_then(|plan| plan.account_identifier_hash.clone()))
            .or_else(|| {
                health
                    .detected_uses
                    .first()
                    .and_then(|use_record| use_record.account_identifier_hash.clone())
            }),
        confidence: account.confidence.clone(),
    });
    let model = model_status
        .and_then(|model| {
            model
                .active_model
                .clone()
                .or_else(|| model.default_model.clone())
        })
        .or_else(|| {
            agent_status.and_then(|snapshot| {
                snapshot
                    .quota_windows
                    .iter()
                    .find_map(|window| window.model.clone())
            })
        });
    let plan = account_status
        .and_then(|account| {
            account
                .subscription_product
                .clone()
                .or_else(|| account.plan_type.clone())
        })
        .or_else(|| {
            current_plan.and_then(|plan| {
                plan.subscription_product
                    .clone()
                    .or_else(|| plan.plan_type.clone())
            })
        })
        .or_else(|| {
            health
                .detected_uses
                .first()
                .and_then(|use_record| use_record.subscription_product.clone())
        });
    let confidence = account_status
        .map(|account| account.confidence.clone())
        .or_else(|| current_plan.map(|plan| plan.confidence.clone()))
        .unwrap_or_default();

    PersonalMeterLocalSourceSnapshot {
        source: health.source.clone(),
        app: source_slug(&health.source).to_string(),
        included_in_totals: false,
        provider,
        account,
        model,
        plan,
        quota_windows: agent_status
            .map(|snapshot| snapshot.quota_windows.clone())
            .unwrap_or_default(),
        pending_local_delta: personal_meter_delta(health),
        freshness: personal_meter_freshness(health),
        collector: personal_meter_collector(health),
        confidence,
        warnings: personal_meter_warnings(health),
        recommendation: health
            .recommended_actions
            .first()
            .map(|action| action.title.clone()),
    }
}

fn current_plan_observation(
    health: &SourceHealth,
) -> Option<&ottto_protocol::AgentStatusPlanObservation> {
    health
        .plan_observations
        .iter()
        .find(|plan| plan.is_current == Some(true))
        .or_else(|| health.plan_observations.first())
}

fn personal_meter_delta(health: &SourceHealth) -> PersonalMeterLocalDelta {
    let recent_token_volume = aggregate_recent_token_volume(health);
    let has_local_usage_evidence =
        !health.detected_uses.is_empty() || !recent_token_volume.is_empty();
    let reconciliation_disabled = health.reconciliation_enabled == Some(false);
    let (status, basis) = if reconciliation_disabled {
        (
            PersonalMeterLocalValueStatus::Unavailable,
            "local_usage_reconciliation_disabled",
        )
    } else if has_local_usage_evidence {
        (
            PersonalMeterLocalValueStatus::Unknown,
            "backend_inclusion_watermark_unavailable",
        )
    } else if health.reconciliation_enabled == Some(true) {
        (
            PersonalMeterLocalValueStatus::Unknown,
            "no_local_usage_evidence_yet",
        )
    } else {
        (
            PersonalMeterLocalValueStatus::Unavailable,
            "local_usage_reconciliation_policy_unknown",
        )
    };

    PersonalMeterLocalDelta {
        status,
        included_in_totals: false,
        basis: basis.to_string(),
        since: None,
        until: None,
        total_tokens: None,
        request_count: None,
        estimated_cost_usd_micros: None,
        detected_use_count: health.detected_uses.len() as u64,
        recent_token_volume,
    }
}

fn aggregate_recent_token_volume(
    health: &SourceHealth,
) -> Vec<ottto_protocol::DetectedUseTokenSample> {
    let mut by_timestamp = BTreeMap::<String, u64>::new();
    for use_record in &health.detected_uses {
        for sample in &use_record.token_volume_recent {
            *by_timestamp.entry(sample.at.clone()).or_default() += sample.tokens;
        }
    }
    by_timestamp
        .into_iter()
        .map(|(at, tokens)| ottto_protocol::DetectedUseTokenSample { at, tokens })
        .collect()
}

fn personal_meter_freshness(health: &SourceHealth) -> PersonalMeterLocalFreshness {
    let agent_status = health.agent_status.as_ref();
    let collector_last_success_at = health
        .collector
        .as_ref()
        .and_then(|collector| collector.last_success_at.clone());
    let status = if let Some(snapshot) = agent_status {
        if snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness == AgentQuotaWindowFreshness::Error)
        {
            PersonalMeterLocalFreshnessStatus::Error
        } else if snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness == AgentQuotaWindowFreshness::Stale)
        {
            PersonalMeterLocalFreshnessStatus::Stale
        } else {
            match snapshot.status {
                AgentStatusState::Available => PersonalMeterLocalFreshnessStatus::Fresh,
                AgentStatusState::Error => PersonalMeterLocalFreshnessStatus::Error,
                AgentStatusState::Unsupported | AgentStatusState::NotInstalled => {
                    PersonalMeterLocalFreshnessStatus::Unsupported
                }
                AgentStatusState::Degraded
                | AgentStatusState::AuthRequired
                | AgentStatusState::Unknown => PersonalMeterLocalFreshnessStatus::Unknown,
            }
        }
    } else if collector_last_success_at.is_some() {
        PersonalMeterLocalFreshnessStatus::Unknown
    } else {
        PersonalMeterLocalFreshnessStatus::Unavailable
    };

    PersonalMeterLocalFreshness {
        status,
        captured_at: agent_status.map(|snapshot| snapshot.captured_at.clone()),
        expires_at: agent_status.map(|snapshot| snapshot.expires_at.clone()),
        last_seen_at: health.last_seen_at.clone(),
        last_verified_at: health.last_verified_at.clone(),
        collector_last_success_at,
    }
}

fn personal_meter_collector(health: &SourceHealth) -> PersonalMeterLocalCollector {
    let status = match (&health.collector, health.reconciliation_enabled) {
        (_, Some(false)) => PersonalMeterLocalCollectorStatus::Disabled,
        (Some(collector), _) if collector.state == ottto_protocol::LocalCollectorState::Failing => {
            PersonalMeterLocalCollectorStatus::Failing
        }
        (Some(_), _) => PersonalMeterLocalCollectorStatus::Ok,
        (None, Some(true)) => PersonalMeterLocalCollectorStatus::Unknown,
        (None, None) => PersonalMeterLocalCollectorStatus::Unavailable,
    };
    let collector = health.collector.as_ref();

    PersonalMeterLocalCollector {
        status,
        state: collector.map(|collector| collector.state.clone()),
        local_usage_reconciliation_enabled: health.reconciliation_enabled,
        last_scan_started_at: collector
            .and_then(|collector| collector.last_scan_started_at.clone()),
        last_scan_finished_at: collector
            .and_then(|collector| collector.last_scan_finished_at.clone()),
        last_success_at: collector.and_then(|collector| collector.last_success_at.clone()),
        last_uploaded_count: collector
            .map(|collector| collector.last_uploaded_count)
            .unwrap_or_default(),
        last_scanned_session_count: collector
            .map(|collector| collector.last_scanned_session_count)
            .unwrap_or_default(),
        last_scanned_file_count: collector
            .map(|collector| collector.last_scanned_file_count)
            .unwrap_or_default(),
        last_scan_cap_hit: collector
            .map(|collector| collector.last_scan_cap_hit)
            .unwrap_or_default(),
        collector_version: collector.and_then(|collector| collector.collector_version.clone()),
        parser_version: collector.and_then(|collector| collector.parser_version.clone()),
    }
}

fn personal_meter_warnings(health: &SourceHealth) -> Vec<String> {
    let mut warnings = Vec::new();
    warnings.extend(health.problems.iter().map(|problem| problem.title.clone()));
    if let Some(agent_status) = health.agent_status.as_ref() {
        warnings.extend(
            agent_status
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    matches!(
                        diagnostic.severity,
                        ottto_protocol::AgentDiagnosticSeverity::Warning
                            | ottto_protocol::AgentDiagnosticSeverity::Error
                    )
                })
                .map(|diagnostic| diagnostic.message.clone()),
        );
    }
    warnings.truncate(8);
    warnings
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

fn source_from_slug(slug: &str) -> Option<SourceKind> {
    match slug {
        "codex" => Some(SourceKind::Codex),
        "claude_code" | "claude-code" => Some(SourceKind::ClaudeCode),
        "pi" => Some(SourceKind::Pi),
        _ => None,
    }
}

fn seed_registered_sources(state: &mut DaemonState, device: Option<&LocalDeviceBinding>) {
    if state.account.state != LocalAccountState::Connected {
        return;
    }
    let Some(device) = device else {
        return;
    };
    let sources = device
        .sources
        .iter()
        .filter_map(|slug| source_from_slug(slug))
        .filter(|source| !state.sources.iter().any(|health| health.source == *source))
        .collect::<Vec<_>>();
    for source in sources {
        state.sources.push(cached_source_health(state, source));
    }
}

fn cached_source_health(state: &DaemonState, source: SourceKind) -> SourceHealth {
    let expected_account_id = state.account.user.as_ref().map(|user| user.id.clone());
    SourceHealth {
        source: source.clone(),
        descriptor: source_descriptor(&source),
        state: SourceState::Verifying,
        grade: HealthGrade::Unknown,
        account_binding: AccountBindingState {
            expected_account_id,
            observed_account_id: None,
            matched: None,
        },
        config: SourceConfigState {
            discovered: true,
            path_hint: config_path_hint(&source).map(str::to_string),
            fingerprint: None,
            drift: Vec::new(),
        },
        collector: None,
        agent_status: None,
        plan_observations: Vec::new(),
        detected_uses: Vec::new(),
        last_seen_at: None,
        last_verified_at: None,
        problems: Vec::new(),
        recommended_actions: Vec::new(),
        connected_at: state.first_seen(&source),
        telemetry_configured: telemetry_configured_for_source(&source),
        reconciliation_enabled: state.reconciliation_enabled(&source),
    }
}

fn config_path_hint(source: &SourceKind) -> Option<&'static str> {
    match source {
        SourceKind::Codex => Some("~/.codex/config.toml"),
        SourceKind::ClaudeCode => Some("~/.claude/settings.json"),
        SourceKind::Pi => None,
    }
}

/// Boot-load persisted first-seen timestamps for all sources from `dir`, keyed
/// by source slug. Missing or unreadable files are skipped (graceful empty),
/// matching the lenient posture of the detected-uses cache.
fn load_source_first_seen(dir: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
        let slug = source_slug(&source);
        let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
        if let Ok(Some(LocalSourceState {
            first_seen_at: Some(first_seen),
            ..
        })) = store.load()
        {
            map.insert(slug.to_string(), first_seen);
        }
    }
    map
}

/// Boot-load the most recent verification-derived source health rows. Missing
/// or unreadable files are skipped, and rows whose persisted source does not
/// match the file slug are ignored so a corrupt file cannot poison another
/// source.
fn load_source_health(state: &DaemonState, dir: &Path) -> Vec<SourceHealth> {
    let mut sources = Vec::new();
    for source in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
        let slug = source_slug(&source);
        let store = FileSourceStateStore::new(dir.join(source_state_file_name(slug)));
        let Ok(Some(LocalSourceState {
            last_health: Some(mut health),
            ..
        })) = store.load()
        else {
            continue;
        };
        if health.source != source {
            continue;
        }
        normalize_persisted_source_health(state, &mut health);
        sources.push(health);
    }
    sources
}

fn normalize_persisted_source_health(state: &DaemonState, health: &mut SourceHealth) {
    health.descriptor = source_descriptor(&health.source);
    health.account_binding.expected_account_id =
        state.account.user.as_ref().map(|user| user.id.clone());
    if health.connected_at.is_none() {
        health.connected_at = state.first_seen(&health.source);
    }
    health.telemetry_configured = telemetry_configured_for_source(&health.source);
    health.reconciliation_enabled = state.reconciliation_enabled(&health.source);
}

/// Whether local live telemetry credentials are configured for `source`.
/// Telemetry is a Codex / Claude Code concept, so Pi returns `None`. Both the
/// legacy per-source key store and the relay-device setup-run path count: the
/// latter is what Companion install actions provision on this Mac.
fn telemetry_configured_for_source(source: &SourceKind) -> Option<bool> {
    match source {
        SourceKind::Codex | SourceKind::ClaudeCode => Some(
            keychain::TelemetryKeyStore::production()
                .latest_key_id(source)
                .is_ok_and(|key| key.is_some())
                || relay_device_credentials_include_source(source),
        ),
        SourceKind::Pi => None,
    }
}

fn relay_device_credentials_include_source(source: &SourceKind) -> bool {
    let slug = source_slug(source);
    crate::snapshot_client::load_snapshot_device_credentials()
        .ok()
        .is_some_and(|(device, _secret)| {
            device
                .sources
                .iter()
                .any(|configured_source| configured_source == slug)
        })
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
    observed_at: &str,
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
    let usage_limited = verification_result_is_usage_limited(result);
    let pi_local_only = result.source == SourceKind::Pi && result.message.code == "pi_local_only";
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
    } else if patch_disabled || usage_limited || pi_local_only {
        (
            SourceState::Healthy,
            if usage_limited || pi_local_only {
                HealthGrade::Warning
            } else {
                HealthGrade::Ok
            },
            Vec::new(),
        )
    } else {
        match result.status {
            SourceVerificationStatus::Verified => {
                (SourceState::Healthy, HealthGrade::Ok, Vec::new())
            }
            SourceVerificationStatus::Warning => (
                if result.verified {
                    SourceState::Healthy
                } else {
                    SourceState::NeedsConfirmation
                },
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
    } else if result.verified || patch_disabled || usage_limited {
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
            result
                .last_received_at
                .clone()
                .or_else(|| Some(observed_at.to_string()))
        } else {
            Some(observed_at.to_string())
        },
        problems,
        recommended_actions,
        connected_at: state.first_seen(&result.source),
        telemetry_configured: telemetry_configured_for_source(&result.source),
        reconciliation_enabled: state.reconciliation_enabled(&result.source),
    }
}

fn upsert_agent_status_snapshot(state: &mut DaemonState, snapshot: AgentStatusSnapshot) {
    state.stamp_first_seen(&snapshot.source, Some(&snapshot.captured_at));
    // Recompute the mutable companion fields up front: the in-place branch
    // below updates an existing row without rebuilding it, so telemetry/
    // reconciliation would otherwise go stale (e.g. after telemetry is
    // configured). connected_at is left untouched — it is a stable first-seen.
    let telemetry_configured = telemetry_configured_for_source(&snapshot.source);
    let reconciliation_enabled = state.reconciliation_enabled(&snapshot.source);
    if let Some(index) = state
        .sources
        .iter()
        .position(|health| health.source == snapshot.source)
    {
        let existing = state.sources[index].clone();
        let mut refreshed = source_health_from_agent_status(state, snapshot);
        if refreshed.config.path_hint.is_none() {
            refreshed.config.path_hint = existing.config.path_hint.clone();
        }
        if refreshed.config.fingerprint.is_none() {
            refreshed.config.fingerprint = existing.config.fingerprint.clone();
        }
        refreshed.config.discovered |= existing.config.discovered;
        if refreshed.collector.is_none() {
            refreshed.collector = existing.collector.clone();
        }
        if refreshed.connected_at.is_none() {
            refreshed.connected_at = existing.connected_at.clone();
        }
        if refreshed.detected_uses.is_empty() {
            refreshed.detected_uses = existing.detected_uses.clone();
        }
        refreshed.telemetry_configured = telemetry_configured;
        refreshed.reconciliation_enabled = reconciliation_enabled;
        preserve_blocking_verification_state(&mut refreshed, &existing);
        state.sources[index] = refreshed;
        return;
    }
    let health = source_health_from_agent_status(state, snapshot);
    state.sources.push(health);
}

/// Source kinds whose health is still in the seeded post-restart `verifying`
/// state.
fn verifying_source_kinds(state: &DaemonState) -> Vec<SourceKind> {
    state
        .sources
        .iter()
        .filter(|health| health.state == SourceState::Verifying)
        .map(|health| health.source.clone())
        .collect()
}

/// Apply a startup re-verify scan: replace each source that is *still*
/// `verifying` with authoritative health, but only when the scan found it
/// `Available`. Skipping non-`Available` results keeps a cold-CLI boot read from
/// flashing a seeded `verifying` row into a spurious attention state; the
/// still-verifying recheck keeps a concurrent Verify/refresh result from being
/// clobbered. Returns the count of sources still `verifying` afterward.
fn apply_verifying_reconfirm(
    state: &mut DaemonState,
    snapshots: Vec<AgentStatusSnapshot>,
) -> usize {
    for snapshot in snapshots {
        if snapshot.status != AgentStatusState::Available {
            continue;
        }
        let still_verifying = state.sources.iter().any(|health| {
            health.source == snapshot.source && health.state == SourceState::Verifying
        });
        if still_verifying {
            upsert_agent_status_snapshot(state, snapshot);
        }
    }
    verifying_source_kinds(state).len()
}

fn has_config_drift_problem(health: &SourceHealth) -> bool {
    health.problems.iter().any(|problem| {
        [
            StableProblemCode::ConfigMissing,
            StableProblemCode::ConfigDrift,
        ]
        .contains(&problem.code)
    })
}

fn has_verification_failure_problem(health: &SourceHealth) -> bool {
    health
        .problems
        .iter()
        .any(|problem| problem.code == StableProblemCode::TelemetryNotVerified)
}

fn has_soft_no_fresh_telemetry_problem(health: &SourceHealth) -> bool {
    health.state == SourceState::NeedsConfirmation
        && health.grade == HealthGrade::Warning
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && problem.title == "No recent telemetry found"
        })
}

fn has_soft_smoke_timeout_problem(health: &SourceHealth) -> bool {
    health.state == SourceState::Failed
        && health.grade == HealthGrade::Critical
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && problem.detail.contains("smoke session timed out")
        })
}

fn has_usage_limited_verification_problem(health: &SourceHealth) -> bool {
    health.last_verified_at.is_some()
        && !health.problems.is_empty()
        && health.problems.iter().all(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem_detail_is_usage_limited(&problem.title)
                    || problem_detail_is_usage_limited(&problem.detail))
        })
}

fn verification_result_is_usage_limited(result: &SourceVerificationResult) -> bool {
    if verification_code_is_usage_limited(&result.message.code) {
        return true;
    }
    let failed_routes = result
        .route_results
        .iter()
        .filter(|route| !route.verified)
        .collect::<Vec<_>>();
    !failed_routes.is_empty()
        && failed_routes.iter().all(|route| {
            route
                .error_code
                .as_deref()
                .is_some_and(verification_code_is_usage_limited)
                || verification_code_is_usage_limited(&route.message.code)
        })
}

fn verification_result_records_success(result: &SourceVerificationResult) -> bool {
    matches!(result.status, SourceVerificationStatus::Verified)
        || (matches!(result.status, SourceVerificationStatus::Warning)
            && (result.verified || verification_result_is_usage_limited(result)))
}

fn verification_code_is_usage_limited(code: &str) -> bool {
    matches!(
        code,
        USAGE_LIMITED_MESSAGE_CODE | SMOKE_QUOTA_LIMITED_MESSAGE_CODE
    )
}

fn has_pi_route_smoke_failure_problem(health: &SourceHealth) -> bool {
    health.source == SourceKind::Pi
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem
                    .detail
                    .contains("No Pi model routes passed smoke verification")
                    || problem.detail.contains(PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE)
                    || problem.title.contains("Pi route check failed"))
        })
}

fn refreshed_pi_status_has_available_routes(refreshed: &SourceHealth) -> bool {
    if refreshed.source != SourceKind::Pi || refreshed.state != SourceState::Healthy {
        return false;
    }
    refreshed
        .agent_status
        .as_ref()
        .and_then(|snapshot| snapshot.model.as_ref())
        .is_some_and(|model| {
            model.active_model.is_some()
                || model.default_model.is_some()
                || !model.available_models.is_empty()
                || !model.available_model_details.is_empty()
        })
}

fn preserve_blocking_verification_state(refreshed: &mut SourceHealth, existing: &SourceHealth) {
    let preserve_config_drift =
        refreshed.config.drift.is_empty() && !existing.config.drift.is_empty();
    if preserve_config_drift {
        refreshed.config.drift = existing.config.drift.clone();
    }
    let clear_failed_verification = has_soft_no_fresh_telemetry_problem(existing)
        || has_soft_smoke_timeout_problem(existing)
        || has_usage_limited_verification_problem(existing)
        || (has_pi_route_smoke_failure_problem(existing)
            && refreshed_pi_status_has_available_routes(refreshed));
    let preserve_failed_verification = existing.last_verified_at.is_some()
        && has_verification_failure_problem(existing)
        && !clear_failed_verification;
    if (preserve_config_drift && has_config_drift_problem(existing)) || preserve_failed_verification
    {
        refreshed.state = existing.state.clone();
        refreshed.grade = existing.grade.clone();
        refreshed.problems = existing.problems.clone();
        refreshed.recommended_actions = existing.recommended_actions.clone();
        refreshed.last_verified_at = existing.last_verified_at.clone();
    }
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
        last_verified_at: None,
        problems,
        recommended_actions: Vec::new(),
        connected_at: state.first_seen(&snapshot.source),
        telemetry_configured: telemetry_configured_for_source(&snapshot.source),
        reconciliation_enabled: state.reconciliation_enabled(&snapshot.source),
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
    let mut detected = prune_detected_uses_for_health(
        load_detected_uses_for_source(source),
        OffsetDateTime::now_utc(),
    );
    if let Some(snapshot) = agent_status {
        merge_current_plan_quota(&mut detected, snapshot);
    }
    detected
}

fn prune_detected_uses_for_health(
    detected: Vec<DetectedUse>,
    now: OffsetDateTime,
) -> Vec<DetectedUse> {
    prune_stale_detected_uses(
        detected,
        now,
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    )
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
        AccountBindingState, DetectedUseTokenSample, HealthGrade, LocalAccountOrganization,
        LocalHealthContractFixture, LocalHealthOverallState, LocalHealthSourceState,
        OperatingSystem, SourceConfigState, SourceState,
    };
    use serial_test::serial;

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
            vec![
                "identity_probe",
                "local_sessions",
                "logs2_trace",
                "otel_config",
                "quota_status"
            ]
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
        assert_eq!(descriptor.maturity, ConnectorMaturity::LocalOnly);
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
    fn verification_result_updates_source_health() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
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
        let health = status
            .canonical_health
            .as_ref()
            .expect("canonical health should be projected");
        assert_eq!(health.overall.state, LocalHealthOverallState::Healthy);
        assert_eq!(
            status
                .runtime_heartbeat
                .as_ref()
                .map(|heartbeat| heartbeat.health_projection_revision),
            Some(health.projection_revision)
        );
        assert!(health
            .capabilities
            .iter()
            .any(|capability| capability == "health.v1"));
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
            "2026-06-15T08:00:00Z",
            "0.1.30-rc1",
        );

        assert_eq!(runtime.daemon_version, "0.1.30-rc1");
        assert_eq!(runtime.service_version.as_deref(), Some("0.1.30-rc1"));
        assert_eq!(runtime.app_bundle_version.as_deref(), Some("0.1.30-rc1"));
        assert!(runtime.version_match);
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
    fn source_update_preserves_failed_verification_result() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("source health should update");

        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
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
                text: "Codex smoke session failed before telemetry could be sent.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record failed verification");
        daemon
            .update_sources(TOKEN, vec![codex_health()])
            .expect("fresh source scan should not clear failed verification");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::Codex);
        assert_eq!(status.sources[0].state, SourceState::Failed);
        assert_eq!(status.sources[0].grade, HealthGrade::Critical);
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::TelemetryNotVerified
        );
        assert_eq!(
            status.sources[0].recommended_actions[0].action,
            RepairActionKind::VerifyTelemetry
        );
    }

    #[test]
    fn available_pi_route_status_clears_stale_aggregate_smoke_failure() {
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
                text: "No Pi model routes passed smoke verification.".to_string(),
            },
            route_results: Vec::new(),
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

    #[test]
    fn available_agent_status_does_not_stamp_verification_authority() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:20:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after refresh");
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert!(
            status.sources[0].last_verified_at.is_none(),
            "local availability scans must not masquerade as Verify attempts"
        );
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Codex)
            .expect("Codex source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
    }

    #[test]
    fn available_agent_status_clears_no_fresh_telemetry_verification() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::NoFreshTelemetry,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "no_fresh_telemetry".to_string(),
                text: "No fresh Codex telemetry was processed after the smoke prompt.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record verification");
        let before_scan = daemon.status(TOKEN).expect("status before scan");
        let attempt_at = before_scan.sources[0]
            .last_verified_at
            .clone()
            .expect("failed verify attempt timestamp");
        assert_eq!(before_scan.sources[0].state, SourceState::NeedsConfirmation);

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:40:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after scan");
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].last_verified_at.is_none());
        assert!(status.sources[0].problems.is_empty());
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Codex)
            .expect("Codex source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
        assert_eq!(source.authority_at, "2026-05-05T10:40:00Z");
        assert!(
            status
                .command_ledger
                .iter()
                .any(|entry| entry.observed_at == attempt_at),
            "the soft verify attempt remains in the ledger for support triage"
        );
    }

    #[test]
    fn available_agent_status_clears_smoke_timeout_verification() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let result = SourceVerificationResult {
            source: SourceKind::Codex,
            config: SourceConfigState {
                discovered: true,
                path_hint: Some("~/.codex/config.toml".to_string()),
                fingerprint: Some("sha256:test".to_string()),
                drift: Vec::new(),
            },
            status: SourceVerificationStatus::Failed,
            verified: false,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "smoke_timeout".to_string(),
                text: "Codex smoke session timed out before telemetry could be sent.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record smoke timeout verification");
        let before_scan = daemon.status(TOKEN).expect("status before scan");
        let attempt_at = before_scan.sources[0]
            .last_verified_at
            .clone()
            .expect("failed verify attempt timestamp");
        assert_eq!(before_scan.sources[0].state, SourceState::Failed);

        {
            let mut state = daemon.inner.lock().expect("state");
            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::Codex, "2026-05-05T10:40:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after scan");
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].last_verified_at.is_none());
        assert!(status.sources[0].problems.is_empty());
        assert!(status
            .command_ledger
            .iter()
            .any(|entry| entry.observed_at == attempt_at
                && entry.status == LocalHealthCommandStatus::Failed
                && entry.error_code.as_deref() == Some("smoke_timeout")));
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Codex)
            .expect("Codex source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
        assert_eq!(source.authority_at, "2026-05-05T10:40:00Z");
    }

    #[test]
    fn available_agent_status_clears_stale_quota_verification_problem() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut stale = codex_health();
        stale.source = SourceKind::ClaudeCode;
        stale.descriptor = source_descriptor(&SourceKind::ClaudeCode);
        stale.state = SourceState::NeedsConfirmation;
        stale.grade = HealthGrade::Warning;
        stale.config = SourceConfigState {
            discovered: true,
            path_hint: None,
            fingerprint: None,
            drift: Vec::new(),
        };
        stale.last_seen_at = Some("2026-05-05T10:00:00Z".to_string());
        stale.last_verified_at = Some("2026-05-05T10:01:00Z".to_string());
        stale.problems = vec![HealthProblem {
            code: StableProblemCode::TelemetryNotVerified,
            title: "Telemetry not verified".to_string(),
            detail: "Claude Code is signed in, but its usage limit is reached. Wait for quota to reset or update usage, then retry Verify.".to_string(),
            retryable: true,
        }];
        stale.recommended_actions = Vec::new();
        daemon
            .update_sources(TOKEN, vec![stale])
            .expect("seed stale quota state");

        let before_scan = daemon.status(TOKEN).expect("status before scan");
        assert_eq!(before_scan.sources[0].state, SourceState::NeedsConfirmation);
        assert_eq!(
            before_scan.canonical_health.as_ref().unwrap().sources[0]
                .blocking_reason
                .as_deref(),
            Some("smoke_quota_limited")
        );

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
        assert!(status.sources[0].last_verified_at.is_none());
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::ClaudeCode)
            .expect("Claude Code source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Runtime);
        assert!(source.blocking_reason.is_none());
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
                text: "Pi provider OAuth re-auth is required before telemetry can be trusted."
                    .to_string(),
            },
            route_results: Vec::new(),
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
    fn pi_local_only_verification_projects_non_blocking_health() {
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
            verified: true,
            records_seen: 0,
            last_record_id: None,
            last_received_at: None,
            smoke_after: Some("2026-05-05T10:00:00Z".to_string()),
            message: StableMessage {
                code: "pi_local_only".to_string(),
                text: "Verified Pi from local session evidence. Live telemetry is not required."
                    .to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record local-only verification");

        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Warning);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
        let command = status
            .command_ledger
            .iter()
            .find(|entry| entry.action_id == "verify_pi")
            .expect("verify command ledger entry");
        assert_eq!(command.status, LocalHealthCommandStatus::Succeeded);
        assert!(command.error_code.is_none());
        assert!(status
            .local_health_events
            .iter()
            .any(|event| event.event_type == "VerifyPassed"));
        let source = status
            .canonical_health
            .expect("canonical health")
            .sources
            .into_iter()
            .find(|source| source.app == SourceKind::Pi)
            .expect("Pi source");
        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Verify);
        assert!(source.blocking_reason.is_none());
    }

    #[test]
    fn quota_limited_verification_projects_non_blocking_local_health() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let detail = "Claude Code is signed in, but its usage limit is reached. Wait for quota to reset or update usage, then retry Verify.";
        let result = SourceVerificationResult {
            source: SourceKind::ClaudeCode,
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
                code: "smoke_quota_limited".to_string(),
                text: detail.to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record quota-limited verification");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Warning);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].recommended_actions.is_empty());
        let command = status
            .command_ledger
            .iter()
            .find(|entry| entry.action_id == "verify_claude_code")
            .expect("verify command ledger entry");
        assert_eq!(command.status, LocalHealthCommandStatus::Succeeded);
        assert!(command.error_code.is_none());

        let health = status.canonical_health.expect("canonical health");
        let source = health
            .sources
            .iter()
            .find(|source| source.app == SourceKind::ClaudeCode)
            .expect("Claude Code source");

        assert_eq!(source.state, LocalHealthSourceState::Healthy);
        assert_eq!(source.authority, LocalHealthAuthority::Verify);
        assert!(source.blocking_reason.is_none());
        assert!(source.clear_condition.is_none());
        assert!(
            health
                .blockers
                .iter()
                .all(|blocker| blocker.code != "smoke_quota_limited"),
            "quota-only verification should not produce a source blocker"
        );
    }

    #[test]
    fn reconnect_required_verification_updates_source_health() {
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
                text: "Use Sign in in the Ottto app to refresh it.".to_string(),
            },
            route_results: Vec::new(),
        };

        daemon
            .record_verification_result(&result)
            .expect("record reconnect result");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].state, SourceState::Failed);
        assert_eq!(status.sources[0].grade, HealthGrade::Critical);
        assert_eq!(
            status.sources[0].problems[0].code,
            StableProblemCode::TelemetryNotVerified
        );
        assert_eq!(
            status.sources[0].recommended_actions[0].action,
            RepairActionKind::VerifyTelemetry
        );
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
    fn health_detected_uses_prunes_stale_cache_rows() {
        let detected = vec![
            DetectedUse {
                gateway_provider: "anthropic".to_string(),
                plan_fingerprint: None,
                account_identifier_hash: None,
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
            .record_reconciliation_enabled(SourceKind::Codex, true)
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
    fn first_seen_is_in_memory_only_without_a_state_dir() {
        // Without a configured state dir the daemon still reports connected_at
        // for the current session but writes nothing to disk.
        let daemon = daemon();
        daemon
            .record_verification_result(&verified_codex("2026-05-05T10:15:00Z"))
            .expect("record verification");
        let status = daemon.status(TOKEN).expect("status");
        assert_eq!(
            status.sources[0].connected_at.as_deref(),
            Some("2026-05-05T10:15:00Z")
        );
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
            .with_registered_device_sources(Some(LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["codex".to_string()],
            }));
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
            .with_registered_device_sources(Some(LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["codex".to_string()],
            }));
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
        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources(Some(device));

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
            })
            .expect("seed source state");

        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_source_state_dir(dir.clone())
            .with_registered_device_sources(Some(LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["codex".to_string()],
            }));
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
    fn startup_reverify_promotes_available_seeded_source() {
        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_registered_device_sources(Some(LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["codex".to_string()],
            }));

        let mut state = restarted.inner.lock().expect("state");
        assert_eq!(state.sources[0].state, SourceState::Verifying);

        let remaining = apply_verifying_reconfirm(
            &mut state,
            vec![available_agent_status(
                SourceKind::Codex,
                "2026-05-05T10:20:00Z",
            )],
        );

        assert_eq!(remaining, 0);
        assert_eq!(state.sources[0].state, SourceState::Healthy);
        assert_eq!(state.sources[0].grade, HealthGrade::Ok);
    }

    #[test]
    fn startup_reverify_leaves_cold_cli_source_verifying() {
        // A non-`Available` scan right after boot is far more likely a cold CLI
        // than a real regression, so the seeded `verifying` row is preserved
        // (no spurious attention flash). The burst retries on a later tick.
        let restarted = daemon()
            .with_account(account("user_1", "ron@example.com"))
            .with_registered_device_sources(Some(LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("machine_test".to_string()),
                sources: vec!["codex".to_string()],
            }));

        let mut state = restarted.inner.lock().expect("state");
        let mut cold = available_agent_status(SourceKind::Codex, "2026-05-05T10:20:00Z");
        cold.status = AgentStatusState::AuthRequired;

        let remaining = apply_verifying_reconfirm(&mut state, vec![cold]);

        assert_eq!(remaining, 1);
        assert_eq!(state.sources[0].state, SourceState::Verifying);
        assert!(state.sources[0].agent_status.is_none());
    }

    #[test]
    fn startup_reverify_does_not_clobber_explicit_verify_result() {
        // A source that an explicit Verify already moved out of `verifying`
        // (e.g. needs_confirmation after a no-fresh-telemetry smoke) must not be
        // promoted back to healthy by a racing startup scan.
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        let mut state = daemon.inner.lock().expect("state");
        let mut confirmed = codex_health();
        confirmed.state = SourceState::NeedsConfirmation;
        confirmed.grade = HealthGrade::Warning;
        state.sources = vec![confirmed];

        let remaining = apply_verifying_reconfirm(
            &mut state,
            vec![available_agent_status(
                SourceKind::Codex,
                "2026-05-05T10:20:00Z",
            )],
        );

        assert_eq!(remaining, 0);
        assert_eq!(state.sources[0].state, SourceState::NeedsConfirmation);
    }

    #[test]
    fn available_agent_status_clears_stale_needs_confirmation() {
        let daemon = daemon().with_account(account("user_1", "ron@example.com"));
        {
            let mut state = daemon.inner.lock().expect("state");
            let mut stale = codex_health();
            stale.source = SourceKind::ClaudeCode;
            stale.descriptor = source_descriptor(&SourceKind::ClaudeCode);
            stale.state = SourceState::NeedsConfirmation;
            stale.grade = HealthGrade::Warning;
            stale.config.path_hint = Some("~/.claude/settings.json".to_string());
            stale.problems = vec![HealthProblem {
                code: StableProblemCode::SecretMissing,
                title: "Claude Code needs account confirmation".to_string(),
                detail: "Ottto could not confirm a signed-in local account from safe CLI metadata."
                    .to_string(),
                retryable: true,
            }];
            state.sources = vec![stale];

            upsert_agent_status_snapshot(
                &mut state,
                available_agent_status(SourceKind::ClaudeCode, "2026-05-05T10:20:00Z"),
            );
        }

        let status = daemon.status(TOKEN).expect("status after refresh");
        assert_eq!(status.sources.len(), 1);
        assert_eq!(status.sources[0].source, SourceKind::ClaudeCode);
        assert_eq!(status.sources[0].state, SourceState::Healthy);
        assert_eq!(status.sources[0].grade, HealthGrade::Ok);
        assert!(status.sources[0].problems.is_empty());
        assert!(status.sources[0].last_verified_at.is_none());
        assert_eq!(
            status.sources[0].config.path_hint.as_deref(),
            Some("~/.claude/settings.json")
        );
        assert!(status.sources[0].agent_status.is_some());
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

        // After a legacy Codex key is stored, Codex also reports configured.
        keychain::TelemetryKeyStore::production()
            .save(&SourceKind::Codex, "key_test", "secret")
            .expect("save telemetry key");
        assert_eq!(
            telemetry_configured_for_source(&SourceKind::Codex),
            Some(true)
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
            .record_reconciliation_enabled(SourceKind::Codex, true)
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
            account_identifier_hash: Some("acct_hash".to_string()),
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("local_status".to_string()),
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
        snapshot.quota_windows = vec![AgentQuotaWindow {
            name: "weekly".to_string(),
            scope: ottto_protocol::AgentQuotaWindowScope::Account,
            status: AgentQuotaWindowStatus::Ok,
            freshness: AgentQuotaWindowFreshness::Fresh,
            model: None,
            account_label: Some("ron@example.com".to_string()),
            window_seconds: Some(604_800),
            started_at: Some("2026-05-04T00:00:00Z".to_string()),
            resets_at: Some("2026-05-11T00:00:00Z".to_string()),
            quota: Some(100),
            remaining: Some(42),
            used_percent: Some(58),
            left_percent: Some(42),
        }];
        snapshot.plan_observations = vec![ottto_protocol::AgentStatusPlanObservation {
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
                text: "Saw recent Codex telemetry.".to_string(),
            },
            route_results: Vec::new(),
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
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for TestEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
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
            last_seen_at: Some("2026-05-05T09:09:00Z".to_string()),
            last_verified_at: Some("2026-05-05T09:09:30Z".to_string()),
            problems: Vec::new(),
            recommended_actions: Vec::new(),
            connected_at: Some("2026-05-05T09:00:00Z".to_string()),
            telemetry_configured: Some(true),
            reconciliation_enabled: Some(true),
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
            claim_code: None,
            api_base_url: "https://api.ottto.net".to_string(),
        }
    }
}
