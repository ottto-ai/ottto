use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const PROTOCOL_VERSION: u16 = 11;
pub const LOCAL_CONTROL_PROTOCOL_VERSION: u16 = PROTOCOL_VERSION;
pub const DIAGNOSTICS_RETENTION_DISCLOSURE: &str =
    "Uploaded diagnostics are retained by Ottto support for 30 days and may be attached to the support request.";

pub type Rfc3339Timestamp = String;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Macos,
    Windows,
    Linux,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Codex,
    ClaudeCode,
    Pi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthGrade {
    Ok,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Healthy,
    NeedsRepair,
    NeedsConfirmation,
    NotFound,
    Verifying,
    Failed,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentity {
    pub machine_id: String,
    pub installation_id: String,
    pub display_name: String,
    pub hostname: String,
    pub os: OperatingSystem,
    pub arch: String,
    pub local_platform_version: String,
    /// Raw hardware identifier (e.g. macOS `IOPlatformUUID`). Populated when
    /// available so the backend can dedup the same physical machine even if
    /// `machine_id` differs across reinstalls (ioreg-fallback vs. canonical).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_uuid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub protocol_version: u16,
    pub daemon_version: String,
    pub machine: MachineIdentity,
    pub account: LocalAccountBinding,
    pub daemon: DaemonRuntimeState,
    pub relay: RelayState,
    pub sources: Vec<SourceHealth>,
    pub update: UpdateState,
    pub generated_at: Rfc3339Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccountBinding {
    pub state: LocalAccountState,
    pub user: Option<LocalAccountUser>,
    pub organization: Option<LocalAccountOrganization>,
    pub connected_at: Option<Rfc3339Timestamp>,
    pub last_refreshed_at: Option<Rfc3339Timestamp>,
    pub message: Option<StableMessage>,
}

impl LocalAccountBinding {
    pub fn not_connected() -> Self {
        Self {
            state: LocalAccountState::NotConnected,
            user: None,
            organization: None,
            connected_at: None,
            last_refreshed_at: None,
            message: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalAccountState {
    NotConnected,
    ClaimPending,
    Connected,
    ResetRequired,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccountUser {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccountOrganization {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStartResponse {
    pub account: LocalAccountBinding,
    pub claim_code: String,
    pub claim_url: String,
    pub nonce: String,
    pub expires_at: Rfc3339Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCompleteResponse {
    pub account: LocalAccountBinding,
    pub setup_run_id: String,
    pub setup_run_token_expires_at: Rfc3339Timestamp,
    pub machine_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResetResponse {
    pub account: LocalAccountBinding,
    pub removed_account: Option<LocalAccountBinding>,
    pub local_only: bool,
    pub cloud_disconnected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<Rfc3339Timestamp>,
    pub message: StableMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonRuntimeState {
    Running,
    Starting,
    Stopping,
    RepairLocked,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayState {
    pub state: RelayRuntimeState,
    pub endpoint: Option<String>,
    pub last_connected_at: Option<Rfc3339Timestamp>,
    pub last_error: Option<StableMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRuntimeState {
    Connected,
    Disconnected,
    Starting,
    Stopping,
    Disabled,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    pub source: SourceKind,
    pub descriptor: SourceDescriptor,
    pub state: SourceState,
    pub grade: HealthGrade,
    pub account_binding: AccountBindingState,
    pub config: SourceConfigState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<LocalCollectorHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_status: Option<AgentStatusSnapshot>,
    #[serde(default)]
    pub plan_observations: Vec<AgentStatusPlanObservation>,
    pub last_seen_at: Option<Rfc3339Timestamp>,
    pub last_verified_at: Option<Rfc3339Timestamp>,
    pub problems: Vec<HealthProblem>,
    pub recommended_actions: Vec<RepairAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDescriptor {
    pub source: SourceKind,
    pub display_name: String,
    pub operations: Vec<SourceOperationDescriptor>,
    pub review_tier: ConnectorReviewTier,
    pub maturity: ConnectorMaturity,
    pub collectors: Vec<CollectorDescriptor>,
    pub local_state_owner: SourceStateOwner,
    pub telemetry_owner: SourceStateOwner,
    pub repair_owner: SourceStateOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorDescriptor {
    pub collector_id: String,
    pub display_name: String,
    pub operations: Vec<SourceOperation>,
    pub data_source_kind: CollectorDataSourceKind,
    pub default_state: CollectorDefaultState,
    pub review_tier: ConnectorReviewTier,
    pub maturity: ConnectorMaturity,
    pub risk_classes: Vec<CollectorRiskClass>,
    pub uploads_raw_content: bool,
    pub emits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorReviewTier {
    Official,
    OtttoLabs,
    ReviewedCommunity,
    Community,
    CustomLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorMaturity {
    Stable,
    Beta,
    Experimental,
    UndocumentedSurface,
    WritesConfig,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorDataSourceKind {
    LocalEnriched,
    LiveTelemetry,
    IntegrationConnector,
    CloudBillingConnector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorDefaultState {
    Enabled,
    RequiresSetup,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorRiskClass {
    AuthAdjacent,
    NetworkCalls,
    HiddenCredentialRead,
    RawPromptOrOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStateOwner {
    LocalDaemon,
    Backend,
    CompanionClient,
    ExternalApp,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOperationDescriptor {
    pub operation: SourceOperation,
    pub supported: bool,
    pub state: SourceOperationState,
    pub requires_approval: bool,
    pub destructive: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOperation {
    Detect,
    Verify,
    Repair,
    CollectUsage,
    MonitorQuota,
    UploadSnapshot,
    Diagnostics,
    UninstallRestore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOperationState {
    Available,
    RequiresSetup,
    Degraded,
    Unsupported,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusSnapshot {
    pub source: SourceKind,
    pub status: AgentStatusState,
    pub collection_method: AgentStatusCollectionMethod,
    pub captured_at: Rfc3339Timestamp,
    pub expires_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<AgentAccountStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<AgentModelStatus>,
    #[serde(default)]
    pub quota_windows: Vec<AgentQuotaWindow>,
    #[serde(default)]
    pub credit_balances: Vec<AgentCreditBalance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<AgentContextStatus>,
    #[serde(default)]
    pub capabilities: Vec<AgentCapabilityGap>,
    #[serde(default)]
    pub plan_observations: Vec<AgentStatusPlanObservation>,
    #[serde(default)]
    pub diagnostics: Vec<AgentStatusDiagnostic>,
}

impl AgentStatusSnapshot {
    pub fn redacted_for_backend(mut self) -> Self {
        if let Some(account) = self.account.as_mut() {
            account.email = safe_optional_text(account.email.take());
            account.account_id = None;
            account.organization_id = None;
            account.organization_label = None;
            account.provider = safe_optional_text(account.provider.take());
            account.auth_method = safe_optional_text(account.auth_method.take());
            account.plan_type = safe_optional_text(account.plan_type.take());
            account.subscription_product = safe_optional_text(account.subscription_product.take());
            account.billing_channel = safe_optional_text(account.billing_channel.take());
            account.account_identifier_hash =
                safe_optional_text(account.account_identifier_hash.take());
            account.organization_identifier_hash =
                safe_optional_text(account.organization_identifier_hash.take());
            account.credential_fingerprint_hash =
                safe_optional_text(account.credential_fingerprint_hash.take());
            account.billing_identity_evidence =
                safe_optional_text(account.billing_identity_evidence.take());
        }

        if let Some(model) = self.model.as_mut() {
            model.active_model = safe_optional_text(model.active_model.take());
            model.default_model = safe_optional_text(model.default_model.take());
            model.provider = safe_optional_text(model.provider.take());
            model.available_models = model
                .available_models
                .drain(..)
                .filter(|value| is_safe_backend_text(value))
                .collect();
            model.available_model_details = model
                .available_model_details
                .drain(..)
                .filter_map(redact_available_model_for_backend)
                .collect();
        }

        self.capabilities = self
            .capabilities
            .drain(..)
            .filter_map(redact_capability_for_backend)
            .collect();
        self.credit_balances = self
            .credit_balances
            .drain(..)
            .filter_map(redact_credit_balance_for_backend)
            .collect();
        self.plan_observations = self
            .plan_observations
            .drain(..)
            .map(redact_plan_observation_for_backend)
            .collect();
        self.diagnostics = self
            .diagnostics
            .drain(..)
            .map(redact_diagnostic_for_backend)
            .collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatusState {
    Available,
    Degraded,
    AuthRequired,
    NotInstalled,
    Unsupported,
    Error,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatusCollectionMethod {
    AppServer,
    CliJson,
    CliText,
    ConfigFile,
    StatusLine,
    CommandProbe,
    ManualFallback,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAccountStatus {
    pub login_state: AgentLoginState,
    pub provider: Option<String>,
    pub auth_method: Option<String>,
    pub email: Option<String>,
    pub account_id: Option<String>,
    pub organization_id: Option<String>,
    pub organization_label: Option<String>,
    pub plan_type: Option<String>,
    pub subscription_product: Option<String>,
    pub billing_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_identity_evidence: Option<String>,
    #[serde(default)]
    pub billing_identity_confidence: AgentStatusConfidence,
    pub confidence: AgentStatusConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusPlanObservation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_identity_evidence: Option<String>,
    #[serde(default)]
    pub billing_identity_confidence: AgentStatusConfidence,
    pub confidence: AgentStatusConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_current: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoginState {
    SignedIn,
    SignedOut,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatusConfidence {
    High,
    Medium,
    Low,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentModelStatus {
    pub active_model: Option<String>,
    pub default_model: Option<String>,
    pub provider: Option<String>,
    pub available_models: Vec<String>,
    #[serde(default)]
    pub available_model_details: Vec<AgentAvailableModelStatus>,
    pub context_window_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAvailableModelStatus {
    pub id: String,
    pub provider: Option<String>,
    pub model_provider: Option<String>,
    pub billing_provider: Option<String>,
    pub billing_channel: Option<String>,
    pub auth_mode: Option<String>,
    pub gateway_provider: Option<String>,
    pub subscription_product: Option<String>,
    pub source_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_identity_evidence: Option<String>,
    #[serde(default)]
    pub billing_identity_confidence: AgentStatusConfidence,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub supports_thinking: Option<bool>,
    pub supports_images: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentQuotaWindow {
    pub name: String,
    pub scope: AgentQuotaWindowScope,
    pub status: AgentQuotaWindowStatus,
    pub freshness: AgentQuotaWindowFreshness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    pub window_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Rfc3339Timestamp>,
    pub resets_at: Option<Rfc3339Timestamp>,
    pub quota: Option<u64>,
    pub remaining: Option<u64>,
    pub used_percent: Option<u8>,
    pub left_percent: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQuotaWindowScope {
    Source,
    Account,
    Organization,
    Model,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQuotaWindowStatus {
    Ok,
    NearLimit,
    Exhausted,
    RateLimited,
    Unsupported,
    Stale,
    Error,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentQuotaWindowFreshness {
    Fresh,
    Stale,
    Unsupported,
    Error,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCreditBalance {
    pub name: String,
    pub status: AgentCreditBalanceStatus,
    pub freshness: AgentQuotaWindowFreshness,
    #[serde(default)]
    pub unit: AgentCreditBalanceUnit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlimited: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Rfc3339Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCreditBalanceStatus {
    Ok,
    Low,
    Exhausted,
    Unlimited,
    Unsupported,
    Stale,
    Error,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentCreditBalanceUnit {
    Credits,
    Usd,
    Tokens,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContextStatus {
    pub status: AgentContextState,
    pub active_tokens: Option<u64>,
    pub max_tokens: Option<u64>,
    pub used_percent: Option<u8>,
    pub remaining_tokens: Option<u64>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextState {
    Available,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilityGap {
    pub capability: String,
    pub status: AgentCapabilityStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCapabilityStatus {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatusDiagnostic {
    pub code: String,
    pub severity: AgentDiagnosticSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalCollectorState {
    Hot,
    Warm,
    Idle,
    Cold,
    Failing,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCollectorHealth {
    pub state: LocalCollectorState,
    pub last_scan_started_at: Option<Rfc3339Timestamp>,
    pub last_scan_finished_at: Option<Rfc3339Timestamp>,
    pub last_success_at: Option<Rfc3339Timestamp>,
    pub last_uploaded_count: u64,
    pub last_scanned_session_count: u64,
    pub last_scanned_file_count: u64,
    pub last_backfill_window_days: u64,
    pub last_backfill_file_limit: u64,
    pub last_discovered_file_count: u64,
    pub last_skipped_file_count_due_to_limit: u64,
    pub last_scan_cap_hit: bool,
    pub next_retry_at: Option<Rfc3339Timestamp>,
    pub collector_version: Option<String>,
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVerificationResult {
    pub source: SourceKind,
    pub status: SourceVerificationStatus,
    pub verified: bool,
    pub records_seen: u64,
    pub last_record_id: Option<String>,
    pub last_received_at: Option<Rfc3339Timestamp>,
    pub smoke_after: Option<Rfc3339Timestamp>,
    pub message: StableMessage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_results: Vec<SourceRouteVerificationResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRouteVerificationResult {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub model_provider: Option<String>,
    pub billing_provider: Option<String>,
    pub billing_channel: Option<String>,
    pub auth_mode: Option<String>,
    pub gateway_provider: Option<String>,
    pub subscription_product: Option<String>,
    pub source_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_identity_evidence: Option<String>,
    #[serde(default)]
    pub billing_identity_confidence: AgentStatusConfidence,
    pub status: SourceVerificationStatus,
    pub verified: bool,
    pub records_seen: u64,
    pub last_record_id: Option<String>,
    pub last_received_at: Option<Rfc3339Timestamp>,
    pub smoke_after: Option<Rfc3339Timestamp>,
    pub command_found: bool,
    pub command_succeeded: bool,
    pub exit_status: Option<i32>,
    pub duration_ms: u64,
    pub diagnostic: Option<String>,
    pub error_code: Option<String>,
    pub local_session_observed: Option<bool>,
    pub message: StableMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceVerificationStatus {
    Verified,
    Warning,
    NoFreshTelemetry,
    AccountNotConnected,
    ReconnectRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBindingState {
    pub expected_account_id: Option<String>,
    pub observed_account_id: Option<String>,
    pub matched: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceConfigState {
    pub discovered: bool,
    pub path_hint: Option<String>,
    pub fingerprint: Option<String>,
    pub drift: Vec<ConfigDrift>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDrift {
    pub key: String,
    pub expected: RedactedValue,
    pub observed: RedactedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProblem {
    pub code: StableProblemCode,
    pub title: String,
    pub detail: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StableProblemCode {
    ConfigMissing,
    ConfigDrift,
    SecretMissing,
    SecretExpired,
    RelayUnavailable,
    TelemetryNotVerified,
    SourceNotInstalled,
    UnsupportedPlatform,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupRun {
    pub setup_run_id: String,
    pub machine_id: String,
    pub sources: Vec<SourceKind>,
    pub status: SetupStatus,
    pub events: Vec<SetupEvent>,
    pub created_at: Rfc3339Timestamp,
    pub updated_at: Rfc3339Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Pending,
    Running,
    WaitingForApproval,
    Succeeded,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupEvent {
    pub event_id: String,
    pub step: SetupStep,
    pub status: EventStatus,
    pub source: Option<SourceKind>,
    pub message: StableMessage,
    pub occurred_at: Rfc3339Timestamp,
    pub metadata: BTreeMap<String, RedactedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStep {
    ClaimMachine,
    DetectSources,
    RequestApproval,
    WriteConfig,
    RotateSecret,
    StartRelay,
    VerifyTelemetry,
    ImportHistory,
    PublishStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Pending,
    Running,
    Waiting,
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairPlan {
    pub plan_id: String,
    pub machine_id: String,
    pub source: SourceKind,
    pub dry_run: bool,
    pub status: RepairPlanStatus,
    pub authority: RepairAuthority,
    pub actions: Vec<RepairAction>,
    pub created_at: Rfc3339Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairPlanStatus {
    Proposed,
    Running,
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairAction {
    pub action: RepairActionKind,
    pub title: String,
    pub detail: String,
    pub requires_approval: bool,
    pub destructive: bool,
    pub approval: RepairActionApproval,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<RepairBackupMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairAuthority {
    pub mode: RepairAuthorityMode,
    pub server_backed: bool,
    pub terminal_approval_allowed: bool,
    pub browser_approval_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_run_id: Option<String>,
    pub message: StableMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairAuthorityMode {
    ServerBackedSetupAction,
    BrowserApprovalRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairActionApproval {
    pub surface: RepairApprovalSurface,
    pub setup_safe: bool,
    pub server_backed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairApprovalSurface {
    None,
    Terminal,
    Browser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairBackupMetadata {
    pub scope: RepairBackupScope,
    pub required: bool,
    pub restore_available: bool,
    pub backup_id: Option<String>,
    pub target_fingerprint: Option<String>,
    pub restore_operation: Option<SourceOperation>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairBackupScope {
    SourceConfig,
    RelayCredential,
    LocalState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionKind {
    WriteConfig,
    RotateSecret,
    RestartRelay,
    StartRelay,
    StopRelay,
    VerifyTelemetry,
    ImportHistory,
    RevokeSecret,
    RemoveLocalState,
    RestoreBackup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsBundle {
    pub bundle_id: String,
    pub machine_id: String,
    pub created_at: Rfc3339Timestamp,
    pub upload: DiagnosticsUploadReport,
    pub redaction: RedactionReport,
    pub sections: Vec<DiagnosticsSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsSection {
    pub name: String,
    pub status: EventStatus,
    pub items: BTreeMap<String, RedactedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsUploadApproval {
    pub approved: bool,
    pub retention_disclosure_accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_claim: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsUploadReport {
    pub requested: bool,
    pub status: DiagnosticsUploadStatus,
    pub approval_required: bool,
    pub approved: bool,
    pub retention: DiagnosticsRetentionDisclosure,
    pub authorization: DiagnosticsUploadAuthorization,
    #[serde(default)]
    pub support_claim_provided: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<Rfc3339Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsRetentionDisclosure {
    pub accepted: bool,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsUploadStatus {
    LocalOnly,
    Uploaded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsUploadAuthorization {
    NotRequested,
    ConnectedAccount,
    SupportClaim,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallPlan {
    pub plan_id: String,
    pub service_label: String,
    pub launchd_target: String,
    pub actions: Vec<UninstallAction>,
    pub warnings: Vec<String>,
    pub requires_confirmation: bool,
    pub cloud_credentials_untouched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallAction {
    pub action: String,
    pub target: String,
    pub kind: String,
    pub requires_confirmation: bool,
    pub destructive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallExecutionResult {
    pub status: String,
    pub plan: UninstallPlan,
    pub credential_status: String,
    pub removed_paths: Vec<String>,
    pub missing_paths: Vec<String>,
    pub warnings: Vec<String>,
    pub failed_operations: Vec<String>,
    pub cloud_credentials_untouched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionSurface {
    Diagnostics,
    SupportOutput,
    AgentOutput,
    SetupError,
    CommandOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionCategory {
    LocalPath,
    SecretToken,
    AccountIdentifier,
    MachineIdentifier,
    RawPrompt,
    CommandOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionReport {
    pub policy_version: u16,
    pub covered_surfaces: Vec<RedactionSurface>,
    pub redacted_categories: Vec<RedactionCategory>,
    pub redacted_fields: Vec<String>,
    pub preserved_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RedactedValue {
    String(String),
    Bool(bool),
    Number(i64),
    List(Vec<RedactedValue>),
    Object(BTreeMap<String, RedactedValue>),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub channel: ReleaseChannel,
    pub status: UpdateStatus,
    #[serde(default)]
    pub gate: UpdateGate,
    #[serde(default)]
    pub install_owner: InstallOwner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_supported_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_protocol_version: Option<u16>,
    pub checked_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_instructions: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Dev,
    Preview,
    #[serde(rename = "stable-candidate")]
    StableCandidate,
    Stable,
}

#[cfg(test)]
mod release_channel_tests {
    use super::ReleaseChannel;

    #[test]
    fn stable_candidate_uses_public_channel_slug() {
        let encoded = serde_json::to_string(&ReleaseChannel::StableCandidate)
            .expect("serialize stable-candidate channel");
        assert_eq!(encoded, "\"stable-candidate\"");
        let decoded: ReleaseChannel = serde_json::from_str("\"stable-candidate\"")
            .expect("deserialize stable-candidate channel");
        assert_eq!(decoded, ReleaseChannel::StableCandidate);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Current,
    UpdateAvailable,
    Downloading,
    Installing,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateGate {
    Current,
    SoftWarn,
    HardBlock,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InstallOwner {
    Homebrew,
    HostedInstaller,
    AppBundle,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableMessage {
    pub code: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliErrorResponse {
    pub error: CliError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliError {
    pub code: CliErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: BTreeMap<String, RedactedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalControlRequest {
    pub request_id: String,
    #[serde(deserialize_with = "deserialize_local_control_protocol_version")]
    pub protocol_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_kind: Option<LocalClientKind>,
    #[serde(flatten)]
    pub command: LocalControlCommand,
}

fn deserialize_local_control_protocol_version<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u16::deserialize(deserializer)?;
    if version != LOCAL_CONTROL_PROTOCOL_VERSION {
        return Err(serde::de::Error::custom(format!(
            "unsupported local control protocol_version {version}; expected {LOCAL_CONTROL_PROTOCOL_VERSION}"
        )));
    }
    Ok(version)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalClientKind {
    Cli,
    CompanionApp,
    WebUi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum LocalControlCommand {
    Status {
        #[serde(default)]
        refresh_agent_status: bool,
    },
    AuthStatus,
    AgentStatusRefresh {
        source: Option<SourceKind>,
    },
    AuthStart,
    AuthComplete {
        claim_code: String,
        nonce: String,
    },
    AuthReset {
        #[serde(default)]
        local_only: bool,
    },
    Account,
    Detect {
        source: SourceKind,
    },
    Setup {
        sources: Vec<SourceKind>,
        claim_code: Option<String>,
        setup_run_id: Option<String>,
        api_base_url: Option<String>,
    },
    SetupAnswer {
        source: SourceKind,
        answer_type: String,
        api_base_url: Option<String>,
    },
    SetupAction {
        source: SourceKind,
        action_type: String,
        api_base_url: Option<String>,
    },
    TelemetryControl {
        action: TelemetryControlAction,
        source: SourceKind,
        control_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base_url: Option<String>,
        key_id: Option<String>,
        organization_id: Option<String>,
        otlp_endpoint: Option<String>,
        ingest_key: Option<SecretString>,
    },
    Repair {
        source: SourceKind,
        dry_run: bool,
    },
    Verify {
        source: SourceKind,
    },
    RelayStart,
    RelayStop,
    DiagnosticsCollect {
        #[serde(default)]
        upload: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upload_approval: Option<DiagnosticsUploadApproval>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base_url: Option<String>,
    },
    UpdateCheck,
    UninstallPlan,
    UninstallExecute {
        confirm: bool,
    },
    Uninstall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryControlAction {
    EnableTelemetry,
    DisableTelemetry,
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallationDetection {
    pub source: SourceKind,
    pub installed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_docs_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResult {
    pub action: TelemetryControlAction,
    pub source: SourceKind,
    pub status: ControlResultStatus,
    pub key_id: Option<String>,
    pub requires_restart: bool,
    pub message: StableMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation: Option<AgentInstallationDetection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlResultStatus {
    Accepted,
    Rejected,
    NeedsAttention,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalControlResponse {
    pub request_id: String,
    pub ok: bool,
    pub payload: Option<serde_json::Value>,
    pub error: Option<CliError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CliErrorCode {
    DaemonUnavailable,
    LocalAuthFailed,
    LocalClientNotTrusted,
    AccountResetRequired,
    BackendUnreachable,
    BackendRejected,
    BackendUnavailable,
    BackendResponseUnexpected,
    SourceUnsupported,
    SourceNotFound,
    RepairLocked,
    NetworkUnavailable,
    PermissionDenied,
    ManualFenceReviewRequired,
    NeedsUserAction,
    TimedOut,
    InvalidRequest,
    Internal,
}

impl CliErrorCode {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliErrorCode::InvalidRequest => 2,
            CliErrorCode::DaemonUnavailable => 10,
            CliErrorCode::LocalAuthFailed => 11,
            CliErrorCode::LocalClientNotTrusted => 12,
            CliErrorCode::AccountResetRequired => 13,
            CliErrorCode::BackendUnreachable => 14,
            CliErrorCode::BackendRejected => 15,
            CliErrorCode::BackendUnavailable => 16,
            CliErrorCode::BackendResponseUnexpected => 17,
            CliErrorCode::SourceUnsupported => 20,
            CliErrorCode::SourceNotFound => 21,
            CliErrorCode::RepairLocked => 30,
            CliErrorCode::NetworkUnavailable => 40,
            CliErrorCode::PermissionDenied => 50,
            CliErrorCode::ManualFenceReviewRequired => 50,
            CliErrorCode::NeedsUserAction => 60,
            CliErrorCode::TimedOut => 61,
            CliErrorCode::Internal => 70,
        }
    }
}

fn safe_optional_text(value: Option<String>) -> Option<String> {
    value.filter(|text| is_safe_backend_text(text))
}

fn is_safe_backend_text(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    if normalized.trim().is_empty() {
        return false;
    }
    let forbidden_fragments = [
        "/users/",
        "\\users\\",
        "/home/",
        "\\home\\",
        "/.codex",
        "\\.codex",
        "/.claude",
        "\\.claude",
        "/.pi/",
        "\\.pi\\",
        "authorization:",
        "bearer ",
        "otdev_",
        "otsi_",
        "otsr_",
        "otsct_",
        "otel_",
        "otrelay_",
        "sk-",
    ];
    if forbidden_fragments
        .iter()
        .any(|fragment| normalized.contains(fragment))
    {
        return false;
    }
    let trimmed = normalized.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']' | '{' | '}'
        )
    });
    !(trimmed.starts_with('/')
        || trimmed.starts_with("~/")
        || trimmed.starts_with("file:/")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://"))
}

fn redact_available_model_for_backend(
    mut detail: AgentAvailableModelStatus,
) -> Option<AgentAvailableModelStatus> {
    if !is_safe_backend_text(&detail.id) {
        return None;
    }
    detail.provider = safe_optional_text(detail.provider.take());
    detail.model_provider = safe_optional_text(detail.model_provider.take());
    detail.billing_provider = safe_optional_text(detail.billing_provider.take());
    detail.billing_channel = safe_optional_text(detail.billing_channel.take());
    detail.auth_mode = safe_optional_text(detail.auth_mode.take());
    detail.gateway_provider = safe_optional_text(detail.gateway_provider.take());
    detail.subscription_product = safe_optional_text(detail.subscription_product.take());
    detail.source_category = safe_optional_text(detail.source_category.take());
    detail.account_identifier_hash = safe_optional_text(detail.account_identifier_hash.take());
    detail.organization_identifier_hash =
        safe_optional_text(detail.organization_identifier_hash.take());
    detail.credential_fingerprint_hash =
        safe_optional_text(detail.credential_fingerprint_hash.take());
    detail.billing_identity_evidence = safe_optional_text(detail.billing_identity_evidence.take());
    Some(detail)
}

fn redact_capability_for_backend(mut capability: AgentCapabilityGap) -> Option<AgentCapabilityGap> {
    if !is_safe_backend_text(&capability.capability) {
        return None;
    }
    capability.detail = safe_optional_text(capability.detail.take());
    Some(capability)
}

fn redact_credit_balance_for_backend(mut credit: AgentCreditBalance) -> Option<AgentCreditBalance> {
    if !is_safe_backend_text(&credit.name) {
        return None;
    }
    credit.account_label = None;
    Some(credit)
}

fn redact_plan_observation_for_backend(
    mut observation: AgentStatusPlanObservation,
) -> AgentStatusPlanObservation {
    observation.evidence_method = safe_optional_text(observation.evidence_method.take());
    observation.source_session_id = safe_optional_text(observation.source_session_id.take());
    observation.provider = safe_optional_text(observation.provider.take());
    observation.billing_provider = safe_optional_text(observation.billing_provider.take());
    observation.model_provider = safe_optional_text(observation.model_provider.take());
    observation.billing_channel = safe_optional_text(observation.billing_channel.take());
    observation.auth_mode = safe_optional_text(observation.auth_mode.take());
    observation.gateway_provider = safe_optional_text(observation.gateway_provider.take());
    observation.subscription_product = safe_optional_text(observation.subscription_product.take());
    observation.plan_type = safe_optional_text(observation.plan_type.take());
    observation.account_label = None;
    observation.account_id = None;
    observation.organization_label = None;
    observation.organization_id = None;
    observation.account_identifier_hash =
        safe_optional_text(observation.account_identifier_hash.take());
    observation.organization_identifier_hash =
        safe_optional_text(observation.organization_identifier_hash.take());
    observation.credential_fingerprint_hash =
        safe_optional_text(observation.credential_fingerprint_hash.take());
    observation.billing_identity_evidence =
        safe_optional_text(observation.billing_identity_evidence.take());
    observation
}

fn redact_diagnostic_for_backend(mut diagnostic: AgentStatusDiagnostic) -> AgentStatusDiagnostic {
    if !is_safe_backend_text(&diagnostic.code) {
        diagnostic.code = "redacted".to_string();
    }
    if !is_safe_backend_text(&diagnostic.message) {
        diagnostic.message = "diagnostic redacted".to_string();
    }
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_exit_codes_are_stable() {
        assert_eq!(CliErrorCode::InvalidRequest.exit_code(), 2);
        assert_eq!(CliErrorCode::DaemonUnavailable.exit_code(), 10);
        assert_eq!(CliErrorCode::BackendUnavailable.exit_code(), 16);
        assert_eq!(CliErrorCode::BackendResponseUnexpected.exit_code(), 17);
        assert_eq!(CliErrorCode::PermissionDenied.exit_code(), 50);
        assert_eq!(CliErrorCode::ManualFenceReviewRequired.exit_code(), 50);
        assert_eq!(CliErrorCode::NeedsUserAction.exit_code(), 60);
        assert_eq!(CliErrorCode::TimedOut.exit_code(), 61);
        assert_eq!(CliErrorCode::Internal.exit_code(), 70);
    }

    #[test]
    fn setup_answer_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_setup_answer",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "companion_app",
            "command": "setup_answer",
            "source": "pi",
            "answer_type": "skip_source"
        }))
        .expect("setup answer request");

        assert_eq!(request.request_id, "req_setup_answer");
        assert_eq!(request.client_kind, Some(LocalClientKind::CompanionApp));
        assert_eq!(
            request.command,
            LocalControlCommand::SetupAnswer {
                source: SourceKind::Pi,
                answer_type: "skip_source".to_string(),
                api_base_url: None,
            }
        );
    }

    #[test]
    fn setup_action_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_setup_action",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "companion_app",
            "command": "setup_action",
            "source": "codex",
            "action_type": "install_source"
        }))
        .expect("setup action request");

        assert_eq!(request.request_id, "req_setup_action");
        assert_eq!(request.client_kind, Some(LocalClientKind::CompanionApp));
        assert_eq!(
            request.command,
            LocalControlCommand::SetupAction {
                source: SourceKind::Codex,
                action_type: "install_source".to_string(),
                api_base_url: None,
            }
        );
    }

    #[test]
    fn auth_reset_defaults_to_cloud_first() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_auth_reset",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "companion_app",
            "command": "auth_reset"
        }))
        .expect("legacy auth reset request");

        assert_eq!(
            request.command,
            LocalControlCommand::AuthReset { local_only: false }
        );

        let local_only: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_auth_reset_local",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "auth_reset",
            "local_only": true
        }))
        .expect("local-only auth reset request");

        assert_eq!(
            local_only.command,
            LocalControlCommand::AuthReset { local_only: true }
        );
    }

    #[test]
    fn telemetry_control_command_round_trips_with_redacted_secret_debug() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_telemetry_enable",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "web_ui",
            "command": "telemetry_control",
            "action": "enable_telemetry",
            "source": "codex",
            "control_token": "header.payload.signature",
            "api_base_url": "https://api.ottto.net",
            "key_id": "key_123",
            "organization_id": "org_123",
            "otlp_endpoint": "https://api.ottto.net",
            "ingest_key": "transit_secret_for_tests"
        }))
        .expect("telemetry control request");

        assert_eq!(request.client_kind, Some(LocalClientKind::WebUi));
        assert_eq!(
            request.command,
            LocalControlCommand::TelemetryControl {
                action: TelemetryControlAction::EnableTelemetry,
                source: SourceKind::Codex,
                control_token: "header.payload.signature".to_string(),
                api_base_url: Some("https://api.ottto.net".to_string()),
                key_id: Some("key_123".to_string()),
                organization_id: Some("org_123".to_string()),
                otlp_endpoint: Some("https://api.ottto.net".to_string()),
                ingest_key: Some(SecretString::new("transit_secret_for_tests")),
            }
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("transit_secret_for_tests"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn agent_status_backend_redaction_preserves_display_plan_fields() {
        let snapshot = AgentStatusSnapshot {
            source: SourceKind::Codex,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::CliText,
            captured_at: "2026-05-07T00:00:00Z".to_string(),
            expires_at: "2026-05-07T00:05:00Z".to_string(),
            account: Some(AgentAccountStatus {
                login_state: AgentLoginState::SignedIn,
                provider: Some("openai".to_string()),
                auth_method: Some("oauth".to_string()),
                email: Some("ron@example.com".to_string()),
                account_id: Some("acct_private".to_string()),
                organization_id: Some("org_private".to_string()),
                organization_label: Some("Private Org".to_string()),
                plan_type: Some("individual".to_string()),
                subscription_product: Some("ChatGPT Pro".to_string()),
                billing_channel: Some("subscription".to_string()),
                account_identifier_hash: Some("abc123hash".to_string()),
                organization_identifier_hash: Some("def456hash".to_string()),
                credential_fingerprint_hash: None,
                billing_identity_evidence: Some("provider_account_id".to_string()),
                billing_identity_confidence: AgentStatusConfidence::High,
                confidence: AgentStatusConfidence::High,
            }),
            model: Some(AgentModelStatus {
                active_model: Some("/Users/ron/.codex/private".to_string()),
                default_model: Some("gpt-5.4".to_string()),
                provider: Some("openai".to_string()),
                available_models: vec!["gpt-5.4".to_string(), "/Users/ron/model".to_string()],
                available_model_details: vec![AgentAvailableModelStatus {
                    id: "gpt-5.4".to_string(),
                    provider: Some("openai".to_string()),
                    model_provider: Some("openai".to_string()),
                    billing_provider: Some("openai".to_string()),
                    billing_channel: Some("subscription".to_string()),
                    auth_mode: Some("oauth".to_string()),
                    gateway_provider: None,
                    subscription_product: Some("chatgpt".to_string()),
                    source_category: Some("chatgpt_openai_subscription".to_string()),
                    account_identifier_hash: Some("abc123hash".to_string()),
                    organization_identifier_hash: None,
                    credential_fingerprint_hash: None,
                    billing_identity_evidence: Some("provider_account_id".to_string()),
                    billing_identity_confidence: AgentStatusConfidence::High,
                    context_window_tokens: Some(128000),
                    max_output_tokens: Some(16384),
                    supports_thinking: Some(true),
                    supports_images: Some(false),
                }],
                context_window_tokens: Some(128000),
            }),
            quota_windows: Vec::new(),
            credit_balances: vec![AgentCreditBalance {
                name: "credits".to_string(),
                status: AgentCreditBalanceStatus::Exhausted,
                freshness: AgentQuotaWindowFreshness::Fresh,
                unit: AgentCreditBalanceUnit::Credits,
                account_label: Some("ron@example.com".to_string()),
                remaining: Some(0),
                used: None,
                quota: None,
                unlimited: Some(false),
                updated_at: Some("2026-05-07T00:00:00Z".to_string()),
            }],
            context: None,
            capabilities: Vec::new(),
            plan_observations: vec![AgentStatusPlanObservation {
                observed_at: Some("2026-05-07T00:00:00Z".to_string()),
                evidence_method: Some("cli_text".to_string()),
                source_session_id: Some("session-safe".to_string()),
                provider: Some("openai".to_string()),
                billing_provider: Some("openai".to_string()),
                model_provider: Some("openai".to_string()),
                billing_channel: Some("subscription".to_string()),
                auth_mode: Some("oauth".to_string()),
                gateway_provider: None,
                subscription_product: Some("ChatGPT Pro".to_string()),
                plan_type: Some("individual".to_string()),
                account_label: Some("ron@example.com".to_string()),
                account_id: Some("acct_private".to_string()),
                organization_label: Some("Private Org".to_string()),
                organization_id: Some("org_private".to_string()),
                account_identifier_hash: Some("abc123hash".to_string()),
                organization_identifier_hash: Some("def456hash".to_string()),
                credential_fingerprint_hash: None,
                billing_identity_evidence: Some("provider_account_id".to_string()),
                billing_identity_confidence: AgentStatusConfidence::High,
                confidence: AgentStatusConfidence::High,
                is_current: Some(true),
            }],
            diagnostics: vec![AgentStatusDiagnostic {
                code: "stderr".to_string(),
                severity: AgentDiagnosticSeverity::Warning,
                message: "failed reading /Users/ron/.codex/config".to_string(),
            }],
        }
        .redacted_for_backend();

        let account = snapshot.account.expect("account");
        assert_eq!(account.provider.as_deref(), Some("openai"));
        assert_eq!(account.auth_method.as_deref(), Some("oauth"));
        assert_eq!(account.subscription_product.as_deref(), Some("ChatGPT Pro"));
        assert_eq!(account.email.as_deref(), Some("ron@example.com"));
        assert_eq!(account.account_id, None);
        assert_eq!(account.organization_id, None);
        assert_eq!(account.organization_label, None);
        assert_eq!(
            account.account_identifier_hash.as_deref(),
            Some("abc123hash")
        );
        assert_eq!(
            account.billing_identity_evidence.as_deref(),
            Some("provider_account_id")
        );
        let model = snapshot.model.expect("model");
        assert_eq!(model.active_model, None);
        assert_eq!(model.default_model.as_deref(), Some("gpt-5.4"));
        assert_eq!(model.available_models, vec!["gpt-5.4"]);
        assert_eq!(
            snapshot.plan_observations[0]
                .subscription_product
                .as_deref(),
            Some("ChatGPT Pro")
        );
        assert_eq!(snapshot.plan_observations[0].account_label, None);
        assert_eq!(
            snapshot.plan_observations[0]
                .account_identifier_hash
                .as_deref(),
            Some("abc123hash")
        );
        assert_eq!(snapshot.credit_balances[0].account_label, None);
        assert_eq!(snapshot.credit_balances[0].remaining, Some(0));
        assert_eq!(snapshot.diagnostics[0].message, "diagnostic redacted");
    }

    #[test]
    fn golden_fixtures_match_protocol_models() {
        let status = serde_json::from_str::<DaemonStatus>(include_str!(
            "../../../fixtures/status/macos-empty.json"
        ))
        .expect("daemon status fixture should deserialize");
        assert_eq!(status.protocol_version, PROTOCOL_VERSION);

        let source_health = serde_json::from_str::<SourceHealth>(include_str!(
            "../../../fixtures/source-health/codex-needs-repair.json"
        ))
        .expect("source health fixture should deserialize");
        assert_eq!(
            source_health.descriptor.review_tier,
            ConnectorReviewTier::Official
        );
        assert_eq!(source_health.descriptor.maturity, ConnectorMaturity::Stable);
        assert_eq!(source_health.descriptor.collectors.len(), 3);

        serde_json::from_str::<SetupRun>(include_str!("../../../fixtures/setup/claim-run.json"))
            .expect("setup run fixture should deserialize");

        serde_json::from_str::<DiagnosticsBundle>(include_str!(
            "../../../fixtures/diagnostics/redacted-bundle.json"
        ))
        .expect("diagnostics fixture should deserialize");

        serde_json::from_str::<LocalControlRequest>(include_str!(
            "../../../fixtures/control/status-request.json"
        ))
        .expect("control request fixture should deserialize");

        let response = serde_json::from_str::<LocalControlResponse>(include_str!(
            "../../../fixtures/control/status-response.json"
        ))
        .expect("control response fixture should deserialize");
        assert_eq!(
            response
                .payload
                .as_ref()
                .and_then(|payload| payload.get("protocol_version"))
                .and_then(serde_json::Value::as_u64),
            Some(PROTOCOL_VERSION as u64)
        );
    }

    #[test]
    fn repair_plan_requires_authority_metadata() {
        let error = serde_json::from_value::<RepairPlan>(serde_json::json!({
            "plan_id": "plan_clean_cutover",
            "machine_id": "machine_clean_cutover",
            "source": "codex",
            "dry_run": true,
            "status": "proposed",
            "actions": [],
            "created_at": "2026-05-21T00:00:00Z"
        }))
        .expect_err("repair plans without authority metadata should be rejected");

        assert!(error.to_string().contains("authority"));
    }

    #[test]
    fn repair_actions_require_approval_metadata() {
        let error = serde_json::from_value::<RepairPlan>(serde_json::json!({
            "plan_id": "plan_clean_cutover",
            "machine_id": "machine_clean_cutover",
            "source": "codex",
            "dry_run": true,
            "status": "proposed",
            "authority": {
                "mode": "browser_approval_required",
                "server_backed": false,
                "terminal_approval_allowed": false,
                "browser_approval_required": true,
                "message": {
                    "code": "browser_approval_required",
                    "text": "Open Ottto in your browser to approve this repair."
                }
            },
            "actions": [
                {
                    "action": "write_config",
                    "title": "Write config",
                    "detail": "Prepare a source config repair.",
                    "requires_approval": true,
                    "destructive": false
                }
            ],
            "created_at": "2026-05-21T00:00:00Z"
        }))
        .expect_err("repair actions without approval metadata should be rejected");

        assert!(error.to_string().contains("approval"));
    }

    #[test]
    fn diagnostics_collect_without_upload_fields_defaults_to_local_only() {
        let request = serde_json::from_str::<LocalControlRequest>(
            r#"{"request_id":"req_test","protocol_version":11,"command":"diagnostics_collect"}"#,
        )
        .expect("current local-only diagnostics request should deserialize");

        assert_eq!(
            request.command,
            LocalControlCommand::DiagnosticsCollect {
                upload: false,
                upload_approval: None,
                api_base_url: None,
            }
        );
    }

    #[test]
    fn local_control_request_requires_protocol_version() {
        let error = serde_json::from_str::<LocalControlRequest>(
            r#"{"request_id":"req_missing","command":"status"}"#,
        )
        .expect_err("missing protocol version should be rejected");

        assert!(error.to_string().contains("protocol_version"));
    }

    #[test]
    fn local_control_request_rejects_stale_protocol_version() {
        let error = serde_json::from_str::<LocalControlRequest>(
            r#"{"request_id":"req_stale","protocol_version":10,"command":"status"}"#,
        )
        .expect_err("stale protocol version should be rejected");

        assert!(error
            .to_string()
            .contains("unsupported local control protocol_version 10"));
        assert!(error.to_string().contains("expected 11"));
    }
}
