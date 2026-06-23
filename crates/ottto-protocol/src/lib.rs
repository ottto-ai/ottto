use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::fmt;

pub const PROTOCOL_VERSION: u16 = 15;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub protocol_version: u16,
    pub daemon_version: String,
    pub machine: MachineIdentity,
    pub account: LocalAccountBinding,
    pub daemon: DaemonRuntimeState,
    #[serde(default)]
    pub service_owner: ServiceOwnerState,
    pub relay: RelayState,
    pub sources: Vec<SourceHealth>,
    pub update: UpdateState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_health: Option<CanonicalLocalHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_heartbeat: Option<MachineRuntimeHeartbeatV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_health_events: Vec<LocalHealthEventV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command_ledger: Vec<LocalHealthCommandResultV1>,
    pub generated_at: Rfc3339Timestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalHealthContractFixture {
    pub fixture_schema_version: String,
    pub case_id: String,
    pub title: String,
    pub contract_version: String,
    pub stable_runtime_version: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_stable_input: Option<serde_json::Value>,
    pub health: LocalMachineHealthV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<MachineRuntimeHeartbeatV1>,
    #[serde(default)]
    pub events: Vec<LocalHealthEventV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<LocalHealthCommandV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_result: Option<LocalHealthCommandResultV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_job: Option<BackfillJobV1>,
    pub expected: LocalHealthFixtureExpectation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthFixtureExpectation {
    pub overall_state: LocalHealthOverallState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_blocker: Option<String>,
    #[serde(default)]
    pub preserved_login: bool,
    #[serde(default)]
    pub preserved_sources: Vec<SourceKind>,
    #[serde(default)]
    pub requires_public_runtime_followup: bool,
    #[serde(default)]
    pub requires_private_consumer_followup: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalMachineHealthV1 {
    pub schema_version: u16,
    pub schema_version_name: String,
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub revision: u64,
    pub projection_revision: u64,
    pub protocol_version: String,
    pub projection_version: String,
    pub event_schema_version: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub observed_at: Rfc3339Timestamp,
    pub computed_at: Rfc3339Timestamp,
    pub fresh_until: Rfc3339Timestamp,
    pub overall: LocalHealthOverall,
    pub runtime: RuntimeIdentityV1,
    pub account: LocalHealthAccountV1,
    #[serde(default)]
    pub sources: Vec<LocalHealthSourceV1>,
    #[serde(default)]
    pub blockers: Vec<LocalHealthBlockerV1>,
    #[serde(default)]
    pub evidence: Vec<LocalHealthEvidenceRefV1>,
}

pub type LocalMachineHealth = LocalMachineHealthV1;
pub type CanonicalLocalHealth = LocalMachineHealthV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthOverall {
    pub state: LocalHealthOverallState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_blocker: Option<String>,
    pub severity: LocalHealthSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthOverallState {
    Healthy,
    Degraded,
    Blocked,
    UpgradeRequired,
    ReconnectRequired,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthSeverity {
    Info,
    Warning,
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeIdentityV1 {
    pub install_owner: InstallOwner,
    pub daemon_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_bundle_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_pid: Option<u32>,
    pub service_executable_path_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_executable_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launchd_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launchd_loaded_program_hash: Option<String>,
    pub started_at: Rfc3339Timestamp,
    pub last_seen_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub version_match: bool,
    pub protocol_match: bool,
    pub schema_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthAccountV1 {
    pub state: LocalHealthAccountState,
    pub device_state: LocalDeviceState,
    pub setup_run_state: LocalSetupRunState,
    pub setup_token_state: LocalSetupTokenState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_controls: Option<OrgTelemetryControlState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgTelemetryControlState {
    pub read_only: bool,
    pub can_mutate_sources: bool,
    pub can_enable_telemetry: bool,
    pub can_disable_telemetry: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthAccountState {
    Connected,
    ReconnectRequired,
    NotConnected,
    ClaimPending,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDeviceState {
    Active,
    Inactive,
    StaleHeartbeat,
    CollisionSuspected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSetupRunState {
    Complete,
    Pending,
    RefreshRequired,
    RebindRequired,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSetupTokenState {
    Valid,
    Expired,
    RefreshRequired,
    Rebound,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthSourceV1 {
    pub source_id: String,
    pub app: SourceKind,
    pub state: LocalHealthSourceState,
    pub authority: LocalHealthAuthority,
    pub authority_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_condition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
    pub projection_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthSourceState {
    Healthy,
    RepairRequired,
    VerifyFailed,
    PendingSetup,
    Removed,
    DisabledByPolicy,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthAuthority {
    Runtime,
    Heartbeat,
    Backend,
    Verify,
    Command,
    Backfill,
    Diagnostics,
    Setup,
    Reducer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthBlockerV1 {
    pub code: String,
    pub severity: LocalHealthSeverity,
    pub owner: String,
    pub source: LocalHealthAuthority,
    pub since: Rfc3339Timestamp,
    pub clear_condition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthEvidenceRefV1 {
    pub event_id: String,
    pub event_type: String,
    pub authority: LocalHealthAuthority,
    pub observed_at: Rfc3339Timestamp,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalHealthEventV1 {
    pub event_id: String,
    pub event_schema_version: String,
    pub event_type: String,
    pub machine_id: String,
    pub observed_at: Rfc3339Timestamp,
    pub sequence: u64,
    pub authority: LocalHealthAuthority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineRuntimeHeartbeatV1 {
    pub schema_version: String,
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub daemon_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_bundle_version: Option<String>,
    pub protocol_version: String,
    pub health_schema_version: String,
    pub executable_path: String,
    pub install_owner: InstallOwner,
    pub launchd_label: String,
    pub started_at: Rfc3339Timestamp,
    pub last_seen_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub health_projection_revision: u64,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalHealthCommandV1 {
    pub action_id: String,
    pub idempotency_key: String,
    pub actor: LocalHealthCommandActor,
    pub target: LocalHealthCommandTarget,
    pub expected_projection_revision: u64,
    pub command_schema_version: String,
    pub command: String,
    pub issued_at: Rfc3339Timestamp,
    pub expires_at: Rfc3339Timestamp,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthCommandActor {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHealthCommandTarget {
    pub machine_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<SourceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalHealthCommandResultV1 {
    pub action_id: String,
    pub idempotency_key: String,
    pub command_schema_version: String,
    pub status: LocalHealthCommandStatus,
    pub terminal: bool,
    pub started_projection_revision: u64,
    pub completed_projection_revision: u64,
    pub observed_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHealthCommandStatus {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Rejected,
    Deduped,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackfillJobV1 {
    pub job_id: String,
    pub machine_id: String,
    pub source_id: String,
    pub app_id: SourceKind,
    pub from: Rfc3339Timestamp,
    pub to: Rfc3339Timestamp,
    pub reason: String,
    pub schema_version: String,
    pub priority: String,
    pub retention_limit: String,
    pub created_at: Rfc3339Timestamp,
    pub expires_at: Rfc3339Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<BackfillJobProgressV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillJobProgressV1 {
    pub status: String,
    pub accepted_chunks: u64,
    pub deduped_chunks: u64,
    pub rejected_chunks: u64,
    pub completed_at: Rfc3339Timestamp,
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
    /// Per-billing-destination usage detected from local session snapshots,
    /// grouped by `(gateway_provider, plan_fingerprint, account_identifier_hash)`.
    /// Populated by the daemon from the snapshot scan; the Companion renders
    /// these in its "Detected Uses" panel. Empty when nothing has been
    /// observed yet (the field is omitted from the wire in that case).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detected_uses: Vec<DetectedUse>,
    pub last_seen_at: Option<Rfc3339Timestamp>,
    pub last_verified_at: Option<Rfc3339Timestamp>,
    pub problems: Vec<HealthProblem>,
    pub recommended_actions: Vec<RepairAction>,
    /// When this source was first observed on this machine (persisted daemon
    /// first-seen, not the in-memory session start). The Companion App v2 shows
    /// it on the source row. Absent on daemons that predate the field, so the
    /// Swift decoder treats it as optional and falls back to an honest blank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<Rfc3339Timestamp>,
    /// Whether a local telemetry key is configured for this source (Codex /
    /// Claude Code only). `None` for sources without local telemetry (e.g. Pi)
    /// and for daemons that predate the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry_configured: Option<bool>,
    /// Whether local usage reconciliation is enabled for this source, per the
    /// most recent workspace activity hint the daemon fetched. `None` when the
    /// daemon has not yet learned the policy (the Companion renders an honest
    /// "managed by workspace" state) and for daemons that predate the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_enabled: Option<bool>,
}

/// One detected billing destination for a source, as observed from local
/// session telemetry. The Companion keys rows on
/// `[gateway_provider, plan_fingerprint ?? "", account_identifier_hash ?? ""]`
/// (see `DetectedUse.id` in the Swift client), so that triple is the grouping
/// key the daemon produces one entry per. Optionals use
/// `skip_serializing_if = "Option::is_none"` to match the Swift lenient
/// decoder, which tolerates absent keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedUse {
    pub gateway_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    pub last_seen_at: Rfc3339Timestamp,
    #[serde(default)]
    pub token_volume_recent: Vec<DetectedUseTokenSample>,
    pub quota_window_state: DetectedUseQuotaWindowState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_used_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_resets_at: Option<Rfc3339Timestamp>,
}

/// One point in a `DetectedUse` token-volume sparkline: the bucket start time
/// and the total tokens attributed to that destination within the bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedUseTokenSample {
    pub at: Rfc3339Timestamp,
    pub tokens: u64,
}

/// Live quota state for the destination that matches the source's current
/// plan. Historical destinations stay `Unknown` (the daemon never smears the
/// current plan's quota across destinations it does not belong to). Matches
/// the Swift `DetectedUseQuotaWindowState` snake_case cases exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedUseQuotaWindowState {
    Ok,
    NearLimit,
    Exhausted,
    RateLimited,
    Stale,
    Error,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalSnapshot {
    pub schema_version: String,
    pub generated_at: Rfc3339Timestamp,
    pub machine_id: String,
    #[serde(default)]
    pub sources: Vec<PersonalMeterLocalSourceSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalSourceSnapshot {
    pub source: SourceKind,
    pub app: String,
    /// Local runtime evidence is never a backend-owned meter total. Consumers
    /// must reconcile it as local freshness/pending evidence only.
    pub included_in_totals: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<PersonalMeterLocalAccount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default)]
    pub quota_windows: Vec<AgentQuotaWindow>,
    pub pending_local_delta: PersonalMeterLocalDelta,
    pub freshness: PersonalMeterLocalFreshness,
    pub collector: PersonalMeterLocalCollector,
    #[serde(default)]
    pub confidence: AgentStatusConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalAccount {
    pub login_state: AgentLoginState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<String>,
    #[serde(default)]
    pub confidence: AgentStatusConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalDelta {
    pub status: PersonalMeterLocalValueStatus,
    pub included_in_totals: bool,
    pub basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd_micros: Option<u64>,
    #[serde(default)]
    pub detected_use_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_token_volume: Vec<DetectedUseTokenSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalFreshness {
    pub status: PersonalMeterLocalFreshnessStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_last_success_at: Option<Rfc3339Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalMeterLocalCollector {
    pub status: PersonalMeterLocalCollectorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<LocalCollectorState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_usage_reconciliation_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_started_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_finished_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<Rfc3339Timestamp>,
    #[serde(default)]
    pub last_uploaded_count: u64,
    #[serde(default)]
    pub last_scanned_session_count: u64,
    #[serde(default)]
    pub last_scanned_file_count: u64,
    #[serde(default)]
    pub last_scan_cap_hit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalMeterLocalValueStatus {
    Available,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalMeterLocalFreshnessStatus {
    Fresh,
    Stale,
    Error,
    Unsupported,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalMeterLocalCollectorStatus {
    Ok,
    Disabled,
    Failing,
    Unavailable,
    Unknown,
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

/// Display-safe default settings captured for an agent runtime.
///
/// These are config/CLI defaults, not proof that a completed session ran with
/// the same values. The backend keeps them separate from per-session selector
/// evidence (`AgentRuntimeDefaultsSnapshot`), and surfaces them on the apps
/// page, session-start defaults, and Advisor facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentRuntimeDefaults {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<Rfc3339Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_mode_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_mode: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selector_context: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub selector_sources: BTreeMap<String, String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_defaults: Option<AgentRuntimeDefaults>,
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

        if let Some(defaults) = self.runtime_defaults.as_mut() {
            defaults.model = safe_optional_text(defaults.model.take());
            defaults.service_tier = safe_optional_text(defaults.service_tier.take());
            defaults.speed_mode = safe_optional_text(defaults.speed_mode.take());
            defaults.reasoning_effort = safe_optional_text(defaults.reasoning_effort.take());
            defaults.approval_policy = safe_optional_text(defaults.approval_policy.take());
            defaults.sandbox_mode = safe_optional_text(defaults.sandbox_mode.take());
            defaults.machine_id = safe_optional_text(defaults.machine_id.take());
            defaults.provenance = safe_optional_text(defaults.provenance.take());
            defaults.selector_context = std::mem::take(&mut defaults.selector_context)
                .into_iter()
                .filter(|(key, value)| is_safe_backend_text(key) && is_safe_backend_text(value))
                .collect();
            defaults.selector_sources = std::mem::take(&mut defaults.selector_sources)
                .into_iter()
                .filter(|(key, value)| is_safe_backend_text(key) && is_safe_backend_text(value))
                .collect();
        }
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
    Resets,
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
    /// Account/subscription this diagnostic is about. `None` means the
    /// diagnostic is provider-wide (applies to the whole source / all accounts).
    /// Populated only for account-attributed diagnostics. Stripped from the
    /// backend-upload copy (see `redact_diagnostic_for_backend`), so the backend
    /// wire format is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    /// Scope hint for the local Companion. Absent on older daemons; a missing
    /// value is treated as provider-wide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AgentDiagnosticScope>,
}

impl AgentStatusDiagnostic {
    /// Provider-wide diagnostic. `scope`/`account_label` are left absent: an
    /// absent scope already means provider-wide, so the wire format is identical
    /// to before these fields existed.
    pub fn source(
        code: impl Into<String>,
        severity: AgentDiagnosticSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            account_label: None,
            scope: None,
        }
    }

    /// Diagnostic attributed to a specific account/subscription. Reserved for
    /// future per-account diagnostics — today every daemon diagnostic is
    /// provider-wide (see `source`).
    pub fn for_account(
        code: impl Into<String>,
        severity: AgentDiagnosticSeverity,
        message: impl Into<String>,
        account_label: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            account_label: Some(account_label.into()),
            scope: Some(AgentDiagnosticScope::Account),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDiagnosticScope {
    Source,
    Account,
    Organization,
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
    pub config: SourceConfigState,
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
    pub source: Option<String>,
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
    /// Guide the user to re-authenticate a failing provider that the daemon
    /// cannot repair on its own (e.g. a Pi route whose provider OAuth token has
    /// expired or been consumed). Advisory: the daemon does not perform the
    /// re-auth itself.
    ReauthProvider,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceOwnerState {
    #[serde(default)]
    pub daemon_owner: InstallOwner,
    #[serde(default)]
    pub plist_owner: InstallOwner,
    #[serde(default)]
    pub loaded_owner: InstallOwner,
    #[serde(default)]
    pub client_owner: InstallOwner,
    #[serde(default)]
    pub owner_drift: bool,
    #[serde(default)]
    pub plist_exists: bool,
    #[serde(default)]
    pub launchd_loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
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
    Dev,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_install_owner: Option<InstallOwner>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContextQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_plan_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub all_machines: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCostsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_plan_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default)]
    pub all_machines: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_plan_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(default)]
    pub all_machines: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecommendationsQuery {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProviderImpactQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
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
    PersonalMeterLocalSnapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<SourceKind>,
    },
    AgentContext {
        #[serde(default)]
        query: AgentContextQuery,
    },
    AgentCosts {
        #[serde(default)]
        query: AgentCostsQuery,
    },
    AgentSessions {
        #[serde(default)]
        query: AgentSessionsQuery,
    },
    AgentRecommendations {
        #[serde(default)]
        query: AgentRecommendationsQuery,
    },
    AgentProviderImpact {
        #[serde(default)]
        query: AgentProviderImpactQuery,
    },
    AuthStart,
    AuthComplete {
        claim_code: String,
        nonce: String,
    },
    AuthCompletePending {
        claim_code: String,
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
        #[serde(default)]
        repair: bool,
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
    // `account_label`/`scope` are Companion-local hints (and the label may carry
    // account/org text); strip them so the backend-upload wire format is
    // unchanged from before these fields existed.
    diagnostic.account_label = None;
    diagnostic.scope = None;
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
    fn agent_context_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_agent_context",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "agent_context",
            "query": {
                "days": 14,
                "range": "last_7_days",
                "timezone": "America/New_York",
                "source": "codex",
                "machine_id": "otm_test",
                "source_plan_profile_id": "018fe251-b6f3-7cc8-9f82-01a76449d111",
                "max_tokens": 4000,
                "all_machines": false
            }
        }))
        .expect("agent context request");

        assert_eq!(request.request_id, "req_agent_context");
        assert_eq!(request.client_kind, Some(LocalClientKind::Cli));
        assert_eq!(
            request.command,
            LocalControlCommand::AgentContext {
                query: AgentContextQuery {
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: None,
                    end_date: None,
                    timezone: Some("America/New_York".to_string()),
                    source: Some("codex".to_string()),
                    machine_id: Some("otm_test".to_string()),
                    source_plan_profile_id: Some(
                        "018fe251-b6f3-7cc8-9f82-01a76449d111".to_string()
                    ),
                    max_tokens: Some(4000),
                    all_machines: false,
                }
            }
        );
    }

    #[test]
    fn agent_costs_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_agent_costs",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "agent_costs",
            "query": {
                "days": 14,
                "range": "last_7_days",
                "timezone": "America/New_York",
                "source": "codex",
                "machine_id": "otm_test",
                "source_plan_profile_id": "018fe251-b6f3-7cc8-9f82-01a76449d111",
                "bucket": "day",
                "mode": "full",
                "all_machines": false
            }
        }))
        .expect("agent costs request");

        assert_eq!(
            request.command,
            LocalControlCommand::AgentCosts {
                query: AgentCostsQuery {
                    days: Some(14),
                    range: Some("last_7_days".to_string()),
                    start_date: None,
                    end_date: None,
                    timezone: Some("America/New_York".to_string()),
                    source: Some("codex".to_string()),
                    machine_id: Some("otm_test".to_string()),
                    source_plan_profile_id: Some(
                        "018fe251-b6f3-7cc8-9f82-01a76449d111".to_string()
                    ),
                    bucket: Some("day".to_string()),
                    mode: Some("full".to_string()),
                    all_machines: false,
                }
            }
        );
    }

    #[test]
    fn agent_sessions_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_agent_sessions",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "agent_sessions",
            "query": {
                "limit": 25,
                "range": "today",
                "source": "claude_code",
                "model": "claude-opus-4-8",
                "machine_id": "otm_test",
                "sort_by": "cost",
                "sort_dir": "desc",
                "search": "expensive",
                "all_machines": false
            }
        }))
        .expect("agent sessions request");

        assert_eq!(
            request.command,
            LocalControlCommand::AgentSessions {
                query: AgentSessionsQuery {
                    limit: Some(25),
                    range: Some("today".to_string()),
                    source: Some("claude_code".to_string()),
                    model: Some("claude-opus-4-8".to_string()),
                    machine_id: Some("otm_test".to_string()),
                    sort_by: Some("cost".to_string()),
                    sort_dir: Some("desc".to_string()),
                    search: Some("expensive".to_string()),
                    all_machines: false,
                    ..AgentSessionsQuery::default()
                }
            }
        );
    }

    #[test]
    fn agent_recommendations_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_agent_recommendations",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "agent_recommendations"
        }))
        .expect("agent recommendations request");

        assert_eq!(
            request.command,
            LocalControlCommand::AgentRecommendations {
                query: AgentRecommendationsQuery::default()
            }
        );
    }

    #[test]
    fn agent_provider_impact_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_agent_provider_impact",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "agent_provider_impact",
            "query": {
                "date_from": "2026-06-01",
                "date_to": "2026-06-08",
                "provider": "openai",
                "app": "codex",
                "kind": "quota",
                "confidence": "high",
                "impact_priority": "critical",
                "status": "verified",
                "q": "subscription",
                "limit": 25
            }
        }))
        .expect("agent provider impact request");

        assert_eq!(
            request.command,
            LocalControlCommand::AgentProviderImpact {
                query: AgentProviderImpactQuery {
                    date_from: Some("2026-06-01".to_string()),
                    date_to: Some("2026-06-08".to_string()),
                    provider: Some("openai".to_string()),
                    app: Some("codex".to_string()),
                    kind: Some("quota".to_string()),
                    confidence: Some("high".to_string()),
                    impact_priority: Some("critical".to_string()),
                    status: Some("verified".to_string()),
                    q: Some("subscription".to_string()),
                    limit: Some(25),
                }
            }
        );
    }

    #[test]
    fn auth_complete_pending_command_round_trips() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_auth_complete_pending",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "auth_complete_pending",
            "claim_code": "claim_123"
        }))
        .expect("auth complete pending request");

        assert_eq!(
            request.command,
            LocalControlCommand::AuthCompletePending {
                claim_code: "claim_123".to_string()
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
    fn verify_command_defaults_repair_to_false() {
        let request: LocalControlRequest = serde_json::from_value(serde_json::json!({
            "request_id": "req_verify_legacy",
            "protocol_version": PROTOCOL_VERSION,
            "client_kind": "cli",
            "command": "verify",
            "source": "codex"
        }))
        .expect("legacy verify request");

        assert_eq!(
            request.command,
            LocalControlCommand::Verify {
                source: SourceKind::Codex,
                repair: false,
            }
        );
    }

    #[test]
    fn verify_command_round_trips_repair_flags() {
        for (repair, source) in [(false, SourceKind::Codex), (true, SourceKind::ClaudeCode)] {
            let request = LocalControlRequest {
                request_id: format!("req_verify_{repair}"),
                protocol_version: PROTOCOL_VERSION,
                token: None,
                client_kind: Some(LocalClientKind::Cli),
                client_install_owner: None,
                command: LocalControlCommand::Verify {
                    source: source.clone(),
                    repair,
                },
            };
            let value = serde_json::to_value(&request).expect("verify request serializes");
            let parsed: LocalControlRequest =
                serde_json::from_value(value).expect("verify request parses");
            assert_eq!(
                parsed.command,
                LocalControlCommand::Verify { source, repair }
            );
        }
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
            diagnostics: vec![AgentStatusDiagnostic::source(
                "stderr",
                AgentDiagnosticSeverity::Warning,
                "failed reading /Users/ron/.codex/config",
            )],
            runtime_defaults: Some(AgentRuntimeDefaults {
                provenance: Some("config_file".to_string()),
                model: Some("gpt-5.4".to_string()),
                service_tier: Some("default".to_string()),
                fast_mode_enabled: Some(false),
                selector_context: BTreeMap::from([
                    ("service_tier".to_string(), "default".to_string()),
                    // Path-like value must be stripped by redaction.
                    ("leaked".to_string(), "/Users/ron/.codex/config".to_string()),
                ]),
                selector_sources: BTreeMap::from([(
                    "service_tier".to_string(),
                    "codex.config.service_tier".to_string(),
                )]),
                ..Default::default()
            }),
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
        let runtime_defaults = snapshot.runtime_defaults.expect("runtime_defaults");
        assert_eq!(runtime_defaults.service_tier.as_deref(), Some("default"));
        assert_eq!(runtime_defaults.fast_mode_enabled, Some(false));
        assert_eq!(
            runtime_defaults
                .selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("default")
        );
        assert_eq!(
            runtime_defaults
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.service_tier")
        );
        // Path-like config value is stripped by backend redaction.
        assert!(!runtime_defaults.selector_context.contains_key("leaked"));
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
    fn local_health_contract_matrix_matches_protocol_models() {
        let fixtures = local_health_contract_fixtures();
        let case_ids: std::collections::BTreeSet<_> = fixtures
            .iter()
            .map(|fixture| fixture.case_id.as_str())
            .collect();
        let required_case_ids = [
            "current_healthy_v1",
            "upgrade_0_1_27_login_sources_preserved",
            "runtime_app_daemon_mismatch_red",
            "protocol_schema_mismatch_upgrade_required",
            "stale_heartbeat_red",
            "inactive_device_red",
            "verify_failure_wins_over_old_green",
            "all_verify_failures_win_over_old_green",
            "source_removed_sync_revision",
            "backfill_success_cannot_green_current_failure",
            "homebrew_owner_conflict_red",
            "dev_owner_no_production_repair",
            "read_only_org_telemetry_controls_disabled",
            "setup_token_refresh_rebind",
            "command_idempotency_terminal_result",
            "object_authorization_rejection",
            "machine_identity_collision_reconnect",
            "corrupt_local_state_recovery",
            "clock_skew_warning",
            "diagnostics_redaction",
        ];

        assert_eq!(fixtures.len(), required_case_ids.len());
        for case_id in required_case_ids {
            assert!(
                case_ids.contains(case_id),
                "missing local health case {case_id}"
            );
        }

        for fixture in &fixtures {
            assert_eq!(
                fixture.fixture_schema_version,
                "local_health_contract_fixture.v1"
            );
            assert_eq!(fixture.contract_version, "local_machine_health.v1");
            assert_eq!(fixture.health.schema_version, 1);
            assert_eq!(
                fixture.health.schema_version_name,
                "local_machine_health.v1"
            );
            assert_eq!(fixture.health.projection_version, "health_projection.v1");
            assert_eq!(fixture.health.event_schema_version, "local_health_event.v1");
            assert!(
                fixture
                    .health
                    .capabilities
                    .iter()
                    .any(|value| value == "health.v1"),
                "{} must advertise health.v1",
                fixture.case_id
            );
            assert_eq!(fixture.expected.overall_state, fixture.health.overall.state);
            assert_eq!(
                fixture.expected.primary_blocker,
                fixture.health.overall.primary_blocker
            );
            assert_eq!(
                fixture.health.revision, fixture.health.projection_revision,
                "{} uses one canonical projection revision in Phase 0",
                fixture.case_id
            );
            for source in &fixture.health.sources {
                assert!(
                    source.projection_revision <= fixture.health.projection_revision,
                    "{} source projection revision moved past health projection",
                    fixture.case_id
                );
            }
            for event in &fixture.events {
                assert_eq!(event.machine_id, fixture.health.machine_id);
                assert_eq!(event.event_schema_version, "local_health_event.v1");
            }
            if let Some(heartbeat) = &fixture.heartbeat {
                assert_eq!(heartbeat.schema_version, "machine_runtime_heartbeat.v1");
                assert_eq!(heartbeat.machine_id, fixture.health.machine_id);
                assert_eq!(
                    heartbeat.health_projection_revision,
                    fixture.health.projection_revision
                );
            }
            if let Some(command) = &fixture.command {
                assert_eq!(command.command_schema_version, "local_command.v1");
                assert!(
                    command.expires_at > command.issued_at,
                    "{} command expiry should be after issue time",
                    fixture.case_id
                );
            }
            if let Some(result) = &fixture.command_result {
                assert_eq!(result.command_schema_version, "local_command.v1");
                assert!(
                    result.terminal,
                    "{} result should be terminal",
                    fixture.case_id
                );
                let command = fixture
                    .command
                    .as_ref()
                    .expect("command result must include command fixture");
                assert_eq!(command.action_id, result.action_id);
                assert_eq!(command.idempotency_key, result.idempotency_key);
                assert!(
                    result.completed_projection_revision >= result.started_projection_revision,
                    "{} command result projection revision regressed",
                    fixture.case_id
                );
            }
        }
    }

    #[test]
    fn local_health_fixture_contract_pins_phase_zero_edge_cases() {
        let fixtures = local_health_contract_fixtures();
        let by_id = |case_id: &str| -> &LocalHealthContractFixture {
            fixtures
                .iter()
                .find(|fixture| fixture.case_id == case_id)
                .unwrap_or_else(|| panic!("missing local health fixture {case_id}"))
        };

        let upgrade = by_id("upgrade_0_1_27_login_sources_preserved");
        assert!(upgrade.previous_stable_input.is_some());
        assert!(upgrade.expected.preserved_login);
        assert_eq!(
            upgrade.expected.preserved_sources,
            vec![SourceKind::Codex, SourceKind::ClaudeCode]
        );

        let mismatch = by_id("runtime_app_daemon_mismatch_red");
        assert!(!mismatch.health.runtime.version_match);
        assert_eq!(
            mismatch.health.overall.primary_blocker.as_deref(),
            Some("service_outdated")
        );

        let protocol = by_id("protocol_schema_mismatch_upgrade_required");
        assert!(!protocol.health.runtime.protocol_match);
        assert!(!protocol.health.runtime.schema_match);
        assert_eq!(
            protocol.health.overall.state,
            LocalHealthOverallState::UpgradeRequired
        );

        let stale = by_id("stale_heartbeat_red");
        assert_eq!(
            stale.health.account.device_state,
            LocalDeviceState::StaleHeartbeat
        );

        let inactive = by_id("inactive_device_red");
        assert_eq!(
            inactive.health.account.device_state,
            LocalDeviceState::Inactive
        );
        assert_eq!(
            inactive.health.overall.state,
            LocalHealthOverallState::ReconnectRequired
        );

        let verify = by_id("verify_failure_wins_over_old_green");
        assert_eq!(
            verify.health.sources[0].authority,
            LocalHealthAuthority::Verify
        );
        assert_eq!(
            verify.health.sources[0].state,
            LocalHealthSourceState::VerifyFailed
        );

        let all_verify = by_id("all_verify_failures_win_over_old_green");
        assert_eq!(all_verify.health.sources.len(), 3);
        assert!(all_verify
            .health
            .sources
            .iter()
            .all(|source| source.authority == LocalHealthAuthority::Verify
                && source.state == LocalHealthSourceState::VerifyFailed));

        let backfill = by_id("backfill_success_cannot_green_current_failure");
        assert!(backfill.backfill_job.is_some());
        assert_eq!(
            backfill.health.sources[0].state,
            LocalHealthSourceState::VerifyFailed
        );

        let homebrew = by_id("homebrew_owner_conflict_red");
        assert_eq!(
            homebrew.health.runtime.install_owner,
            InstallOwner::Homebrew
        );

        let dev = by_id("dev_owner_no_production_repair");
        assert_eq!(dev.health.runtime.install_owner, InstallOwner::Dev);

        let read_only = by_id("read_only_org_telemetry_controls_disabled");
        let controls = read_only
            .health
            .account
            .telemetry_controls
            .as_ref()
            .expect("read-only fixture should include telemetry controls");
        assert!(controls.read_only);
        assert!(!controls.can_enable_telemetry);
        assert!(!controls.can_disable_telemetry);

        let setup = by_id("setup_token_refresh_rebind");
        assert_eq!(
            setup.health.account.setup_token_state,
            LocalSetupTokenState::RefreshRequired
        );

        let source_removed = by_id("source_removed_sync_revision");
        assert_eq!(
            source_removed.health.sources[0].state,
            LocalHealthSourceState::Removed
        );

        let command = by_id("command_idempotency_terminal_result");
        assert_eq!(
            command
                .command_result
                .as_ref()
                .expect("command result")
                .status,
            LocalHealthCommandStatus::Deduped
        );

        let object_auth = by_id("object_authorization_rejection");
        assert_eq!(
            object_auth
                .command_result
                .as_ref()
                .expect("command result")
                .status,
            LocalHealthCommandStatus::Rejected
        );

        let collision = by_id("machine_identity_collision_reconnect");
        assert_eq!(
            collision.health.account.device_state,
            LocalDeviceState::CollisionSuspected
        );

        let corrupt = by_id("corrupt_local_state_recovery");
        assert_eq!(
            corrupt.health.overall.primary_blocker.as_deref(),
            Some("local_state_recovery_required")
        );

        let skew = by_id("clock_skew_warning");
        assert_eq!(skew.health.overall.state, LocalHealthOverallState::Degraded);

        let diagnostics = by_id("diagnostics_redaction");
        assert_eq!(
            diagnostics.health.sources[0].authority,
            LocalHealthAuthority::Diagnostics
        );
    }

    #[test]
    fn diagnostics_local_health_fixture_is_redacted() {
        let fixtures = local_health_contract_fixtures();
        let diagnostics = fixtures
            .iter()
            .find(|fixture| fixture.case_id == "diagnostics_redaction")
            .expect("diagnostics fixture");
        let encoded =
            serde_json::to_string(diagnostics).expect("diagnostics fixture should serialize");
        for forbidden in [
            "sk-",
            "ghp_",
            "password=",
            concat!("BEGIN ", "PRIVATE KEY"),
            "raw_cookie",
            "hardware_serial_value",
            "setup_secret_value",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "diagnostics fixture leaked forbidden marker {forbidden}"
            );
        }
    }

    #[test]
    #[ignore = "Phase 1+ reducer work: fixtures are present, runtime reducer is not implemented yet"]
    fn local_health_reducer_replays_contract_matrix() {
        let fixtures = local_health_contract_fixtures();
        assert!(
            !fixtures.is_empty(),
            "future reducer should replay each fixture into its expected health state"
        );
    }

    fn local_health_contract_fixtures() -> Vec<LocalHealthContractFixture> {
        serde_json::from_str(include_str!(
            "../../../fixtures/local-health/contract-matrix.v1.json"
        ))
        .expect("local health contract matrix should deserialize")
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
        let request = serde_json::from_str::<LocalControlRequest>(&format!(
            r#"{{"request_id":"req_test","protocol_version":{PROTOCOL_VERSION},"command":"diagnostics_collect"}}"#
        ))
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
    fn personal_meter_local_snapshot_command_round_trips() {
        let request = serde_json::from_str::<LocalControlRequest>(&format!(
            r#"{{"request_id":"req_meter","protocol_version":{PROTOCOL_VERSION},"command":"personal_meter_local_snapshot","source":"codex"}}"#
        ))
        .expect("personal meter local snapshot request should deserialize");

        assert_eq!(
            request.command,
            LocalControlCommand::PersonalMeterLocalSnapshot {
                source: Some(SourceKind::Codex),
            }
        );
        let encoded = serde_json::to_value(request).expect("request serializes");
        assert_eq!(
            encoded["command"],
            serde_json::json!("personal_meter_local_snapshot")
        );
        assert_eq!(encoded["source"], serde_json::json!("codex"));
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
        assert!(error
            .to_string()
            .contains(&format!("expected {PROTOCOL_VERSION}")));
    }

    #[test]
    fn detected_use_serializes_to_swift_contract_keys() {
        let detected = DetectedUse {
            gateway_provider: "vertex".to_string(),
            plan_fingerprint: Some("pro::20604".to_string()),
            account_identifier_hash: Some("hash123".to_string()),
            subscription_product: Some("pro".to_string()),
            account_label: Some("Pro".to_string()),
            last_seen_at: "2026-05-28T10:00:00Z".to_string(),
            token_volume_recent: vec![DetectedUseTokenSample {
                at: "2026-05-28T09:00:00Z".to_string(),
                tokens: 4096,
            }],
            quota_window_state: DetectedUseQuotaWindowState::NearLimit,
            quota_used_percent: Some(82),
            quota_resets_at: Some("2026-06-01T00:00:00Z".to_string()),
        };
        let value = serde_json::to_value(&detected).expect("detected use serializes");
        let object = value.as_object().expect("detected use is a JSON object");
        // Every key the Swift `DetectedUse.CodingKeys` contract decodes, in
        // snake_case. If any drifts the Companion panel silently empties.
        let expected_keys = [
            "gateway_provider",
            "plan_fingerprint",
            "account_identifier_hash",
            "subscription_product",
            "account_label",
            "last_seen_at",
            "token_volume_recent",
            "quota_window_state",
            "quota_used_percent",
            "quota_resets_at",
        ];
        for key in expected_keys {
            assert!(object.contains_key(key), "missing JSON key {key}");
        }
        assert_eq!(object.len(), expected_keys.len(), "unexpected extra keys");
        assert_eq!(object["gateway_provider"], serde_json::json!("vertex"));
        assert_eq!(
            object["quota_window_state"],
            serde_json::json!("near_limit")
        );
        assert_eq!(object["quota_used_percent"], serde_json::json!(82));
        assert_eq!(
            object["token_volume_recent"],
            serde_json::json!([{"at": "2026-05-28T09:00:00Z", "tokens": 4096}])
        );

        let parsed: DetectedUse = serde_json::from_value(value).expect("round-trips");
        assert_eq!(parsed, detected);
    }

    #[test]
    fn detected_use_quota_window_state_uses_snake_case_slugs() {
        for (variant, slug) in [
            (DetectedUseQuotaWindowState::Ok, "ok"),
            (DetectedUseQuotaWindowState::NearLimit, "near_limit"),
            (DetectedUseQuotaWindowState::Exhausted, "exhausted"),
            (DetectedUseQuotaWindowState::RateLimited, "rate_limited"),
            (DetectedUseQuotaWindowState::Stale, "stale"),
            (DetectedUseQuotaWindowState::Error, "error"),
            (DetectedUseQuotaWindowState::Unsupported, "unsupported"),
            (DetectedUseQuotaWindowState::Unknown, "unknown"),
        ] {
            let encoded = serde_json::to_string(&variant).expect("state serializes");
            assert_eq!(encoded, format!("\"{slug}\""));
            let decoded: DetectedUseQuotaWindowState =
                serde_json::from_str(&encoded).expect("state deserializes");
            assert_eq!(decoded, variant);
        }
    }

    #[test]
    fn detected_use_omits_none_optionals_and_empty_samples() {
        let detected = DetectedUse {
            gateway_provider: "anthropic".to_string(),
            plan_fingerprint: None,
            account_identifier_hash: None,
            subscription_product: None,
            account_label: None,
            last_seen_at: "2026-05-28T10:00:00Z".to_string(),
            token_volume_recent: Vec::new(),
            quota_window_state: DetectedUseQuotaWindowState::Unknown,
            quota_used_percent: None,
            quota_resets_at: None,
        };
        let object = serde_json::to_value(&detected)
            .expect("serializes")
            .as_object()
            .cloned()
            .expect("object");
        // Lenient-decoder contract: None optionals are omitted entirely; the
        // required keys remain so the Swift decoder never falls back blindly.
        assert!(!object.contains_key("plan_fingerprint"));
        assert!(!object.contains_key("quota_used_percent"));
        assert_eq!(object["token_volume_recent"], serde_json::json!([]));
        assert_eq!(object["quota_window_state"], serde_json::json!("unknown"));
    }

    #[test]
    fn personal_meter_snapshot_keeps_local_evidence_out_of_totals() {
        let snapshot = PersonalMeterLocalSnapshot {
            schema_version: "personal_meter.local_snapshot.v1".to_string(),
            generated_at: "2026-06-17T09:00:00Z".to_string(),
            machine_id: "machine_test".to_string(),
            sources: vec![PersonalMeterLocalSourceSnapshot {
                source: SourceKind::Codex,
                app: "codex".to_string(),
                included_in_totals: false,
                provider: Some("openai".to_string()),
                account: Some(PersonalMeterLocalAccount {
                    login_state: AgentLoginState::SignedIn,
                    label: Some("ron@example.com".to_string()),
                    account_identifier_hash: Some("acct_hash".to_string()),
                    confidence: AgentStatusConfidence::High,
                }),
                model: Some("gpt-5-codex".to_string()),
                plan: Some("ChatGPT Plus".to_string()),
                quota_windows: Vec::new(),
                pending_local_delta: PersonalMeterLocalDelta {
                    status: PersonalMeterLocalValueStatus::Unknown,
                    included_in_totals: false,
                    basis: "backend_inclusion_watermark_unavailable".to_string(),
                    since: None,
                    until: None,
                    total_tokens: None,
                    request_count: None,
                    estimated_cost_usd_micros: None,
                    detected_use_count: 1,
                    recent_token_volume: vec![DetectedUseTokenSample {
                        at: "2026-06-17T08:00:00Z".to_string(),
                        tokens: 2048,
                    }],
                },
                freshness: PersonalMeterLocalFreshness {
                    status: PersonalMeterLocalFreshnessStatus::Fresh,
                    captured_at: Some("2026-06-17T08:55:00Z".to_string()),
                    expires_at: Some("2026-06-17T09:10:00Z".to_string()),
                    last_seen_at: Some("2026-06-17T08:55:00Z".to_string()),
                    last_verified_at: Some("2026-06-17T08:55:00Z".to_string()),
                    collector_last_success_at: Some("2026-06-17T08:56:00Z".to_string()),
                },
                collector: PersonalMeterLocalCollector {
                    status: PersonalMeterLocalCollectorStatus::Ok,
                    state: Some(LocalCollectorState::Warm),
                    local_usage_reconciliation_enabled: Some(true),
                    last_scan_started_at: Some("2026-06-17T08:55:30Z".to_string()),
                    last_scan_finished_at: Some("2026-06-17T08:56:00Z".to_string()),
                    last_success_at: Some("2026-06-17T08:56:00Z".to_string()),
                    last_uploaded_count: 1,
                    last_scanned_session_count: 1,
                    last_scanned_file_count: 1,
                    last_scan_cap_hit: false,
                    collector_version: Some("local-enriched/1".to_string()),
                    parser_version: Some("codex-jsonl/1".to_string()),
                },
                confidence: AgentStatusConfidence::High,
                warnings: Vec::new(),
                recommendation: None,
            }],
        };

        let value = serde_json::to_value(&snapshot).expect("snapshot serializes");
        assert_eq!(
            value["sources"][0]["included_in_totals"],
            serde_json::json!(false)
        );
        assert_eq!(
            value["sources"][0]["pending_local_delta"]["included_in_totals"],
            serde_json::json!(false)
        );
        assert_eq!(
            value["sources"][0]["pending_local_delta"]["status"],
            serde_json::json!("unknown")
        );
        assert_eq!(
            value["sources"][0]["pending_local_delta"]["basis"],
            serde_json::json!("backend_inclusion_watermark_unavailable")
        );

        let parsed: PersonalMeterLocalSnapshot =
            serde_json::from_value(value).expect("snapshot round-trips");
        assert_eq!(parsed, snapshot);
    }
}
