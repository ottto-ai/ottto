//! protocol for local control.

use crate::control::AgentStatusSnapshot;
use crate::control::BTreeMap;
use crate::control::Deserialize;
use crate::control::DiagnosticsBundle;
use crate::control::DiagnosticsUploadAuthorization;
use crate::control::Duration;
use crate::control::InstallOwner;
use crate::control::LocalApiError;
use crate::control::LocalConnectionBinding;
use crate::control::PendingDeviceCredentialRequestAuthority;
use crate::control::PriorDeviceCredential;
use crate::control::ReleaseChannel;
use crate::control::SecretString;
use crate::control::Serialize;
use crate::control::SourceVerificationResult;
use crate::control::DEFAULT_API_BASE_URL;

#[derive(Debug, Serialize)]
pub(super) struct DiagnosticsUploadBody<'a> {
    pub(super) bundle: &'a DiagnosticsBundle,
    pub(super) approval: DiagnosticsUploadApprovalSummary,
    pub(super) client: DiagnosticsUploadClient,
}

#[derive(Debug, Serialize)]
pub(super) struct DiagnosticsUploadApprovalSummary {
    pub(super) approved: bool,
    pub(super) retention_disclosure_accepted: bool,
    pub(super) retention_disclosure: &'static str,
    pub(super) authorization: DiagnosticsUploadAuthorization,
    pub(super) support_claim_provided: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct DiagnosticsUploadClient {
    pub(super) protocol_version: u16,
    pub(super) local_platform_version: String,
    pub(super) machine_id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DiagnosticsUploadResponse {
    pub(super) upload_id: Option<String>,
    pub(super) uploaded_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendControlTokenClaims {
    pub(super) organization_id: Option<String>,
    pub(super) user_id: Option<String>,
    pub(super) device_id: Option<String>,
    pub(super) key_id: Option<String>,
    pub(super) token_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct BackendControlTokenValidationRequest {
    pub(super) token: String,
    pub(super) source: String,
    pub(super) action: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct BackendControlTokenValidationResponse {
    pub(super) organization_id: Option<String>,
    pub(super) user_id: Option<String>,
    pub(super) device_id: Option<String>,
    pub(super) key_id: Option<String>,
    pub(super) token_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct SetupClaimCreateResponse {
    #[serde(default)]
    pub(super) client_nonce: Option<String>,
    pub(super) claim_code: String,
    pub(super) claim_token: String,
    pub(super) claim_url: String,
    pub(super) expires_at: String,
}

impl std::fmt::Debug for SetupClaimCreateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetupClaimCreateResponse([redacted])")
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupClaimCompleteResponse {
    pub(super) setup_run_id: String,
    pub(super) setup_run_token: String,
    pub(super) setup_run_token_expires_at: String,
    pub(super) machine_id: Option<String>,
    pub(super) relay_device: Option<SetupClaimCompleteRelayDevice>,
    pub(super) relay_device_secret: Option<String>,
    #[serde(default)]
    pub(super) relay_device_credential_preparation: Option<DeviceCredentialPreparationApiResponse>,
    pub(super) connected_at: String,
    pub(super) user: SetupClaimCompleteUser,
    pub(super) organization: SetupClaimCompleteOrganization,
    /// Additive local-history backfill policy ("full" | "from"); absent on old
    /// backends, which means full-backfill behavior (same as "full").
    #[serde(default)]
    pub(super) backfill_policy: Option<String>,
    /// Server-UTC takeover moment accompanying `backfill_policy: "from"`.
    #[serde(default)]
    pub(super) backfill_cutoff_at: Option<String>,
}

/// Claim completion plus the exact prior authority snapshot used to authorize
/// it. Deliberately has no `Debug` implementation because it owns a Keychain
/// secret until the non-secret recovery journal is staged.
pub(super) struct SetupClaimCompletion {
    pub(super) response: SetupClaimCompleteResponse,
    pub(super) prior_device_credential: Option<PriorDeviceCredential>,
    pub(super) request_authority: PendingDeviceCredentialRequestAuthority,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupClaimCompleteRelayDevice {
    pub(super) id: String,
    pub(super) machine_id: Option<String>,
    pub(super) sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupClaimCompleteUser {
    pub(super) id: String,
    pub(super) email: String,
    pub(super) display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupClaimCompleteOrganization {
    pub(super) id: String,
    pub(super) name: String,
}

pub(super) fn api_url(path: &str) -> String {
    let base =
        std::env::var("OTTTO_API_BASE_URL").unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string());
    format!("{}{}", base.trim_end_matches('/'), path)
}

pub(super) fn append_nonce_to_claim_url(claim_url: &str, nonce: &str) -> String {
    let separator = if claim_url.contains('?') { '&' } else { '?' };
    format!("{claim_url}{separator}nonce={nonce}")
}

pub(super) fn to_value(value: impl Serialize) -> Result<serde_json::Value, LocalApiError> {
    serde_json::to_value(value).or_state_poisoned()
}

/// Maps any failure of a local state read or write to `StatePoisoned`; the
/// cause is not reported.
pub(super) trait OrStatePoisoned<T> {
    fn or_state_poisoned(self) -> Result<T, LocalApiError>;
}

impl<T, E> OrStatePoisoned<T> for Result<T, E> {
    fn or_state_poisoned(self) -> Result<T, LocalApiError> {
        self.map_err(|_| LocalApiError::StatePoisoned)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ReleaseManifest {
    pub(super) schema_version: u16,
    pub(super) product: String,
    pub(super) version: String,
    pub(super) channel: ReleaseChannel,
    pub(super) commit: String,
    pub(super) min_supported_version: String,
    pub(super) min_protocol_version: u16,
    pub(super) supported_install_owners: Vec<InstallOwner>,
    #[serde(default)]
    pub(super) release_notes: Option<String>,
    pub(super) rollback: ReleaseRollback,
    #[serde(default)]
    pub(super) artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReleaseRollback {
    pub(super) strategy: String,
    pub(super) immutable_prefix: String,
    pub(super) latest_manifest_url: String,
    pub(super) preserve_failed_version: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReleaseArtifact {
    pub(super) kind: String,
    pub(super) platform: String,
    pub(super) arch: String,
    pub(super) url: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupRunAttachResponse {
    pub(super) setup_run_id: String,
    pub(super) setup_run_token: String,
    pub(super) expires_at: String,
    pub(super) run: SetupRunApiRun,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SetupRunDetailApiResponse {
    pub(super) run: SetupRunApiRun,
    #[serde(default)]
    pub(super) sources: Vec<SetupRunSourceApiResponse>,
    pub(super) next_action: Option<SetupRunActionApiResponse>,
    pub(super) next_question: Option<serde_json::Value>,
    // Web claim URL the app opens when a setup run waits on browser approval
    // (e.g. a verify_source that found no fresh telemetry transitions to
    // waiting_for_user). Surfaced to the Swift app so it can open the re-claim
    // tab instead of leaving the user stuck on "waiting for approval".
    #[serde(default)]
    pub(super) setup_claim_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SetupRunApiRun {
    pub(super) id: String,
    pub(super) status: String,
    pub(super) machine_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SetupRunSourceApiResponse {
    pub(super) source: String,
    pub(super) detected: bool,
    pub(super) readiness_percent: u64,
    pub(super) state: String,
    #[serde(default)]
    pub(super) missing_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) local_import_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) live_telemetry_required: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct SetupRunActionApiResponse {
    pub(super) id: String,
    pub(super) action_type: String,
    pub(super) source: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SetupScanPayload {
    pub(super) machine: BTreeMap<String, serde_json::Value>,
    pub(super) companion: BTreeMap<String, serde_json::Value>,
    pub(super) relay_runtime: BTreeMap<String, serde_json::Value>,
    pub(super) service: BTreeMap<String, serde_json::Value>,
    pub(super) sources: Vec<SetupScanSource>,
    pub(super) missing_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SetupScanSource {
    pub(super) source: &'static str,
    /// When this scan observed the source. The backend reads it before the
    /// status row's own `captured_at`, which may be an earlier cached reading.
    pub(super) captured_at: String,
    pub(super) detected: bool,
    pub(super) installed: bool,
    pub(super) telemetry_installed: bool,
    pub(super) local_health: &'static str,
    pub(super) missing_fields: Vec<String>,
    pub(super) attribution_guess: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) agent_status: Option<AgentStatusSnapshot>,
    /// Redacted preview of the on-disk Ottto-managed fence region, so the
    /// dashboard's "View managed config" modal shows what is really
    /// configured on this machine instead of a canned template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) managed_config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) local_import_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) live_telemetry_required: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(super) struct SetupActionResult {
    pub(super) action_id: String,
    pub(super) action_type: String,
    pub(super) source: Option<String>,
    pub(super) status: String,
    pub(super) detail: Option<SetupRunDetailApiResponse>,
    /// The result a verify_source action computed; it appears only in the
    /// response of the call that ran the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) verification: Option<SourceVerificationResult>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupRunRefreshResponse {
    pub(super) run: Option<SetupRunApiRun>,
    pub(super) setup_run_id: Option<String>,
    pub(super) setup_run_token: String,
    pub(super) expires_at: String,
}

#[derive(Debug, Clone)]
pub(super) struct RefreshedSetupRunToken {
    pub(super) run: Option<SetupRunApiRun>,
    pub(super) setup_run_token: String,
    pub(super) connection: LocalConnectionBinding,
}

#[derive(Debug, Clone)]
pub(super) struct SetupRunCredentials {
    pub(super) setup_run_token: String,
    pub(super) connection: LocalConnectionBinding,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupRunDisconnectResponse {
    pub(super) setup_run_id: String,
    #[allow(dead_code, reason = "part of the server response shape; not read")]
    pub(super) run_status: String,
    #[allow(dead_code, reason = "part of the server response shape; not read")]
    pub(super) client_disconnected: bool,
    pub(super) disconnected_at: String,
    /// True only when the server authenticated the release proof and revoked
    /// this Mac's device registration. Older servers omit the field.
    #[serde(default)]
    pub(super) device_released: bool,
    #[serde(default)]
    pub(super) revocation_receipt: Option<SecretString>,
}

/// This Mac's active relay-device id and secret, presented on a cloud
/// disconnect so the server can release the device registration. Read before
/// any local deletion. Secret; redacted from `Debug` and never logged.
pub(super) struct DeviceReleaseProof {
    pub(super) device_id: String,
    pub(super) device_secret: String,
}

impl std::fmt::Debug for DeviceReleaseProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceReleaseProof")
            .field("device_id", &self.device_id)
            .field("device_secret", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DeviceSelfReleaseResponse {
    pub(super) device_released: bool,
    #[serde(default)]
    pub(super) revocation_receipt: Option<SecretString>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupRunNextActionResponse {
    #[serde(default)]
    pub(super) run_status: Option<String>,
    pub(super) action: Option<SetupRunActionApiResponse>,
}

pub(super) struct SetupActionEvent<'a> {
    pub(super) event_type: &'a str,
    pub(super) status: &'a str,
    pub(super) message: &'a str,
    pub(super) metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct InstallSessionApiResponse {
    pub(super) install_session_id: String,
    pub(super) install_session_token: String,
}

#[derive(Clone, Deserialize)]
pub(super) struct DeviceCredentialPreparationApiResponse {
    pub(super) preparation_id: String,
    pub(super) capability: String,
    pub(super) expires_at: String,
    pub(super) credential_generation: u64,
    pub(super) device: TelemetryDeviceApiResponse,
    pub(super) candidate_secret: String,
    #[serde(default)]
    pub(super) identity_continuity_capability: Option<String>,
    pub(super) credential_rotation_planned: bool,
    #[serde(default)]
    pub(super) prior_device_id: Option<String>,
}

impl std::fmt::Debug for DeviceCredentialPreparationApiResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceCredentialPreparationApiResponse")
            .field("preparation_id", &"[redacted]")
            .field("capability", &self.capability)
            .field("expires_at", &self.expires_at)
            .field("credential_generation", &self.credential_generation)
            .field("device", &"[redacted]")
            .field("candidate_secret", &"[redacted]")
            .field(
                "identity_continuity_capability",
                &self.identity_continuity_capability,
            )
            .field(
                "credential_rotation_planned",
                &self.credential_rotation_planned,
            )
            .field("prior_device_id", &self.prior_device_id)
            .finish()
    }
}

#[derive(Deserialize)]
pub(super) struct DeviceCredentialConfirmationApiResponse {
    pub(super) preparation_id: String,
    pub(super) status: String,
    pub(super) confirmed_at: String,
    pub(super) credential_generation: u64,
    pub(super) device: TelemetryDeviceApiResponse,
    #[serde(default)]
    pub(super) identity_continuity_capability: Option<String>,
    pub(super) credential_rotation_performed: bool,
    #[serde(default)]
    pub(super) rotated_prior_device_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeviceCredentialPreparationStatusApiResponse {
    pub(super) preparation_id: String,
    pub(super) status: String,
    pub(super) expires_at: String,
    pub(super) credential_generation: u64,
    pub(super) device: TelemetryDeviceApiResponse,
    #[serde(default)]
    pub(super) confirmed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct TelemetryDeviceApiResponse {
    pub(super) id: String,
    pub(super) machine_id: Option<String>,
    #[serde(default)]
    pub(super) sources: Vec<String>,
}

pub(super) struct InstallSessionEvent<'a> {
    pub(super) event_type: &'a str,
    pub(super) status: &'a str,
    pub(super) message: &'a str,
    pub(super) metadata: Option<serde_json::Value>,
    pub(super) device_id: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SetupRunVerificationResponse {
    pub(super) verified: bool,
    pub(super) records_seen: u64,
    pub(super) last_record_id: Option<String>,
    pub(super) last_received_at: Option<String>,
    pub(super) smoke_after: String,
    #[serde(default)]
    pub(super) error_code: Option<String>,
    #[serde(default)]
    pub(super) clear_condition: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct SetupRunVerificationFilters {
    pub(super) model: Option<String>,
    pub(super) model_provider: Option<String>,
    pub(super) billing_provider: Option<String>,
}

#[derive(Clone, Copy)]
pub(super) struct SetupVerificationTimeouts {
    pub(super) wait: Duration,
    pub(super) request: Duration,
}
