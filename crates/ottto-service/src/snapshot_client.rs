use crate::snapshots::{SnapshotBatchRequest, SnapshotSource};
use anyhow::{anyhow, Result};
use ottto_core::{
    compiled_release_version, redact_inline, ControlTokenStore, FileDeviceStore,
    KeychainSecretStore, LocalDeviceBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
};
use ottto_protocol::{AgentStatusSnapshot, LocalMachineHealthV1, MachineRuntimeHeartbeatV1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

// Direct API host; the apex `ottto.net/backend` proxy is retired in the marketing cutover.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const SNAPSHOT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const SNAPSHOT_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const SNAPSHOT_BATCH_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(120);
const SNAPSHOT_HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOUD_SESSION_HEARTBEAT_ACK_SCHEMA_VERSION: &str = "cloud_session_heartbeat_ack.v1";
const CLOUD_SCAN_CHUNK_ACK_SCHEMA_VERSION: &str = "cloud_session_scan_chunk_ack.v1";
const CLOUD_SCAN_FINALIZE_ACK_SCHEMA_VERSION: &str = "cloud_session_scan_finalize_ack.v1";

/// The backend rejected a snapshot batch because the payload did not satisfy the
/// strict daemon/backend contract. Carries the redacted response body so support
/// can see the actual validator failure instead of guessing schema-version drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRejected {
    pub status: u16,
    pub body_excerpt: Option<String>,
}

impl std::fmt::Display for BatchRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.body_excerpt.as_deref() {
            Some(body) => write!(
                f,
                "backend rejected snapshot batch payload: HTTP {} body_excerpt={}",
                self.status, body
            ),
            None => write!(
                f,
                "backend rejected snapshot batch payload: HTTP {}",
                self.status
            ),
        }
    }
}

impl std::error::Error for BatchRejected {}

/// The backend refused a snapshot batch before payload validation because the
/// relay authorization was missing, stale, or not permitted for this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchAuthorizationRejected {
    pub status: u16,
}

impl std::fmt::Display for BatchAuthorizationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected snapshot batch authorization: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for BatchAuthorizationRejected {}

/// The dedicated cloud-session ingest route rejected the relay principal.
/// Kept typed so the transport can refresh once without inspecting response
/// bodies or logging token-adjacent material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudSessionAuthorizationRejected {
    pub status: u16,
}

impl std::fmt::Display for CloudSessionAuthorizationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected cloud-session relay authorization: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for CloudSessionAuthorizationRejected {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudSessionContractRejected {
    pub status: u16,
}

impl std::fmt::Display for CloudSessionContractRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected cloud-session observation contract: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for CloudSessionContractRejected {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudSessionHeartbeatAckV1 {
    schema_version: String,
    accepted: bool,
    observations_written: u32,
    noop: bool,
    grant_status: String,
    fresh_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudSessionScanChunkAckV1 {
    schema_version: String,
    accepted: bool,
    scan_id: String,
    chunk_index: u8,
    chunk_identity_digest: String,
    chunk_semantic_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudSessionScanFinalizeAckV1 {
    schema_version: String,
    accepted: bool,
    scan_id: String,
    chunk_count: u8,
    unique_entity_count: u32,
    inventory_digest: String,
    epoch_digest: String,
}

/// The backend refused to mint a relay token for this local device. Keep this
/// typed so the daemon can mark canonical local health as an auth/rebind issue
/// instead of treating the projection as merely delayed by a transient upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTokenAuthorizationRejected {
    pub status: u16,
}

impl std::fmt::Display for RelayTokenAuthorizationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected relay token authorization: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for RelayTokenAuthorizationRejected {}

/// The backend rejected the local-health contract payload. Keep this distinct
/// from transport failures so the daemon never calls schema drift "unreachable".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHealthProjectionRejected {
    pub status: u16,
}

impl std::fmt::Display for LocalHealthProjectionRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected local health projection: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for LocalHealthProjectionRejected {}

/// The backend refused the relay token on a local-health upload endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalHealthAuthorizationRejected {
    pub status: u16,
}

impl std::fmt::Display for LocalHealthAuthorizationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected local health authorization: HTTP {}",
            self.status
        )
    }
}

impl std::error::Error for LocalHealthAuthorizationRejected {}

/// Redacted upload failure classification for field diagnostics. This never
/// carries raw response bodies, request IDs, tokens, account IDs, or machine IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadFailureDiagnostics {
    operation: &'static str,
    endpoint: &'static str,
    status_family: &'static str,
    retryable: bool,
    request_id_present: bool,
}

impl UploadFailureDiagnostics {
    fn http(
        operation: &'static str,
        endpoint: &'static str,
        status: u16,
        response: &ureq::Response,
    ) -> Self {
        Self {
            operation,
            endpoint,
            status_family: http_status_family(status),
            retryable: http_status_retryable(status),
            request_id_present: response_has_request_id(response),
        }
    }

    pub(crate) fn transport(
        operation: &'static str,
        endpoint: &'static str,
        error: &ureq::Error,
    ) -> Self {
        Self {
            operation,
            endpoint,
            status_family: transport_status_family(error),
            retryable: true,
            request_id_present: false,
        }
    }

    /// The redacted failure family (`transport_connection`, `http_5xx`, ...).
    /// `net_resilience` keys the transport-layer outage streak on this.
    pub(crate) fn status_family(&self) -> &'static str {
        self.status_family
    }

    pub fn safe_message(&self) -> String {
        format!(
            "{} failed (endpoint={}, status_family={}, retryable={}, request_id={})",
            self.operation,
            self.endpoint,
            self.status_family,
            self.retryable,
            if self.request_id_present {
                "present"
            } else {
                "absent"
            }
        )
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        operation: &'static str,
        endpoint: &'static str,
        status_family: &'static str,
        retryable: bool,
        request_id_present: bool,
    ) -> Self {
        Self {
            operation,
            endpoint,
            status_family,
            retryable,
            request_id_present,
        }
    }
}

impl std::fmt::Display for UploadFailureDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.safe_message())
    }
}

impl std::error::Error for UploadFailureDiagnostics {}

#[derive(Clone, Deserialize)]
pub struct ActivityHintResponse {
    pub source: String,
    pub server_time: String,
    pub last_data_at: Option<String>,
    pub record_count_15m: u64,
    pub record_count_24h: u64,
    pub local_usage_reconciliation_enabled: bool,
    pub backfill_window_days: u64,
    #[serde(default = "default_true")]
    pub session_titles_enabled: bool,
    #[serde(default = "default_true")]
    pub workspace_labels_enabled: bool,
    #[serde(default)]
    pub session_artifacts_enabled: bool,
    // Opt-out (default on). The backend resolves the full cascade (telemetry-off
    // / source-disabled / harvest-off ⇒ false); the daemon honors it per cycle.
    // Defaults true so an older backend that omits the field keeps harvesting.
    #[serde(default = "default_true")]
    pub mcp_inventory_harvest_enabled: bool,
    #[serde(default = "default_true")]
    pub context_footprint_harvest_enabled: bool,
    #[serde(default)]
    pub session_attribution_enabled: bool,
    #[serde(default)]
    pub session_attribution_hmac_key: Option<String>,
    #[serde(default)]
    pub session_attribution_hmac_key_version: Option<String>,
    pub recommended_scan_after: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotBatchResponse {
    pub accepted: u64,
    pub sessions_reconciled: u64,
    pub session_ids: Vec<String>,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotStatusRequest {
    pub schema_version: u16,
    pub source: String,
    pub machine_id: String,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
    pub last_scan_started_at: Option<String>,
    pub last_scan_finished_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_error_code: Option<String>,
    pub last_error_message: Option<String>,
    pub last_uploaded_count: u64,
    pub last_scanned_session_count: u64,
    pub last_scanned_file_count: u64,
    pub last_backfill_window_days: u64,
    pub last_backfill_file_limit: u64,
    pub last_discovered_file_count: u64,
    pub last_skipped_file_count_due_to_limit: u64,
    pub last_scan_cap_hit: bool,
    pub consecutive_failures: u64,
    pub next_retry_at: Option<String>,
    pub collector_version: Option<String>,
    pub parser_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotStatusResponse {
    pub accepted: bool,
    pub source: String,
    pub machine_id: String,
    pub disabled: bool,
    pub disabled_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentStatusSnapshotUploadRequest {
    pub machine_id: String,
    pub snapshots: Vec<AgentStatusSnapshot>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentStatusSnapshotUploadResponse {
    pub accepted: u64,
    pub machine_id: String,
    pub sources: Vec<String>,
    /// AI-generated machine icon the web shows, echoed back by the backend so the
    /// daemon can surface it on `status.machine.icon_url`. Absent on older
    /// backends (serde default → None).
    #[serde(default)]
    pub machine_icon_url: Option<String>,
    #[serde(default)]
    pub machine_icon_version: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct RelayTokenResponse {
    token: String,
}

pub fn relay_token_request_payload(device: &LocalDeviceBinding, source: &str) -> Value {
    let mut payload = json!({
        "source": source,
        "platform": std::env::consts::OS,
        "client_name": "ottto-service",
        "client_version": compiled_release_version(),
    });
    if let Some(machine_id) = device.machine_id.as_deref().map(str::trim) {
        if !machine_id.is_empty() {
            payload["machine_id"] = json!(machine_id);
        }
    }
    payload
}

#[derive(Debug, Clone)]
pub struct SnapshotApiClient {
    api_base_url: String,
    agent: ureq::Agent,
    batch_agent: ureq::Agent,
}

impl SnapshotApiClient {
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("OTTTO_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string()),
        )
    }

    pub fn new(api_base_url: impl Into<String>) -> Self {
        // Clients are constructed per sync/upload cycle, but the underlying
        // agents (and their connection pools) are process-wide and shared with
        // every other upload path, so a warm connection anywhere benefits all
        // subsystems and a sustained DNS outage rebuilds them in one place.
        // See `net_resilience` for the 2026-07-15 incident this hardens against.
        let (agent, batch_agent) = crate::net_resilience::shared_agents();
        Self {
            api_base_url: api_base_url.into(),
            agent,
            batch_agent,
        }
    }

    pub fn issue_relay_token(
        &self,
        device: &LocalDeviceBinding,
        device_secret: &str,
        source: SnapshotSource,
    ) -> Result<String> {
        self.issue_relay_token_with_agent(
            &self.agent,
            device,
            device_secret,
            source,
            SNAPSHOT_HTTP_READ_TIMEOUT,
        )
    }

    pub fn issue_relay_token_with_timeout(
        &self,
        device: &LocalDeviceBinding,
        device_secret: &str,
        source: SnapshotSource,
        timeout: Duration,
    ) -> Result<String> {
        let (agent, request_timeout) = cloud_session_deadline_agent(timeout)?;
        self.issue_relay_token_with_agent(&agent, device, device_secret, source, request_timeout)
    }

    fn issue_relay_token_with_agent(
        &self,
        agent: &ureq::Agent,
        device: &LocalDeviceBinding,
        device_secret: &str,
        source: SnapshotSource,
        timeout: Duration,
    ) -> Result<String> {
        let url = self.api_url(&format!(
            "/api/v1/telemetry/devices/{}/relay-token",
            device.device_id
        ));
        let response: RelayTokenResponse = agent
            .post(&url)
            .timeout(timeout)
            .set("Accept", "application/json")
            .set("X-Ottto-Device-Secret", device_secret)
            .send_json(relay_token_request_payload(device, source.api_slug()))
            .map_err(|error| match error {
                ureq::Error::Status(status @ (401 | 403), _response) => {
                    anyhow::Error::new(RelayTokenAuthorizationRejected { status })
                }
                ureq::Error::Status(status, response) => {
                    anyhow::Error::new(UploadFailureDiagnostics::http(
                        "relay token request",
                        "relay_token",
                        status,
                        &response,
                    ))
                }
                other => anyhow::Error::new(UploadFailureDiagnostics::transport(
                    "relay token request",
                    "relay_token",
                    &other,
                )),
            })?
            .into_json()
            .map_err(|error| anyhow!("parse relay token response failed: {error}"))?;
        Ok(response.token)
    }

    pub fn get_activity_hint(&self, relay_token: &str) -> Result<ActivityHintResponse> {
        self.agent
            .get(&self.api_url("/api/v1/agent-session-snapshots/activity-hints"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .call()
            // Typed diagnostics (not a plain string) so a transport-layer
            // failure on this early per-source call feeds the outage streak.
            .map_err(|error| match error {
                ureq::Error::Status(status, response) => {
                    anyhow::Error::new(UploadFailureDiagnostics::http(
                        "activity hint request",
                        "activity_hint",
                        status,
                        &response,
                    ))
                }
                other => anyhow::Error::new(UploadFailureDiagnostics::transport(
                    "activity hint request",
                    "activity_hint",
                    &other,
                )),
            })?
            .into_json()
            .map_err(|error| anyhow!("parse activity hint response failed: {error}"))
    }

    pub fn upload_batch(
        &self,
        relay_token: &str,
        request: &SnapshotBatchRequest,
    ) -> Result<SnapshotBatchResponse> {
        match self
            .batch_agent
            .post(&self.api_url("/api/v1/agent-session-snapshots/batches"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse snapshot batch response failed: {error}")),
            // 401/403 means relay authorization failed, not schema drift.
            // Keep it typed and body-free so the caller can surface an auth
            // diagnostic without leaking backend details or token-adjacent text.
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(BatchAuthorizationRejected {
                    status: code,
                }))
            }
            // Validation-like statuses mean the backend refused the payload
            // contract. Keep a redacted/truncated body excerpt so field logs show
            // the exact validator failure (for example, missing usage_buckets)
            // without leaking tokens, paths, account IDs, or machine IDs.
            Err(ureq::Error::Status(code @ (400 | 422), response)) => {
                Err(anyhow::Error::new(BatchRejected {
                    status: code,
                    body_excerpt: response_body_excerpt(response),
                }))
            }
            Err(ureq::Error::Status(code, response)) => {
                Err(anyhow::Error::new(UploadFailureDiagnostics::http(
                    "local snapshot upload",
                    "snapshot_batch",
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "local snapshot upload",
                "snapshot_batch",
                &error,
            ))),
        }
    }

    pub fn report_status(
        &self,
        relay_token: &str,
        request: &SnapshotStatusRequest,
    ) -> Result<SnapshotStatusResponse> {
        self.agent
            .post(&self.api_url("/api/v1/agent-session-snapshots/status"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
            // Typed diagnostics (not a plain string) so a transport-layer
            // failure on a status receipt feeds the outage streak.
            .map_err(|error| match error {
                ureq::Error::Status(status, response) => {
                    anyhow::Error::new(UploadFailureDiagnostics::http(
                        "snapshot status report",
                        "snapshot_status",
                        status,
                        &response,
                    ))
                }
                other => anyhow::Error::new(UploadFailureDiagnostics::transport(
                    "snapshot status report",
                    "snapshot_status",
                    &other,
                )),
            })?
            .into_json()
            .map_err(|error| anyhow!("parse snapshot status response failed: {error}"))
    }

    pub fn upload_agent_status(
        &self,
        relay_token: &str,
        request: &AgentStatusSnapshotUploadRequest,
    ) -> Result<AgentStatusSnapshotUploadResponse> {
        match self
            .agent
            .post(&self.api_url("/api/v1/agent-status/snapshots"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse agent status response failed: {error}")),
            Err(ureq::Error::Status(code, response)) => {
                Err(anyhow::Error::new(UploadFailureDiagnostics::http(
                    "agent status upload",
                    "agent_status",
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "agent status upload",
                "agent_status",
                &error,
            ))),
        }
    }

    /// POST a configured-MCP inventory capture to the footprint ingest endpoint.
    ///
    /// Auth is the same source-scoped relay token used for snapshot batches; the
    /// backend validates the relay principal and enforces the agent_source
    /// scope. The body is the pre-built `McpInventoryIngestRequest` JSON. A
    /// 401/403 surfaces as a relay-authorization error so the caller can refresh
    /// credentials; 400/422 means the inventory contract drifted.
    pub fn upload_mcp_inventory(&self, relay_token: &str, request: &Value) -> Result<Value> {
        match self
            .agent
            .post(&self.api_url("/api/v1/mcp/inventory"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse mcp inventory response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(RelayTokenAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow!("backend rejected mcp inventory: HTTP {code}"))
            }
            Err(error) => Err(anyhow!("upload mcp inventory failed: {error}")),
        }
    }

    pub fn upload_context_footprint(&self, relay_token: &str, request: &Value) -> Result<Value> {
        match self
            .agent
            .post(&self.api_url("/api/v1/context-footprint/snapshot"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse context footprint response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(RelayTokenAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow!("backend rejected context footprint: HTTP {code}"))
            }
            Err(error) => Err(anyhow!("upload context footprint failed: {error}")),
        }
    }

    /// Upload one bounded, content-free cloud-session batch using the same
    /// source-scoped relay principal as local snapshots. Response bodies are
    /// never retained on auth/contract failures.
    pub fn upload_cloud_session_batch(&self, relay_token: &str, request: &Value) -> Result<Value> {
        self.upload_cloud_session_batch_with_timeout(
            relay_token,
            request,
            SNAPSHOT_HTTP_READ_TIMEOUT,
        )
    }

    pub fn upload_cloud_session_batch_with_timeout(
        &self,
        relay_token: &str,
        request: &Value,
        timeout: Duration,
    ) -> Result<Value> {
        let (agent, request_timeout) = cloud_session_deadline_agent(timeout)?;
        match agent
            .post(&self.api_url("/api/v1/cloud-session-observations/batches"))
            .timeout(request_timeout)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => {
                let receipt = response.into_json().map_err(|error| {
                    anyhow!("parse cloud-session batch response failed: {error}")
                })?;
                validate_cloud_session_heartbeat_receipt(request, &receipt)?;
                Ok(receipt)
            }
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(CloudSessionAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 404 | 409 | 422), _response)) => {
                Err(anyhow::Error::new(CloudSessionContractRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code, response)) => {
                Err(anyhow::Error::new(UploadFailureDiagnostics::http(
                    "cloud-session upload",
                    "cloud_session_batch",
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "cloud-session upload",
                "cloud_session_batch",
                &error,
            ))),
        }
    }

    /// Upload one idempotent positive-observation chunk for a bounded v2 scan.
    pub fn upload_cloud_session_scan_chunk(
        &self,
        relay_token: &str,
        scan_id: &str,
        request: &Value,
    ) -> Result<Value> {
        self.upload_cloud_session_scan_chunk_with_timeout(
            relay_token,
            scan_id,
            request,
            SNAPSHOT_HTTP_READ_TIMEOUT,
        )
    }

    pub fn upload_cloud_session_scan_chunk_with_timeout(
        &self,
        relay_token: &str,
        scan_id: &str,
        request: &Value,
        timeout: Duration,
    ) -> Result<Value> {
        self.upload_cloud_session_scan_request(
            relay_token,
            scan_id,
            "chunks",
            request,
            "cloud_session_scan_chunk",
            timeout,
        )
    }

    /// Finalize an ordered v2 scan epoch after every chunk is acknowledged.
    pub fn finalize_cloud_session_scan(
        &self,
        relay_token: &str,
        scan_id: &str,
        request: &Value,
    ) -> Result<Value> {
        self.finalize_cloud_session_scan_with_timeout(
            relay_token,
            scan_id,
            request,
            SNAPSHOT_HTTP_READ_TIMEOUT,
        )
    }

    pub fn finalize_cloud_session_scan_with_timeout(
        &self,
        relay_token: &str,
        scan_id: &str,
        request: &Value,
        timeout: Duration,
    ) -> Result<Value> {
        self.upload_cloud_session_scan_request(
            relay_token,
            scan_id,
            "finalize",
            request,
            "cloud_session_scan_finalize",
            timeout,
        )
    }

    fn upload_cloud_session_scan_request(
        &self,
        relay_token: &str,
        scan_id: &str,
        action: &str,
        request: &Value,
        operation: &'static str,
        timeout: Duration,
    ) -> Result<Value> {
        if !valid_cloud_scan_id(scan_id)
            || request.get("scan_id").and_then(Value::as_str) != Some(scan_id)
        {
            return Err(anyhow!(
                "cloud-session scan path and payload scan_id are invalid or do not match"
            ));
        }
        let (agent, request_timeout) = cloud_session_deadline_agent(timeout)?;
        let path = format!("/api/v1/cloud-sessions/scans/{scan_id}/{action}");
        match agent
            .post(&self.api_url(&path))
            .timeout(request_timeout)
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => {
                let receipt = response.into_json().map_err(|error| {
                    anyhow!("parse cloud-session scan response failed: {error}")
                })?;
                validate_cloud_session_scan_receipt(action, request, &receipt)?;
                Ok(receipt)
            }
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(CloudSessionAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 404 | 409 | 422), _response)) => {
                Err(anyhow::Error::new(CloudSessionContractRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code, response)) => {
                Err(anyhow::Error::new(UploadFailureDiagnostics::http(
                    "cloud-session scan upload",
                    operation,
                    code,
                    &response,
                )))
            }
            Err(error) => Err(anyhow::Error::new(UploadFailureDiagnostics::transport(
                "cloud-session scan upload",
                operation,
                &error,
            ))),
        }
    }

    /// POST a per-day context-composition capture to the composition ingest
    /// endpoint. Auth is the same source-scoped relay token used for snapshot
    /// batches; the backend validates the relay principal and enforces the
    /// agent_source scope. The body is the pre-built request JSON (aggregates
    /// only; the backend rejects unknown fields and absolute paths with 422).
    pub fn upload_context_composition(&self, relay_token: &str, request: &Value) -> Result<Value> {
        match self
            .agent
            .post(&self.api_url("/api/v1/context-composition/snapshot"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse context composition response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(RelayTokenAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow!("backend rejected context composition: HTTP {code}"))
            }
            Err(error) => Err(anyhow!("upload context composition failed: {error}")),
        }
    }

    pub fn upload_local_health_heartbeat(
        &self,
        relay_token: &str,
        request: &MachineRuntimeHeartbeatV1,
    ) -> Result<Value> {
        match self
            .agent
            .post(&self.api_url("/api/v1/apps/health/heartbeat"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse local health heartbeat response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(LocalHealthAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow::Error::new(LocalHealthProjectionRejected {
                    status: code,
                }))
            }
            Err(error) => Err(anyhow!("upload local health heartbeat failed: {error}")),
        }
    }

    pub fn upload_local_health_projection(
        &self,
        relay_token: &str,
        request: &LocalMachineHealthV1,
    ) -> Result<Value> {
        match self
            .agent
            .post(&self.api_url("/api/v1/apps/health/projection"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse local health projection response failed: {error}")),
            Err(ureq::Error::Status(code @ (401 | 403), _response)) => {
                Err(anyhow::Error::new(LocalHealthAuthorizationRejected {
                    status: code,
                }))
            }
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow::Error::new(LocalHealthProjectionRejected {
                    status: code,
                }))
            }
            Err(error) => Err(anyhow!("upload local health projection failed: {error}")),
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.api_base_url.trim_end_matches('/'), path)
    }
}

fn valid_cloud_scan_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn validate_cloud_session_heartbeat_receipt(request: &Value, receipt: &Value) -> Result<()> {
    let ack: CloudSessionHeartbeatAckV1 = serde_json::from_value(receipt.clone())
        .map_err(|error| anyhow!("invalid cloud-session heartbeat receipt: {error}"))?;
    let collected_at = request
        .get("collected_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("cloud-session heartbeat request is missing collected_at"))?;
    let observed_at = request
        .pointer("/health/observed_at")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("cloud-session heartbeat request is missing health.observed_at"))?;
    if ack.schema_version != CLOUD_SESSION_HEARTBEAT_ACK_SCHEMA_VERSION
        || !ack.accepted
        || ack.observations_written != 0
        || !ack.noop
        || ack.grant_status != "enabled"
        || ack.fresh_at != collected_at
        || ack.fresh_at != observed_at
        || OffsetDateTime::parse(&ack.fresh_at, &Rfc3339).is_err()
    {
        return Err(anyhow!(
            "cloud-session heartbeat receipt does not acknowledge the exact heartbeat"
        ));
    }
    Ok(())
}

fn validate_cloud_session_scan_receipt(
    action: &str,
    request: &Value,
    receipt: &Value,
) -> Result<()> {
    let request_string = |field: &str| {
        request
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("cloud-session scan request is missing {field}"))
    };
    match action {
        "chunks" => {
            let ack: CloudSessionScanChunkAckV1 = serde_json::from_value(receipt.clone())
                .map_err(|error| anyhow!("invalid cloud-session chunk receipt: {error}"))?;
            let chunk_index = request
                .get("chunk_index")
                .and_then(Value::as_u64)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| anyhow!("cloud-session chunk request is missing chunk_index"))?;
            if ack.schema_version != CLOUD_SCAN_CHUNK_ACK_SCHEMA_VERSION
                || !ack.accepted
                || ack.scan_id != request_string("scan_id")?
                || ack.chunk_index != chunk_index
                || ack.chunk_identity_digest != request_string("chunk_identity_digest")?
                || ack.chunk_semantic_digest != request_string("chunk_semantic_digest")?
            {
                return Err(anyhow!(
                    "cloud-session chunk receipt does not acknowledge the exact request"
                ));
            }
        }
        "finalize" => {
            let ack: CloudSessionScanFinalizeAckV1 = serde_json::from_value(receipt.clone())
                .map_err(|error| anyhow!("invalid cloud-session finalize receipt: {error}"))?;
            let request_u64 = |field: &str| {
                request
                    .get(field)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow!("cloud-session finalize request is missing {field}"))
            };
            if ack.schema_version != CLOUD_SCAN_FINALIZE_ACK_SCHEMA_VERSION
                || !ack.accepted
                || ack.scan_id != request_string("scan_id")?
                || u64::from(ack.chunk_count) != request_u64("chunk_count")?
                || u64::from(ack.unique_entity_count) != request_u64("unique_entity_count")?
                || ack.inventory_digest != request_string("inventory_digest")?
                || ack.epoch_digest != request_string("epoch_digest")?
            {
                return Err(anyhow!(
                    "cloud-session finalize receipt does not acknowledge the exact request"
                ));
            }
        }
        _ => return Err(anyhow!("unsupported cloud-session scan action")),
    }
    Ok(())
}

pub(crate) fn timeout_agent(read_timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(SNAPSHOT_HTTP_CONNECT_TIMEOUT)
        .timeout_read(read_timeout)
        .timeout_write(SNAPSHOT_HTTP_WRITE_TIMEOUT)
        // Disable idle keep-alive connection reuse on this shared upload agent.
        // After a network transition (VPN flap / macOS en0 MAGICWAKE wake) ureq
        // 2.12.1 pooled a keep-alive socket bound to the now-dead local IP and
        // reused it — its liveness peek only detects a peer-closed socket, not a
        // locally-dead one — so every upload failed status_family=
        // transport_connection until a manual daemon restart (2026-07-17
        // incident, ~2.75h stall). ureq 2.12.1 exposes no idle-age/TTL knob, so
        // setting max_idle_connections(0) to disable idle reuse is the only way
        // to bound stale-socket reuse short of rebuilding the agent: every
        // request opens a fresh connect and can never reuse a socket bound to a
        // dead local IP. Intentional tradeoff: this forfeits the shared pool's
        // warm-socket survival that #234 relied on, but DNS-incident coverage is
        // retained independently by the FallbackDnsResolver below, and the cost
        // is one extra TCP+TLS handshake per request at the 5-min/60-s upload
        // cadence (bounded by the 5-s connect timeout) — negligible. Do NOT
        // apply this to the OTLP UPSTREAM_HTTP_AGENT, whose warm pool is
        // intentional.
        .max_idle_connections(0)
        // Survive process-local resolver breakage (pinned scoped-DNS state
        // after a VPN/network transition): fall back to an out-of-process
        // probe, then the last successfully resolved addresses. TLS SNI and
        // certificate validation still use the URL hostname.
        .resolver(crate::net_resilience::shared_fallback_resolver())
        .build()
}

/// Build a one-shot agent whose DNS and HTTP phases share the caller's hard
/// budget. `ureq::Request::timeout` begins only after resolution, so using the
/// shared resolver here would let a blocked `getaddrinfo` escape the scan
/// deadline. Half the budget is reserved for DNS and the remainder for the
/// request; neither phase can consume the other's allocation.
fn cloud_session_deadline_agent(timeout: Duration) -> Result<(ureq::Agent, Duration)> {
    let dns_timeout = timeout / 2;
    let request_timeout = timeout.saturating_sub(dns_timeout);
    if dns_timeout.is_zero() || request_timeout.is_zero() {
        return Err(anyhow!("cloud-session request deadline is too small"));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(SNAPSHOT_HTTP_CONNECT_TIMEOUT.min(request_timeout))
        .timeout_read(request_timeout)
        .timeout_write(SNAPSHOT_HTTP_WRITE_TIMEOUT.min(request_timeout))
        .max_idle_connections(0)
        .resolver(crate::net_resilience::deadline_fallback_resolver(
            dns_timeout,
        ))
        .build();
    Ok((agent, request_timeout))
}

fn http_status_family(status: u16) -> &'static str {
    match status {
        400..=499 => {
            if status == 429 {
                "http_429"
            } else {
                "http_4xx"
            }
        }
        500..=599 => "http_5xx",
        300..=399 => "http_3xx",
        _ => "http_other",
    }
}

fn http_status_retryable(status: u16) -> bool {
    status == 408
        || status == 409
        || status == 425
        || status == 429
        || (500..=599).contains(&status)
}

fn transport_status_family(error: &ureq::Error) -> &'static str {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("timed out") || text.contains("timeout") {
        "transport_timeout"
    } else if text.contains("dns") || text.contains("resolve") {
        "transport_dns"
    } else if text.contains("tls") || text.contains("certificate") {
        "transport_tls"
    } else if text.contains("connection") || text.contains("connect") {
        "transport_connection"
    } else {
        "transport_error"
    }
}

fn response_has_request_id(response: &ureq::Response) -> bool {
    [
        "x-request-id",
        "x-correlation-id",
        "x-amzn-requestid",
        "x-amz-request-id",
        "x-amz-cf-id",
    ]
    .iter()
    .any(|header| response.header(header).is_some())
}

fn response_body_excerpt(response: ureq::Response) -> Option<String> {
    response
        .into_string()
        .ok()
        .and_then(|body| safe_response_body_excerpt(&body))
}

fn safe_response_body_excerpt(body: &str) -> Option<String> {
    let compact = body
        .split_whitespace()
        .take(80)
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return None;
    }
    Some(truncate_diagnostic(&redact_inline(&compact)))
}

fn truncate_diagnostic(value: &str) -> String {
    const MAX_DIAGNOSTIC_CHARS: usize = 500;
    if value.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return value.to_string();
    }
    let mut truncated = value.chars().take(MAX_DIAGNOSTIC_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

pub fn load_snapshot_device_credentials() -> Result<(LocalDeviceBinding, String)> {
    let device = FileDeviceStore::default()
        .load()?
        .ok_or_else(|| anyhow!("relay device binding is missing"))?;
    let secret = KeychainSecretStore::new(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT)
        .load()
        .map_err(|error| anyhow!("relay device secret is missing: {error}"))?;
    Ok((device, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshots::{CODEX_SNAPSHOT_PARSER_VERSION, SNAPSHOT_SCHEMA_VERSION};

    #[test]
    fn batch_rejected_downcasts_from_anyhow_and_keeps_status() {
        // The upload_batch validation path wraps BatchRejected in anyhow::Error;
        // the snapshot_sync caller relies on downcast_ref to choose the loud
        // payload-validation diagnostic over the generic network-error path.
        let err = anyhow::Error::new(BatchRejected {
            status: 422,
            body_excerpt: Some(
                r#"{"detail":"usage_buckets are required for schema_version 6 usage snapshots"}"#
                    .to_string(),
            ),
        });
        let rejected = err
            .downcast_ref::<BatchRejected>()
            .expect("BatchRejected must downcast from anyhow::Error");
        assert_eq!(rejected.status, 422);
        assert!(rejected
            .body_excerpt
            .as_deref()
            .expect("body")
            .contains("usage_buckets"));
        assert!(err.to_string().contains("422"));
        assert!(err.to_string().contains("usage_buckets"));

        // A plain transport error must NOT masquerade as a schema rejection.
        let other = anyhow!("upload snapshot batch failed: connection refused");
        assert!(other.downcast_ref::<BatchRejected>().is_none());
    }

    #[test]
    fn batch_authorization_rejected_downcasts_separately_from_schema_rejection() {
        let err = anyhow::Error::new(BatchAuthorizationRejected { status: 401 });
        let rejected = err
            .downcast_ref::<BatchAuthorizationRejected>()
            .expect("BatchAuthorizationRejected must downcast from anyhow::Error");
        assert_eq!(rejected.status, 401);
        assert!(err.to_string().contains("401"));
        assert!(err.to_string().contains("authorization"));
        assert!(err.downcast_ref::<BatchRejected>().is_none());
    }

    #[test]
    fn upload_failure_diagnostics_are_classified_and_redacted() {
        assert_eq!(http_status_family(500), "http_5xx");
        assert_eq!(http_status_family(429), "http_429");
        assert_eq!(http_status_family(404), "http_4xx");
        assert!(http_status_retryable(500));
        assert!(http_status_retryable(429));
        assert!(!http_status_retryable(404));

        let diagnostics = UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_5xx",
            true,
            true,
        );
        assert_eq!(
            diagnostics.safe_message(),
            "local snapshot upload failed (endpoint=snapshot_batch, status_family=http_5xx, retryable=true, request_id=present)"
        );
        assert!(!diagnostics.safe_message().contains("req_"));
        assert!(!diagnostics.safe_message().contains("Bearer"));
    }

    #[test]
    fn resolver_failure_through_real_agent_classifies_as_transport_dns() {
        // The 2026-07-15 incident signature: in-process DNS resolution fails
        // persistently for a long-running daemon. The failure must classify as
        // transport_dns end-to-end through the real ureq stack so field logs
        // and the resilience layer key off the right family.
        let resolver = crate::net_resilience::FallbackDnsResolver::with_hooks(
            |_| {
                Err(std::io::Error::other(
                    "simulated getaddrinfo failure after network transition",
                ))
            },
            |_| None,
        );
        let agent = ureq::AgentBuilder::new().resolver(resolver).build();

        let error = agent
            .post("http://ottto-transport-dns.test/api/v1/telemetry")
            .call()
            .expect_err("resolution must fail");

        assert_eq!(transport_status_family(&error), "transport_dns");
        let diagnostics =
            UploadFailureDiagnostics::transport("relay token request", "relay_token", &error);
        assert_eq!(
            diagnostics.safe_message(),
            "relay token request failed (endpoint=relay_token, status_family=transport_dns, retryable=true, request_id=absent)"
        );
    }

    #[test]
    fn relay_token_authorization_rejected_downcasts_separately() {
        let err = anyhow::Error::new(RelayTokenAuthorizationRejected { status: 403 });
        let rejected = err
            .downcast_ref::<RelayTokenAuthorizationRejected>()
            .expect("RelayTokenAuthorizationRejected must downcast from anyhow::Error");
        assert_eq!(rejected.status, 403);
        assert!(err.to_string().contains("403"));
        assert!(err.to_string().contains("relay token authorization"));
        assert!(err.downcast_ref::<BatchAuthorizationRejected>().is_none());
        assert!(err.downcast_ref::<BatchRejected>().is_none());
    }

    #[test]
    fn local_health_rejections_downcast_separately() {
        let rejected = anyhow::Error::new(LocalHealthProjectionRejected { status: 422 });
        assert!(rejected
            .downcast_ref::<LocalHealthProjectionRejected>()
            .is_some());
        assert!(rejected
            .downcast_ref::<LocalHealthAuthorizationRejected>()
            .is_none());
        assert!(rejected
            .downcast_ref::<RelayTokenAuthorizationRejected>()
            .is_none());

        let unauthorized = anyhow::Error::new(LocalHealthAuthorizationRejected { status: 401 });
        assert!(unauthorized
            .downcast_ref::<LocalHealthAuthorizationRejected>()
            .is_some());
        assert!(unauthorized
            .downcast_ref::<LocalHealthProjectionRejected>()
            .is_none());
    }

    #[test]
    fn api_urls_are_joined_without_double_slashes() {
        let client = SnapshotApiClient::new("https://ottto.test/backend/");
        assert_eq!(
            client.api_url("/api/v1/agent-session-snapshots/status"),
            "https://ottto.test/backend/api/v1/agent-session-snapshots/status"
        );
        assert_eq!(
            client.api_url("/api/v1/agent-status/snapshots"),
            "https://ottto.test/backend/api/v1/agent-status/snapshots"
        );
    }

    #[test]
    fn cloud_scan_path_rejects_mismatched_payload_scan_id_before_io() {
        let client = SnapshotApiClient::new("http://127.0.0.1:1");
        let error = client
            .upload_cloud_session_scan_chunk(
                "relay-token",
                "00000000-0000-4000-8000-000000000001",
                &json!({"scan_id":"00000000-0000-4000-8000-000000000002"}),
            )
            .unwrap_err();
        assert!(error.to_string().contains("scan_id are invalid"));
    }

    #[test]
    fn snapshot_batch_timeout_covers_initial_backfill_reconciliation() {
        // Initial backfills can synchronously reconcile many historical
        // sessions. Keep the longer read window scoped to batch uploads so
        // health/status calls still fail quickly when production is unhealthy.
        assert!(SNAPSHOT_BATCH_HTTP_READ_TIMEOUT >= Duration::from_secs(120));
        assert!(SNAPSHOT_HTTP_READ_TIMEOUT <= Duration::from_secs(15));
    }

    #[test]
    fn snapshot_rejection_body_excerpt_is_redacted_and_bounded() {
        let token = format!("ghp_{}", "AbCdEf1234567890aaaaaaaaaaaaaaaaaa");
        let body = format!(
            "{{\"detail\":\"usage_buckets are required Authorization: Bearer {token} machine_id otm_1234567890abcdef path /Users/ron/.codex/sessions/a.jsonl\"}}"
        );
        let excerpt = safe_response_body_excerpt(&body).expect("excerpt");
        assert!(excerpt.contains("usage_buckets"));
        assert!(excerpt.contains("[REDACTED]"));
        assert!(excerpt.contains("[machine_id]"));
        assert!(excerpt.contains("[path]"));
        assert!(!excerpt.contains("/Users/ron"));
        assert!(excerpt.chars().count() <= 503);
    }

    #[test]
    fn status_payload_uses_safe_error_fields() {
        let status = SnapshotStatusRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: "codex".to_string(),
            machine_id: "otm_test".to_string(),
            enabled: true,
            disabled_reason: None,
            last_scan_started_at: None,
            last_scan_finished_at: None,
            last_success_at: None,
            last_error_code: Some("auth_error".to_string()),
            last_error_message: Some("relay device credentials are missing".to_string()),
            last_uploaded_count: 0,
            last_scanned_session_count: 0,
            last_scanned_file_count: 0,
            last_backfill_window_days: 183,
            last_backfill_file_limit: 1_000,
            last_discovered_file_count: 1_100,
            last_skipped_file_count_due_to_limit: 100,
            last_scan_cap_hit: true,
            consecutive_failures: 1,
            next_retry_at: None,
            collector_version: Some("0.1.0".to_string()),
            parser_version: Some(CODEX_SNAPSHOT_PARSER_VERSION.to_string()),
        };
        let serialized = serde_json::to_string(&status).expect("serialize");
        assert!(!serialized.contains(".codex"));
        assert!(!serialized.contains("/Users/"));
    }
}
