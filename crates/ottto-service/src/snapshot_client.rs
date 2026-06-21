use crate::snapshots::{SnapshotBatchRequest, SnapshotSource};
use anyhow::{anyhow, Result};
use ottto_core::{
    compiled_release_version, ControlTokenStore, FileDeviceStore, KeychainSecretStore,
    LocalDeviceBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
};
use ottto_protocol::{AgentStatusSnapshot, LocalMachineHealthV1, MachineRuntimeHeartbeatV1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

// Direct API host; the apex `ottto.net/backend` proxy is retired in the marketing cutover.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const SNAPSHOT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SNAPSHOT_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const SNAPSHOT_BATCH_HTTP_READ_TIMEOUT: Duration = Duration::from_secs(120);
const SNAPSHOT_HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// The backend rejected a snapshot batch because the payload did not satisfy the
/// strict daemon/backend contract. Surfaced as a typed error so `snapshot_sync`
/// can emit a loud, specific diagnostic and report `schema_rejected` instead of
/// burying real contract drift as a generic upload failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchRejected {
    pub status: u16,
}

impl std::fmt::Display for BatchRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend rejected snapshot batch: HTTP {} (likely daemon/backend schema mismatch)",
            self.status
        )
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

#[derive(Debug, Clone, Deserialize)]
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
        Self {
            api_base_url: std::env::var("OTTTO_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string()),
            agent: timeout_agent(SNAPSHOT_HTTP_READ_TIMEOUT),
            batch_agent: timeout_agent(SNAPSHOT_BATCH_HTTP_READ_TIMEOUT),
        }
    }

    pub fn new(api_base_url: impl Into<String>) -> Self {
        Self {
            api_base_url: api_base_url.into(),
            agent: timeout_agent(SNAPSHOT_HTTP_READ_TIMEOUT),
            batch_agent: timeout_agent(SNAPSHOT_BATCH_HTTP_READ_TIMEOUT),
        }
    }

    pub fn issue_relay_token(
        &self,
        device: &LocalDeviceBinding,
        device_secret: &str,
        source: SnapshotSource,
    ) -> Result<String> {
        let url = self.api_url(&format!(
            "/api/v1/telemetry/devices/{}/relay-token",
            device.device_id
        ));
        let response: RelayTokenResponse = self
            .agent
            .post(&url)
            .set("Accept", "application/json")
            .set("X-Ottto-Device-Secret", device_secret)
            .send_json(relay_token_request_payload(device, source.api_slug()))
            .map_err(|error| match error {
                ureq::Error::Status(status @ (401 | 403), _response) => {
                    anyhow::Error::new(RelayTokenAuthorizationRejected { status })
                }
                other => anyhow!("issue relay token failed: {other}"),
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
            .map_err(|error| anyhow!("get activity hint failed: {error}"))?
            .into_json()
            .map_err(|error| anyhow!("parse activity hint failed: {error}"))
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
            // contract. We deliberately do NOT echo the response body: it can
            // carry backend-internal detail, and the status code plus daemon
            // schema version is enough to diagnose and act on.
            Err(ureq::Error::Status(code @ (400 | 422), _response)) => {
                Err(anyhow::Error::new(BatchRejected { status: code }))
            }
            Err(error) => Err(anyhow!("upload snapshot batch failed: {error}")),
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
            .map_err(|error| anyhow!("report snapshot status failed: {error}"))?
            .into_json()
            .map_err(|error| anyhow!("parse snapshot status response failed: {error}"))
    }

    pub fn upload_agent_status(
        &self,
        relay_token: &str,
        request: &AgentStatusSnapshotUploadRequest,
    ) -> Result<AgentStatusSnapshotUploadResponse> {
        self.agent
            .post(&self.api_url("/api/v1/agent-status/snapshots"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
            .map_err(|error| anyhow!("upload agent status failed: {error}"))?
            .into_json()
            .map_err(|error| anyhow!("parse agent status response failed: {error}"))
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

fn timeout_agent(read_timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(SNAPSHOT_HTTP_CONNECT_TIMEOUT)
        .timeout_read(read_timeout)
        .timeout_write(SNAPSHOT_HTTP_WRITE_TIMEOUT)
        .build()
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
        // schema-mismatch diagnostic over the generic network-error path.
        let err = anyhow::Error::new(BatchRejected { status: 422 });
        let rejected = err
            .downcast_ref::<BatchRejected>()
            .expect("BatchRejected must downcast from anyhow::Error");
        assert_eq!(rejected.status, 422);
        assert!(err.to_string().contains("422"));
        assert!(err.to_string().contains("schema mismatch"));

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
    fn snapshot_batch_timeout_covers_initial_backfill_reconciliation() {
        // Initial backfills can synchronously reconcile many historical
        // sessions. Keep the longer read window scoped to batch uploads so
        // health/status calls still fail quickly when production is unhealthy.
        assert!(SNAPSHOT_BATCH_HTTP_READ_TIMEOUT >= Duration::from_secs(120));
        assert!(SNAPSHOT_HTTP_READ_TIMEOUT <= Duration::from_secs(15));
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
