use crate::snapshots::{SnapshotBatchRequest, SnapshotSource};
use anyhow::{anyhow, Result};
use ottto_core::{
    ControlTokenStore, FileDeviceStore, KeychainSecretStore, LocalDeviceBinding,
    OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
};
use ottto_protocol::AgentStatusSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::json;

const DEFAULT_API_BASE_URL: &str = "https://ottto.net/backend";

/// The backend rejected a snapshot batch with an HTTP 4xx. This is almost
/// always a daemon<->backend schema/contract mismatch (the daemon emitting a
/// shape the backend's strict validator refuses), not a transient transport
/// fault. Surfaced as a typed error so `snapshot_sync` can emit a loud,
/// specific diagnostic and report a `schema_rejected` collector status instead
/// of burying it as a generic `network_error` — the failure mode that let the
/// v5->v6 break run silently.
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
}

#[derive(Debug, Clone, Deserialize)]
struct RelayTokenResponse {
    token: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotApiClient {
    api_base_url: String,
}

impl SnapshotApiClient {
    pub fn from_env() -> Self {
        Self {
            api_base_url: std::env::var("OTTTO_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_API_BASE_URL.to_string()),
        }
    }

    pub fn new(api_base_url: impl Into<String>) -> Self {
        Self {
            api_base_url: api_base_url.into(),
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
        let response: RelayTokenResponse = ureq::post(&url)
            .set("Accept", "application/json")
            .set("X-Ottto-Device-Secret", device_secret)
            .send_json(json!({ "source": source.api_slug() }))
            .map_err(|error| anyhow!("issue relay token failed: {error}"))?
            .into_json()
            .map_err(|error| anyhow!("parse relay token response failed: {error}"))?;
        Ok(response.token)
    }

    pub fn get_activity_hint(&self, relay_token: &str) -> Result<ActivityHintResponse> {
        ureq::get(&self.api_url("/api/v1/agent-session-snapshots/activity-hints"))
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
        match ureq::post(&self.api_url("/api/v1/agent-session-snapshots/batches"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
        {
            Ok(response) => response
                .into_json()
                .map_err(|error| anyhow!("parse snapshot batch response failed: {error}")),
            // 4xx = the backend refused the payload (schema/contract mismatch),
            // not a transient fault. Tag it typed so the caller can be loud and
            // specific. We deliberately do NOT echo the response body: it can
            // carry backend-internal detail, and the status code plus the daemon
            // schema version is enough to diagnose and act on.
            Err(ureq::Error::Status(code, _response)) if (400..500).contains(&code) => {
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
        ureq::post(&self.api_url("/api/v1/agent-session-snapshots/status"))
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
        ureq::post(&self.api_url("/api/v1/agent-status/snapshots"))
            .set("Accept", "application/json")
            .set("Authorization", &format!("Bearer {relay_token}"))
            .send_json(request)
            .map_err(|error| anyhow!("upload agent status failed: {error}"))?
            .into_json()
            .map_err(|error| anyhow!("parse agent status response failed: {error}"))
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.api_base_url.trim_end_matches('/'), path)
    }
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
        // The upload_batch 4xx path wraps BatchRejected in anyhow::Error; the
        // snapshot_sync caller relies on downcast_ref to choose the loud
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
